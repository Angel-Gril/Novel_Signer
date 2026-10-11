"""Fresh ELF factory composition against original ARM64, with explicit services.

No native pages feed the model. Sample names, payloads and decoded constructor
values remain private runtime data. Frees/finalizers are logical effects.
"""
from pathlib import Path
import argparse,hashlib,json
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM,ARM64_OP_REG
import verify_vm9_alternative_root_20261011 as v
import verify_vm9_alternative_ast_module_code_20261011 as code
from vm9_allocator import _read_span,_write_span,RefillUnsupported
alternative=v.alternative
ARENA=0x79000000;ARENA_SIZE=0x1000000


def constructor_inputs(pages,base,frame):
 dis=Cs(CS_ARCH_ARM64,CS_MODE_ARM);dis.detail=True;regs={'sp':frame,'xzr':0};writes=[]
 def reg(op):
  name=dis.reg_name(op.reg);return 'x'+name[1:] if name.startswith('w') else name
 def val(op):
  if op.type==ARM64_OP_IMM:return op.imm<<op.shift.value
  assert op.type==ARM64_OP_REG;return regs[reg(op)]
 for i in dis.disasm(_read_span(pages,base+0x29ECB8,0x29F2C8-0x29ECB8),0x29ECB8):
  ops=i.operands
  if i.mnemonic=='adrp':regs[reg(ops[0])]=base+ops[1].imm
  elif i.mnemonic=='add':regs[reg(ops[0])]=val(ops[1])+val(ops[2])
  elif i.mnemonic=='mov':regs[reg(ops[0])]=val(ops[1])
  elif i.mnemonic=='movk':
   name=reg(ops[0]);shift=ops[1].shift.value;regs[name]=(regs[name]&~(65535<<shift))|val(ops[1])
  else:
   assert i.mnemonic in ('str','strb') and dis.reg_name(ops[1].mem.base)=='sp' and not i.writeback
   width=1 if i.mnemonic=='strb' else 4 if dis.reg_name(ops[0].reg).startswith('w') else 8
   address=frame+ops[1].mem.disp;value=val(ops[0])
   _write_span(pages,address,value.to_bytes(width,'little'));writes.append((i.address,address-frame,width,value))
 assert [regs['x'+str(i)] for i in (0,1,3,5,7)]==[base+0x387D20,0x37FD0,0,16,22]
 return [regs['x'+str(i)] for i in range(8)],writes

def prepare(args,base,sp=v.SP,padding=0xA5,stack_padding=0):
 p=v.fresh(args,base,padding=padding,stack_padding=stack_padding)
 for a in range(ARENA,ARENA+ARENA_SIZE,4096):p[a>>12]=bytearray(bytes([padding])*4096)
 argv,_=constructor_inputs(p,base,v.oracle.GUEST+0x120000)
 v.put(p,sp,v.oracle.GUEST+0x120048);v.put(p,sp+8,3)
 return p,argv


def synthetic(args,base,label,sp=v.SP,padding=0xA5,stack_padding=0):
 p,argv=prepare(args,base,sp,padding,stack_padding)
 blob=b'A'*8
 if label=='empty_definition':blob=code.spec(label,[code.body()],definitions=[([],[])])['blob']
 elif label=='two_definitions':blob=code.spec(label,[code.body(),code.body()],definitions=[([],[])],function_types=[0,0])['blob']
 elif label=='bound_import':blob=code.spec(label,imports=[(b'mod',b'external',0,b'\0')],definitions=[([],[])])['blob']
 elif label=='zero_size':blob=b''
 elif label=='four_bytes':blob=b'A'*4
 address=base+0x387D20 if label=='image_empty' else v.oracle.GUEST+0x8000
 codec=v.u(p,sp);_write_span(p,codec,bytes(72))
 key={'xor7':7,'xor255':255}.get(label,0)
 _write_span(p,address,bytes(b^key for b in blob));_write_span(p,codec+(len(blob)%3)*24+2,bytes([key]))
 argv=[address,len(blob),0,0,0,0,0,0]
 if label=='bound_import':
  pointer=v.oracle.GUEST+0x9000;binding=v.oracle.GUEST+0x1202A0
  _write_span(p,pointer,b'external\0');v.put(p,binding,pointer);v.put(p,binding+8,base+0x29E908);v.put(p,binding+16,0,1)
  argv[4:6]=[binding,1]
 return p,argv


def model(p,argv,base,sp=v.SP,tid=137,changes=None):
 cursor=ARENA
 def allocate(size):
  nonlocal cursor
  a=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=ARENA+ARENA_SIZE;return a
 kw=dict(image_base=base,blob_address=argv[0],blob_size=argv[1],output_address=v.OUTPUT,
  function_bindings_address=argv[4],function_binding_count=argv[5],global_bindings_address=argv[6],global_binding_count=argv[7],
  codec_table_address=v.u(p,sp),codec_table_count=v.u(p,sp+8),entry_stack_address=sp,thread_id=tid,
  varuint_scratch_address=0x78001000,expression_scratch_address=0x78001008,custom_scratch_address=0x78001010,allocate=allocate)
 kw.update(changes or {})
 return alternative.run_module_factory(p,**kw)


def compare(args,p,argv,base,label,sp=v.SP,tid=137):
 cpu,row=native(args,p,argv,base,sp,tid);r=model(p,argv,base,sp,tid)
 assert r.address==row['root'],label
 assert [(e.kind,e.address,e.size,e.owner_bytes.hex()) for e in r.effects]==[tuple(e) for e in row['effects']],(label,'effects')
 assert all(e.owner_address==v.OUTPUT for e in r.effects) and list(r.finalizers)==row['finalizers'],label
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),label=label,constructed=bool(r.address),descriptors=r.descriptor_count,
  imported_descriptors=r.imported_count,instructions=r.instruction_count,allocations=sum(e.kind=='allocate' for e in r.effects),
  frees=sum(e.kind=='free' for e in r.effects),finalizers=len(r.finalizers),natural_return_SP_and_output_match=True,
  all_guest_heap_image_pages_match=True,ordered_effects_owner_publication_and_finalizers_match=True,native_snapshot_input=False)


def native(args,p,argv,base,sp=v.SP,tid=137):
 saved=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];cursor=ARENA;events=[];finalizers=[];sizes={};phases=[]
 entries={0x31B360:'reader',0x2CD5A4:'parse',0x2CAFD0:'root',0x2CB968:'converted_cleanup',0x2CBADC:'ast_cleanup'}
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(ARENA,ARENA_SIZE);cpus.append(cpu);return cpu
 def allocate(cpu,size):
  nonlocal cursor
  a=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=ARENA+ARENA_SIZE;sizes[a]=size
  events.append(('allocate',a,size,bytes(cpu.mem_read(v.OUTPUT,8)).hex()));return a
 def free(cpu):
  a=reg(cpu,0);events.append(('free',a,sizes[a],bytes(cpu.mem_read(v.OUTPUT,8)).hex()));return 0
 def gettid(cpu):assert reg(cpu,0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(reg(cpu,i) for i in range(3)));return 0
 def memcmp(cpu):cpu.reg_write(v.arm.UC_ARM64_REG_PC,v.defined.builder.catalog.heap.libc_memcmp(args.libc));return None
 def observe(cpu,address):
  if address-base in entries:
   phases.append(dict(phase=entries[address-base],sp=cpu.reg_read(v.arm.UC_ARM64_REG_SP),fp=cpu.reg_read(v.arm.UC_ARM64_REG_FP),
    arguments=[reg(cpu,i) for i in range(9)],x22=reg(cpu,22),x28=reg(cpu,28),effect_index=len(events)))
 try:
  v.oracle.Uc=factory;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,0x2CBDC8,argv[:5],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},real_mutexes=True,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_X8:v.OUTPUT,
    v.arm.UC_ARM64_REG_X5:argv[5],v.arm.UC_ARM64_REG_X6:argv[6],v.arm.UC_ARM64_REG_X7:argv[7]},
   instruction_limit=60000000,instruction_observer=observe,
   code_hook_ranges=(*((base+x,base+x) for x in entries),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_PC)==v.oracle.STOP and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpu,dict(phases=phases,effects=events,finalizers=finalizers,root=int.from_bytes(cpu.mem_read(v.OUTPUT,8),'little'))


def negatives(args):
 base=0x122C0000;initial,argv=synthetic(args,base,'empty_definition');rows=[]
 def reject(label,changes=None,mutation=None,fault=None,source=None):
  p={k:bytearray(data) for k,data in (source or initial).items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=alternative._write_span;hits=[]
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected factory write failure')
   return saved(p,a,d)
  try:
   if fault:alternative._write_span=write
   try:model(p,argv,base,changes=changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted factory guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=v.SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),('thread_bound',dict(thread_id=1<<31)),
  ('boolean_blob_size',dict(blob_size=True)),('negative_blob_size',dict(blob_size=-1)),
  ('short_reader_zero',dict(blob_size=0)),('short_reader_four',dict(blob_size=4)),
  ('input_bound',dict(max_input_bytes=4)),('codec_bound',dict(codec_table_count=4097)),
  ('binding_bound',dict(function_binding_count=65537)),('boolean_binding_count',dict(global_binding_count=True)),
  ('node_bound',dict(max_nodes=0)),('byte_bound',dict(max_vector_bytes=0)),('word_bound',dict(max_code_words=1048577)),
  ('null_input',dict(blob_address=0)),('unmapped_input',dict(blob_address=0x76000000)),
  ('output_alias_input',dict(output_address=argv[0])),('output_alias_frame',dict(output_address=v.SP-0x100)),
  ('scratch_alias',dict(expression_scratch_address=0x78001000)),('scratch_alias_frame',dict(custom_scratch_address=v.SP-0x100)),
  ('codec_alias_frame',dict(codec_table_address=v.SP-0x100)),('unmapped_allocator',dict(allocate=lambda n:0x76000000)),
  ('image_allocator',dict(allocate=lambda n:base+0x387D20)),('input_allocator',dict(allocate=lambda n:argv[0])),
  ('frame_allocator',dict(allocate=lambda n:v.SP-0x100)),('shared_allocations',dict(allocate=lambda n:ARENA)),
  ('reserved_heap',dict(reserved_regions=((ARENA,ARENA+ARENA_SIZE),))),('no_allocator',dict(allocate=None))):reject(label,changes)
 reject('codec_field_bound',mutation=lambda p:v.put(p,v.u(p,v.SP)+16,1025,4))
 reject('reader_failure',mutation=lambda p:_write_span(p,argv[0]+8,b'\x0d'))
 for label,target in (('AST_clear',v.SP-0x190),('first_allocation',ARENA),
  ('converted_clear',v.SP-0x210),('catalog_publication',base+0x3E25E0),('root_publication',v.OUTPUT)):
  reject(label,fault=lambda a,d,t=target:a==t)
 count=[0]
 def cleanup_failure(a,d):
  if a==v.SP-0x210+16 and len(d)==8:count[0]+=1
  return count[0]==2
 reject('converted_cleanup',fault=cleanup_failure)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base in (0x122C0000,0x775C205000):
  for label in ('image_empty','external_empty','xor7','xor255','empty_definition','two_definitions','bound_import'):
   p,argv=synthetic(args,base,label);rows.append(compare(args,p,argv,base,label))
  for pad in (0,0x39,0xFF):
   p,argv=synthetic(args,base,'empty_definition',padding=pad,stack_padding=pad)
   rows.append(compare(args,p,argv,base,'padding_'+str(pad)))
  for delta,tid in ((-0xC80,1),(0x100,0x7FFFFFFF)):
   sp=v.SP+delta;p,argv=synthetic(args,base,'empty_definition',sp)
   rows.append(compare(args,p,argv,base,'SP_'+str(delta),sp,tid))
  print('Factory',hex(base),'synthetic controls passed',flush=True)
  p,argv=prepare(args,base);r=compare(args,p,argv,base,'complete_actual_ELF')
  assert r['descriptors']==139 and r['instructions']==54533 and r['imported_descriptors']==18
  assert r['allocations']==2330 and r['frees']==1836 and r['finalizers']==4
  r['actual_ELF_complete_module']=True;rows.append(r)
  print('Factory',hex(base),'complete actual module passed',flush=True)
 evidence=dict(schema='vm9-alternative-factory-composition-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_factory_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=7,
  actual_ELF_complete_module_controls=2,actual_ELF_descriptors=278,actual_ELF_runtime_instructions=109066,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  native_TLS_error_paths_implemented=False,independent_Python_factory_implemented=True,
  complete_python_bootstrap_controls=0,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Factory controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
