"""Fresh root construction from synthetic or independently parsed ELF inputs.

Original ARM64 is the oracle. Native pages never supply model inputs; names,
payloads and constructor frames remain local to this verification process.
"""
from pathlib import Path
import argparse,hashlib,json
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM,ARM64_OP_REG
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_alternative_imported_descriptor_20261011 as imported
from vm9_allocator import _read_span,_write_span,RefillUnsupported
defined=imported.defined;alternative=imported.alternative;oracle=imported.oracle
MODULE=oracle.GUEST+0xB100;OUTPUT=oracle.GUEST+0xB300
FUNCTIONS=oracle.GUEST+0x20000;IMPORTS=oracle.GUEST+0x30000;EXPORTS=oracle.GUEST+0x40000
OFFSETS=oracle.GUEST+0x50000;DATA=oracle.GUEST+0x60000;WORDS=oracle.GUEST+0x70000
BINDINGS=oracle.GUEST+0x100000;GLOBALS=oracle.GUEST+0x110000;KEYS=oracle.GUEST+0x130000
HEAP=0x79200000;HEAP_SIZE=0x400000;SP=0x781FF000


def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def put(p,a,n,w=8):_write_span(p,a,n.to_bytes(w,'little'))
def vector(p,a,begin,size):_write_span(p,a,b''.join(n.to_bytes(8,'little') for n in (begin,begin+size,begin+size)))


def bind_imports(args,base,p):
 with args.library.open('rb') as stream:
  elf=ELFFile(stream)
  for section in elf.iter_sections():
   if section['sh_type']!='SHT_RELA':continue
   symbols=elf.get_section(section['sh_link'])
   for relocation in section.iter_relocations():
    name=symbols.get_symbol(relocation['r_info_sym']).name
    offset={'memcpy':0x347F60,'memset':0x347F20,'strlen':0x347F40}.get(name)
    if relocation['r_info_type']==257 and offset is not None:put(p,base+relocation['r_offset'],base+offset)


def fresh(args,base,padding=0xA5,stack_padding=0xA5):
 p=oracle.image_pages(args.library,base)
 for start,size,pad in ((oracle.GUEST,0x160000,padding),(0x78000000,0x200000,stack_padding),
  (0x79000000,0x200000,padding),(HEAP,HEAP_SIZE,padding)):
  for a in range(start,start+size,4096):p[a>>12]=bytearray(bytes([pad])*4096)
 _write_span(p,MODULE,bytes(128));_write_span(p,OUTPUT,bytes(8));bind_imports(args,base,p)
 return p


def synthetic(args,base,*,definitions=(),imports=(),exports=(),functions=(),globals_=(),
 padding=0xA5,stack_padding=0xA5,heap_short=False):
 p=fresh(args,base,padding,stack_padding);pointer=KEYS;words=WORDS
 def string(address,name,force=False):
  nonlocal pointer
  if len(name)>22 or force:
   capacity=(len(name)+16)&~15;put(p,address,capacity|1);put(p,address+8,len(name));put(p,address+16,pointer)
   _write_span(p,pointer,name+b'\0');pointer+=capacity
  else:_write_span(p,address,bytes([len(name)*2])+name+b'\0')
 for i,(name,records) in enumerate(definitions):
  a=FUNCTIONS+i*64;put(p,a,i,4);put(p,a+4,sum(kind==0 for _,kind in imports)+i,4)
  put(p,a+8,0x89ABCDEF01234567);string(a+16,name,heap_short)
  vector(p,a+40,words if records else 0,len(records)*12)
  if records:_write_span(p,words,b''.join(records));words+=(len(records)*12+15)&~15
 imported_count=0;global_count=0
 for i,(name,kind) in enumerate(imports):
  a=IMPORTS+i*64;string(a,b'');string(a+24,name,heap_short);put(p,a+48,kind,4);put(p,a+52,0,4)
  put(p,a+56,imported_count if kind==0 else 0xFFFFFFFF,4)
  if kind==0:imported_count+=1
  else:assert kind==3;put(p,OFFSETS+global_count*4,global_count*16,4);global_count+=1
 for i,(name,index) in enumerate(exports):
  a=EXPORTS+i*32;string(a,name,heap_short);put(p,a+24,0,4);put(p,a+28,index,4)
 put(p,MODULE,imported_count+len(definitions),4)
 for offset,start,n,width in ((8,FUNCTIONS,len(definitions),64),(32,IMPORTS,len(imports),64),(56,EXPORTS,len(exports),32),(80,OFFSETS,global_count,4),(104,DATA,global_count,16)):
  vector(p,MODULE+offset,start if n else 0,n*width)
 for table,rows in ((BINDINGS,functions),(GLOBALS,globals_)):
  for i,(name,value) in enumerate(rows):
   a=table+i*24;put(p,a,pointer);_write_span(p,pointer,name+b'\0');pointer+=len(name)+1
   put(p,a+8,value);put(p,a+16,0,1)
 return p,(BINDINGS,len(functions),GLOBALS,len(globals_))


def constructor_bindings(p,base,frame):
 dis=Cs(CS_ARCH_ARM64,CS_MODE_ARM);dis.detail=True;regs={'sp':frame,'xzr':0};stores=0
 def reg(op):
  name=dis.reg_name(op.reg);return 'x'+name[1:] if name.startswith('w') else name
 def val(op):
  if op.type==ARM64_OP_IMM:return op.imm<<op.shift.value
  assert op.type==ARM64_OP_REG;return regs[reg(op)]
 for i in dis.disasm(_read_span(p,base+0x29ECB8,0x29F110-0x29ECB8),0x29ECB8):
  ops=i.operands
  if i.mnemonic=='adrp':regs[reg(ops[0])]=base+ops[1].imm
  elif i.mnemonic=='add':regs[reg(ops[0])]=val(ops[1])+val(ops[2])
  elif i.mnemonic=='mov':regs[reg(ops[0])]=val(ops[1])
  else:
   assert i.mnemonic in ('str','strb') and dis.reg_name(ops[1].mem.base)=='sp' and not i.writeback
   width=1 if i.mnemonic=='strb' else 4 if dis.reg_name(ops[0].reg).startswith('w') else 8
   put(p,frame+ops[1].mem.disp,val(ops[0]),width);stores+=1
 assert stores==114
 return frame+0x2A0,16,frame+0x90,22


def actual_input(args,base):
 p,_=defined.actual_input(args,base);frame=oracle.GUEST+0x120000
 bindings=constructor_bindings(p,base,frame);_write_span(p,OUTPUT,bytes(8));bind_imports(args,base,p)
 for a in range(HEAP,HEAP+HEAP_SIZE,4096):p[a>>12]=bytearray(b'\xa5'*4096)
 return p,bindings


def native(args,base,p,bindings,*,sp=SP,tid=137):
 saved=oracle.Uc,oracle.GUEST_SIZE;cpus=[];cursor=HEAP;events=[];finalizers=[];sizes={}
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(0x79000000,0xE00000);cpus.append(cpu);return cpu
 def snapshot(cpu):return bytes(cpu.mem_read(OUTPUT,8))
 def allocate(cpu,size):
  nonlocal cursor
  a=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=HEAP+HEAP_SIZE
  sizes[a]=size;events.append(('allocate',a,size,snapshot(cpu)));return a
 def free(cpu):
  a=cpu.reg_read(arm.UC_ARM64_REG_X0);events.append(('free',a,sizes[a],snapshot(cpu)));return 0
 def gettid(cpu):assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)));return 0
 def memcmp(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,defined.builder.catalog.heap.libc_memcmp(args.libc));return None
 fb,fc,gb,gc=bindings
 try:
  oracle.Uc=factory;oracle.GUEST_SIZE=0x160000
  oracle.native(args.library,base,0x2CAFD0,[MODULE,0,0,fb,fc],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},real_mutexes=True,
   extra_registers={arm.UC_ARM64_REG_SP:sp,arm.UC_ARM64_REG_X8:OUTPUT,arm.UC_ARM64_REG_X5:gb,arm.UC_ARM64_REG_X6:gc},
   instruction_limit=40000000,code_hook_ranges=((base+0x347E00,base+0x348800),))
 finally:oracle.Uc,oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 return cpu,events,finalizers


def compare(args,base,p,bindings,*,label,sp=SP,tid=137):
 cpu,events,finalizers=native(args,base,p,bindings,sp=sp,tid=tid);cursor=HEAP;calls=[]
 def allocate(size):
  nonlocal cursor
  a=cursor;cursor+=(size+15)&~15;calls.append((a,size));return a
 result=alternative.construct_parser_root(p,image_base=base,module_address=MODULE,output_address=OUTPUT,
  function_bindings_address=bindings[0],function_binding_count=bindings[1],global_bindings_address=bindings[2],global_binding_count=bindings[3],
  entry_stack_address=sp,thread_id=tid,allocate=allocate)
 assert result.address==int.from_bytes(cpu.mem_read(OUTPUT,8),'little'),label
 assert calls==[(a,n) for k,a,n,_ in events if k=='allocate'],label
 assert [(e.kind,e.address,e.size,e.owner_bytes) for e in result.effects]==events,(label,'effects/publication')
 assert all(e.owner_address==OUTPUT for e in result.effects) and list(result.finalizers)==finalizers,label
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 if result.address:
  for offset,size in ((0xA0,36),(0xD0,36),(0x100,36),(0x130,36),(0x170,36),(0x148,24),(0x178,8)):
   assert _read_span(p,sp-offset,size)==bytes(cpu.mem_read(sp-offset,size)),(label,'root temporary',hex(offset))
 return dict(base=hex(base),label=label,constructed=bool(result.address),descriptors=result.descriptor_count,
  imported_descriptors=result.imported_count,instructions=result.instruction_count,allocations=len(calls),
  frees=sum(e.kind=='free' for e in result.effects),finalizers=len(finalizers),natural_return_SP_and_output_match=True,
  all_guest_heap_image_pages_match=True,ordered_effects_owner_publication_and_finalizers_match=True,
  root_temporary212_match=True,native_snapshot_input=False)


def cases(base):
 d=defined.builder.decoded;word=d(0)
 rows=[('empty',{}),('empty_definition',dict(definitions=[(b'unit',[])])),
  ('word_definition',dict(definitions=[(b'unit',[word])],exports=[(b'public',0)])),
  ('functions',dict(definitions=[(b'unit',[word]*i) for i in range(5)],exports=[(b'entry'+bytes([65+i]),i) for i in range(5)])),
  ('bound_import',dict(imports=[(b'external',0)],functions=[(b'external',base+0x29E908)])),
  ('null_callback',dict(imports=[(b'external',0)],functions=[(b'external',0)])),
  ('duplicate_binding',dict(imports=[(b'external',0)],functions=[(b'external',base+0x29E908),(b'external',0)])),
  ('duplicate_export',dict(definitions=[(b'unit',[]),(b'unit',[])],exports=[(b'same',0),(b'same',1)])),
  ('export_matches_import',dict(imports=[(b'external',0)],functions=[(b'external',base+0x29E908)],definitions=[(b'unit',[])],exports=[(b'external',1)])),
  ('globals',dict(imports=[(b'global_a',3),(b'global_b',3)],globals_=[(b'global_a',base+0x34F5E8),(b'global_b',0)])),
  ('mixed',dict(imports=[(b'external',0),(b'global_a',3)],functions=[(b'external',base+0x29E908)],
   globals_=[(b'global_a',base+0x34F5E8)],definitions=[(b'unit',[word])],exports=[(b'public',1)]))]
 for n in (0,22,23,32):rows.append(('name_'+str(n),dict(definitions=[(b'n'*n,[word])],exports=[(b'x'*n,0)])))
 for n in (0,4,22):rows.append(('heap_short_'+str(n),dict(definitions=[(b'h'*n,[])],exports=[(b'e'*n,0)],heap_short=True)))
 rows.append(('heap_short_after_import',dict(imports=[(b'external',0)],functions=[(b'external',base+0x29E908)],
  definitions=[(b'h',[])],exports=[(b'public',1)],heap_short=True)))
 rows.append(('consecutive_heap_short',dict(definitions=[(b'h'*n,[]) for n in (0,4,22)],exports=[(b'public',2)],heap_short=True)))
 rows.append(('heap_short_after_duplicate_import',dict(imports=[(b'external',0),(b'external',0)],functions=[(b'external',base+0x29E908)],
  definitions=[(b'h',[])],exports=[(b'public',2)],heap_short=True)))
 for pad in (0,0x39,0xFF):rows.append(('padding_'+str(pad),dict(definitions=[(b'unit',[word])],exports=[(b'public',0)],padding=pad,stack_padding=pad)))
 return rows


def wide_record(args,base):
 builder=defined.builder;p=builder.catalog.prepare(args,base,warm=True)
 records,_,_=builder.graph_cases(args,base)
 source=oracle.GUEST+0x8000;output=oracle.GUEST+0x9000
 for record in records:
  _write_span(p,source,record)
  result=alternative.build_parser_runtime_instruction(p,image_base=base,catalog_address=0x79200000,
   decoded_address=source,output_address=output)
  if result.status and u(p,output+40)==102:return record
 raise AssertionError('synthetic graph lacks the wide root-data instruction')


def negatives(args):
 base=0x122C0000;initial,bindings=synthetic(args,base,definitions=[(b'unit',[defined.builder.decoded(0)])],exports=[(b'public',0)])
 rows=[]
 def reject(label,changes=None,mutation=None,fault=None):
  p={k:bytearray(v) for k,v in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(v) for k,v in p.items()};cursor=HEAP;hits=[]
  def allocate(size):
   nonlocal cursor
   a=cursor;cursor+=(size+15)&~15;return a
  kw=dict(image_base=base,module_address=MODULE,output_address=OUTPUT,function_bindings_address=bindings[0],function_binding_count=bindings[1],
   global_bindings_address=bindings[2],global_binding_count=bindings[3],entry_stack_address=SP,thread_id=137,allocate=allocate);kw.update(changes or {})
  saved=alternative._write_span
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected root write failure')
   return saved(p,a,d)
  try:
   if fault:alternative._write_span=write
   try:alternative.construct_parser_root(p,**kw)
   except (ValueError,RefillUnsupported):pass
   else:raise AssertionError('accepted root guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(v) for k,v in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),('thread_limit',dict(thread_id=1<<31)),
  ('binding_bound',dict(function_binding_count=65537)),('negative_binding_count',dict(function_binding_count=-1)),
  ('boolean_binding_count',dict(function_binding_count=True)),('function_budget',dict(max_functions=0)),
  ('instruction_budget',dict(max_instructions=0)),('boolean_instruction_budget',dict(max_instructions=True)),
  ('byte_budget',dict(max_vector_bytes=23)),('no_allocator',dict(allocate=None)),
  ('unmapped_allocator',dict(allocate=lambda n:0x76000000)),('module_alias_allocator',dict(allocate=lambda n:MODULE)),
  ('frame_alias_allocator',dict(allocate=lambda n:SP-0x170)),('source_alias_allocator',dict(allocate=lambda n:WORDS)),
  ('shared_allocations',dict(allocate=lambda n:HEAP)),('reserved_heap',dict(reserved_regions=((HEAP,HEAP+HEAP_SIZE),))),
  ('output_alias',dict(output_address=MODULE))):reject(label,changes)
 for label,a,value,width in (
  ('definition_index',FUNCTIONS+4,1,4),('missing_function_slot',MODULE,2,4),('export_index',EXPORTS+28,1,4),
  ('inline_name',FUNCTIONS+16,46,1),('runtime_source_end',FUNCTIONS+48,WORDS+13,8),('module_vector_alias',MODULE+32,FUNCTIONS,8),
  ('primary_opcode_bound',WORDS+4,64,1)):
  reject(label,mutation=lambda p,a=a,v=value,w=width:put(p,a,v,w))
 reject('missing_nested_builder',mutation=lambda p:_write_span(p,WORDS,defined.builder.decoded(15)))
 for label,a in (('map_header',SP-0x100),('first_allocation',HEAP),('data_move',MODULE+104),
  ('catalog_publication',base+0x3E2710),('nested_descriptor',SP-0x178),('output_publication',OUTPUT)):
  reject(label,fault=lambda x,d,target=a:x==target)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base in (0x122C0000,0x775C205000):
  for label,options in cases(base):
   p,bindings=synthetic(args,base,**options);rows.append(compare(args,base,p,bindings,label=label))
  p,bindings=synthetic(args,base,imports=[(b'external',0)],functions=[(b'external',base+0x29E908)],
   definitions=[(b'unit',[wide_record(args,base)])])
  rows.append(compare(args,base,p,bindings,label='wide_variant_after_import'))
  for n in (6,29):
   key=next(k for k,_ in imported.builtin_keys(args,base) if len(k)==n)
   p,bindings=synthetic(args,base,imports=[(key,0)]);rows.append(compare(args,base,p,bindings,label='builtin_'+str(n)))
  for delta,tid in ((-0xC80,1),(0x100,0x7FFFFFFF)):
   p,bindings=synthetic(args,base,definitions=[(b'unit',[defined.builder.decoded(0)])]);rows.append(compare(args,base,p,bindings,label='SP_'+str(delta),sp=SP+delta,tid=tid))
  p,bindings=synthetic(args,base);rows.append(compare(args,base,p,(*bindings[:3],1),label='global_count_mismatch'))
  print('Parser root',hex(base),'synthetic controls passed',flush=True)
  p,bindings=actual_input(args,base);row=compare(args,base,p,bindings,label='complete_actual_ELF')
  assert row['descriptors']==139 and row['imported_descriptors']==18 and row['instructions']==54533
  assert row['allocations']==544 and row['frees']==52 and row['finalizers']==3
  row['actual_ELF_complete_module']=True;rows.append(row)
  print('Parser root',hex(base),'139 actual descriptors/54533 instructions passed',flush=True)
 evidence=dict(schema='vm9-alternative-root-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=defined.builder.catalog.heap.LIBC_HASH,
  native_Python_root_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=9,
  actual_ELF_complete_module_controls=2,actual_ELF_descriptors=278,actual_ELF_runtime_instructions=109066,
  native_input_snapshot_used=False,private_names_or_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  nonempty_name_filter_or_registration_flags_implemented=False,independent_Python_factory_implemented=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Root controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
