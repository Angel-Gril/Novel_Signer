"""Fresh original B constructor against independent Python ELF bootstrap.

Full module construction and all 121 original publication sites are compared.
Native pages never supply model inputs; private names/payloads stay local.
"""
from pathlib import Path
import argparse,hashlib,json
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import verify_vm9_alternative_factory_composition_20261011 as factory
from vm9_allocator import _read_span,_write_span,RefillUnsupported
v=factory.v;alternative=factory.alternative
ARENA=factory.ARENA;ARENA_SIZE=factory.ARENA_SIZE


def prepare(args,base,padding=0xA5,stack_padding=0):
 p=v.fresh(args,base,padding,stack_padding)
 for address in range(ARENA,ARENA+ARENA_SIZE,4096):p[address>>12]=bytearray(bytes([padding])*4096)
 return p


def model(p,base,sp=v.SP,tid=137,changes=None):
 cursor=ARENA
 def allocate(size):
  nonlocal cursor
  address=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=ARENA+ARENA_SIZE;return address
 kw=dict(image_base=base,entry_stack_address=sp,thread_id=tid,varuint_scratch_address=0x78001000,
  expression_scratch_address=0x78001008,custom_scratch_address=0x78001010,allocate=allocate)
 kw.update(changes or {})
 return alternative.run_module_constructor(p,**kw)


def publication_sites(p,base):
 dis=Cs(CS_ARCH_ARM64,CS_MODE_ARM);dis.detail=True;address=None;result=[]
 for instruction in dis.disasm(_read_span(p,base+0x29F2DC,0x2A0018-0x29F2DC),0x29F2DC):
  ops=instruction.operands
  if instruction.mnemonic=='adrp' and instruction.op_str.startswith('x8,'):address=base+ops[1].imm
  elif instruction.mnemonic=='add' and instruction.op_str.startswith('x8, x8,'):address+=ops[2].imm
  elif instruction.mnemonic=='str':
   assert instruction.op_str.startswith('x0, [x8');result.append(address+ops[1].mem.disp)
 assert len(result)==121
 return result


def compare(args,base,sp,tid,padding,stack_padding,label):
 p=prepare(args,base,padding,stack_padding);sites=publication_sites(p,base)
 cpu,expected=native(args,p,base,sp,tid);result=model(p,base,sp,tid)
 assert result.address==expected['root'] and result.address
 assert len(result.publications)==121 and [a for a,_ in result.publications]==sites
 assert [(e.kind,e.address,e.size,e.owner_bytes.hex()) for e in result.effects]==[tuple(e) for e in expected['effects']]
 assert all(e.owner_address==sp-0x440-0x18 for e in result.effects) and list(result.finalizers)==expected['finalizers']
 for address,value in result.publications:assert value and value==int.from_bytes(cpu.mem_read(address,8),'little')
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(label,hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),label=label,descriptors=result.descriptor_count,instructions=result.instruction_count,
  publications=len(sites),unique_publication_slots=len(set(sites)),allocations=sum(e.kind=='allocate' for e in result.effects),
  frees=sum(e.kind=='free' for e in result.effects),finalizers=len(result.finalizers),natural_return_SP_and_root_match=True,
  all_guest_heap_image_pages_match=True,ordered_effects_owner_publication_and_finalizers_match=True,
  all_121_descriptor_publications_match=True,native_snapshot_input=False)


def native(args,p,base,sp=v.SP,tid=137):
 output=sp-0x440-0x18
 saved=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];cursor=ARENA;events=[];finalizers=[];sizes={};phases=[]
 entries={0x31B360:'reader',0x2CD5A4:'parse',0x2CAFD0:'root',0x2CB968:'converted_cleanup',0x2CBADC:'ast_cleanup'}
 def reg(cpu,i):return cpu.reg_read(getattr(v.arm,'UC_ARM64_REG_X'+str(i)))
 def factory(*a,**kw):
  cpu=saved[0](*a,**kw);cpu.mem_map(0x78000000,0x200000);cpu.mem_map(ARENA,ARENA_SIZE);cpus.append(cpu);return cpu
 def allocate(cpu,size):
  nonlocal cursor
  a=cursor;cursor+=(max(size,1)+15)&~15;assert cursor<=ARENA+ARENA_SIZE;sizes[a]=size
  events.append(('allocate',a,size,bytes(cpu.mem_read(output,8)).hex()));return a
 def free(cpu):
  a=reg(cpu,0);events.append(('free',a,sizes[a],bytes(cpu.mem_read(output,8)).hex()));return 0
 def gettid(cpu):assert reg(cpu,0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(reg(cpu,i) for i in range(3)));return 0
 def memcmp(cpu):cpu.reg_write(v.arm.UC_ARM64_REG_PC,v.defined.builder.catalog.heap.libc_memcmp(args.libc));return None
 def observe(cpu,address):
  if address-base in entries:
   phases.append(dict(phase=entries[address-base],sp=cpu.reg_read(v.arm.UC_ARM64_REG_SP),fp=cpu.reg_read(v.arm.UC_ARM64_REG_FP),
    arguments=[reg(cpu,i) for i in range(9)],x22=reg(cpu,22),x28=reg(cpu,28),effect_index=len(events)))
 try:
  v.oracle.Uc=factory;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,0x29ECAC,[],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},real_mutexes=True,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_X8:output,
    v.arm.UC_ARM64_REG_X5:0,v.arm.UC_ARM64_REG_X6:0,v.arm.UC_ARM64_REG_X7:0},
   instruction_limit=60000000,instruction_observer=observe,
   code_hook_ranges=(*((base+x,base+x) for x in entries),(base+0x347E00,base+0x348800)))
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_PC)==v.oracle.STOP and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpu,dict(phases=phases,effects=events,finalizers=finalizers,root=int.from_bytes(cpu.mem_read(base+0x3E1EB0,8),'little'))


def negatives(args):
 base=0x122C0000;initial=prepare(args,base);rows=[];frame=v.SP-0x440
 def reject(label,changes=None,mutation=None,fault=None):
  p={k:bytearray(data) for k,data in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=alternative._write_span;hits=[]
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected constructor write failure')
   return saved(p,a,d)
  try:
   if fault:alternative._write_span=write
   try:model(p,base,changes=changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted constructor guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=v.SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('low_SP',dict(entry_stack_address=0x1000)),('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),
  ('node_bound',dict(max_nodes=0)),('word_bound',dict(max_code_words=1048577)),('byte_bound',dict(max_vector_bytes=0)),
  ('unaligned_image',dict(image_base=base+1)),('scratch_caller_alias',dict(custom_scratch_address=frame+0x100)),
  ('scratch_alias',dict(expression_scratch_address=0x78001000)),('unmapped_allocator',dict(allocate=lambda n:0x76000000)),
  ('caller_frame_allocator',dict(allocate=lambda n:frame+0x100)),('image_allocator',dict(allocate=lambda n:base+0x387D20)),
  ('shared_allocator',dict(allocate=lambda n:ARENA)),('no_allocator',dict(allocate=None)),
  ('reserved_caller',dict(reserved_regions=((frame,frame+0x440),))),
  ('reserved_heap',dict(reserved_regions=((ARENA,ARENA+ARENA_SIZE),)))):reject(label,changes)
 reject('unsupported_setup_instruction',mutation=lambda p:_write_span(p,base+0x29ECB8,bytes(4)))
 reject('input_store_failure',fault=lambda a,d:frame<=a<frame+0x440)
 reject('wrapper_arguments_failure',fault=lambda a,d:a==frame-0x30)
 print('Constructor',len(rows),'early rollback guards passed',flush=True)
 reject('last_publication_failure',fault=lambda a,d:a==base+0x3E21E8)
 print('Constructor complete-module late rollback passed',flush=True)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base,delta,tid,padding,stack_padding in ((0x122C0000,0,137,0xA5,0),(0x775C205000,-0xC80,1,0xFF,0x39)):
  row=compare(args,base,v.SP+delta,tid,padding,stack_padding,'complete_actual_ELF' if not delta else 'complete_actual_ELF_relocated_padded')
  assert row['descriptors']==139 and row['instructions']==54533 and row['publications']==121
  assert row['allocations']==2330 and row['frees']==1836 and row['finalizers']==4
  rows.append(row);print('Constructor',hex(base),'121 publications passed',flush=True)
 evidence=dict(schema='vm9-alternative-constructor-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_constructor_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=4,
  actual_ELF_complete_module_controls=2,actual_ELF_descriptors=278,actual_ELF_runtime_instructions=109066,
  actual_ELF_descriptor_publications=242,native_input_snapshot_used=False,private_names_or_payloads_published=False,
  whole_native_stack_TLS_OS_compared=False,independent_Python_factory_implemented=True,
  independent_Python_constructor_implemented=True,complete_python_bootstrap_controls=0,
  B_VM_executed=False,complete_python_medusa=False,fresh_signer_output_verified=False,
  live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Constructor controls',len(rows),'guards',len(guards),flush=True)


if __name__=='__main__':main()
