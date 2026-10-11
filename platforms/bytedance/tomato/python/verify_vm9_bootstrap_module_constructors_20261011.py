"""Fresh original ELF module constructors against independent Python inputs.

Verify the four additional loader constructors and the existing B constructor.
Private binding names, payloads, native snapshots and decoded data stay local.
"""
from pathlib import Path
import argparse,hashlib,json
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import verify_vm9_alternative_constructor_20261011 as previous
from vm9_allocator import _read_span,_write_span,RefillUnsupported
v=previous.v;alternative=previous.alternative
ARENA=previous.ARENA;ARENA_SIZE=previous.ARENA_SIZE
# entry: frame bytes, factory BL, RET, root slot, publication count.
SPECS={
 0x299B30:(0x900,0x29A6AC,0x29A704,0x3E1E48,2),
 0x29C518:(0x470,0x29CB38,0x29CBAC,0x3E1E60,3),
 0x2A1AC0:(0xA20,0x2A278C,0x2A288C,0x3E2400,8),
 0x2A2D40:(0x290,0x2A3130,0x2A3230,0x3E2448,8),
}


def model(p,base,entry,sp=v.SP,tid=137,changes=None):
 kw=dict(constructor_entry=entry);kw.update(changes or {})
 return previous.model(p,base,sp,tid,kw)


def publication_sites(p,base,entry):
 frame,bl,ret,root,count=SPECS[entry]
 dis=Cs(CS_ARCH_ARM64,CS_MODE_ARM);dis.detail=True;address=None;result=[]
 for instruction in dis.disasm(_read_span(p,base+bl+20,ret-12-bl-20),bl+20):
  ops=instruction.operands
  if instruction.mnemonic=='adrp' and instruction.op_str.startswith('x8,'):address=base+ops[1].imm
  elif instruction.mnemonic=='add' and instruction.op_str.startswith('x8, x8,'):address+=ops[2].imm
  elif instruction.mnemonic=='str':
   assert instruction.op_str.startswith('x0, [x8');result.append(address+ops[1].mem.disp)
 assert len(result)==count
 return result


def native(args,p,base,entry,sp=v.SP,tid=137):
 frame,bl,ret,root,count=SPECS[entry];output=sp-frame-0x18
 saved=v.oracle.Uc,v.oracle.GUEST_SIZE;cpus=[];cursor=ARENA;events=[];finalizers=[];sizes={}
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
 try:
  v.oracle.Uc=factory;v.oracle.GUEST_SIZE=0x160000
  v.oracle.native(args.library,base,entry,[],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},real_mutexes=True,
   extra_registers={v.arm.UC_ARM64_REG_SP:sp,v.arm.UC_ARM64_REG_X8:output,
    v.arm.UC_ARM64_REG_X5:0,v.arm.UC_ARM64_REG_X6:0,v.arm.UC_ARM64_REG_X7:0},
   instruction_limit=60000000)
 finally:v.oracle.Uc,v.oracle.GUEST_SIZE=saved
 cpu=cpus[0];assert cpu.reg_read(v.arm.UC_ARM64_REG_PC)==v.oracle.STOP and cpu.reg_read(v.arm.UC_ARM64_REG_SP)==sp
 return cpu,dict(effects=events,finalizers=finalizers,root=int.from_bytes(cpu.mem_read(base+root,8),'little'))


def compare(args,base,entry,sp,tid,padding,stack_padding):
 p=previous.prepare(args,base,padding,stack_padding);sites=publication_sites(p,base,entry)
 cpu,expected=native(args,p,base,entry,sp,tid);result=model(p,base,entry,sp,tid)
 assert result.address==expected['root'] and result.address
 assert [a for a,_ in result.publications]==sites
 assert [(e.kind,e.address,e.size,e.owner_bytes.hex()) for e in result.effects]==[tuple(e) for e in expected['effects']]
 assert all(e.owner_address==sp-SPECS[entry][0]-0x18 for e in result.effects)
 assert list(result.finalizers)==expected['finalizers']
 for address,value in result.publications:assert value and value==int.from_bytes(cpu.mem_read(address,8),'little')
 for page,data in p.items():
  if 0x78000000<=page<<12<0x78200000:continue
  actual=bytes(cpu.mem_read(page<<12,4096))
  assert bytes(data)==actual,(hex(entry),hex(page<<12),[(hex((page<<12)+i),x,y) for i,(x,y) in enumerate(zip(data,actual)) if x!=y][:12])
 return dict(base=hex(base),entry=hex(entry),descriptors=result.descriptor_count,instructions=result.instruction_count,
  publications=len(sites),allocations=sum(e.kind=='allocate' for e in result.effects),
  frees=sum(e.kind=='free' for e in result.effects),finalizers=len(result.finalizers),
  natural_return_SP_and_root_match=True,all_guest_heap_image_pages_match=True,
  ordered_effects_owner_publication_and_finalizers_match=True,all_descriptor_publications_match=True,
  fresh_independent_ELF_inputs=True,native_snapshot_input=False)


def negatives(args):
 rows=previous.negatives(args);base=0x122C0000;initial=previous.prepare(args,base)
 def reject(entry,label,changes=None,mutation=None,fault=None):
  p={k:bytearray(data) for k,data in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(data) for k,data in p.items()};saved=alternative._write_span;hits=[]
  def write(p,a,d):
   if fault(a,d):hits.append(a);raise RefillUnsupported('injected bootstrap constructor failure')
   return saved(p,a,d)
  try:
   if fault:alternative._write_span=write
   try:model(p,base,entry,changes=changes)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted constructor guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(data) for k,data in p.items()},label
  if fault:assert hits,label
  rows.append(dict(entry=hex(entry) if type(entry) is int else str(entry),label=label,
   rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for entry in (True,0,0x299B34):reject(entry,'unsupported_constructor_entry')
 for entry,(frame_size,bl,ret,root,count) in SPECS.items():
  frame=v.SP-frame_size
  for label,changes in (
   ('scratch_caller_alias',dict(custom_scratch_address=frame+0x100)),
   ('reserved_caller',dict(reserved_regions=((frame,v.SP),))),
   ('unmapped_allocator',dict(allocate=lambda n:0x76000000)),
   ('reused_allocator',dict(allocate=lambda n:ARENA)),
   ('code_word_budget',dict(max_code_words=1)),('node_budget',dict(max_nodes=1)),
   ('invalid_byte_budget',dict(max_vector_bytes=0))):reject(entry,label,changes)
  reject(entry,'unsupported_setup_instruction',mutation=lambda p:_write_span(p,base+entry+12,bytes(4)))
  reject(entry,'input_store_failure',fault=lambda a,d:frame<=a<v.SP)
  reject(entry,'wrapper_arguments_failure',fault=lambda a,d:a==frame-0x30)
  reject(entry,'root_publication_failure',fault=lambda a,d:a==base+root)
  reject(entry,'last_publication_failure',fault=lambda a,d:a==base+root+count*8)
  reject(entry,'unsupported_publication_instruction',mutation=lambda p:_write_span(p,base+ret-16,bytes(4)))
  print('Constructor guards',hex(entry),'passed',flush=True)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==v.oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==v.defined.builder.catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[];regressions=[]
 for base,delta,tid,padding,stack_padding in ((0x122C0000,0,137,0xA5,0),(0x775C205000,-0xC80,1,0xFF,0x39)):
  for entry in SPECS:
   row=compare(args,base,entry,v.SP+delta,tid,padding,stack_padding);rows.append(row)
   print('Constructor',hex(base),hex(entry),row['descriptors'],row['instructions'],'passed',flush=True)
  regressions.append(previous.compare(args,base,v.SP+delta,tid,padding,stack_padding,'existing_B_constructor'))
  print('Existing B constructor',hex(base),'passed',flush=True)
 evidence=dict(schema='vm9-bootstrap-module-constructors-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=v.oracle.LIBRARY_SHA256,matching_libc_sha256=v.defined.builder.catalog.heap.LIBC_HASH,
  native_Python_constructor_controls=len(rows),existing_B_constructor_regression_controls=len(regressions),
  rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=8,
  additional_ELF_module_constructors=4,total_supported_ELF_module_constructors=5,
  actual_ELF_descriptors=sum(r['descriptors'] for r in rows),actual_ELF_runtime_instructions=sum(r['instructions'] for r in rows),
  actual_ELF_descriptor_publications=sum(r['publications'] for r in rows),native_input_snapshot_used=False,
  private_names_or_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  independent_Python_constructors_implemented=True,full_ELF_loader_verified=False,full_JNI_bootstrap_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
  cases=rows,regression_cases=regressions,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('Constructor controls',len(rows),'regressions',len(regressions),'guards',len(guards),flush=True)


if __name__=='__main__':main()
