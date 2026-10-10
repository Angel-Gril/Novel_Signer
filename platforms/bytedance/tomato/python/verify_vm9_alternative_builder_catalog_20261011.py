"""Fresh instruction-builder catalog initialization and warm guard controls.

Caller inputs are independent ELF pages and explicit serial services. Native
snapshots are assertions only; no private names or payloads are exported.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_alternative_ast_module_function_imports_20261010 as heap
import vm9_alternative_startup as alternative
from vm9_allocator import _read_span,_write_span,RefillUnsupported

def prepare(args,base,*,root=0x79200000,child=0x79300000,pad=0xA5,warm=False,tid=137):
 p=oracle.fresh_pages();p.update(oracle.image_pages(args.library,base))
 for start,size in ((root,0x9000),(child,0x4000),(0x78000000,0x200000)):
  for address in range(start,start+size,4096):p[address>>12]=bytearray(bytes([pad])*4096)
 if warm:
  addresses=iter((root,child))
  alternative.initialize_instruction_builder_catalog(p,image_base=base,thread_id=tid,allocate=lambda n:next(addresses))
 return p

def native(args,base,pages,*,root=0x79200000,child=0x79300000,tid=137,sp=0x781FF000):
 saved=oracle.Uc;cpus=[];allocations=[];finalizers=[]
 def factory(*a,**kw):
  cpu=saved(*a,**kw);cpu.mem_map(root,0x9000);cpu.mem_map(child,0x4000);cpu.mem_map(0x78000000,0x200000);cpus.append(cpu);return cpu
 def allocate(cpu,size):
  pointer=(root,child)[len(allocations)]
  assert size==(0x8A18,0x3840)[len(allocations)]
  allocations.append((pointer,size,bytes(cpu.mem_read(base+0x3E2710,8))));return pointer
 def gettid(cpu):assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)));return 0
 try:
  oracle.Uc=factory
  result,_,_,_=oracle.native(args.library,base,0x2CC038,[],pages,libc=args.libc,malloc_handler=allocate,
   host_imports={0x348310:gettid,0x347EA0:register},real_mutexes=True,
   extra_registers={arm.UC_ARM64_REG_SP:sp},instruction_limit=100000,
   code_hook_ranges=((base+0x347E00,base+0x348800),))
 finally:oracle.Uc=saved
 cpu=cpus[0];assert cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 assert result==root
 return cpu,allocations,finalizers


def compare(args,base,*,root=0x79200000,child=0x79300000,pad=0xA5,warm=False,tid=137,sp=0x781FF000):
 p=prepare(args,base,root=root,child=child,pad=pad,warm=warm,tid=tid)
 initial_stack=_read_span(p,0x78000000,0x200000)
 cpu,allocations,finalizers=native(args,base,p,root=root,child=child,tid=tid,sp=sp)
 addresses=iter((root,child));calls=[]
 def allocate(size):
  address=next(addresses);calls.append((address,size));return address
 result=alternative.initialize_instruction_builder_catalog(p,image_base=base,thread_id=tid,allocate=allocate)
 assert result.address==root and calls==[(a,n) for a,n,_ in allocations]
 assert [(e.address,e.size,e.owner_bytes) for e in result.effects]==allocations
 assert all(e.kind=='allocate' and e.owner_address==base+0x3E2710 for e in result.effects)
 assert list(result.finalizers)==finalizers
 assert len(calls)==(0 if warm else 2) and len(finalizers)==(0 if warm else 1)
 assert _read_span(p,0x78000000,0x200000)==initial_stack
 for page,data in p.items():
  if not 0x78000000<=page<<12<0x78200000:
   expected=bytes(cpu.mem_read(page<<12,4096))
   assert bytes(data)==expected,(hex(base),warm,pad,hex(page<<12))
 return dict(base=hex(base),root=hex(root),child=hex(child),padding=pad,warm=warm,thread_id=tid,entry_sp=hex(sp),
  allocations=len(calls),finalizers=len(finalizers),natural_return_SP_and_catalog_address_match=True,
  all_guest_heap_image_pages_match=True,ordered_effects_and_finalizers_match=True,model_stack_unchanged=True,
  native_snapshot_input=False)


def negatives(args):
 base=0x122C0000;initial=prepare(args,base);rows=[]
 def put(p,address,value):_write_span(p,address,value.to_bytes(8,'little'))
 def reject(label,changes=None,mutation=None,fault=None,warm=False):
  p=prepare(args,base,warm=True) if warm else {k:bytearray(value) for k,value in initial.items()}
  if mutation:mutation(p)
  before={k:bytes(value) for k,value in p.items()};addresses=iter((0x79200000,0x79300000))
  params=dict(image_base=base,thread_id=137,allocate=lambda n:next(addresses));params.update(changes or {})
  saved=alternative._write_span;hits=[]
  def write(current,address,data):
   if fault(address,data):hits.append(address);raise RefillUnsupported('injected builder catalog write failure')
   return saved(current,address,data)
  try:
   if fault:alternative._write_span=write
   try:alternative.initialize_instruction_builder_catalog(p,**params)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted catalog guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(value) for k,value in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),('thread_overflow',dict(thread_id=1<<31)),
  ('cold_byte_budget',dict(max_vector_bytes=0x8A17)),('missing_allocator',dict(allocate=None)),
  ('unmapped_allocation',dict(allocate=lambda n:0x76000000)),('image_allocation',dict(allocate=lambda n:base+0x1000)),
  ('shared_allocations',dict(allocate=lambda n:0x79200000)),
  ('overlapping_allocations',dict(allocate=lambda n:0x79200000 if n==0x8A18 else 0x79201000)),
  ('unaligned_allocation',dict(allocate=lambda n:0x79200001)),
  ('reserved_allocation',dict(reserved_regions=((0x79200000,0x79209000),))),
  ('unmapped_second_allocation',dict(allocate=lambda n:0x79200000 if n==0x8A18 else 0x76000000))):reject(label,changes)
 reject('busy_guard',mutation=lambda p:put(p,base+0x3E2718,2))
 reject('stale_cold_pointer',mutation=lambda p:put(p,base+0x3E2710,0x79200000))
 reject('ready_null_pointer',mutation=lambda p:put(p,base+0x3E2718,1))
 reject('warm_byte_budget',dict(max_vector_bytes=0x8A17),warm=True)
 reject('warm_shared_storage',mutation=lambda p:put(p,0x79200200,0x79200000),warm=True)
 reject('warm_unmapped_secondary',mutation=lambda p:put(p,0x79200200,0x76000000),warm=True)
 reject('first_graph_write_failure',fault=lambda a,d:a==0x79200000)
 reject('secondary_write_failure',fault=lambda a,d:a==0x79300000+599*16)
 reject('publication_write_failure',fault=lambda a,d:a==base+0x3E2710)
 reject('guard_release_write_failure',fault=lambda a,d:a==base+0x3E2718)
 return rows


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==heap.LIBC_HASH
 rows=[];guards=negatives(args)
 for base in (0x122C0000,0x775C205000):
  for warm in (False,True):
   for pad in (0,0x39,0xA5,0xFF):rows.append(compare(args,base,warm=warm,pad=pad))
   for root,child in ((0x7C000000,0x7D000000),(0x7000000000,0x7000100000)):
    rows.append(compare(args,base,warm=warm,root=root,child=child))
   for delta in (-0xC80,0x100):rows.append(compare(args,base,warm=warm,sp=0x781FF000+delta))
   for tid in (1,0x12345678):rows.append(compare(args,base,warm=warm,tid=tid))
  print('Instruction builder catalog',hex(base),'passed',flush=True)
 evidence=dict(schema='vm9-alternative-builder-catalog-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=heap.LIBC_HASH,
  native_Python_builder_catalog_controls=len(rows),rollback_negative_controls=len(guards),pre_change_behavior_RED_controls=8,
  cold_catalog_controls=20,warm_catalog_controls=20,relocated_heap_controls=8,relocated_entry_stack_controls=8,alternate_thread_id_controls=8,
  main_graph_bytes=0x8A18,secondary_catalog_bytes=0x3840,main_typed_nodes=529,dispatch_tables=99,secondary_typed_nodes=600,
  native_input_snapshot_used=False,private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  instruction_builders_executed=False,independent_Python_factory_implemented=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Instruction builder catalog',len(rows),'native/Python',len(guards),'rollback checks',flush=True)

if __name__=='__main__':main()
