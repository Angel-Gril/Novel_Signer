"""Fresh builtin-function catalog and 0..32-byte hash versus original ARM64.

Inputs are ELF pages, caller padding and explicit serial services. Native
snapshots are assertions only; builtin names and decoded payloads stay private.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_alternative_builder_catalog_20261011 as catalog
from vm9_allocator import _read_span,_write_span,RefillUnsupported
oracle=catalog.oracle;alternative=catalog.alternative
HEAP=0x79200000;HEAP_SIZE=0x10000;SP=0x781FF000

def prepare(args,base,*,heap=HEAP,padding=0xA5,sp=SP,tid=137,warm=False,decoded_ready=False):
 p=oracle.fresh_pages();p.update(oracle.image_pages(args.library,base))
 for start,size in ((heap,HEAP_SIZE),(0x78000000,0x200000)):
  for address in range(start,start+size,4096):p[address>>12]=bytearray(bytes([padding])*4096)
 if warm or decoded_ready:
  cursor=heap
  def allocate(size):
   nonlocal cursor
   address=cursor;cursor+=(size+15)&~15;return address
  alternative.initialize_builtin_function_catalog(p,image_base=base,entry_stack_address=sp,thread_id=tid,allocate=allocate)
  for address in range(0x78000000,0x78200000,4096):p[address>>12]=bytearray(bytes([padding])*4096)
  if decoded_ready:
   _write_span(p,base+0x3E2720,bytes(48))
   for address in range(heap,heap+HEAP_SIZE,4096):p[address>>12]=bytearray(bytes([padding])*4096)
 return p

def native(args,base,p,*,heap=HEAP,sp=SP,tid=137):
 saved=oracle.Uc;cpus=[];cursor=heap;events=[];finalizers=[];sizes={}
 def factory(*a,**kw):
  cpu=saved(*a,**kw);cpu.mem_map(heap,HEAP_SIZE);cpu.mem_map(0x78000000,0x200000);cpus.append(cpu);return cpu
 def snapshot(cpu):return bytes(cpu.mem_read(base+0x3E2728,40))
 def allocate(cpu,size):
  nonlocal cursor
  address=cursor;cursor+=(size+15)&~15;assert cursor<=heap+HEAP_SIZE
  sizes[address]=size;events.append(('allocate',address,size,snapshot(cpu)));return address
 def free(cpu):
  address=cpu.reg_read(arm.UC_ARM64_REG_X0);events.append(('free',address,sizes[address],snapshot(cpu)));return 0
 def gettid(cpu):assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0xB2;return tid
 def register(cpu):finalizers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)));return 0
 def memcmp(cpu):cpu.reg_write(arm.UC_ARM64_REG_PC,catalog.heap.libc_memcmp(args.libc));return None
 try:
  oracle.Uc=factory
  result,_,_,_=oracle.native(args.library,base,0x2CC0F8,[],p,libc=args.libc,malloc_handler=allocate,
   host_imports={0x347FA0:free,0x348310:gettid,0x347EA0:register,0x347FE0:memcmp},real_mutexes=True,
   extra_registers={arm.UC_ARM64_REG_SP:sp},instruction_limit=1000000,code_hook_ranges=((base+0x347E00,base+0x348800),))
 finally:oracle.Uc=saved
 cpu=cpus[0];assert result==base+0x3E2728 and cpu.reg_read(arm.UC_ARM64_REG_PC)==oracle.STOP and cpu.reg_read(arm.UC_ARM64_REG_SP)==sp
 return cpu,events,finalizers

def compare(args,base,label,*,heap=HEAP,sp=SP,tid=137,padding=0xA5,warm=False,decoded_ready=False):
 p=prepare(args,base,heap=heap,sp=sp,tid=tid,padding=padding,warm=warm,decoded_ready=decoded_ready)
 initial_stack=_read_span(p,0x78000000,0x200000)
 cpu,events,finalizers=native(args,base,p,heap=heap,sp=sp,tid=tid);cursor=heap;calls=[]
 def allocate(size):
  nonlocal cursor
  address=cursor;cursor+=(size+15)&~15;calls.append((address,size));return address
 result=alternative.initialize_builtin_function_catalog(p,image_base=base,entry_stack_address=sp,thread_id=tid,allocate=allocate)
 assert result.address==base+0x3E2728 and result.entry_count==73
 assert calls==[(a,n) for k,a,n,s in events if k=='allocate']
 assert [(e.kind,e.address,e.size,e.owner_bytes) for e in result.effects]==events
 assert all(e.owner_address==base+0x3E2728 for e in result.effects) and list(result.finalizers)==finalizers
 assert len(calls)==(0 if warm else 98) and sum(e.kind=='free' for e in result.effects)==(0 if warm else 12)
 assert len(finalizers)==(0 if warm else 1)
 for page,data in p.items():
  if not 0x78000000<=page<<12<0x78200000:
   assert bytes(data)==bytes(cpu.mem_read(page<<12,4096)),(label,hex(page<<12))
 if warm:assert _read_span(p,0x78000000,0x200000)==initial_stack
 else:
  for a,n in ((sp-0x70,24),(sp-0x38,8)):assert _read_span(p,a,n)==bytes(cpu.mem_read(a,n)),(label,'temporary',hex(a))
 return dict(base=hex(base),label=label,heap=hex(heap),entry_sp=hex(sp),thread_id=tid,padding=padding,warm=warm,
  decoded_guards_ready=decoded_ready,entries=73,buckets=128,allocations=len(calls),frees=sum(e.kind=='free' for e in result.effects),
  natural_return_SP_and_catalog_address_match=True,all_guest_heap_image_pages_match=True,
  ordered_effects_and_owner_bytes_and_finalizers_match=True,consumed_temporary32_or_warm_stack_match=True,native_snapshot_input=False)

def hash_controls(args):
 rows=[]
 for base in (0x122C0000,0x775C205000):
  image=oracle.image_pages(args.library,base)
  for length in range(33):
   for pattern in (0,0xFF,0x39):
    p=oracle.fresh_pages();p.update({k:bytearray(v) for k,v in image.items()});pointer=oracle.GUEST+0x2000
    payload=bytes(((i*37+length)^pattern)&255 for i in range(length));_write_span(p,pointer,payload)
    before={k:bytes(v) for k,v in p.items()}
    value,memory,alloc,ledger=oracle.native(args.library,base,0x2AA744,[oracle.GUEST+0x2A00,pointer,length],p)
    assert alternative.hash_descriptor_name(payload)==alternative.hash_descriptor_name(bytearray(payload))==value
    assert memory==_read_span(p,oracle.GUEST,0xA000) and not alloc and not ledger
    assert before=={k:bytes(v) for k,v in p.items()}
    rows.append(dict(base=hex(base),length=length,pattern=pattern,native_Python_hash_match=True,no_model_page_writes=True))
  print('Descriptor hash',hex(base),'99 controls passed',flush=True)
 return rows

def negatives(args):
 base=0x122C0000;initial=prepare(args,base);ready=prepare(args,base,warm=True);rows=[]
 def put(p,a,n,w=8):_write_span(p,a,n.to_bytes(w,'little'))
 def reject(label,changes=None,mutation=None,fault=None,warm=False):
  p={k:bytearray(v) for k,v in (ready if warm else initial).items()}
  if mutation:mutation(p)
  before={k:bytes(v) for k,v in p.items()};cursor=HEAP;hits=[]
  def allocate(size):
   nonlocal cursor
   address=cursor;cursor+=(size+15)&~15;return address
  params=dict(image_base=base,entry_stack_address=SP,thread_id=137,allocate=allocate);params.update(changes or {})
  saved=alternative._write_span
  def write(p,a,data):
   if fault(a,data):hits.append(a);raise RefillUnsupported('injected builtin catalog write failure')
   return saved(p,a,data)
  try:
   if fault:alternative._write_span=write
   try:alternative.initialize_builtin_function_catalog(p,**params)
   except (RefillUnsupported,ValueError):pass
   else:raise AssertionError('accepted builtin guard '+label)
  finally:alternative._write_span=saved
  assert before=={k:bytes(v) for k,v in p.items()},label
  if fault:assert hits,label
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 for label,changes in (
  ('unaligned_SP',dict(entry_stack_address=SP+1)),('boolean_SP',dict(entry_stack_address=True)),
  ('zero_thread',dict(thread_id=0)),('boolean_thread',dict(thread_id=True)),('thread_bound',dict(thread_id=1<<31)),
  ('bucket_budget',dict(max_vector_bytes=1023)),('no_allocator',dict(allocate=None)),
  ('unmapped_allocator',dict(allocate=lambda n:0x76000000)),('alias_stack_allocator',dict(allocate=lambda n:SP-0x70)),
  ('shared_allocations',dict(allocate=lambda n:HEAP)),('reserved_heap',dict(reserved_regions=((HEAP,HEAP+HEAP_SIZE),))),
  ('reserved_temporary',dict(reserved_regions=((SP-0x70,SP-0x58),)))):reject(label,changes)
 reject('busy_guard',mutation=lambda p:put(p,base+0x3E2720,2))
 reject('stale_cold_catalog',mutation=lambda p:put(p,base+0x3E2728,HEAP))
 literal=next(row[3][0][1] for row in alternative._BUILTIN_FUNCTION_ENTRIES if row[3])
 reject('literal_instruction',mutation=lambda p:put(p,base+literal,0,4))
 source,destination,period,flag=alternative._BUILTIN_FUNCTION_ENTRIES[0][2]
 reject('cached_name_terminator',mutation=lambda p:(put(p,base+flag,1,4),put(p,base+destination+6,1,1)))
 reject('bucket_publication_failure',fault=lambda a,d:a==base+0x3E2728)
 reject('decoded_bytes_failure',fault=lambda a,d:a==base+destination)
 reject('decoded_guard_failure',fault=lambda a,d:a==base+flag)
 reject('first_node_name_failure',fault=lambda a,d:a==HEAP+1024+16)
 reject('guard_release_failure',fault=lambda a,d:a==base+0x3E2720)
 reject('final_temporary_failure',fault=lambda a,d:a==SP-0x70 and len(d)==8)
 def u(a):return int.from_bytes(_read_span(ready,a,8),'little')
 root=base+0x3E2728;head=u(root+16);buckets=u(root)
 for label,address,value in (
  ('ready_count',root+24,72),('ready_bucket_count',root+8,64),('ready_unmapped_buckets',root,0x76000000),
  ('ready_cycle',head,head),('ready_wrong_hash',head+8,u(head+8)^1),('ready_wrong_function',head+40,base+0x2E8C68),
  ('ready_wrong_predecessor',buckets+(u(head+8)&127)*8,0)):
  reject(label,mutation=lambda p,a=address,n=value:put(p,a,n),warm=True)
 reject('ready_reserved_node',dict(reserved_regions=((head,head+48),)),warm=True)
 for label,payload in (('hash_string','bad'),('hash_none',None),('hash_view',memoryview(b'x')),('hash_length_33',bytes(33))):
  try:alternative.hash_descriptor_name(payload)
  except RefillUnsupported:pass
  else:raise AssertionError(label)
  rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
 return rows

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('library','libc','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==catalog.heap.LIBC_HASH
 guards=negatives(args);rows=[]
 for base in (0x122C0000,0x775C205000):
  for warm in (False,True):
   for pad in (0xA5,0,0x39,0xFF):rows.append(compare(args,base,'padding_'+str(pad)+'_'+str(warm),padding=pad,warm=warm))
   for delta,tid in ((-0xC80,1),(0x100,0x7FFFFFFF)):
    rows.append(compare(args,base,'SP_'+str(delta)+'_'+str(warm),sp=SP+delta,tid=tid,warm=warm))
   rows.append(compare(args,base,'heap_'+str(warm),heap=0x79600000,warm=warm))
  for pad in (0xA5,0):rows.append(compare(args,base,'decoded_ready_'+str(pad),padding=pad,decoded_ready=True))
  print('Builtin function catalog',hex(base),'16 controls passed',flush=True)
 hashes=hash_controls(args)
 evidence=dict(schema='vm9-alternative-builtin-functions-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
  sample_sha256=oracle.LIBRARY_SHA256,matching_libc_sha256=catalog.heap.LIBC_HASH,native_Python_catalog_controls=len(rows),
  native_Python_hash_controls=len(hashes),rollback_and_type_guards=len(guards),pre_change_behavior_RED_controls=20,
  builtin_function_entries=73,builtin_function_buckets=128,guarded_ELF_name_sources=61,literal_instruction_name_sources=12,
  maximum_actual_builtin_name_length=29,hash_maximum_supported_length=32,native_input_snapshot_used=False,
  decoded_names_or_private_payloads_published=False,whole_native_stack_TLS_OS_compared=False,
  imported_descriptor_implemented=False,full_root_construction_implemented=False,independent_Python_factory_implemented=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,cases=rows,hash_cases=hashes,negative_cases=guards)
 args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
 print('Builtin catalog',len(rows),'hashes',len(hashes),'guards',len(guards),flush=True)

if __name__=='__main__':main()
