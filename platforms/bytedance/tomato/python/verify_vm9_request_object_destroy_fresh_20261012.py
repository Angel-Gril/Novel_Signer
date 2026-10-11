"""Original request destruction without event emission versus fresh Python pages.

Actual reference/diagnostic helpers and matching libc locks run in the oracle.
Synthetic allocation/free effects and logical diagnostic scratch are compared.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_request_object_fresh_20261012 as fixture
import vm9_request_leaf_prefixes as leaf
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=fixture.G;SP=fixture.SP;TP=fixture.TP;PACKED=G+0x2800;BUFFER=G+0x3500
REFERENCED=G+0x3700;REF_BUFFER=G+0x3800;COUNTER=G+0x3900
BASES=fixture.BASES
PROFILES=(('cold_NULL',{}),('warm_NULL',dict(warm=True)),('cross_page',dict(cross_page=True)),
 ('empty_string',dict(payload=b'')),('binary_string',dict(payload=b'\x00\x80\xff')),
 ('NULL_count',dict(count=None)),('zero_count',dict(count=0)),('retained_count',dict(count=2)),
 ('signed_max',dict(count=0x7FFFFFFF)),('signed_min',dict(count=0x80000000)),
 ('wrapped_count',dict(count=0xFFFFFFFF)),('owned_string',dict(owned_string=True)),
 ('already_emitted',dict(flag=1,emitted=1)),('nonboolean_emitted',dict(flag=255,emitted=128)))
def fresh(library,base,profile):
 p,_,out=fixture.fresh(library,base,profile);blocks={}
 _write_span(p,out,bytes(0x50));fixture.w(p,out,base+0x35B868)
 data=profile.get('payload',b'destruct\0request')
 fixture.w(p,out+0x10,base+0x34F5F8);fixture.w(p,out+0x18,len(data)+1,4)
 fixture.w(p,out+0x1C,len(data),4);fixture.w(p,out+0x20,BUFFER)
 _write_span(p,BUFFER,data+b'\0');blocks[BUFFER]=len(data)+1
 pointer=REFERENCED if profile.get('owned_string') else 0
 if pointer:
  fixture.w(p,pointer,base+0x34F5F8);fixture.w(p,pointer+8,6,4);fixture.w(p,pointer+12,5,4)
  fixture.w(p,pointer+16,REF_BUFFER);_write_span(p,REF_BUFFER,b'owned\0');blocks.update({pointer:24,REF_BUFFER:6})
 count=profile.get('count',1);fixture.w(p,out+0x28,pointer);fixture.w(p,out+0x30,0 if count is None else COUNTER)
 if count is not None:fixture.w(p,COUNTER,count,4);blocks[COUNTER]=4
 fixture.w(p,out+0x40,profile.get('emitted',0),1);fixture.w(p,out+0x48,profile.get('flag',0),1)
 _write_span(p,PACKED,(base+0x25CF98).to_bytes(8,'little')+out.to_bytes(8,'little')+b'\xa5'*16)
 return p,blocks,out
def native(library,libc,base,p,out,service,wrapper):
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 observed[SP-0x60,24]=None
 def watch(c,a):
  off=a-base
  if off in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
  if off==0x348310:service.diagnostic('gettid',137)
 _,memory,_,_=fixture.oracle.native(library,base,0x285F9C if wrapper else 0x25CF98,
  [PACKED] if wrapper else [out],p,libc=libc,real_diagnostics=True,real_singletons=True,
  real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
  extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},host_imports={0x347FA0:service.native_free},
  malloc_handler=service.native_malloc,observed_memory=observed,instruction_observer=watch,instruction_limit=100000)
 return memory,observed
def compare(library,libc,base,label,profile,wrapper):
 p,blocks,out=fresh(library,base,profile);expected=fixture.ReferenceServices(blocks);actual=fixture.ReferenceServices(blocks)
 memory,observed=native(library,libc,base,p,out,expected,wrapper)
 leaf.destroy_request_object(p,image_base=base,entry_stack_address=SP,object_address=out,
  thread_pointer=TP,thread_id=137,allocate=actual.malloc,free=actual.free,diagnostic_observer=actual.diagnostic)
 assert _read_span(p,G,0xA000)==memory,(label,wrapper,'payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),(label,wrapper,'image/scope')
 assert actual.events==expected.events and actual.freed==expected.freed,(label,wrapper,'order/free bytes')
 assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
 print('PASS',hex(base),'request destroy',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
  full_guest_payload_ELF_and_logical_scope_match=True,reference_and_string_cleanup_order_heap_and_bytes_match=True,
  actual_reference_helper_executed=True,event_emission_branch_not_taken=True,
  incidental_native_X0_not_claimed=True,native_snapshot_input=False)
def compare_free(library,base,label):
 p,blocks,out=fresh(library,base,{})
 pointer=0 if label=='NULL' else PACKED if label=='packed_payload' else BUFFER
 if pointer==PACKED:blocks[PACKED]=32
 _write_span(p,PACKED,(base+0x32A264).to_bytes(8,'little')+pointer.to_bytes(8,'little')+b'\xa5'*16)
 expected=fixture.ReferenceServices(blocks);actual=fixture.ReferenceServices(blocks)
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 _,memory,_,_=fixture.oracle.native(library,base,0x285910,[PACKED],p,
  host_imports={0x347FA0:expected.native_free},observed_memory=observed,instruction_limit=10000)
 actual.free(p,int.from_bytes(_read_span(p,PACKED+8,8),'little'))
 assert _read_span(p,G,0xA000)==memory and all(_read_span(p,a,n)==v for (a,n),v in observed.items())
 assert actual.events==expected.events and actual.freed==expected.freed
 assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
 print('PASS',hex(base),'final free wrapper',label,flush=True)
 return dict(image_base=hex(base),case=label,operation='final_free',actual_wrapper=True,
  original_returned=True,full_guest_payload_ELF_and_free_order_match=True,
  NULL_forwarded_to_owning_free_service=label=='NULL',packed_return_slot_not_written=True,native_snapshot_input=False)


def compare_delete(library,base,label,profile,wrapper):
 import verify_vm9_request_tree_destroy_fresh_20261012 as tree_fixture,vm9_registry as registry
 p,blocks,next_address=tree_fixture.fresh(library,base,profile)
 blocks[tree_fixture.CONTAINER]=40
 _write_span(p,tree_fixture.PACKED,(base+0x25C12C).to_bytes(8,'little')+tree_fixture.CONTAINER.to_bytes(8,'little')+b'\xa5'*16)
 expected=fixture.ReferenceServices(blocks);actual=fixture.ReferenceServices(blocks)
 expected.effects.next=actual.effects.next=next_address
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 observed[SP-0xA8,32]=None
 _,memory,_,_=fixture.oracle.native(library,base,0x285B70 if wrapper else 0x25C12C,
  [tree_fixture.PACKED] if wrapper else [tree_fixture.CONTAINER],p,
  host_imports={0x347FA0:expected.native_free},observed_memory=observed,instruction_limit=300000)
 registry.delete_configuration_tree(p,container_address=tree_fixture.CONTAINER,
  entry_stack_address=SP,image_base=base,free=actual.free)
 assert _read_span(p,G,0xA000)==memory and all(_read_span(p,a,n)==v for (a,n),v in observed.items())
 assert actual.events==expected.events and actual.freed==expected.freed
 assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks and not actual.effects.blocks
 print('PASS',hex(base),'deleting tree',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=label,operation='tree_delete',actual_wrapper=wrapper,original_returned=True,
  full_guest_payload_ELF_logical_iterator_and_free_order_match=True,container_freed_after_owned_tree_blocks=True,
  all_owned_blocks_released=True,native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','free','delete','delete_guards','guards','entry','all'),default='all')
 args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==fixture.oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 cases=[];guards=[];entries=[]
 if args.group in ('native','all'):
  for base in BASES:
   for label,profile in PROFILES:
    for wrapper in (False,True):cases.append(compare(args.library,args.libc,base,label,profile,wrapper))
 if args.group in ('free','all'):
  for base in BASES:
   for label in ('NULL','ordinary_payload','packed_payload'):cases.append(compare_free(args.library,base,label))
 if args.group in ('delete','all'):
  import verify_vm9_request_tree_destroy_fresh_20261012 as tree_fixture
  for base in BASES:
   for label,profile in (tree_fixture.PROFILES[i] for i in (0,1,4,5)):
    for wrapper in (False,True):cases.append(compare_delete(args.library,base,label,profile,wrapper))
 if args.group in ('delete_guards','all'):
  import verify_vm9_request_tree_destroy_fresh_20261012 as tree_fixture,vm9_registry as registry
  for base in BASES:
   for label in ('missing_free','container_free_exception','unaligned_stack'):
    p,blocks,next_address=tree_fixture.fresh(args.library,base,tree_fixture.PROFILES[5][1])
    blocks[tree_fixture.CONTAINER]=40;service=fixture.ReferenceServices(blocks)
    def free(p,pointer):
     if label=='container_free_exception' and pointer==tree_fixture.CONTAINER:
      _write_span(p,tree_fixture.PACKED,b'\xa5');raise RefillUnsupported('injected deleting tree free failure')
     return service.free(p,pointer)
    before={k:bytes(v) for k,v in p.items()}
    try:registry.delete_configuration_tree(p,container_address=tree_fixture.CONTAINER,
     entry_stack_address=SP-1 if label=='unaligned_stack' else SP,image_base=base,free=None if label=='missing_free' else free)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),operation='tree_delete',case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS deleting tree rollback',hex(base),label,flush=True)
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_allocator','missing_free','free_exception','unaligned_stack','unmapped_scope','guard_wait','unrecovered_emission','unknown_reference_destructor'):
    p,blocks,out=fresh(args.library,base,dict(owned_string=True));service=fixture.ReferenceServices(blocks)
    kw=dict(image_base=base,entry_stack_address=SP,object_address=out,thread_pointer=TP,
     thread_id=137,allocate=service.malloc,free=service.free,diagnostic_observer=service.diagnostic)
    if label=='missing_allocator':kw['allocate']=None
    elif label=='missing_free':kw['free']=None
    elif label=='free_exception':
     def free(p,pointer):
      _write_span(p,PACKED,b'\xa5');raise RefillUnsupported('injected request object free failure')
     kw['free']=free
    elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
    elif label=='unmapped_scope':kw['entry_stack_address']=0x66001000
    elif label=='guard_wait':fixture.w(p,base+0x3DEDA1,2,1)
    elif label=='unrecovered_emission':fixture.w(p,out+0x48,1,1)
    elif label=='unknown_reference_destructor':fixture.w(p,REFERENCED,base+0x35B7C0)
    before={k:bytes(v) for k,v in p.items()}
    try:leaf.destroy_request_object(p,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS request destroy rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')
if __name__=='__main__':main()
