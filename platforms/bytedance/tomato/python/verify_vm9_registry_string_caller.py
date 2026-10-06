"""Newly constructed registry + caller + VM, using explicit warm TLS providers.

Same-run repeats compare all32 slots at each native return, guest/image/TLS
bytes, pre-free bytes, allocator state and TLS/wake order. This component
uses synthetic allocator effects; it is not same-startup actual-root joining.
"""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_TPIDR_EL0
import vm9_registry as model,vm9_objects as objects
from vm9_allocator import RefillUnsupported,_read_span,_write_span
import verify_vm9_registry_initialization as h
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects,fields
from verify_vm9_recursive_mutex import bindings
from verify_vm9_libc_mapping import LIBC_SHA256

LABELS=('cold_once','same_run_three','long_growth_before_format','empty_binary','relocated_stack_canary','allocator_padding')


def fixture(library,base):
 p,blocks,_=h.fixture(library,base,[]);h.warm_tls(p)
 prefix=Effects(blocks=blocks)
 objects.construct_registry_layout320(p,object_address=h.OBJECT,image_base=base,allocate=prefix.malloc)
 obj,data=oracle.GUEST+0x2000,oracle.GUEST+0x3000
 _write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little'))
 fields(p,obj+8,6,5,data);_write_span(p,data,b'alpha\0')
 return p,prefix,obj,data


def values_for(label):
 if label=='cold_once':return [b'alpha']
 if label=='long_growth_before_format':return [b'x'*97,b'y'*63]
 if label=='empty_binary':return [b'a\0tail',b'',b'\xff\x80']
 return [b'alpha',b'beta',b'suffix']


def case(library,libc,base,label,vm_module,exports):
 pages,prefix,obj,data=fixture(library,base)
 stack=h.ENTRY_SP-0x1000 if label=='relocated_stack_canary' else h.ENTRY_SP
 if label=='relocated_stack_canary':_write_span(pages,h.TLS+0x28,(0x3F71A29C5DE408B6).to_bytes(8,'little'))
 values=values_for(label)
 def payload(write,value):
  write(obj+8,(len(value)+1).to_bytes(4,'little')+len(value).to_bytes(4,'little')+data.to_bytes(8,'little'))
  write(data,value+b'\0')
 payload(lambda a,b:_write_span(pages,a,b),values[0])
 def mutation(kind,index,read,write):
  if label=='allocator_padding' and kind=='malloc' and index==0:
   write(stack-0x480-0x180-0x48+9,b'padding')
 expected,actual=Effects(blocks=prefix.blocks,mutate=mutation),Effects(blocks=prefix.blocks,mutate=mutation)
 expected.next=actual.next=prefix.next
 native_events=[];model_events=[];completed=[];native_freed=[];model_freed=[]
 def native_tls(cpu):
  ctrl=cpu.reg_read(UC_ARM64_REG_X0);native_events.append(['tls',ctrl-base,len(expected.calls)])
  return {base+0x382470:h.FLAG,base+0x382450:h.TREE}[ctrl]
 def get_tls(p,ctrl):
  model_events.append(['tls',ctrl-base,len(actual.calls)]);return {base+0x382470:h.FLAG,base+0x382450:h.TREE}[ctrl]
 def initialize(p):
  objects.initialize_scoped_tls_registry(p,image_base=base,get_tls=get_tls,
   register_destructor=lambda *args:(_ for _ in ()).throw(AssertionError('warm TLS registered twice')))
 def wake(p,ptr,operation,count):model_events.append(['wake',ptr,operation,count,len(actual.calls)]);return 0
 def broadcast(p,ptr):return objects.broadcast_condition_no_waiters(p,condition_address=ptr,wake=wake)
 def syscall(cpu,number):
  assert number==98
  native_events.append(['wake',cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X2),len(expected.calls)])
  return 0
 def native_broadcast(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_cond_broadcast'])
 def native_free(cpu):
  ptr=cpu.reg_read(UC_ARM64_REG_X0)
  if ptr:native_freed.append((ptr,bytes(cpu.mem_read(ptr,expected.blocks[ptr]))))
  return expected.native(cpu,'free',pointer=ptr)
 def free(p,ptr):
  if ptr:model_freed.append((ptr,_read_span(p,ptr,actual.blocks[ptr])))
  return actual.free(p,ptr)
 def done(cpu):
  assert cpu.reg_read(UC_ARM64_REG_SP)==stack
  backing=stack-0x480+0x338
  completed.append(dict(registers=[int.from_bytes(cpu.mem_read(backing+i*8,8),'little') for i in range(32)],
   guest=bytes(cpu.mem_read(oracle.GUEST,0xA000)),calls=list(expected.calls),blocks=dict(expected.blocks),events=list(native_events)))
  if len(completed)==len(values):cpu.reg_write(UC_ARM64_REG_PC,oracle.STOP);return
  payload(cpu.mem_write,values[len(completed)])
  cpu.reg_write(UC_ARM64_REG_X0,h.OBJECT);cpu.reg_write(UC_ARM64_REG_X1,obj)
  cpu.reg_write(UC_ARM64_REG_X30,h.DISPATCH);cpu.reg_write(UC_ARM64_REG_PC,base+0x256E50)
 observed={(page<<12,4096):None for page in pages if base<=page<<12<base+0x400000};observed[h.TLS,0xB00]=None
 oracle.native(library,base,0x256E50,[h.OBJECT,obj],pages,libc=libc,real_mutexes=True,real_singletons=True,thread_id=137,
  malloc_handler=lambda cpu,size:expected.native(cpu,'malloc',size),
  host_imports={0x34377C:native_tls,0x3485A0:native_broadcast,h.DISPATCH-base:done,0x347FA0:native_free,
   0x348320:lambda cpu:expected.native(cpu,'realloc',cpu.reg_read(UC_ARM64_REG_X1),cpu.reg_read(UC_ARM64_REG_X0))},
  extra_registers={UC_ARM64_REG_TPIDR_EL0:h.TLS,UC_ARM64_REG_SP:stack,UC_ARM64_REG_X30:h.DISPATCH},
  syscall_handler=syscall,observed_memory=observed,instruction_limit=1000000)
 assert len(completed)==len(values)
 results=[];previous=vm_module.B
 for value,control in zip(values,completed):
  payload(lambda a,b:_write_span(pages,a,b),value)
  result=model.append_registry_string_caller(pages,registry_address=h.OBJECT,source_object_address=obj,
   entry_stack_address=stack,return_address=h.DISPATCH,thread_pointer=h.TLS,image_base=base,vm_module=vm_module,
   allocate=actual.malloc,reallocate=actual.realloc,free=free,get_tls=get_tls,initialize_registry=initialize,broadcast=broadcast)
  diffs=[(i,hex(x),hex(y)) for i,(x,y) in enumerate(zip(result.registers,control['registers'])) if x!=y]
  guest=_read_span(pages,oracle.GUEST,0xA000)
  if diffs or guest!=control['guest']:
   print('registry string mismatch',label,'registers',diffs,'guest offsets',
    [i for i,(x,y) in enumerate(zip(guest,control['guest'])) if x!=y][:16],flush=True)
  assert not diffs and guest==control['guest']
  assert actual.calls==control['calls'] and actual.blocks==control['blocks'] and model_events==control['events']
  results.append(dict(steps=result.steps,stop_offset=hex(result.stop_offset),modeled_callbacks=result.modeled_callbacks))
 if native_freed!=model_freed:
  print('pre-free differences',label,[(index,hex(first[0]),[(i,x,y) for i,(x,y) in enumerate(zip(first[1],second[1])) if x!=y]) for index,(first,second) in enumerate(zip(native_freed,model_freed)) if first!=second],flush=True)
 assert vm_module.B==previous and native_freed==model_freed
 assert all(_read_span(pages,*span)==expected_data for span,expected_data in observed.items())
 return dict(case=label,image_base=hex(base),same_run_calls=len(results),vm_results=results,
  all_32_slots_match_at_every_return=True,guest_image_tls_bytes_and_padding_match=True,
  ordered_allocator_tls_wake_effects_and_live_blocks_match=True,all_pre_free_bytes_match=True,
  physical_stack_compared=False,explicit_warm_tls=True,explicit_allocator_effects=True,native_input_snapshot_used=False)


def rejection_cases(library,vm_module):
 rows=[];base=0x122C0000
 for label in ('unaligned_stack','tagged_return','missing_source','vm_step_bound','late_free_provider_failure','formatting_branch_unrecovered'):
  p,prefix,obj,data=fixture(library,base)
  effects=Effects(blocks=prefix.blocks);effects.next=prefix.next
  def get_tls(p,ctrl):return {base+0x382470:h.FLAG,base+0x382450:h.TREE}[ctrl]
  def initialize(p):objects.initialize_scoped_tls_registry(p,image_base=base,get_tls=get_tls,register_destructor=lambda *a:None)
  def free(p,ptr):
   effects.free(p,ptr)
   if label=='late_free_provider_failure':raise RefillUnsupported('injected release failure')
  if label=='formatting_branch_unrecovered':
   for value in (b'x'*97,b'y'*63):
    fields(p,obj+8,len(value)+1,len(value),data);_write_span(p,data,value+b'\0')
    model.append_registry_string_caller(p,registry_address=h.OBJECT,source_object_address=obj,
     entry_stack_address=h.ENTRY_SP,return_address=h.DISPATCH,thread_pointer=h.TLS,image_base=base,
     vm_module=vm_module,allocate=effects.malloc,reallocate=effects.realloc,free=free,get_tls=get_tls,
     initialize_registry=initialize,broadcast=lambda p,ptr:objects.broadcast_condition_no_waiters(p,condition_address=ptr,wake=lambda *a:0))
   fields(p,obj+8,5,4,data);_write_span(p,data,b'last\0')
  before={key:bytes(value) for key,value in p.items()};previous=vm_module.B
  try:model.append_registry_string_caller(p,registry_address=h.OBJECT,
   source_object_address=oracle.GUEST+0x10000 if label=='missing_source' else obj,
   entry_stack_address=h.ENTRY_SP+1 if label=='unaligned_stack' else h.ENTRY_SP,
   return_address=1<<63 if label=='tagged_return' else h.DISPATCH,thread_pointer=h.TLS,image_base=base,
   vm_module=vm_module,allocate=effects.malloc,reallocate=effects.realloc,free=free,get_tls=get_tls,
   initialize_registry=initialize,broadcast=lambda p,ptr:objects.broadcast_condition_no_waiters(p,condition_address=ptr,wake=lambda *a:0),
   max_steps=1 if label=='vm_step_bound' else 100000)
  except (RefillUnsupported,ValueError) as exc:
   if label=='formatting_branch_unrecovered':assert str(exc)=='unrecovered registry string callback +0x256ff0 -> +0x248908'
  else:raise AssertionError((label,'expected rejection'))
  assert before=={key:bytes(value) for key,value in p.items()} and vm_module.B==previous
  rows.append(dict(case=label,rejected=True,guest_pages_and_vm_base_unchanged=True,
   external_allocator_effects_not_rolled_back=label=='late_free_provider_failure'))
 return rows


def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
 parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
 exports=bindings(args.libc)
 rows=[]
 for base in (0x122C0000,0x775C205000):
  for label in LABELS:
   rows.append(case(args.library,args.libc,base,label,vm_full,exports));print('registry string',hex(base),label,'PASS',flush=True)
 rejected=rejection_cases(args.library,vm_full)
 report=dict(schema='vm9-registry-string-caller-native-v1',sample_sha256=oracle.LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
  cases=rows,rejection_cases=rejected,native_controls=len(rows),rollback_checks=len(rejected),
  native_input_snapshot_used=False,python_registry_string_caller_verified=True,explicit_warm_tls=True,
  explicit_allocator_effects=True,actual_allocator_outer_startup_composed=False,matching_libc_realloc_restored=False,
  large_registry_formatting_branch_restored=False,
  full_python_outer_constructor_verified=False,complete_python_medusa=False,current_online_header_matrix_verified=False)
 args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('registry string caller',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
