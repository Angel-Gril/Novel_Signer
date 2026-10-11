"""Actual delayed JNI callable with two image VMs and bounded Java lookup.

Guest ELF supplies bytecode, encoded lazy strings and CRC tables. The serial
fixture has an unavailable default Java object and absent log files. Its
error reference is constructed, hashed, published and destroyed in native
order. Live Java string conversion and timed queue dispatch remain separate
boundaries. Providers must stage their own effects; no host thread is run.
"""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,_read_span,_write_span,RefillUnsupported
import vm9_objects as objects
import vm9_jni_environment as environment
import vm9_diagnostics as diagnostics
import vm9_logger as logger
import vm9_configuration_init as configuration
import vm9_registry as registry

MASK64=(1<<64)-1
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def delta(base,entry):
 pc=base+entry
 return (((((~pc|0xA060400A021040)&0xA061440A061440)+(pc&0x10400040400))|0x1010104)^0xFF5F9EBBF41DFED4)&MASK64
def encoded(p,base,d,offset):return (u(p,base+offset)+d)&MASK64
def lazy(p,base,d,destination,flag):
 destination,flag,source,mask=[encoded(p,base,d,x) for x in (destination,flag,flag+8,flag+16)]
 if not u(p,flag,4):
  objects.decode_masked_bytes(p,source_address=source,destination_address=destination,mask_address=mask,max_bytes=0x1000)
  w(p,flag,1,4)

def crc_string_object(p,base,object_address):
 length=objects._s32(u(p,object_address+12,4))
 if length>0x100000:raise RefillUnsupported('follow-up string CRC bound exceeded')
 data=_read_span(p,u(p,object_address+16),max(0,length))
 crc=0xFFFFFFFF
 for byte in data:crc=u(p,base+0x96144+((crc^byte)&255)*4,4)^(crc>>8)
 return crc^0xFFFFFFFF

def unavailable_default_object(p,*,base,sp,allocate,free,read_property,system,thread_pointer):
 for flag,source,dest,mask in ((0x3D1C60,0x7CF24,0x3D1C58,0x7D064),(0x3D1C94,0x7CF30,0x3D1C70,0x7D040)):
  if not u(p,base+flag,4):
   objects.decode_masked_bytes(p,source_address=base+source,destination_address=base+dest,mask_address=base+mask)
   w(p,base+flag,1,4)
 if u(p,base+0x3DEEE0):raise RefillUnsupported('follow-up live default Java object is unrecovered')
 temporary=sp-0x60
 objects.construct_string_object(p,object_address=temporary,source_address=base+0x3D1C58,
  allocate=allocate,vtable_address=base+0x34F5F8,empty_descriptor_address=base+0x6E168)
 logger.log_literal_unavailable(p,object_address=temporary,format_address=base+0x3D1C70,
  entry_stack_address=temporary,image_base=base,read_property=read_property,syscall=system,errno_address=thread_pointer+0x10)
 objects.destroy_string_object(p,object_address=temporary,image_base=base,free=free)

def initialize_absent_object(p,*,base,sp,receiver,allocate,free,read_property,system,thread_pointer,
 get_tls,register_destructor,invoke_javavm):
 d=delta(base,0x2191D4)
 for destination,flag in ((0x37EA30,0x37EAA8),(0x37EA38,0x37EAC0),(0x37EB38,0x37EBA8),(0x37EB48,0x37EBD8),
  *((0x37EDF8+i*8,0x37EED0+i*24) for i in range(27))):lazy(p,base,d,destination,flag)
 if u(p,receiver+0x20,1):return
 mutex=u(p,receiver+0x30)+8;scope=sp-0x1F0
 w(p,scope,base+0x34C778);w(p,scope+8,mutex-8)
 w(p,scope+0x10,objects.lock_uncontended_mutex(p,mutex_address=mutex),4)
 if not u(p,receiver+0x20,1):
  w(p,receiver+0x20,1,1)
  unavailable_default_object(p,base=base,sp=sp-0x220,allocate=allocate,free=free,
   read_property=read_property,system=system,thread_pointer=thread_pointer)
  environment.acquire_thread_environment(p,image_base=base,entry_stack_address=sp-0x220,
   output_pair_address=sp-0x210,get_tls=get_tls,register_destructor=register_destructor,invoke_javavm=invoke_javavm)
 w(p,scope,base+0x34C778)
 objects.unlock_uncontended_mutex(p,mutex_address=u(p,scope+8)+8)

def recover_absent_java_string(pages,*,image_base,entry_stack_address,receiver_address,output_reference_address,
 thread_pointer,thread_id,allocate,free,get_tls,register_destructor,invoke_javavm,read_property,system):
 p=_PageTransaction(pages);base=image_base;sp=entry_stack_address;receiver=receiver_address;out=output_reference_address
 if sp&15:raise RefillUnsupported('follow-up helper SP is unaligned')
 if u(p,receiver+0x28):raise RefillUnsupported('follow-up live Java string branch is unrecovered')
 d=delta(base,0x21CBEC)
 for dest,flag in ((0x37EA28,0x37EA90),*((0x37F1D8+i*8,0x37F218+i*24) for i in range(8))):lazy(p,base,d,dest,flag)
 env=environment.acquire_thread_environment(p,image_base=base,entry_stack_address=sp-0x1D0,
  output_pair_address=sp-0x140,get_tls=get_tls,register_destructor=register_destructor,invoke_javavm=invoke_javavm)
 if not env.environment:raise RefillUnsupported('follow-up NULL environment branch is unrecovered')
 initializer=encoded(p,base,d,0x37E9E8)
 if initializer!=base+0x2191D4:raise RefillUnsupported('follow-up initializer target is unrecovered')
 initialize_absent_object(p,base=base,sp=sp-0x1D0,receiver=receiver,allocate=allocate,free=free,
  read_property=read_property,system=system,thread_pointer=thread_pointer,get_tls=get_tls,
  register_destructor=register_destructor,invoke_javavm=invoke_javavm)
 if u(p,receiver+0x28):raise RefillUnsupported('follow-up initialized live Java string is unrecovered')
 # +21cd60 spills the owning output reference. The next scoped setter copies
 # its upper seven bytes as padding into a TLS node after this frame returns.
 w(p,sp-0xA0,out)
 error=objects._allocate(p,allocate,24)
 objects.construct_string_object(p,object_address=error,source_address=encoded(p,base,d,0x37EA28),
  allocate=allocate,vtable_address=base+0x34F5F8,empty_descriptor_address=base+0x6E168)
 _write_span(p,out,bytes(16));scope=sp-0x220
 diagnostics.enter_diagnostic_scope(p,object_address=scope,input_word=error,image_base=base,
  thread_pointer=thread_pointer,thread_id=thread_id,allocate=allocate)
 objects.construct_reference_wrapper(p,object_address=out,referenced_address=error,allocate=allocate)
 diagnostics.leave_diagnostic_scope(p,object_address=scope,image_base=base,thread_pointer=thread_pointer)
 p.commit()

@dataclass(frozen=True)
class FollowupResult:
 payload_address: int
 checksum_vm_steps: int
 lookup_vm_steps: int
 callback_pairs: tuple[tuple[int,int],...]
 configuration_value: int

def _run_vm(p,*,base,sp,payload,entry,thread_pointer,thread_id,allocate,free,get_tls,
 initialize_registry,broadcast,register_destructor,invoke_javavm,read_property,system,vm_module,max_steps):
 if entry==0x895B0:frame,top_delta,argument_delta,ret,tables,exit_offset=0x320,0x2F0,0,0x203AEC,(0,0),0x89640
 elif entry==0x89650:frame,top_delta,argument_delta,ret,tables,exit_offset=0x560,0x530,8,0x203B70,(base+0x34F090,base+0x34F0E0),0x89D18
 else:raise RefillUnsupported('unknown delayed VM entry')
 C=sp-frame;E=C+top_delta;backing=E-0x118;callback=base+0x2043D4;callback_sp=E-0x6B0
 for address,value in ((C+argument_delta,payload),(C+0x10,callback),(C+0x18,E),(C+0x20,base+ret),
  (backing,0),(backing+4*8,C+argument_delta),(backing+5*8,tables[0]),(backing+6*8,tables[1]),
  (backing+7*8,callback),(backing+29*8,(E-0x130)&~15),(backing+31*8,base+ret),(E-0x120,base+entry)):
  w(p,address,value)
 class Memory(vm_module.Mem):
  def __init__(self,pages):self.pages=pages
  def _pg(self,address):
   if address>>12 not in self.pages:raise RefillUnsupported('unmapped delayed VM page')
   return self.pages[address>>12]
 old=vm_module.B;pairs=[]
 try:
  vm_module.B=base;vm=vm_module.VM(Memory(p),entry,0,0,0,callback,base+ret,maxsteps=max_steps)
  vm.R=[u(p,backing+i*8) for i in range(32)];vm.register_backing_base=backing
  vm._vm_tmp32=u(p,backing+0x100);vm._vm_tmp33=u(p,backing+0x108)
  def native(current,function,arg):
   wrapper=function-base;target=u(p,arg)-base
   if entry!=0x89650:raise RefillUnsupported('unexpected checksum VM callback')
   if (wrapper,target)==(0x2043E0,0x167E54):
    objects.decode_masked_bytes(p,source_address=u(p,arg+8),destination_address=u(p,arg+16),mask_address=u(p,arg+24))
   elif (wrapper,target)==(0x2043F4,0x21CBEC):
    recover_absent_java_string(p,image_base=base,entry_stack_address=callback_sp-0x10,
     receiver_address=u(p,arg+16),output_reference_address=u(p,arg+8),thread_pointer=thread_pointer,
     thread_id=thread_id,allocate=allocate,free=free,get_tls=get_tls,register_destructor=register_destructor,
     invoke_javavm=invoke_javavm,read_property=read_property,system=system)
   elif (wrapper,target)==(0x20440C,0x26C858):
    diagnostics.enter_diagnostic_scope(p,object_address=u(p,arg+8),input_word=u(p,arg+16),image_base=base,
     thread_pointer=thread_pointer,thread_id=thread_id,allocate=allocate)
   elif (wrapper,target)==(0x20441C,0x26C9D0):
    diagnostics.leave_diagnostic_scope(p,object_address=u(p,arg+8),image_base=base,thread_pointer=thread_pointer)
   elif (wrapper,target)==(0x204428,0x24880C):
    w(p,arg+24,int(configuration.string_equals_cstring(p,object_address=u(p,arg+8),cstring_address=u(p,arg+16))),1)
   elif (wrapper,target)==(0x204464,0x258BAC):
    w(p,arg+16,crc_string_object(p,base,u(p,arg+8)),4)
   elif (wrapper,target)==(0x2044D0,0x248344):
    objects.construct_string_object(p,object_address=u(p,arg+8),source_address=u(p,arg+16),allocate=allocate,
     vtable_address=base+0x34F5F8,empty_descriptor_address=base+0x6E168)
   elif (wrapper,target)==(0x2044E0,0x2568C8):
    result=registry.set_configuration_u32(p,registry_address=u(p,arg+8),key_address=u(p,arg+16),value=u(p,arg+24,4),
     entry_stack_address=callback_sp-0x10,image_base=base,allocate=allocate,free=free,get_tls=get_tls,
     initialize_registry=initialize_registry,broadcast=broadcast)
    w(p,arg+28,result,4)
   elif wrapper==0x204458 and target in (0x2484B8,0x2484FC):
    objects.destroy_string_object(p,object_address=u(p,arg+8),image_base=base,free=free,delete_object=target==0x2484FC)
   elif (wrapper,target)==(0x20444C,0x32A264):free(p,u(p,arg+8))
   else:raise RefillUnsupported(f'unknown delayed VM callback +{wrapper:#x} -> +{target:#x}')
   pairs.append((wrapper,target))
  vm.native_hook=native;exited=False
  try:vm.run()
  except vm_module.VMExit:exited=True
  except RuntimeError as error:
   if vm.steps>max_steps:raise RefillUnsupported('delayed VM budget exhausted') from error
   raise
  if not exited or vm.pc!=base+exit_offset:raise RefillUnsupported('delayed VM did not reach its recovered exit')
  for index,value in enumerate(vm.R):w(p,backing+index*8,value)
  return vm.steps,tuple(pairs)
 finally:vm_module.B=old

def run_delayed_followup_callable(pages,*,callable_address,image_base,entry_stack_address,thread_pointer,thread_id,
 allocate,free,read_clock,get_tls,initialize_registry,broadcast,register_destructor,invoke_javavm,
 read_property,system,vm_module,max_steps=10000000):
 """+0x2043bc -> singleton136 -> +0x203948, without draining the timed queue.

 The existing inline callable and initialized serial main-thread services are
 inputs. Both VM bodies run from guest bytecode to their original exits. A
 successful call includes configuration writes and owning string cleanup.
 Unsupported branches roll back pages; external provider ledgers are separate.
 """
 if type(max_steps) is not int or not 1<=max_steps<=10000000:raise ValueError('invalid delayed VM instruction bound')
 if type(entry_stack_address) is not int or entry_stack_address<0x1000 or entry_stack_address&15:
  raise RefillUnsupported('delayed callable stack must be aligned')
 objects._image_address(image_base,0x3E31F8)
 if type(thread_id) is not int or not 0<thread_id<=0xFFFFFFFF:raise RefillUnsupported('delayed callable requires a nonzero thread id')
 if not all(callable(f) for f in (allocate,free,read_clock,get_tls,initialize_registry,broadcast,register_destructor,
  invoke_javavm,read_property,system)):raise RefillUnsupported('delayed callable requires explicit services')
 p=_PageTransaction(pages);b=image_base;S=entry_stack_address;obj=callable_address
 if not obj or u(p,obj)!=b+0x34F058 or u(p,obj+0x20)!=obj or u(p,b+0x34F088)!=b+0x2043BC:
  raise RefillUnsupported('unknown delayed inline callable')
 if not u(p,b+0x3D1680,1)&1:raise RefillUnsupported('delayed callable requires initialized singleton136')
 r=registry.get_singleton136_reference(p,image_base=b,entry_stack_address=S-0x10,thread_id=thread_id,
  allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast)
 payload=u(p,r.wrapper_address)
 if not u(p,b+0x3D9E34,4):
  objects.decode_masked_bytes(p,source_address=b+0x89490,destination_address=b+0x3D9E10,mask_address=b+0x89580)
  w(p,b+0x3D9E34,1,4)
 w(p,payload+0x50,u(p,payload+0x50,4)|1,4)
 kw=dict(base=b,sp=S-0x90,payload=payload,thread_pointer=thread_pointer,thread_id=thread_id,
  allocate=allocate,free=free,get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast,
  register_destructor=register_destructor,invoke_javavm=invoke_javavm,read_property=read_property,
  system=system,vm_module=vm_module,max_steps=max_steps)
 first,_=_run_vm(p,entry=0x895B0,**kw);second,pairs=_run_vm(p,entry=0x89650,**kw)
 r=registry.get_registry320_reference(p,image_base=b,entry_stack_address=S-0x90,thread_id=thread_id,
  allocate=allocate,free=free,read_clock=read_clock,get_tls=get_tls,initialize_registry=initialize_registry,broadcast=broadcast)
 temporary=S-0x90
 objects.construct_string_object(p,object_address=temporary,source_address=b+0x3D9E10,allocate=allocate,
  vtable_address=b+0x34F5F8,empty_descriptor_address=b+0x6E168)
 value=u(p,payload+0x50,4)
 registry.set_configuration_u32(p,registry_address=u(p,r.wrapper_address),key_address=temporary,value=value,
  entry_stack_address=S-0x90,image_base=b,allocate=allocate,free=free,get_tls=get_tls,
  initialize_registry=initialize_registry,broadcast=broadcast)
 objects.destroy_string_object(p,object_address=temporary,image_base=b,free=free)
 result=FollowupResult(payload,first,second,pairs,value);p.commit();return result
