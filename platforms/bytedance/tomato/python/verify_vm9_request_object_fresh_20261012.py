"""Fresh original request object construction, reference lifetime and realtime.

Original diagnostic scopes and matching libc locks execute normally. Clock,
allocator and free services are explicit inputs; no native snapshot is input.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
from verify_vm9_reference_scopes_fresh_20261011 import Services as ReferenceServices
from verify_vm9_jni_byte_array_fresh_20261011 import fresh as reference_fresh,w,SP,TP
import verify_vm9_signer_objects as oracle
import vm9_request_leaf_prefixes as leaf
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;OUT=G+0x1400;SOURCE=G+0x1600;DATA=G+0x1700;REF=G+0x1800;COUNT=G+0x1900
BASES=(0x122C0000,0x775C205000)
def fresh(library,base,profile):
 p=reference_fresh(library,base,warm=profile.get('warm',False),referenced=0)
 out=G+0x1FE0 if profile.get('cross_page') else OUT
 payload=profile.get('payload',b'request\0object');length=profile.get('length',len(payload))
 w(p,SOURCE,base+0x34F5F8);w(p,SOURCE+8,(length+1)&0xFFFFFFFF,4);w(p,SOURCE+12,length,4)
 w(p,SOURCE+16,0 if length>=0x80000000 else DATA);_write_span(p,DATA,payload+b'\0')
 w(p,REF,profile.get('reference_pointer',0));w(p,REF+8,0 if profile.get('count') is None else COUNT)
 blocks={}
 if profile.get('count') is not None:w(p,COUNT,profile['count'],4);blocks[COUNT]=4
 return p,blocks,out
class Services(ReferenceServices):
 def __init__(self,base,blocks,profile):
  super().__init__(blocks,profile.get('failures',()));self.base=base;self.profile=profile
 def clock(self,p,clock_id):
  assert clock_id==0
  result=self.profile.get('clock',(0,1791023800,500999999));self.events.append(['clock',clock_id,*result]);return result
 def imports(self):
  def clock(c):
   status,sec,nsec=self.clock(None,c.reg_read(arm.UC_ARM64_REG_X0))
   c.mem_write(c.reg_read(arm.UC_ARM64_REG_X1),sec.to_bytes(8,'little',signed=True)+nsec.to_bytes(8,'little',signed=True));return status
  return {0x347FA0:self.native_free,0x348450:clock}
 def execute(self,p,out,**options):
  kw=dict(image_base=self.base,entry_stack_address=SP,object_address=out,kind=self.profile.get('kind',7),
   source_string_address=SOURCE,mode=self.profile.get('mode',4),flag=self.profile.get('flag',1),
   thread_pointer=TP,thread_id=137,allocate=self.malloc,free=self.free,read_clock=self.clock,
   diagnostic_observer=self.diagnostic)
  kw.update(options)
  if self.profile.get('direct'):
   kw.pop('free');kw['reference_address']=REF
   return leaf.construct_request_object(p,**kw)
  return leaf.construct_request_object_with_null_reference(p,**kw)
def native(library,libc,base,p,service,out):
 profile=service.profile;observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 if not profile.get('direct'):observed[SP-0x58,16]=None
 def watch(c,a):
  off=a-base
  if off in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
  if off==0x348310:service.diagnostic('gettid',137)
 args=[out,profile.get('kind',7),SOURCE]
 args += [REF,profile.get('mode',4),profile.get('flag',1)] if profile.get('direct') else [profile.get('mode',4),profile.get('flag',1)]
 entry=0x25CE68 if profile.get('direct') else 0x25CDD4
 if profile.get('wrapper'):
  assert not profile.get('direct')
  packed=G+0x2000
  _write_span(p,packed,(base+0x25CDD4).to_bytes(8,'little')+out.to_bytes(8,'little')
   +profile.get('kind',7).to_bytes(4,'little')+bytes(4)+SOURCE.to_bytes(8,'little')
   +profile.get('mode',4).to_bytes(4,'little')+bytes((profile.get('flag',1)&255,))+bytes(11))
  entry=0x285AA0;args=[packed]
 registers={arm.UC_ARM64_REG_TPIDR_EL0:TP}
 if profile.get('direct'):registers[arm.UC_ARM64_REG_X5]=profile.get('flag',1)
 result,memory,_,_=oracle.native(library,base,entry,args,p,
  libc=libc,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,
  extra_registers=registers,thread_id=137,host_imports=service.imports(),
  malloc_handler=service.native_malloc,observed_memory=observed,instruction_observer=watch,instruction_limit=300000)
 return result,memory,observed


def compare(library,libc,base,label,profile):
 p,blocks,out=fresh(library,base,profile);expected=Services(base,blocks,profile);actual=Services(base,blocks,profile)
 returned,memory,observed=native(library,libc,base,p,expected,out)
 result=actual.execute(p,out)
 got=_read_span(p,G,0xA000)
 if got!=memory:
  offset=next(i for i,(a,b) in enumerate(zip(got,memory)) if a!=b)
  raise AssertionError((label,'guest mismatch',hex(offset)))
 for (a,n),v in observed.items():assert _read_span(p,a,n)==v,(label,'observed',hex(a),n)
 assert expected.events==actual.events,(label,'service order',expected.events,actual.events)
 assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
 assert actual.freed==expected.freed
 if profile.get('direct'):assert returned==result&((1<<64)-1)
 print('PASS',hex(base),'request object',label,flush=True)
 return dict(image_base=hex(base),case=label,component='direct_constructor' if profile.get('direct') else 'null_reference_constructor',
  wrapper_executed=bool(profile.get('wrapper')),original_returned=True,
  full_guest_payload_and_ELF_pages_match=True,temporary_reference_matches=not profile.get('direct'),
  clock_allocator_free_and_diagnostic_order_match=True,final_heap_and_pre_free_bytes_match=True,
  native_direct_return_matches=bool(profile.get('direct')),native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True)
 ap.add_argument('--group',choices=('native','guards','entry','all'),default='all')
 args=ap.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 profiles=[('cold',{}),('warm',dict(warm=True)),('cross_page',dict(cross_page=True)),
  ('empty_string',dict(payload=b'')),('one_byte',dict(payload=b'x')),
  ('length31',dict(payload=bytes(range(31)))),('length32',dict(payload=bytes(range(32)))),
  ('length33',dict(payload=bytes(range(33)))),('negative_length',dict(length=0x80000000)),
  ('wrapped_length',dict(length=0xFFFFFFFF)),('max_kind',dict(kind=0xFFFFFFFF)),
  ('max_mode',dict(mode=0xFFFFFFFF)),('flag_truncation',dict(flag=0xABCDEF12)),
  ('zero_time',dict(clock=(0,0,0))),('sub_millisecond',dict(clock=(0,0,999999))),
  ('negative_time',dict(clock=(0,-2,999999999))),('negative_sub_millisecond',dict(clock=(0,-1,999999999))),
  ('maximum_seconds_wrap',dict(clock=(0,(1<<63)-1,999999999))),
  ('minimum_seconds_wrap',dict(clock=(0,-(1<<63),0))),
  ('NULL_string_allocation',dict(warm=True,failures=(1,))),
  ('tail_wrapper',dict(wrapper=True)),('tail_wrapper_uint32',dict(wrapper=True,kind=0xFFFFFFFF,mode=0x80000000,flag=255))]
 for count in (None,0,1,2,0xFFFFFFFF):profiles.append(('direct_count_'+str(count),dict(direct=True,count=count)))
 profiles += [('direct_opaque_reference',dict(direct=True,count=2,reference_pointer=DATA)),
  ('direct_NULL_string_allocation',dict(direct=True,warm=True,failures=(0,))),
  ('direct_empty_string',dict(direct=True,payload=b''))]
 cases=[];guards=[];entries=[]
 if args.group in ('native','all'):
  for base in BASES:
   for label,profile in profiles:cases.append(compare(args.library,args.libc,base,label,profile))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_allocator','missing_free','missing_clock','clock_exception','clock_error',
    'invalid_nanoseconds','invalid_seconds','malformed_clock','NULL_count_allocation','unaligned_stack',
    'missing_string','payload_bound','kind_overflow','mode_overflow','flag_overflow','guard_wait'):
    profile=dict(warm=True,failures=(0,)) if label=='NULL_count_allocation' else {}
    p,blocks,out=fresh(args.library,base,profile);service=Services(base,blocks,profile);kw={}
    if label=='missing_allocator':kw['allocate']=None
    elif label=='missing_free':kw['free']=None
    elif label=='missing_clock':kw['read_clock']=None
    elif label=='clock_exception':
     def fail(*a):raise RefillUnsupported('injected request realtime failure')
     kw['read_clock']=fail
    elif label=='clock_error':kw['read_clock']=lambda *a:(1,0,0)
    elif label=='invalid_nanoseconds':kw['read_clock']=lambda *a:(0,0,1000000000)
    elif label=='invalid_seconds':kw['read_clock']=lambda *a:(0,1<<63,0)
    elif label=='malformed_clock':kw['read_clock']=lambda *a:(0,0)
    elif label=='unaligned_stack':kw['entry_stack_address']=SP+1
    elif label=='missing_string':kw['source_string_address']=0
    elif label=='payload_bound':kw['max_payload_bytes']=1
    elif label=='kind_overflow':kw['kind']=1<<32
    elif label=='mode_overflow':kw['mode']=1<<32
    elif label=='flag_overflow':kw['flag']=1<<32
    elif label=='guard_wait':w(p,base+0x3DEDA1,2,1)
    before={k:bytes(v) for k,v in p.items()}
    try:service.execute(p,out,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS request object rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
