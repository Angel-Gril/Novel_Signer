"""Fresh original scoped registry counter lookup, saturation and insertion.

Existing tree/scope owners build independent fixture inputs. Original ELF
counter, lookup, clone and insertion execute; native snapshots are never input.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
import vm9_objects as objects
import vm9_registry as registry
from vm9_allocator import _read_span,_write_span,RefillUnsupported
from verify_vm9_reference_scopes_fresh_20261011 import Services as ReferenceServices
from verify_vm9_registry_initialization import warm_tls,FLAG,TREE,ENTRY_SP
from verify_vm9_registry import fixture,BASES
from verify_vm9_root_configuration import TLS,LIBC_BASE
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
G=oracle.GUEST;OBJECT=G+0x1000;QUERY=G+0x1800;DATA=G+0x1C00
def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def fresh(library,base,profile):
 keys=profile.get('keys',[]);p,blocks,addresses=fixture(library,base,keys)
 warm_tls(p);prefix=Effects(blocks=blocks)
 objects.construct_registry_layout320(p,object_address=OBJECT,image_base=base,allocate=prefix.malloc)
 for i,(obj,payload,value) in enumerate(addresses):
  w(p,value,profile.get('values',[0]*len(addresses))[i],4)
  registry.insert_configuration_pair(p,container_address=OBJECT+8,key_address=obj,value_address=value,
   image_base=base,allocate=prefix.malloc,free=prefix.free)
 key=profile.get('key',b'counter');w(p,QUERY,base+0x34F5F8);w(p,QUERY+8,len(key)+1,4);w(p,QUERY+12,len(key),4)
 w(p,QUERY+16,DATA);_write_span(p,DATA,key+b'\0')
 return p,prefix.blocks,prefix.next
class Services(ReferenceServices):
 def __init__(self,base,blocks,next_address,profile):
  super().__init__(blocks,profile.get('failures',()));self.base=base;self.profile=profile;self.effects.next=next_address
 def tls(self,p,control):
  self.events.append(['TLS',control-self.base,len(self.effects.calls)])
  return {self.base+0x382470:FLAG,self.base+0x382450:TREE}[control]
 def initialize(self,p):
  objects.initialize_scoped_tls_registry(p,image_base=self.base,get_tls=self.tls,
   register_destructor=lambda *a:(_ for _ in ()).throw(AssertionError('warm TLS registered twice')))
 def wake(self,p,pointer,operation,count):
  self.events.append(['wake',pointer,operation,count,len(self.effects.calls)]);return 0
 def broadcast(self,p,pointer):return objects.broadcast_condition_no_waiters(p,condition_address=pointer,wake=self.wake)
 def execute(self,p,**options):
  kw=dict(registry_address=OBJECT,key_address=QUERY,
   entry_stack_address=ENTRY_SP-(16 if self.profile.get('wrapper') else 0),image_base=self.base,
   allocate=self.malloc,free=self.free,get_tls=self.tls,initialize_registry=self.initialize,broadcast=self.broadcast)
  kw.update(options);result=registry.increment_configuration_counter(p,**kw)
  if self.profile.get('wrapper'):w(p,G+0x1918,result,4)
  return result
 def imports(self,libc):
  with libc.open('rb') as stream:
   elf=ELFFile(stream);exports={s.name:LIBC_BASE+s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols()}
  def tls(c):return self.tls(None,c.reg_read(arm.UC_ARM64_REG_X0))
  def broadcast(c):c.reg_write(arm.UC_ARM64_REG_PC,exports['pthread_cond_broadcast'])
  return {0x34377C:tls,0x3485A0:broadcast,0x347FA0:self.native_free}
 def syscall(self,c,n):
  assert n==98
  return self.wake(None,c.reg_read(arm.UC_ARM64_REG_X0),c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X2))
def native(library,libc,base,p,services):
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 observed[TLS,0xB00]=None
 entry=0x256AB0;arguments=[OBJECT,QUERY]
 if services.profile.get('wrapper'):
  _write_span(p,G+0x1900,(base+entry).to_bytes(8,'little')+OBJECT.to_bytes(8,'little')+QUERY.to_bytes(8,'little')+b'\xa5'*8)
  entry=0x285ABC;arguments=[G+0x1900]
 return oracle.native(library,base,entry,arguments,p,libc=libc,
  real_mutexes=True,real_singletons=True,thread_id=137,
  extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TLS},host_imports=services.imports(libc),
  syscall_handler=services.syscall,malloc_handler=services.native_malloc,observed_memory=observed,
  instruction_limit=300000),observed


def compare(library,libc,base,label,profile):
 p,blocks,next_address=fresh(library,base,profile)
 expected=Services(base,blocks,next_address,profile);actual=Services(base,blocks,next_address,profile)
 (returned,memory,_,_),observed=native(library,libc,base,p,expected)
 result=actual.execute(p);assert result==returned&0xFFFFFFFF,(label,'return')
 got=_read_span(p,G,0xA000)
 if got!=memory:
  offset=next(i for i,(a,b) in enumerate(zip(got,memory)) if a!=b)
  raise AssertionError((label,'guest mismatch',hex(offset)))
 for (a,n),v in observed.items():assert _read_span(p,a,n)==v,(label,'observed',hex(a))
 assert expected.events==actual.events,(label,'TLS/wake order',expected.events,actual.events)
 assert expected.effects.calls==actual.effects.calls and expected.effects.blocks==actual.effects.blocks
 assert expected.freed==actual.freed,(label,'free bytes')
 print('PASS',hex(base),'request counter',label,flush=True)
 return dict(image_base=hex(base),case=label,wrapper_executed=bool(profile.get('wrapper')),
  original_returned=True,native_u32_return_matches=True,full_guest_payload_ELF_and_TLS_pages_match=True,
  ordered_TLS_allocator_free_and_wake_effects_match=True,final_heap_and_pre_free_bytes_match=True,
  native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True)
 ap.add_argument('--group',choices=('native','guards','entry','all'),default='all');args=ap.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 profiles=[('missing',{}),('missing_left',dict(keys=[b'm'],key=b'a',values=[2])),
  ('missing_right',dict(keys=[b'a'],key=b'z',values=[2])),
  ('missing_balanced',dict(keys=[b'm',b'f',b't',b'b',b'h',b'p',b'x'],values=[3]*7,key=b'j')),
  ('missing_empty',dict(key=b'')),('embedded_NUL',dict(key=b'a\0tail')),
  ('tail_wrapper',dict(wrapper=True)),
  ('existing_NUL_prefix',dict(keys=[b'a\0old'],key=b'a\0new',values=[2]))]
 for value in (0,1,42,0x7FFFFFFC,0x7FFFFFFD,0x7FFFFFFE,0x7FFFFFFF,0x80000000,0xFFFFFFFE,0xFFFFFFFF):
  profiles.append(('existing_'+hex(value),dict(keys=[b'counter'],values=[value])))
 profiles += [('existing_balanced',dict(keys=[b'm',b'f',b't',b'b',b'h',b'p',b'x'],values=[3]*7,key=b'h')),
  ('existing_wrapper_uint32',dict(wrapper=True,keys=[b'counter'],values=[0xFFFFFFFF]))]
 cases=[];guards=[];entries=[]
 if args.group in ('native','all'):
  for base in BASES:
   for label,profile in profiles:cases.append(compare(args.library,args.libc,base,label,profile))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_allocator','missing_free','missing_TLS','missing_initializer','missing_broadcast',
    'TLS_exception','multiple_TLS_keys','active_readers','contended_mutex','NULL_scope_allocation',
    'NULL_key_allocation','NULL_value_allocation','unaligned_stack','missing_key','payload_bound','tree_bound'):
    profile={}
    if label.startswith('NULL_'):profile['failures']=({'NULL_scope_allocation':0,'NULL_key_allocation':1,'NULL_value_allocation':3}[label],)
    p,blocks,next_address=fresh(args.library,base,profile);service=Services(base,blocks,next_address,profile);kw={}
    if label=='missing_allocator':kw['allocate']=None
    elif label=='missing_free':kw['free']=None
    elif label=='missing_TLS':kw['get_tls']=None
    elif label=='missing_initializer':kw['initialize_registry']=None
    elif label=='missing_broadcast':kw['broadcast']=None
    elif label=='TLS_exception':
     def fail(*a):raise RefillUnsupported('injected request counter TLS failure')
     kw['get_tls']=fail
    elif label=='multiple_TLS_keys':w(p,TREE+16,2)
    elif label=='active_readers':w(p,OBJECT+0x110,1,4)
    elif label=='contended_mutex':w(p,OBJECT+0x88,2,2)
    elif label=='unaligned_stack':kw['entry_stack_address']=ENTRY_SP+1
    elif label=='missing_key':kw['key_address']=0
    elif label=='payload_bound':kw['max_bytes']=1
    elif label=='tree_bound':kw['max_nodes']=0
    before={k:bytes(v) for k,v in p.items()}
    try:service.execute(p,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS request counter rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
