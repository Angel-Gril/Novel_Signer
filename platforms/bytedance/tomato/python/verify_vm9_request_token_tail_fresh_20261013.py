"""Actual nested append and scoped Base64 reference consumers.

Independent inputs and live allocator mutations test actual wrapper packing.
Matching libc reference scopes execute; accepted helper groups are not rerun.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_diagnostics as diagnostics
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SP=dependency.SP;TP=dependency.TP;PACKED=G+0x2400
OUT=G+0x1000;SOURCE=G+0x1800;DEST=G+0x1900;DATA=G+0x2000;SECOND=G+0x2C00
BASES=(0x122C0000,0x775C205000)
APPEND_CASES=('binary','empty','self','source_output_alias','cross_page','NULL_malloc','growth_failure')
REFERENCE_CASES=('length_0','length_1','length_2','length_3','length_32','binary','warm','live_shorter','live_data','cross_page')


def word(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def string(p,a,base,pointer,data):
 word(p,a,base+0x34F5F8);word(p,a+8,len(data)+1,4);word(p,a+12,len(data),4);word(p,a+16,pointer)
 _write_span(p,pointer,data+b'\0')


def fixture(library,base,kind,label):
 p=dependency.fresh(library,base,warm=label=='warm');blocks={};failures=();packed=PACKED
 if kind=='append':
  wrapper=0x288BF0;target=0x248684;dest=DEST;source=SOURCE
  string(p,dest,base,DATA,b'ab\0c');string(p,source,base,SECOND,b'XYZ\xff')
  blocks={DATA:5,SECOND:5}
  if label=='empty':word(p,source+12,0,4)
  elif label=='self':source=dest
  elif label=='source_output_alias':dest=source
  elif label=='cross_page':packed=G+0x6FF8
  elif label=='NULL_malloc':failures=(0,)
  elif label=='growth_failure':failures=(0,1,2)
  words=(base+target,dest,source,0xA5A5A5A5A5A5A5A5)
 else:
  wrapper=0x288C10;target=0x258C14;out=OUT
  data=bytes(range(int(label[7:]))) if label.startswith('length_') else b'fixture\0bytes'
  if label=='cross_page':out=G+0x1FF8
  string(p,SOURCE,base,DATA,data);words=(base+target,out,SOURCE,0xA5A5A5A5A5A5A5A5)
 _write_span(p,packed,b''.join(v.to_bytes(8,'little') for v in words)+b'\xA5'*8)
 return p,packed,wrapper,blocks,failures


class Services(dependency.Services):
 def __init__(self,blocks,failures,label):super().__init__(blocks,failures);self.label=label;self.index=0
 def mutation(self,write):
  if self.index==0:
   if self.label=='live_shorter':write(SOURCE+12,(1).to_bytes(4,'little'))
   elif self.label=='live_data':write(DATA,b'revised\0bytes')
  self.index+=1
 def malloc(self,p,n):
  result=super().malloc(p,n);self.mutation(lambda a,b:_write_span(p,a,b));return result
 def native_malloc(self,c,n):
  result=super().native_malloc(c,n);self.mutation(c.mem_write);return result


def original(library,libc,base,p,packed,wrapper,service):
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000};scopes=[]
 if wrapper==0x288C10:watch[SP-0x60,16]=None
 def observe(c,a):
  offset=a-base
  if offset in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
  elif offset==0x348310:service.diagnostic('gettid',137)
  elif offset==0x26C9D0:
   scope=c.reg_read(arm.UC_ARM64_REG_X0);scopes.append((scope,bytes(c.mem_read(scope,24))))
 returned,memory,_,_=oracle.native(library,base,wrapper,[packed],p,libc=libc,
  real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
  malloc_handler=service.native_malloc,host_imports={0x347FA0:service.native_free,
   0x348320:lambda c:service.effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))},
  extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},observed_memory=watch,instruction_observer=observe,instruction_limit=300000)
 return returned,memory,watch,scopes


def red(library,libc):
 assert importlib.util.find_spec('vm9_request_token_tail') is None;rows=[]
 for base in BASES:
  for kind in ('append','reference'):
   p,packed,wrapper,blocks,failures=fixture(library,base,kind,'binary');service=Services(blocks,failures,'binary')
   returned,memory,watch,scopes=original(library,libc,base,p,packed,wrapper,service)
   assert service.events and (returned==DEST if kind=='append' else bool(scopes))
   rows.append(dict(image_base=hex(base),kind=kind,original_tail_consumer_returned=True,
    prior_nested_tail_consumers_missing=True,native_snapshot_input=False))
 return rows


def compare(library,libc,base,kind,label,model):
 p,packed,wrapper,blocks,failures=fixture(library,base,kind,label);expected=Services(blocks,failures,label)
 returned,memory,watch,expected_scopes=original(library,libc,base,p,packed,wrapper,expected)
 actual=Services(blocks,failures,label);scopes=[];leave=diagnostics.leave_diagnostic_scope
 def record(p,**kw):
  a=kw['object_address'];scopes.append((a,_read_span(p,a,24)));return leave(p,**kw)
 diagnostics.leave_diagnostic_scope=record
 try:result=model.apply_token_tail_callback(p,wrapper_offset=wrapper,argument_block_address=packed,image_base=base,
  entry_stack_address=SP,thread_pointer=TP,thread_id=137,allocate=actual.malloc,reallocate=actual.effects.realloc,free=actual.free,observer=actual.diagnostic)
 finally:diagnostics.leave_diagnostic_scope=leave
 got=_read_span(p,G,0xA000)
 assert got==memory,(kind,label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(got,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(kind,label,'ELF/scratch')
 assert scopes==expected_scopes and actual.events==expected.events and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks and actual.freed==expected.freed,(kind,label,'effects/scopes')
 if kind=='append':assert result==returned
 print('PASS nested tail',hex(base),kind,label,flush=True)
 return dict(image_base=hex(base),kind=kind,case=label,original_consumer_returned=True,
  all_guest_ELF_packed_and_defined_length_canary_equal=True,scope_exit_bytes_equal=True,
  ordered_allocator_free_realloc_mutex_gettid_and_prefree_bytes_equal=True,
  actual_matching_libc_recursive_mutexes=kind=='reference',native_snapshot_input=False)


def guards(library,model):
 rows=[]
 for label in ('bad_target','unmapped_source','unmapped_destination','input_bound','negative_length','guard_wait','allocation_NULL','canary_change'):
  base=BASES[0];p,packed,wrapper,blocks,failures=fixture(library,base,'reference','binary');service=Services(blocks,failures,'binary')
  kw=dict(wrapper_offset=wrapper,argument_block_address=packed,image_base=base,entry_stack_address=SP,
   thread_pointer=TP,thread_id=137,allocate=service.malloc,reallocate=service.effects.realloc,free=service.free)
  if label=='bad_target':word(p,packed,base+0x258D6C)
  elif label=='unmapped_source':word(p,packed+16,0x64000000)
  elif label=='unmapped_destination':word(p,packed+8,0x64000000)
  elif label=='input_bound':kw['max_bytes']=12
  elif label=='negative_length':word(p,SOURCE+12,0xFFFFFFFF,4)
  elif label=='guard_wait':word(p,base+diagnostics.GUARD+1,2,1)
  elif label=='allocation_NULL':kw['allocate']=lambda p,n:0
  elif label=='canary_change':
   def changed(p,n):result=service.malloc(p,n);word(p,TP+0x28,7);return result
   kw['allocate']=changed
  before={k:bytes(v) for k,v in p.items()}
  try:model.apply_token_tail_callback(p,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_rollback_verified=False))
 return rows


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True)
 p.add_argument('--libc',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--group',choices=('red','consumer','guards','all'),default='all');args=p.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256 and hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
 e=dict(schema='vm9-request-token-tail-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  libc_sha256=dependency.LIBC_SHA256,cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library,args.libc)
 else:
  import vm9_request_token_tail as model
  if args.group in ('consumer','all'):e['cases']=[compare(args.library,args.libc,b,k,n,model) for b in BASES for k,names in (('append',APPEND_CASES),('reference',REFERENCE_CASES)) for n in names]
  if args.group in ('guards','all'):e['negative_cases']=guards(args.library,model)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS nested tail',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
