"""Actual nested MD5 wrapper and its scoped reference lifecycle.

Packed hidden X8 and byte flag are independently constructed. Matching libc
recursive mutexes run; old digest/helper groups are not repeated.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import vm9_request_token_vm as model
import vm9_diagnostics as diagnostics
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;OUT=G+0x1000;OBJ=G+0x1800;DATA=G+0x2000
PACKED=G+0x2400;SP=dependency.SP;TP=dependency.TP
PROFILES=('raw_empty','raw_binary','raw_padding','raw_two_blocks','raw_NULL_source','raw_flag_two',
 'hex_empty','hex_binary','hex_padding','hex_two_blocks','hex_NULL_source','hex_high_flag',
 'hex_warm','raw_warm','hex_cross_page_output','raw_cross_page_packed')


def fresh(library,base,label):
 p=dependency.fresh(library,base,warm=label.endswith('warm'));payload=b'fixture\0bytes'
 flag=1 if label.startswith('hex') else 0;out=OUT;packed=PACKED
 if label.endswith('empty'):payload=b''
 elif label.endswith('padding'):payload=bytes(range(45))
 elif label.endswith('two_blocks'):payload=bytes(range(60))
 elif label.endswith('flag_two'):flag=2
 elif label.endswith('high_flag'):flag=0xABCDEF0180000001
 elif label.endswith('cross_page_output'):out=G+0x1FF8
 elif label.endswith('cross_page_packed'):packed=G+0x6FF8
 dependency.w(p,OBJ,base+0x34F5F8);dependency.w(p,OBJ+8,len(payload)+1,4)
 dependency.w(p,OBJ+12,len(payload),4);dependency.w(p,OBJ+16,0 if label.endswith('NULL_source') else DATA)
 _write_span(p,DATA,payload+b'\0')
 _write_span(p,packed,(base+0x25874C).to_bytes(8,'little')+out.to_bytes(8,'little')+OBJ.to_bytes(8,'little')+flag.to_bytes(8,'little')+b'\xA5'*8)
 return p,packed,out


def original(library,libc,base,p,packed):
 effects=dependency.Services();scopes=[]
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 child=SP-16
 for span in ((child-0x58,16),(child-0x48,16)):watch[span]=None
 def observe(cpu,a):
  offset=a-base
  if offset in (0x347F00,0x347F10):effects.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
  elif offset==0x348310:effects.diagnostic('gettid',137)
  elif offset==0x26C9D0:
   scope=cpu.reg_read(arm.UC_ARM64_REG_X0);scopes.append((scope,bytes(cpu.mem_read(scope,24))))
 returned,memory,_,_=oracle.native(library,base,0x288BBC,[packed],p,libc=libc,real_diagnostics=True,
  real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
  malloc_handler=effects.native_malloc,host_imports={0x347FA0:effects.native_free},instruction_observer=observe,
  extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},observed_memory=watch,instruction_limit=300000)
 return memory,watch,scopes,effects


def red(library,libc):
 assert not hasattr(model,'apply_token_digest_callback');rows=[]
 for base in BASES:
  p,packed,out=fresh(library,base,'hex_binary');memory,watch,scopes,effects=original(library,libc,base,p,packed)
  assert scopes and len(effects.events)>4 and int.from_bytes(memory[out-G:out-G+8],'little')
  rows.append(dict(image_base=hex(base),original_digest_consumer_returned=True,prior_nested_digest_consumer_missing=True,
   actual_matching_libc_recursive_mutexes=True,native_snapshot_input=False))
 return rows


def compare(library,libc,base,label):
 p,packed,out=fresh(library,base,label);memory,watch,expected_scopes,expected=original(library,libc,base,p,packed)
 actual=dependency.Services();scopes=[];leave=diagnostics.leave_diagnostic_scope
 def record(p,**kw):
  a=kw['object_address'];scopes.append((a,_read_span(p,a,24)));return leave(p,**kw)
 diagnostics.leave_diagnostic_scope=record
 try:result=model.apply_token_digest_callback(p,argument_block_address=packed,image_base=base,
  entry_stack_address=SP,thread_pointer=TP,thread_id=137,allocate=actual.malloc,
  reallocate=actual.effects.realloc,free=actual.free,observer=actual.diagnostic)
 finally:diagnostics.leave_diagnostic_scope=leave
 got=_read_span(p,G,0xA000)
 assert got==memory,(label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(got,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(label,'ELF/scratch')
 assert scopes==expected_scopes,(label,'scopes')
 assert actual.events==expected.events and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks and actual.freed==expected.freed,(label,'effects')
 assert result==int.from_bytes(_read_span(p,out,8),'little')
 print('PASS nested MD5 consumer',hex(base),label,flush=True)
 return dict(image_base=hex(base),case=label,original_consumer_returned=True,
  all_guest_ELF_packed_and_defined_digest_scratch_equal=True,scope_exit_bytes_equal=True,
  ordered_allocator_free_mutex_gettid_and_prefree_bytes_equal=True,actual_matching_libc_recursive_mutexes=True,
  native_snapshot_input=False,native_physical_X0_compared=False)


def guards(library):
 rows=[]
 for label in ('bad_target','unaligned_stack','unmapped_source','unmapped_output','digest_bound','guard_wait','NULL_allocate','unmapped_scope'):
  base=BASES[0];p,packed,out=fresh(library,base,'hex_binary');service=dependency.Services()
  kw=dict(argument_block_address=packed,image_base=base,entry_stack_address=SP,thread_pointer=TP,thread_id=137,
   allocate=service.malloc,reallocate=service.effects.realloc,free=service.free)
  if label=='bad_target':dependency.w(p,packed,base+0x258780)
  elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
  elif label=='unmapped_source':dependency.w(p,packed+16,0x64000000)
  elif label=='unmapped_output':dependency.w(p,packed+8,0x64000000)
  elif label=='digest_bound':kw['max_source_bytes']=12
  elif label=='guard_wait':dependency.w(p,base+diagnostics.GUARD+1,2,1)
  elif label=='NULL_allocate':kw['allocate']=lambda p,n:0
  elif label=='unmapped_scope':kw['entry_stack_address']=0x64001000
  before={k:bytes(v) for k,v in p.items()}
  try:model.apply_token_digest_callback(p,**kw)
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
 e=dict(schema='vm9-request-token-digest-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  libc_sha256=dependency.LIBC_SHA256,cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library,args.libc)
 if args.group in ('consumer','all'):e['cases']=[compare(args.library,args.libc,b,n) for b in BASES for n in PROFILES]
 if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS nested digest',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
