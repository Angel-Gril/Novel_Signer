"""Fresh original process-exit registration wrapper and ELF import binding.

Exit registration is an explicit service. This does not execute process exit,
call a destructor, or prove Android libc __cxa_atexit table behavior.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_callbacks as callbacks
import verify_vm9_request_prefix_fresh_20261007 as prefix
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x1400;OUT=G+0x1500
STATUS=(0,1,-1,0xFFFFFFFF,-(1<<31),0x7FFFFFFF)


def fresh(library,base):
 return {**oracle.image_pages(library,base),**oracle.fresh_pages()}


def compare(library,base,label,status,words):
 p=fresh(library,base);ledger=prefix.resolve_request_memory_imports(p,library,base)
 target=int.from_bytes(_read_span(p,base+0x382CD8,8),'little');assert target==base+0x347EA0
 arguments=(target,*words)
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in arguments)+b'\xa5'*8)
 native_calls=[];model_calls=[]
 def native_registration(c):
  args=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3))
  assert args==words;native_calls.append(args)
  c.mem_write(OUT,(status&0xFFFFFFFF).to_bytes(4,'little'));return status&0xFFFFFFFF
 returned,memory,_,_=oracle.native(library,base,0x285B7C,[PACKED],p,
  host_imports={0x347EA0:native_registration},instruction_limit=10000)
 def register(p,*args):
  assert args==words;model_calls.append(args)
  _write_span(p,OUT,(status&0xFFFFFFFF).to_bytes(4,'little'));return status
 result=callbacks.register_process_destructor(p,destructor_address=words[0],object_address=words[1],
  dso_address=words[2],register_exit=register)
 _write_span(p,PACKED+32,result.to_bytes(4,'little'))
 assert result==returned&0xFFFFFFFF and _read_span(p,G,0xA000)==memory
 assert native_calls==model_calls
 assert any(r['symbol']=='__cxa_atexit' and r['relocation_offset']=='0x382cd8' for r in ledger)
 print('PASS',hex(base),'process registration',label,flush=True)
 return dict(image_base=hex(base),case=label,original_wrapper_returned=True,
  full_payload_and_packed_u32_status_match=True,process_exit_service_arguments_and_order_match=True,
  atexit_ABS64_and_PLT_binding_verified=True,registration_provider_is_explicit=True,native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','guards','entry','all'),default='all')
 args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 cases=[];guards=[];entries=[]
 if args.group in ('native','all'):
  for base in BASES:
   for status in STATUS:
    cases.append(compare(args.library,base,'status_'+str(status),status,(base+0x2484B8,base+0x3E0D98,base+0x34C700)))
   cases.append(compare(args.library,base,'NULL_words',0,(0,0,0)))
   cases.append(compare(args.library,base,'full_uint64_words',0,((1<<64)-1,)*3))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_service','provider_exception','invalid_status','status_overflow','word_overflow'):
    p=fresh(args.library,base)
    def register(p,*args):
     _write_span(p,OUT,b'\xa5'*4)
     if label=='provider_exception':raise RefillUnsupported('injected process registration failure')
     return None if label=='invalid_status' else 1<<32 if label=='status_overflow' else 0
    kw=dict(destructor_address=base+0x2484B8,object_address=OUT,dso_address=base+0x34C700,
     register_exit=None if label=='missing_service' else register)
    if label=='word_overflow':kw['object_address']=1<<64
    before={k:bytes(v) for k,v in p.items()}
    try:callbacks.register_process_destructor(p,**kw)
    except RefillUnsupported:pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS registration rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  real_libc_process_atexit_table_verified=False,registered_destructor_executed=False,
  live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
