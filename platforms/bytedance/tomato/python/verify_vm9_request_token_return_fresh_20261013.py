"""Nested caller return and actual outer tail wrapper ABI controls.

Short synthetic bytecode is explicit input. Original caller, interpreter,
callback trampoline and epilogue execute; no native snapshots seed Python.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_request_caller_return_fresh_20261012 import load64
import vm9_request_caller as caller
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;TP=G+0xD000;OBJECT=G+0x4000;CALLBACK=G+0xF680;PACKED=G+0x2200
BASES=(0x122C0000,0x775C205000)
def word(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
def jump(index):
 return 13|((index&31)<<11)|(((index>>5)&31)<<6)|(((index>>10)&31)<<16)|(((index>>15)&31)<<26)|(((index>>20)&31)<<21)|(((index>>25)&1)<<31)
def fresh(library,base,top,callback,saved):
 p=oracle.image_pages(library,base);p.update(oracle.fresh_pages());p[CALLBACK>>12]=bytearray(4096)
 word(p,TP+0x28,saved[0]);word(p,OBJECT,CALLBACK);word(p,PACKED,base+0x287500);word(p,PACKED+8,OBJECT)
 program=[]
 if callback:program=[load64(4,5,0),load64(5,4,0),17|(50<<6)|(2<<17)|(7<<22)]
 program.append(jump((0x118F44-0x118570)//4))
 _write_span(p,base+0x118570,b''.join(v.to_bytes(4,'little') for v in program))
 assert _read_span(p,base+0x118F44,4)==(0x07C00791).to_bytes(4,'little')
 inputs=dict(entry_stack_address=top,return_address=oracle.STOP,thread_pointer=TP,image_base=base,
  object_address=OBJECT,saved_frame_pointer=saved[1],saved_x28=saved[2],saved_x19=saved[3])
 return p,inputs,len(program)+1
def original(library,base,p,inputs,callback,saved,wrapper):
 observed=[];calls=[];handlers=[]
 def watch(c,a):
  if a==base+0x16A974:handlers.append(a-base)
  if a==base+0x287578:
   observed.append(dict(pc=c.reg_read(arm.UC_ARM64_REG_X30),sp=c.reg_read(arm.UC_ARM64_REG_SP),
    **{'x'+str(i):c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in (0,19,28,29,30)}))
 def cb(c):
  assert c.reg_read(arm.UC_ARM64_REG_X0)==OBJECT;calls.append(True);return 0xFEDCBA9876543210
 returned,memory,allocations,effects=oracle.native(library,base,0x285EA8 if wrapper else 0x287500,
  [PACKED if wrapper else OBJECT],p,extra_registers={arm.UC_ARM64_REG_SP:inputs['entry_stack_address'],
   arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_X19:saved[3],arm.UC_ARM64_REG_X28:saved[2],arm.UC_ARM64_REG_X29:saved[1]},
  host_imports={CALLBACK-base:cb},instruction_observer=watch,instruction_limit=100000)
 assert not allocations and not effects and handlers==[0x16A974],(allocations,effects,handlers)
 return returned,observed,calls
def red(library):
 assert not hasattr(caller,'finish_request_token_vm_caller');rows=[]
 for base in BASES:
  saved=(1,2,3,4);p,inputs,_=fresh(library,base,G+0xEF00,True,saved)
  returned,observed,calls=original(library,base,p,inputs,True,saved,True)
  assert returned==base+0x2884AC and calls==[True]
  rows.append(dict(image_base=hex(base),original_token_caller_and_outer_wrapper_returned=True,
   prior_nested_return_owner_missing=True,callback_clobbered_X0_preserved=True,native_snapshot_input=False))
 return rows
def compare(library,base,top,callback,profile,wrapper):
 import vm_full
 saved={'zero':(0,0,0,0),'pattern':(0xFEDCBA9876543210,0x3456,0x2345,0x1234)}[profile]
 initial,inputs,count=fresh(library,base,top,callback,saved)
 returned,observed,calls=original(library,base,initial,inputs,callback,saved,wrapper)
 p={k:bytearray(v) for k,v in initial.items()};frame=caller.prepare_request_token_vm_caller(p,**inputs)
 m=vm_full.Mem();m.pages=p;old=vm_full.B;vm_full.B=base
 v=vm_full.VM(m,frame.bytecode_offset,frame.packed_arguments_address,base+0x35F5E0,base+0x35F650,base+0x2884AC,oracle.STOP,maxsteps=count)
 v.R=list(frame.registers);pycalls=[]
 def cb(vm,fn,arg):assert (fn,arg)==(CALLBACK,OBJECT);pycalls.append(True)
 v.native_hook=cb
 try:v.run()
 except vm_full.VMExit:pass
 finally:vm_full.B=old
 before={k:bytes(b) for k,b in p.items()}
 exit_state=caller.validate_request_token_vm_exit(p,image_base=base,pc=v.pc,registers=tuple(v.R),return_address=oracle.STOP)
 result=caller.finish_request_token_vm_caller(p,image_base=base,entry_stack_address=top,thread_pointer=TP,callback_sentinel=v.cb)
 assert returned==result.x0 and observed==[dict(vars(result))] and exit_state['selected_slot']==31
 assert calls==pycalls==([True] if callback else []) and before=={k:bytes(b) for k,b in p.items()}
 print('PASS nested return',hex(base),hex(top),callback,profile,wrapper,flush=True)
 return dict(image_base=hex(base),stack_variant=0 if top==G+0xEF00 else 1,case=profile,
  actual_outer_wrapper=wrapper,callback_clobbered_native_X0=callback,
  original_token_caller_returned=True,callback_sentinel_X0_and_PC_SP_X19_X28_X29_X30_equal=True,
  original_interpreter_return_branch_and_caller_epilogue_executed=True,
  return_owner_pages_unchanged=True,explicit_synthetic_bytecode=True,native_snapshot_input=False)
def guards(library):
 rows=[]
 for label in ('wrong_pc','wrong_word','wrong_target','wrong_register_count','canary_mismatch',
  'unaligned_stack','wrong_callback','unmapped_frame','tagged_return','unmapped_TLS'):
  base=BASES[0];p,inputs,_=fresh(library,base,G+0xEF00,False,(1,2,3,4));caller.prepare_request_token_vm_caller(p,**inputs)
  registers=[0]*32;registers[31]=oracle.STOP
  exit_kw=dict(image_base=base,pc=base+0x118F44,registers=registers,return_address=oracle.STOP)
  return_kw=dict(image_base=base,entry_stack_address=inputs['entry_stack_address'],thread_pointer=TP,callback_sentinel=base+0x2884AC)
  if label=='wrong_pc':exit_kw['pc']+=4
  elif label=='wrong_word':word(p,base+0x118F44,0x07C007D1,4)
  elif label=='wrong_target':registers[31]+=4
  elif label=='wrong_register_count':exit_kw['registers']=registers[:31]
  elif label=='canary_mismatch':
   word(p,TP+0x28,2)
   oracle.native(library,base,0x28755C,[],p,extra_registers={arm.UC_ARM64_REG_SP:inputs['entry_stack_address']-0x680,
    arm.UC_ARM64_REG_X19:TP,arm.UC_ARM64_REG_X29:inputs['entry_stack_address']-0x20},stop_offset=0x347EB0,instruction_limit=20)
  elif label=='unaligned_stack':return_kw['entry_stack_address']+=1
  elif label=='wrong_callback':return_kw['callback_sentinel']+=4
  elif label=='unmapped_frame':return_kw['entry_stack_address']=0x66001000
  elif label=='tagged_return':word(p,inputs['entry_stack_address']-0x18,1<<63)
  else:return_kw['thread_pointer']=0x66000000
  before={k:bytes(b) for k,b in p.items()}
  try:
   caller.validate_request_token_vm_exit(p,**exit_kw);caller.finish_request_token_vm_caller(p,**return_kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(b) for k,b in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,
   original_canary_failure_target_observed=label=='canary_mismatch',external_provider_rollback_verified=False))
 return rows
def integration(library):
 import vm_full,vm9_request_token_vm as token
 rows=[]
 for label in ('enabled','default_disabled','invalid_option','wrong_exit_word','budget_exhausted'):
  base=BASES[0];p,inputs,count=fresh(library,base,G+0xEF00,False,(1,2,3,4))
  kw=dict(vm_module=vm_full,maxsteps=count,continue_caller_return=True,**inputs)
  if label=='default_disabled':kw.pop('continue_caller_return')
  elif label=='invalid_option':kw['continue_caller_return']=1
  elif label=='wrong_exit_word':word(p,base+0x118F44,0x07800791,4)
  elif label=='budget_exhausted':kw['maxsteps']=1
  before={k:bytes(b) for k,b in p.items()};oldbase=vm_full.B
  try:result=token.execute_request_token_vm_prefix(p,**kw)
  except (RefillUnsupported,RuntimeError) as exc:
   if type(exc) is RuntimeError:assert label=='budget_exhausted'
   assert label!='enabled' and before=={k:bytes(b) for k,b in p.items()}
  else:
   assert label=='enabled' and isinstance(result,token.RequestTokenVmReturn)
   assert result.steps==2 and result.caller_return.x0==base+0x2884AC
   assert result.exit_state['selected_slot']==31 and before!={k:bytes(b) for k,b in p.items()}
  assert vm_full.B==oldbase
  rows.append(dict(case=label,constructed_runtime_entry_verified=True,
   rejected=label!='enabled',all_pages_unchanged=label!='enabled',vm_module_base_restored=True,
   native_snapshot_input=False))
 return rows
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','caller','guards','integration','all'),default='all');args=ap.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
 assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
 e=dict(schema='vm9-request-token-return-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  cases=[],negative_cases=[],integration_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,whole_nested_request_native_differential_verified=False)
 if args.group=='red':e['red_cases']=red(args.library)
 else:
  if args.group in ('caller','all'):e['cases']=[compare(args.library,b,t,c,n,w) for b in BASES for t in (G+0xEF00,G+0xEC00) for c in (False,True) for n in ('zero','pattern') for w in (False,True)]
  if args.group in ('guards','all'):
   e['negative_cases']=guards(args.library);e['integration_cases']=integration(args.library)
  elif args.group=='integration':e['integration_cases']=integration(args.library)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS nested return',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
