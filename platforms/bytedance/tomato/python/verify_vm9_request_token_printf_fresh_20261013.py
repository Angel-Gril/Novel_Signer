"""Actual nested allocated printf wrapper packing and live input controls.

Original wrapper and guest formatter execute from independent fixtures.
Accepted standalone formatter groups are not repeated.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import verify_vm9_request_alloc_format_fresh_20261013 as formatting
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SP=dependency.SP;TP=dependency.TP
PACKED=G+0x2400;OUT=formatting.OUT;FMT=formatting.FMT;DATA=formatting.DATA
BASES=(0x122C0000,0x775C205000)
CASES=('length_0','length_1','length_32','length_128','empty_format','literal',
 'percent','decimal_min','unsigned_max','embedded_NUL','second_pass_longer',
 'second_pass_shorter','format_changes','NULL_malloc','output_source_alias',
 'output_cross_page','packed_cross_page','packed_result_alias')


def word(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))


def fixture(library,base,label):
 p,out,args=formatting.fixture(library,base,label);packed=PACKED
 if label=='unsigned_max':_write_span(p,FMT,b'%u\0');args=(0x12345678FFFFFFFF,)
 if label=='packed_cross_page':packed=G+0x6FF8
 if label=='packed_result_alias':out=packed+32
 argument=args[0] if args else 0xDEADBEEF
 _write_span(p,packed,b''.join(v.to_bytes(8,'little') for v in
  (base+0x278314,out,FMT,argument,0xA5A5A5A5A5A5A5A5))+b'\x5A'*8)
 return p,packed


def original(library,base,p,packed,service):
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 watch[SP-0x58,8]=None
 returned,memory,_,_=oracle.native(library,base,0x288C28,[packed],p,
  malloc_handler=service.native_malloc,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},
  observed_memory=watch,instruction_limit=200000)
 return returned,memory,watch


def red(library,model):
 assert not hasattr(model,'apply_token_printf_callback');rows=[]
 for base in BASES:
  p,packed=fixture(library,base,'length_32');service=formatting.Services('length_32')
  returned,memory,watch=original(library,base,p,packed,service)
  assert returned==32 and int.from_bytes(memory[packed-G+32:packed-G+36],'little')==32
  assert service.events
  rows.append(dict(image_base=hex(base),original_printf_consumer_returned=True,
   prior_nested_printf_consumer_missing=True,native_snapshot_input=False))
 return rows


def compare(library,base,label,model):
 p,packed=fixture(library,base,label);expected=formatting.Services(label)
 returned,memory,watch=original(library,base,p,packed,expected)
 actual=formatting.Services(label)
 result=model.apply_token_printf_callback(p,argument_block_address=packed,image_base=base,
  entry_stack_address=SP,thread_pointer=TP,allocate=actual.malloc)
 own=_read_span(p,G,0xA000)
 assert own==memory,(label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(own,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(label,'ELF/canary')
 assert result==returned&0xFFFFFFFF and actual.events==expected.events
 assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
 print('PASS nested printf',hex(base),label,flush=True)
 return dict(image_base=hex(base),case=label,original_consumer_returned=True,
  uint32_return_guest_ELF_packed_padding_and_defined_canary_equal=True,
  ordered_allocator_effects_and_two_live_format_passes_equal=True,
  original_guest_formatter_executed=True,native_snapshot_input=False)


def guards(library,model):
 rows=[]
 for label in ('bad_target','unmapped_format','unmapped_argument','unmapped_output',
   'unmapped_result','unsupported_conversion','input_bound','allocation_invalid',
   'stack_alignment','canary_change'):
  base=BASES[0];p,packed=fixture(library,base,'length_32');s=formatting.Services('length_32')
  kw=dict(argument_block_address=packed,image_base=base,entry_stack_address=SP,
   thread_pointer=TP,allocate=s.malloc)
  if label=='bad_target':word(p,packed,base+0x278410)
  elif label=='unmapped_format':word(p,packed+16,0x66000000)
  elif label=='unmapped_argument':word(p,packed+24,0x66000000)
  elif label=='unmapped_output':word(p,packed+8,0x66000000)
  elif label=='unmapped_result':
   new=G+0xFFE0;_write_span(p,new,_read_span(p,packed,32));kw['argument_block_address']=new
  elif label=='unsupported_conversion':_write_span(p,FMT,b'%x\0')
  elif label=='input_bound':kw['max_bytes']=8
  elif label=='allocation_invalid':kw['allocate']=lambda p,n:1<<64
  elif label=='stack_alignment':kw['entry_stack_address']=SP+1
  else:
   def change(p,n):result=s.malloc(p,n);word(p,TP+0x28,7);return result
   kw['allocate']=change
  before={k:bytes(v) for k,v in p.items()}
  try:model.apply_token_printf_callback(p,**kw)
  except (RefillUnsupported,ValueError,TypeError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_rollback_verified=False))
 return rows


def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','consumer','guards','all'),default='all');args=ap.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
 import vm_full,vm9_request_token_tail as model
 assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
 e=dict(schema='vm9-request-token-printf-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library,model)
 else:
  if args.group in ('consumer','all'):e['cases']=[compare(args.library,b,n,model) for b in BASES for n in CASES]
  if args.group in ('guards','all'):e['negative_cases']=guards(args.library,model)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS nested printf',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
