"""Fresh original request round schedule and block helpers.

No old helper groups or native input snapshots are used. The recovered block
reuses the existing Helios VM owner after binding its bytecode to guest ELF.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000
KEY_CASES=('zero','walk','pattern','key_context_alias','key_cross_page','context_cross_page','key_scratch_alias')
BLOCK_CASES=('zero','walk','pattern','inplace','output_before','output_after','output_key_alias','input_key_alias','cross_page')


def fixture(library,base,kind,label):
 p=oracle.image_pages(library,base);p.update(oracle.fresh_pages())
 context=G+0x1800;key=G+0x2800;source=G+0x3000;output=G+0x3800
 if kind=='key':
  data=bytes(32) if label=='zero' else bytes(range(32)) if label=='walk' else bytes((i*73+19)&255 for i in range(32))
  if label=='key_context_alias':key=context+8
  elif label=='key_cross_page':key=G+0x2FF8
  elif label=='context_cross_page':context=G+0x1FF8
  elif label=='key_scratch_alias':key=SP-0x90
  _write_span(p,key,data)
 else:
  _write_span(p,context,bytes(272) if label=='zero' else bytes((i*17+31)&255 for i in range(272)))
  data=bytes(16) if label=='zero' else bytes(range(16)) if label=='walk' else bytes((i*29+7)&255 for i in range(16))
  if label=='inplace':output=source
  elif label=='output_before':output=source-5
  elif label=='output_after':output=source+3
  elif label=='output_key_alias':output=context+8
  elif label=='input_key_alias':source=context+8
  elif label=='cross_page':source=G+0x2FF8;output=G+0x3FF8
  _write_span(p,source,data)
 return p,context,key,source,output


def original(library,base,p,kind,context,key,source,output):
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 if kind=='key':watch[SP-0x90,32]=None;watch[SP-0x68,8]=None
 else:watch[SP-0x28,8]=None
 returned,memory,allocations,ledger=oracle.native(library,base,0x287EDC if kind=='key' else 0x2881CC,
  [key,context] if kind=='key' else [context,source,output],p,observed_memory=watch,instruction_limit=100000)
 assert not allocations and not ledger
 return returned,memory,watch


def red(library):
 assert importlib.util.find_spec('vm9_request_token_cipher') is None;rows=[]
 for base in BASES:
  for kind in ('key','block'):
   p,context,key,source,output=fixture(library,base,kind,'walk')
   returned,memory,watch=original(library,base,p,kind,context,key,source,output)
   assert memory[context-G:context-G+8]!=b'\xA5'*8
   rows.append(dict(image_base=hex(base),kind=kind,original_cipher_helper_returned=True,
    prior_schedule_and_block_owner_missing=True,native_snapshot_input=False))
 return rows


def compare(library,base,kind,label,model):
 p,context,key,source,output=fixture(library,base,kind,label)
 returned,memory,watch=original(library,base,p,kind,context,key,source,output)
 resolved=model.resolve_token_cipher_helpers(p,image_base=base)
 assert resolved==(base+0x287EDC,base+0x2881CC)
 if kind=='key':model.prepare_token_round_schedule(p,context_address=context,key_address=key,
  entry_stack_address=SP,thread_pointer=TP)
 else:model.encrypt_token_block(p,context_address=context,source_address=source,
  output_address=output,entry_stack_address=SP,thread_pointer=TP,image_base=base)
 got=_read_span(p,G,0xA000)
 assert got==memory,(kind,label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(got,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(kind,label,'scratch/image')
 print('PASS token cipher helper',hex(base),kind,label,flush=True)
 return dict(image_base=hex(base),kind=kind,case=label,original_helper_returned=True,
  all_guest_ELF_and_defined_scratch_equal=True,encoded_helper_slots_resolve=True,
  guest_bytecode_bound_to_reused_block_owner=kind=='block',no_allocator_or_service_effects=True,
  native_physical_X0_compared=False,native_snapshot_input=False)


def guards(library,model):
 rows=[]
 for label in ('key_unmapped','context_unmapped','unaligned_stack','key_spill_alias','canary_alias','block_unmapped','bytecode_changed','helper_slot_changed'):
  base=BASES[0];kind='block' if label.startswith(('block','bytecode')) else 'key'
  p,context,key,source,output=fixture(library,base,kind,'pattern');stack=SP
  if label=='key_unmapped':key=0x64000000
  elif label=='context_unmapped':context=0x64000000
  elif label=='unaligned_stack':stack=SP-1
  elif label=='key_spill_alias':key=SP-0x60
  elif label=='canary_alias':context=TP+0x28
  elif label=='block_unmapped':output=0x64000000
  elif label=='bytecode_changed':_write_span(p,base+0x118F50,bytes(4))
  elif label=='helper_slot_changed':_write_span(p,base+0x383548,bytes(8))
  before={k:bytes(v) for k,v in p.items()}
  try:
   if label=='helper_slot_changed':model.resolve_token_cipher_helpers(p,image_base=base)
   elif kind=='key':model.prepare_token_round_schedule(p,context_address=context,key_address=key,entry_stack_address=stack,thread_pointer=TP)
   else:model.encrypt_token_block(p,context_address=context,source_address=source,output_address=output,
    entry_stack_address=stack,thread_pointer=TP,image_base=base)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
 return rows


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','helper','guards','all'),default='all');args=p.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 e=dict(schema='vm9-request-token-cipher-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library)
 else:
  import vm9_request_token_cipher as model
  if args.group in ('helper','all'):e['cases']=[compare(args.library,b,k,n,model) for b in BASES for k,names in (('key',KEY_CASES),('block',BLOCK_CASES)) for n in names]
  if args.group in ('guards','all'):e['negative_cases']=guards(args.library,model)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS token cipher helpers',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
