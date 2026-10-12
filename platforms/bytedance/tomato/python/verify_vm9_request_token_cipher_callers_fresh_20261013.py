"""Fresh padded block caller, StringObject caller and actual nested consumer.

Allocator effects are explicit and ordered. Original helper/VM instructions
are output oracles; previously accepted standalone helper groups are not run.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
import vm9_request_token_cipher as model
import vm9_request_token_vm as callbacks
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SP=G+0xEF00;TP=G+0xD000;BASES=(0x122C0000,0x775C205000)
INPUT=G+0x1800;OUTPUT=G+0x1900;KEY=G+0x1A00;DATA=G+0x2000;KEYDATA=G+0x2800
OUTPAY=G+0x2C00;PACKED=G+0x2400;OUTPTR=G+0x1000;OUTLEN=G+0x1008
ALLOCATED_CASES=tuple('length_'+str(n) for n in (0,1,15,16,17,31,32,47,64))+('NULL_output_malloc',)
WRAPPER_CASES=tuple('key_'+str(n) for n in (0,1,16,31,32,40))+('NULL_receiver','NULL_output_malloc','existing_destination','empty_input')
DIRECT_CASES=('key_0','key_32','existing_destination','NULL_output_malloc')


def word(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def string(p,a,base,pointer,data,capacity=None):
 word(p,a,base+0x34F5F8);word(p,a+8,len(data)+1 if capacity is None else capacity,4)
 word(p,a+12,len(data),4);word(p,a+16,pointer);_write_span(p,pointer,data+b'\0')


def fixture(library,base,kind,label):
 p=oracle.image_pages(library,base);p.update(oracle.fresh_pages());blocks={};failures=()
 if kind=='allocated':
  size=int(label[7:]) if label.startswith('length_') else 26
  data=bytes((i*73+19)&255 for i in range(size));key=bytes((i*29+3)&255 for i in range(32))
  _write_span(p,DATA,data);_write_span(p,KEYDATA,key)
  if label=='NULL_output_malloc':failures=(6,)
  args=(DATA,size,OUTPTR,OUTLEN,KEYDATA)
 else:
  size=int(label[4:]) if label.startswith('key_') else 32
  key=bytes((i*29+3)&255 for i in range(size));data=b'' if label=='empty_input' else b'fixture\0'+b'X'*18
  assert len(data)==26 or not data
  string(p,INPUT,base,DATA,data);string(p,KEY,base,KEYDATA,key)
  prior=b'old-destination' if label=='existing_destination' else b'';capacity=64 if prior else 8
  string(p,OUTPUT,base,OUTPAY,prior,capacity);blocks[OUTPAY]=capacity
  receiver=0 if label=='NULL_receiver' else INPUT
  if label=='NULL_output_malloc':failures=(7,)
  args=(receiver,OUTPUT,KEY)
  _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x287580,*args))+b'\xA5'*8)
 return p,args,blocks,failures


def original(library,base,p,kind,args,effects):
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 if kind=='allocated':
  local=SP-0x310
  for address in (local+0x48,local+0x60,local+0x78,local+0x90):watch[address,24]=None
  watch[SP-0x70,8]=None
 else:watch[SP-0x38,8]=None
 entry=0x287A78 if kind=='allocated' else 0x288BDC if kind=='wrapper' else 0x287580
 returned,memory,_,_=oracle.native(library,base,entry,[PACKED] if kind=='wrapper' else list(args),p,
  malloc_handler=lambda c,n:effects.native(c,'malloc',n),host_imports={
   0x347FA0:lambda c:effects.native(c,'free',pointer=c.reg_read(arm.UC_ARM64_REG_X0)),
   0x348320:lambda c:effects.native(c,'realloc',c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))},
  extra_registers={arm.UC_ARM64_REG_X5:32},observed_memory=watch,instruction_limit=300000)
 return memory,watch


def red(library):
 assert not hasattr(model,'allocate_token_ciphertext') and not hasattr(model,'encrypt_token_string_object')
 assert not hasattr(callbacks,'apply_token_cipher_callback');rows=[]
 for base in BASES:
  for kind in ('allocated','wrapper'):
   p,args,blocks,failures=fixture(library,base,kind,'length_16' if kind=='allocated' else 'key_32')
   memory,watch=original(library,base,p,kind,args,Effects(blocks=blocks))
   assert int.from_bytes(memory[(OUTPTR if kind=='allocated' else OUTPUT+12)-G:(OUTPTR if kind=='allocated' else OUTPUT+12)-G+4],'little')
   rows.append(dict(image_base=hex(base),kind=kind,original_cipher_caller_returned=True,
    prior_allocated_string_cipher_consumers_missing=True,native_snapshot_input=False))
 return rows


def compare(library,base,kind,label):
 p,args,blocks,failures=fixture(library,base,kind,label);expected=Effects(blocks=blocks,failures=failures)
 memory,watch=original(library,base,p,kind,args,expected);actual=Effects(blocks=blocks,failures=failures)
 kw=dict(entry_stack_address=SP,thread_pointer=TP,image_base=base,allocate=actual.malloc,reallocate=actual.realloc,free=actual.free)
 if kind=='allocated':model.allocate_token_ciphertext(p,source_address=args[0],length=args[1],
  output_pointer_address=args[2],output_length_address=args[3],key_address=args[4],**kw)
 elif kind=='wrapper':callbacks.apply_token_cipher_callback(p,argument_block_address=PACKED,**kw)
 else:model.encrypt_token_string_object(p,source_object_address=args[0],object_address=args[1],key_object_address=args[2],**kw)
 got=_read_span(p,G,0xA000)
 assert got==memory,(kind,label,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(got,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(kind,label,'defined locals/ELF')
 assert actual.calls==expected.calls and actual.blocks==expected.blocks,(kind,label,'effects',actual.calls,expected.calls)
 print('PASS token cipher caller',hex(base),kind,label,flush=True)
 return dict(image_base=hex(base),kind=kind,case=label,original_caller_returned=True,
  all_guest_ELF_and_defined_parent_locals_equal=True,ordered_malloc_realloc_free_and_allocator_blocks_equal=True,
  actual_nested_consumer_executed=kind=='wrapper',native_snapshot_input=False,native_physical_X0_compared=False)


def guards(library):
 rows=[]
 for label in ('bad_target','unaligned_stack','unmapped_source','unmapped_destination','source_bound','key_negative','provider_NULL_key','changed_slots','changed_bytecode','canary_change'):
  base=BASES[0];p,args,blocks,failures=fixture(library,base,'wrapper','key_32');effect=Effects(blocks=blocks)
  kw=dict(argument_block_address=PACKED,entry_stack_address=SP,thread_pointer=TP,image_base=base,
   allocate=effect.malloc,reallocate=effect.realloc,free=effect.free)
  if label=='bad_target':word(p,PACKED,base+0x287A78)
  elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
  elif label=='unmapped_source':word(p,PACKED+8,0x64000000)
  elif label=='unmapped_destination':word(p,PACKED+16,0x64000000)
  elif label=='source_bound':kw['max_bytes']=25
  elif label=='key_negative':word(p,KEY+12,0x80000000,4)
  elif label=='provider_NULL_key':kw['allocate']=lambda p,n:0
  elif label=='changed_slots':_write_span(p,base+0x383548,bytes(8))
  elif label=='changed_bytecode':_write_span(p,base+0x118F50,bytes(4))
  elif label=='canary_change':
   def changed(p,n):result=effect.malloc(p,n);word(p,TP+0x28,7);return result
   kw['allocate']=changed
  before={k:bytes(v) for k,v in p.items()}
  try:callbacks.apply_token_cipher_callback(p,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(v) for k,v in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_rollback_verified=False))
 return rows


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--group',choices=('red','caller','guards','all'),default='all');args=p.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 e=dict(schema='vm9-request-token-cipher-callers-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False,complete_nested_caller_return_verified=False)
 if args.group=='red':e['red_cases']=red(args.library)
 if args.group in ('caller','all'):e['cases']=[compare(args.library,b,k,n) for b in BASES
  for k,names in (('allocated',ALLOCATED_CASES),('direct',DIRECT_CASES),('wrapper',WRAPPER_CASES)) for n in names]
 if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS token cipher callers',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
