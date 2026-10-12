"""Actual request URL condition, lazy constants and one-byte wrapper result.

Patterns are derived from fresh ELF inputs through the accepted decoder.
No decoded private names or native snapshots are published.
"""
from pathlib import Path
import argparse,hashlib,json,os
import verify_vm9_signer_objects as oracle
import vm9_objects as objects
import vm9_request_transform as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;HANDLER=G+0x1000;SOURCE=G+0x1800;DATA=G+0x2000;PACKED=G+0x2400
BASES=(0x122C0000,0x775C205000)
GLOBALS=((0x3E0B70,0xF2398,0x3E0B60,0xF2564),(0x3E0B80,0xF23A8,0x3E0B74,0xF2558),(0x3E0BA8,0xF23C0,0x3E0B90,0xF2540))
CASES=('disabled','disabled_unmapped_URL','first','second','third','missing','empty','binary_tail','byte_255','packed_cross_page')
def word(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def fixture(library,base,label,warm):
 p=oracle.image_pages(library,base);p.update(oracle.fresh_pages());copy={k:bytearray(v) for k,v in p.items()}
 patterns=[]
 for flag,source,destination,mask in GLOBALS:
  n=objects.decode_masked_bytes(copy,source_address=base+source,destination_address=base+destination,mask_address=base+mask)
  patterns.append(objects._cstring(copy,base+destination,64)[:-1])
  if warm:_write_span(p,base+destination,_read_span(copy,base+destination,n));word(p,base+flag,2,4)
 data=b'fixture://invalid/path'
 if label in ('first','second','third'):data=b'prefix/'+patterns[('first','second','third').index(label)]+b'/tail'
 elif label=='binary_tail':data=b'before\0'+patterns[2]+b'/tail'
 elif label=='byte_255':data=patterns[1]
 elif label=='empty':data=b''
 pointer=SOURCE if label!='disabled_unmapped_URL' else 0x66000000
 word(p,HANDLER+0x53,0 if label.startswith('disabled') else (255 if label=='byte_255' else 1),1)
 word(p,SOURCE,base+0x34F5F8);word(p,SOURCE+8,len(data)+1,4);word(p,SOURCE+12,len(data),4);word(p,SOURCE+16,DATA)
 _write_span(p,DATA,data+b'\0');packed=G+0x6FF8 if label=='packed_cross_page' else PACKED
 _write_span(p,packed,b''.join(v.to_bytes(8,'little') for v in (base+0x2828D4,HANDLER,pointer,0xA5A5A5A5A5A5A5A5)))
 return p,packed
def original(library,base,p,packed):
 watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 returned,memory,allocations,effects=oracle.native(library,base,0x285F14,[packed],p,observed_memory=watch,instruction_limit=30000)
 assert not allocations and not effects
 return returned,memory,watch
def red(library):
 assert not hasattr(model,'apply_request_url_condition_callback');rows=[]
 for base in BASES:
  p,packed=fixture(library,base,'third',False);returned,memory,watch=original(library,base,p,packed)
  assert returned==1 and memory[packed-G+24]==1
  rows.append(dict(image_base=hex(base),original_url_condition_wrapper_returned=True,
   prior_url_condition_owner_missing=True,native_snapshot_input=False))
 return rows
def compare(library,base,label,warm):
 p,packed=fixture(library,base,label,warm);returned,memory,watch=original(library,base,p,packed)
 result=model.apply_request_url_condition_callback(p,argument_block_address=packed,image_base=base,entry_stack_address=G+0xEF00)
 own=_read_span(p,G,0xA000)
 assert own==memory,(label,warm,'guest',next(((hex(i),a,b) for i,(a,b) in enumerate(zip(own,memory)) if a!=b),None))
 assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),(label,warm,'ELF')
 assert result==bool(returned&1)
 print('PASS URL condition',hex(base),label,warm,flush=True)
 return dict(image_base=hex(base),case=label,warm_constants=warm,
  original_consumer_returned=True,all_guest_ELF_lazy_flags_packed_result_and_padding_equal=True,
  no_allocator_or_service_effects=True,native_snapshot_input=False)
def guards(library):
 rows=[]
 for label in ('bad_target','unmapped_handler','unmapped_URL','unmapped_payload','source_bound','pattern_bound','unmapped_result'):
  base=BASES[0];p,packed=fixture(library,base,'missing',False);kw=dict(argument_block_address=packed,image_base=base,entry_stack_address=G+0xEF00)
  if label=='bad_target':word(p,packed,base+0x2829F4)
  elif label=='unmapped_handler':word(p,packed+8,0x66000000)
  elif label=='unmapped_URL':word(p,packed+16,0x66000000)
  elif label=='unmapped_payload':word(p,SOURCE+16,0x66000000)
  elif label=='source_bound':kw['max_bytes']=8
  elif label=='pattern_bound':kw['max_pattern_bytes']=1
  else:
   packed=G+0xFFE8;_write_span(p,packed,_read_span(p,PACKED,24));kw['argument_block_address']=packed
  before={k:bytes(b) for k,b in p.items()}
  try:model.apply_request_url_condition_callback(p,**kw)
  except (RefillUnsupported,ValueError):pass
  else:raise AssertionError(label)
  assert before=={k:bytes(b) for k,b in p.items()}
  rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
 return rows
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('red','consumer','guards','all'),default='all');args=ap.parse_args()
 assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
 assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
 e=dict(schema='vm9-request-url-condition-fresh-v1',evidence_date='2026-10-13',sample_sha256=oracle.LIBRARY_SHA256,
  cases=[],negative_cases=[],native_snapshot_input=False,private_names_or_payloads_published=False,
  whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
  actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
  fresh_signer_output_verified=False,live_server_matrix_verified=False)
 if args.group=='red':e['red_cases']=red(args.library)
 else:
  if args.group in ('consumer','all'):e['cases']=[compare(args.library,b,n,w) for b in BASES for n in CASES for w in (False,True)]
  if args.group in ('guards','all'):e['negative_cases']=guards(args.library)
 e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
 args.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS URL condition',args.group,e['native_Python_controls'],e['rollback_guards'])
if __name__=='__main__':main()
