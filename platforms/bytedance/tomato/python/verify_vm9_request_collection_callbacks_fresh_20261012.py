"""Actual request collection wrappers over previously recovered owners.

Fixtures are independently constructed from synthetic input and ELF pages.
No native output supplies a Python input or callback result.
"""
from pathlib import Path
import argparse,hashlib,json
import vm9_registry as registry
import vm9_logger as logger
import verify_vm9_signer_objects as oracle
from verify_vm9_registry import fixture,CONTAINER,DESCRIPTOR,BASES
from verify_vm9_strings import Effects
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;PACKED=G+0x1700


def fresh(library,base,label):
 keys=[] if label in ('empty','NULL_query') else [b'a',b'b',b'c']
 query={'found':b'b','absent_left':b'0','absent_right':b'z','NUL_equivalent':b'a\0tail',
  'NULL_value':b'b','full_uint64_value':b'b'}.get(label,b'q')
 p,blocks,addresses=fixture(library,base,keys+[query]);effects=Effects(blocks=blocks)
 registry.construct_configuration_tree(p,container_address=CONTAINER,descriptor_address=DESCRIPTOR,
  image_base=base,allocate=effects.malloc)
 for i,(key,payload,value) in enumerate(addresses[:-1]):
  if label=='NULL_value' and i==1:value=0
  if label=='full_uint64_value' and i==1:value=(1<<64)-1
  registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=key,value_address=value,
   image_base=base,allocate=effects.malloc,free=effects.free)
 query=0 if label=='NULL_query' else addresses[-1][0]
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x25C168,CONTAINER,query,0xA5A5A5A5A5A5A5A5)))
 return p,query


def compare(library,base,label):
 p,query=fresh(library,base,label)
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 result,memory,_,_=oracle.native(library,base,0x285BB0,[PACKED],p,
  observed_memory=observed,instruction_limit=20000)
 pointer=registry.lookup_configuration_value(p,container_address=CONTAINER,key_address=query,image_base=base)
 _write_span(p,PACKED+24,pointer.to_bytes(8,'little'))
 assert pointer==result and _read_span(p,G,0xA000)==memory,(label,'lookup ABI/payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items())
 print('PASS',hex(base),'request lookup',label,flush=True)
 return dict(image_base=hex(base),operation='lookup',case=label,original_wrapper_returned=True,
  full_guest_payload_and_packed_u64_result_match=True,all_ELF_pages_match=True,
  existing_owner_reused=True,native_snapshot_input=False)


def compare_cstring(library,base,label):
 p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
 pointer=0 if label=='NULL' else G+0x2FFD if label=='cross_page' else G+0x2000
 data={'empty':b'', 'ascii':b'bounded', 'embedded_NUL':b'a\0tail',
  'binary':bytes((0xFF,0x80,1)), 'cross_page':b'across-page'}.get(label,b'')
 if pointer:_write_span(p,pointer,data+b'\0')
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x27617C,pointer,0xA5A5A5A5A5A5A5A5,0xA5A5A5A5A5A5A5A5)))
 result,memory,_,_=oracle.native(library,base,0x285C00,[PACKED],p,instruction_limit=20000)
 length=len(logger.cstring(p,pointer));_write_span(p,PACKED+16,length.to_bytes(8,'little'))
 assert length==result and _read_span(p,G,0xA000)==memory
 print('PASS',hex(base),'request cstring length',label,flush=True)
 return dict(image_base=hex(base),operation='cstring_length',case=label,original_wrapper_returned=True,
  full_guest_payload_and_packed_u64_result_match=True,all_ELF_pages_match=True,
  existing_owner_reused=True,native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('lookup','length','guards','entry','all'),default='all')
 args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 cases=[];guards=[];entries=[]
 if args.group in ('lookup','all'):
  for base in BASES:
   for label in ('empty','NULL_query','found','absent_left','absent_right','NUL_equivalent','NULL_value','full_uint64_value'):
    cases.append(compare(args.library,base,label))
 if args.group in ('length','all'):
  for base in BASES:
   for label in ('NULL','empty','ascii','embedded_NUL','binary','cross_page'):
    cases.append(compare_cstring(args.library,base,label))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_controller','unknown_comparator','node_bound','missing_query'):
    p,query=fresh(args.library,base,'found');kw={}
    if label=='missing_controller':_write_span(p,CONTAINER+32,bytes(8))
    elif label=='unknown_comparator':_write_span(p,CONTAINER+24,bytes(8))
    elif label=='node_bound':kw['max_nodes']=1
    else:query=0x66000000
    before={k:bytes(v) for k,v in p.items()}
    try:registry.lookup_configuration_value(p,container_address=CONTAINER,key_address=query,image_base=base,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),operation='lookup',case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS lookup rollback',hex(base),label,flush=True)
   for label in ('unmapped_cstring','unterminated_cstring'):
    p={**oracle.image_pages(args.library,base),**oracle.fresh_pages()}
    pointer=0x66000000 if label=='unmapped_cstring' else G+0x2000
    before={k:bytes(v) for k,v in p.items()}
    try:logger.cstring(p,pointer,max_bytes=8)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),operation='cstring_length',case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS cstring rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
