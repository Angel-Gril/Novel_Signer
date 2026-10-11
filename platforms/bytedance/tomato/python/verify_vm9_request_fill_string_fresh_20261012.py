"""Fresh fill-string owner and actual request tail-wrapper comparison.

Original ELF functions run with explicit allocation/memset boundaries. Fresh
synthetic input pages initialize both runs; native output never initializes Python.
"""
from pathlib import Path
import argparse,hashlib,json
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported

BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x1400
PROFILES=(
 ('empty',0,0,False,False),('one',0x123456A9,1,False,False),
 ('fifteen',0x123456A9,15,False,False),('zero_fill',0,256,False,False),
 ('full_byte',0xFFFFFFFF,256,False,False),('cross_page',0x123456A9,4097,True,False),
 ('negative_min',0x123456A9,0x80000000,False,False),
 ('negative_all_ones',0x123456A9,0xFFFFFFFF,False,False),
 ('malloc_NULL_empty',0x123456A9,0,False,True),
 ('malloc_NULL_nonempty',0x123456A9,31,False,True))


def fresh(library,base,profile,wrapper):
 _,fill,length,cross,fail=profile
 p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
 obj=G+0x1FF8 if cross else G+0x1800
 _write_span(p,PACKED,(base+0x248274).to_bytes(8,'little')+obj.to_bytes(8,'little')
  +fill.to_bytes(4,'little')+length.to_bytes(4,'little')+b'\xa5'*8)
 expected=Services(failures=(0,) if fail else ());actual=Services(failures=(0,) if fail else ())
 if cross:expected.effects.next=actual.effects.next=G+0x4FF8
 return p,obj,expected,actual


def native(library,base,profile,wrapper,p,obj,services):
 _,fill,length,_,_=profile
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 result,memory,_,_=oracle.native(library,base,0x285B9C if wrapper else 0x248274,
  [PACKED] if wrapper else [obj,fill,length],p,malloc_handler=services.native_malloc,
  observed_memory=observed,instruction_limit=20000)
 return result,memory,observed


def compare(library,base,profile,wrapper):
 p,obj,expected,actual=fresh(library,base,profile,wrapper)
 _,memory,observed=native(library,base,profile,wrapper,p,obj,expected)
 _,fill,length,_,_=profile
 pointer=objects.construct_filled_string_object(p,object_address=obj,
  fill=fill&255 if wrapper else fill,length=length,image_base=base,allocate=actual.malloc)
 assert pointer==int.from_bytes(_read_span(p,obj+16,8),'little')
 assert _read_span(p,G,0xA000)==memory,(profile[0],wrapper,'payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),(profile[0],wrapper,'ELF')
 assert expected.events==actual.events and expected.effects.calls==actual.effects.calls
 assert expected.effects.blocks==actual.effects.blocks
 print('PASS',hex(base),'fill string',profile[0],'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=profile[0],actual_wrapper=wrapper,
  original_returned=True,packed_ABI_and_full_guest_payload_match=True,
  all_ELF_pages_match=True,allocator_order_and_heap_match=True,
  returned_buffer_field_matches=True,incidental_native_X0_not_claimed=True,native_snapshot_input=False)


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
   for profile in PROFILES:
    for wrapper in (False,True):cases.append(compare(args.library,base,profile,wrapper))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('invalid_fill','invalid_length','payload_bound','unmapped_object','unmapped_buffer','provider_exception'):
    p,obj,_,actual=fresh(args.library,base,PROFILES[1],True)
    kw=dict(object_address=obj,fill=0xA9,length=1,image_base=base,allocate=actual.malloc)
    if label=='invalid_fill':kw['fill']=1<<32
    elif label=='invalid_length':kw['length']=-1
    elif label=='payload_bound':kw['max_payload_bytes']=0
    elif label=='unmapped_object':kw['object_address']=0x66000000
    elif label=='unmapped_buffer':kw['allocate']=lambda p,n:0x66000000
    else:
     def fail(p,n):
      _write_span(p,PACKED,b'\xa5');raise RefillUnsupported('injected fill allocation failure')
     kw['allocate']=fail
    before={k:bytes(v) for k,v in p.items()}
    try:objects.construct_filled_string_object(p,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS fill string rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
