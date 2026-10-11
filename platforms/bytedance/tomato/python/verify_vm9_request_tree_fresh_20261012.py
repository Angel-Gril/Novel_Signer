"""Original request tree construction and begin/end iterator wrapper ABIs.

Existing constructors build independent iterator inputs. Original wrappers
execute under Unicorn; native output is compared and never initializes Python.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_registry as registry
from verify_vm9_registry import fixture,BASES,CONTAINER,DESCRIPTOR
from verify_vm9_reference_scopes_fresh_20261011 import Services
import verify_vm9_signer_objects as oracle
from verify_vm9_strings import Effects
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=oracle.GUEST;PACKED=G+0x1700


def fresh(library,base,profile):
 p,blocks,addresses=fixture(library,base,[b'seed'] if profile.get('nonempty') else [])
 prefix=Effects(blocks=blocks);container=G+0x1FF8 if profile.get('cross_page') else CONTAINER
 if profile.get('operation')!='construct':
  registry.construct_configuration_tree(p,container_address=container,descriptor_address=DESCRIPTOR,
   image_base=base,allocate=prefix.malloc)
  for obj,payload,value in addresses:
   registry.insert_configuration_pair(p,container_address=container,key_address=obj,value_address=value,
    image_base=base,allocate=prefix.malloc,free=prefix.free)
 target={'construct':0x25BF14,'begin':0x25C180,'end':0x25C188}[profile['operation']]
 words=(base+target,container,DESCRIPTOR,0xA5A5A5A5A5A5A5A5)
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in words))
 return p,prefix.blocks,prefix.next,container


def execute(p,base,profile,container,services,**kw):
 if profile['operation']=='construct':
  options=dict(container_address=container,descriptor_address=DESCRIPTOR,image_base=base,allocate=services.malloc)
  options.update(kw);return registry.construct_configuration_tree(p,**options)
 options=dict(container_address=container,image_base=base,position=profile['operation']);options.update(kw)
 pair=registry.configuration_tree_iterator(p,**options)
 _write_span(p,PACKED+16,b''.join(v.to_bytes(8,'little') for v in pair));return pair


def native(library,base,p,profile,service):
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 result,memory,_,_=oracle.native(library,base,0x285ADC if profile['operation']=='construct' else 0x285AEC,
  [PACKED],p,malloc_handler=service.native_malloc,observed_memory=observed,instruction_limit=50000)
 return result,memory,observed


def compare(library,base,label,profile):
 p,blocks,next_address,container=fresh(library,base,profile)
 expected=Services(blocks);actual=Services(blocks);expected.effects.next=actual.effects.next=next_address
 result,memory,observed=native(library,base,p,profile,expected);out=execute(p,base,profile,container,actual)
 assert _read_span(p,G,0xA000)==memory,(label,'payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),(label,'ELF')
 assert expected.events==actual.events and expected.effects.calls==actual.effects.calls
 assert expected.effects.blocks==actual.effects.blocks
 if profile['operation']!='construct':assert out[0]==result
 print('PASS',hex(base),'request tree',label,flush=True)
 return dict(image_base=hex(base),case=label,operation=profile['operation'],original_wrapper_returned=True,
  packed_ABI_full_guest_payload_and_ELF_pages_match=True,allocator_order_and_heap_match=True,
  iterator_pair_matches=profile['operation']!='construct',native_snapshot_input=False)


def compare_pairs(library,base,label,first,second,short_circuit=False):
 p,_,_=fixture(library,base,[]);a=G-8 if short_circuit else G+0x1500;b=G+0x1600
 if short_circuit:_write_span(p,a+8,first[1].to_bytes(8,'little'))
 else:_write_span(p,a,b''.join(v.to_bytes(8,'little') for v in first))
 _write_span(p,b,b''.join(v.to_bytes(8,'little') for v in second))
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x24C600,a,b,0xA5A5A5A5A5A5A5A5)))
 result,memory,_,_=oracle.native(library,base,0x285B08,[PACKED],p,instruction_limit=10000)
 equal=registry.configuration_tree_iterators_equal(p,first_address=a,second_address=b)
 _write_span(p,PACKED+24,int(equal).to_bytes(4,'little'))
 assert int(equal)==result and _read_span(p,G,0xA000)==memory
 print('PASS',hex(base),'iterator comparison',label,flush=True)
 return dict(image_base=hex(base),case=label,operation='compare',original_wrapper_returned=True,
  packed_ABI_full_guest_payload_and_ELF_pages_match=True,allocator_order_and_heap_match=True,
  iterator_pair_matches=True,native_snapshot_input=False,table_load_short_circuited=short_circuit)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','compare','guards','entry','all'),default='all')
 args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 cases=[];guards=[];entries=[]
 profiles=[('constructor',dict(operation='construct')),('constructor_cross_page',dict(operation='construct',cross_page=True))]
 profiles += [(operation+('_nonempty' if nonempty else '_empty'),dict(operation=operation,nonempty=nonempty))
  for operation in ('begin','end') for nonempty in (False,True)]
 if args.group in ('native','all'):
  for base in BASES:
   for label,profile in profiles:cases.append(compare(args.library,base,label,profile))
 if args.group in ('compare','all'):
  for base in BASES:
   for label,first,second,short in (
    ('equal',(base+0x381B20,G+0x4000),(base+0x381B20,G+0x4000),False),
    ('different_nodes',(1,2),(1,3),False),('different_tables',(1,2),(3,2),False),
    ('NULL_words',(0,0),(0,0),False),('full_uint64',((1<<64)-1,(1<<64)-1),((1<<64)-1,(1<<64)-1),False),
    ('unmapped_tables_not_loaded',(0,1),(0,2),True)):
    cases.append(compare_pairs(args.library,base,label,first,second,short))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_descriptor','NULL_allocation','missing_controller','invalid_iterator_position'):
    profile=dict(operation='construct' if label in ('missing_descriptor','NULL_allocation') else 'end')
    p,blocks,next_address,container=fresh(args.library,base,profile);services=Services(blocks);services.effects.next=next_address;kw={}
    if label=='missing_descriptor':kw['descriptor_address']=0
    elif label=='NULL_allocation':services.effects.failures={0}
    elif label=='missing_controller':_write_span(p,container+0x20,bytes(8))
    else:kw['position']='unsupported'
    before={k:bytes(v) for k,v in p.items()}
    try:execute(p,base,profile,container,services,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS request tree rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
