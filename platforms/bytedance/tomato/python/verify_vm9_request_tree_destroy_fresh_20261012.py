"""Original local-tree destructor and value cleanup versus fresh Python pages."""
from pathlib import Path
import argparse,hashlib,json
import vm9_registry as registry
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_registry import fixture,CONTAINER,DESCRIPTOR
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x1700;SP=G+0xEF00
PROFILES=(('empty_raw',dict(keys=[],strings=False)),('empty_string',dict(keys=[],strings=True)),
 ('one_raw',dict(keys=[b'a'],strings=False)),('one_string',dict(keys=[b'a'],strings=True)),
 ('balanced_raw',dict(keys=[b'd',b'b',b'f',b'a',b'c',b'e',b'g'],strings=False)),
 ('balanced_string',dict(keys=[b'd',b'b',b'f',b'a',b'c',b'e',b'g'],strings=True)),
 ('descending_string',dict(keys=[b'g',b'f',b'e',b'd',b'c',b'b',b'a'],strings=True)),
 ('binary_string',dict(keys=[b'\xff',b'\x80',b'\x01',b'',b'\xfe'],strings=True)))


def fresh(library,base,profile):
 p,blocks,addresses=fixture(library,base,profile['keys'])
 if profile['strings']:
  _write_span(p,DESCRIPTOR+8,(base+0x182D6C).to_bytes(8,'little'))
  for _,_,raw_value in addresses:blocks.pop(raw_value)
 entries=[]
 for i,(key,payload,raw_value) in enumerate(addresses):
  if profile['strings']:
   value=G+0x2800+i*0x40;buffer=G+0x3800+i*0x40
   data=bytes((i+1,0,128,255));_write_span(p,value,(base+0x34F5F8).to_bytes(8,'little')+(len(data)+1).to_bytes(4,'little')+len(data).to_bytes(4,'little')+buffer.to_bytes(8,'little'))
   _write_span(p,buffer,data+b'\0');blocks.update({value:24,buffer:len(data)+1})
  else:value=raw_value
  entries.append((key,value))
 service=Services(blocks)
 registry.construct_configuration_tree(p,container_address=CONTAINER,descriptor_address=DESCRIPTOR,image_base=base,allocate=service.malloc)
 for key,value in entries:registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=key,value_address=value,
  image_base=base,allocate=service.malloc,free=service.free)
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x25C01C,CONTAINER,0xA5A5A5A5A5A5A5A5,0xA5A5A5A5A5A5A5A5)))
 return p,service.effects.blocks,service.effects.next


def native(library,base,p,wrapper,services):
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 helper_sp=SP
 observed[helper_sp-0x88,32]=None
 _,memory,_,_=oracle.native(library,base,0x285B70 if wrapper else 0x25C01C,
  [PACKED] if wrapper else [CONTAINER],p,malloc_handler=services.native_malloc,
  host_imports={0x347FA0:services.native_free},observed_memory=observed,instruction_limit=300000)
 return memory,observed


def compare(library,base,label,profile,wrapper):
 p,blocks,next_address=fresh(library,base,profile);expected=Services(blocks);actual=Services(blocks)
 expected.effects.next=actual.effects.next=next_address
 memory,observed=native(library,base,p,wrapper,expected)
 registry.destroy_configuration_tree(p,container_address=CONTAINER,entry_stack_address=SP,image_base=base,free=actual.free)
 assert _read_span(p,G,0xA000)==memory,(label,wrapper,'payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),(label,wrapper,'ELF/iterator scratch')
 assert actual.events==expected.events and actual.freed==expected.freed,(label,wrapper,'free order/bytes')
 assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
 assert not actual.effects.blocks
 print('PASS',hex(base),'tree destroy',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=label,actual_wrapper=wrapper,original_returned=True,
  full_guest_payload_ELF_and_logical_iterator_scratch_match=True,free_order_heap_and_pre_free_bytes_match=True,
  all_owned_blocks_released=True,incidental_native_X0_not_claimed=True,native_snapshot_input=False)


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
   for label,profile in PROFILES:
    for wrapper in (False,True):cases.append(compare(args.library,base,label,profile,wrapper))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('missing_free','free_exception','unknown_key_cleanup','unknown_value_cleanup','missing_controller','node_bound','unmapped_iterator_scratch','unaligned_stack'):
    p,blocks,next_address=fresh(args.library,base,PROFILES[5][1]);actual=Services(blocks);kw={}
    if label=='unknown_key_cleanup':_write_span(p,CONTAINER+8,bytes(8))
    elif label=='unknown_value_cleanup':_write_span(p,CONTAINER+16,bytes(8))
    elif label=='missing_controller':_write_span(p,CONTAINER+32,bytes(8))
    elif label=='node_bound':kw['max_nodes']=1
    elif label=='unmapped_iterator_scratch':kw['entry_stack_address']=0x66001000
    elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
    def free(p,pointer):
     _write_span(p,PACKED,b'\xa5')
     if label=='free_exception':raise RefillUnsupported('injected tree destructor free failure')
     return actual.free(p,pointer)
    options=dict(container_address=CONTAINER,entry_stack_address=SP,image_base=base,free=None if label=='missing_free' else free);options.update(kw)
    before={k:bytes(v) for k,v in p.items()}
    try:registry.destroy_configuration_tree(p,**options)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS tree destructor rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
