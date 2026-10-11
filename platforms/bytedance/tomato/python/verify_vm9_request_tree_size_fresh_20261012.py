"""Actual tree size and duplicate string-value cleanup over fresh pages."""
from pathlib import Path
import argparse,hashlib,json
import vm9_registry as registry
import vm9_objects as objects
import verify_vm9_signer_objects as oracle
from verify_vm9_registry import fixture,CONTAINER,DESCRIPTOR
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x1400
PROFILES=(('empty',0,False),('one',1,False),('cross_page',3,True),
 ('full_u32',0xFFFFFFFF,False),('high_bit',1<<63,False),('full_u64',(1<<64)-1,False))


def fresh(library,base,profile):
 p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
 _,count,cross=profile;obj=G+0x1FDC if cross else G+0x1800;control=G+0x2FF4 if cross else G+0x2400
 _write_span(p,obj+32,control.to_bytes(8,'little'));_write_span(p,control+8,count.to_bytes(8,'little'))
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x25C150,obj,0xA5A5A5A5A5A5A5A5,0xA5A5A5A5A5A5A5A5)))
 return p,obj,control


def compare(library,base,profile,wrapper):
 p,obj,_=fresh(library,base,profile)
 result,memory,_,_=oracle.native(library,base,0x285F44 if wrapper else 0x25C150,
  [PACKED] if wrapper else [obj],p,instruction_limit=10000)
 size=registry.configuration_tree_size(p,container_address=obj)
 if wrapper:_write_span(p,PACKED+16,size.to_bytes(8,'little'))
 assert size==result==profile[1] and _read_span(p,G,0xA000)==memory
 print('PASS',hex(base),'tree size',profile[0],'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=profile[0],actual_wrapper=wrapper,original_returned=True,
  full_guest_payload_and_packed_u64_size_match=True,double_indirect_controller_count_verified=True,
  native_snapshot_input=False)


def fresh_replacement(library,base,label):
 p,blocks,addresses=fixture(library,base,[b'a',b'a'])
 for _,_,value in addresses:blocks.pop(value)
 _write_span(p,DESCRIPTOR+8,(base+0x182D6C).to_bytes(8,'little'))
 values=(G+0x2600,G+0x2640);payloads=(G+0x3800,G+0x3840)
 old=b'' if label=='empty_old' else b'old\0suffix' if label=='embedded_NUL' else bytes((255,128,1)) if label=='binary' else b'old'
 for obj,buffer,data in zip(values,payloads,(old,b'new')):
  _write_span(p,obj,(base+0x34F5F8).to_bytes(8,'little')+(len(data)+1).to_bytes(4,'little')+len(data).to_bytes(4,'little')+buffer.to_bytes(8,'little'))
  _write_span(p,buffer,data+b'\0');blocks.update({obj:24,buffer:len(data)+1})
 old_value=0 if label=='NULL_old' else values[0]
 if not old_value:blocks.pop(values[0]);blocks.pop(payloads[0])
 new_value=old_value if label=='same_old_value' else values[1]
 prefix=Services(blocks)
 registry.construct_configuration_tree(p,container_address=CONTAINER,descriptor_address=DESCRIPTOR,image_base=base,allocate=prefix.malloc)
 pair=registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=addresses[0][0],value_address=old_value,
  image_base=base,allocate=prefix.malloc,free=prefix.free)
 incoming_key=addresses[1][0]
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x25BF3C,CONTAINER,incoming_key,new_value)))
 return p,incoming_key,new_value,pair,prefix.effects.blocks,prefix.effects.next


class ReplacementServices(Services):
 def __init__(self,base,blocks,next_address,key,label):
  super().__init__(blocks);self.effects.next=next_address;self.base=base;self.key=key;self.label=label
 def mutate(self,pointer,write):
  if pointer==self.key and self.label in ('reload_raw_cleanup','unknown_callback_after_key_free'):
   write(CONTAINER+16,(self.base+0x165334 if self.label=='reload_raw_cleanup' else 0).to_bytes(8,'little'))
 def free(self,p,pointer):
  super().free(p,pointer);self.mutate(pointer,lambda a,b:_write_span(p,a,b))
 def native_free(self,c):
  from unicorn.arm64_const import UC_ARM64_REG_X0
  pointer=c.reg_read(UC_ARM64_REG_X0);result=super().native_free(c)
  self.mutate(pointer,lambda a,b:c.mem_write(a,b));return result


def native_replacement(library,base,p,key,value,wrapper,services):
 observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
 _,memory,_,_=oracle.native(library,base,0x2859B8 if wrapper else 0x25BF3C,
  [PACKED] if wrapper else [CONTAINER,key,value],p,malloc_handler=services.native_malloc,
  host_imports={0x347FA0:services.native_free},observed_memory=observed,instruction_limit=100000)
 return memory,observed


def compare_replacement(library,base,label,wrapper):
 p,key,value,pair,blocks,next_address=fresh_replacement(library,base,label)
 expected=ReplacementServices(base,blocks,next_address,key,label);actual=ReplacementServices(base,blocks,next_address,key,label)
 memory,observed=native_replacement(library,base,p,key,value,wrapper,expected)
 out=registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=key,value_address=value,
  image_base=base,allocate=actual.malloc,free=actual.free)
 assert out==pair and int.from_bytes(_read_span(p,pair+8,8),'little')==value
 assert _read_span(p,G,0xA000)==memory,(label,wrapper,'payload')
 assert all(_read_span(p,a,n)==v for (a,n),v in observed.items())
 assert expected.events==actual.events and expected.freed==actual.freed
 assert expected.effects.calls==actual.effects.calls and expected.effects.blocks==actual.effects.blocks
 print('PASS',hex(base),'string value replacement',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),case=label,operation='string_value_replacement',actual_wrapper=wrapper,
  original_returned=True,full_guest_payload_and_ELF_pages_match=True,destruction_free_order_heap_and_pre_free_bytes_match=True,
  cleanup_callback_reloaded_after_key_destruction=label=='reload_raw_cleanup',incidental_native_X0_not_claimed=True,native_snapshot_input=False)


def fresh_iterator_pair(library,base,label):
 p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
 iterator=G-8 if label=='unmapped_table_word' else G+0x1FF4 if label=='cross_page' else G+0x1800
 node=G+0x2FDC if label=='cross_page' else G+0x2400
 pair={'NULL_pair':0,'full_u64_pair':(1<<64)-1,'unmapped_pair_pointer':0x66000000}.get(label,G+0x3000)
 if label!='unmapped_table_word':_write_span(p,iterator,(base+0x381B20).to_bytes(8,'little'))
 _write_span(p,iterator+8,node.to_bytes(8,'little'));_write_span(p,node+32,pair.to_bytes(8,'little'))
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x24C59C,iterator,0xA5A5A5A5A5A5A5A5,0xA5A5A5A5A5A5A5A5)))
 return p,iterator,pair


def compare_iterator_pair(library,base,label,wrapper):
 p,iterator,pair=fresh_iterator_pair(library,base,label)
 result,memory,_,_=oracle.native(library,base,0x285B28 if wrapper else 0x24C59C,[PACKED] if wrapper else [iterator],p)
 out=registry.configuration_tree_iterator_pair(p,iterator_address=iterator)
 if wrapper:_write_span(p,PACKED+16,out.to_bytes(8,'little'))
 assert out==result==pair and _read_span(p,G,0xA000)==memory
 print('PASS',hex(base),'iterator pair',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),operation='iterator_pair',case=label,actual_wrapper=wrapper,original_returned=True,
  full_guest_payload_and_packed_u64_pair_match=True,table_word_and_pair_payload_not_read=True,native_snapshot_input=False)


def compare_clone_wrapper(library,base,label):
 p={**oracle.image_pages(library,base),**oracle.fresh_pages()}
 source=G+0x2400;obj=source if label=='self_alias' else G+0x1FF8 if label=='cross_page' else G+0x1800
 data=b'' if label=='empty' else b'ab\0cd' if label=='embedded_NUL' else b'clone'
 length=0x80000000 if label=='negative_min' else 0xFFFFFFFF if label=='negative_all_ones' else len(data)
 _write_span(p,source,(base+0x34F5F8).to_bytes(8,'little')+(len(data)+1).to_bytes(4,'little')+length.to_bytes(4,'little')+(G+0x2FFD).to_bytes(8,'little'))
 _write_span(p,G+0x2FFD,data+b'\0')
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x2483E0,obj,source,0xA5A5A5A5A5A5A5A5)))
 expected=Services(failures=(0,) if label=='malloc_NULL' else ());actual=Services(failures=(0,) if label=='malloc_NULL' else ())
 result,memory,_,_=oracle.native(library,base,0x285B44,[PACKED],p,malloc_handler=expected.native_malloc)
 out=objects.clone_string_object(p,object_address=obj,source_object_address=source,image_base=base,allocate=actual.malloc)
 assert out==result and _read_span(p,G,0xA000)==memory
 assert expected.events==actual.events and expected.effects.calls==actual.effects.calls and expected.effects.blocks==actual.effects.blocks
 print('PASS',hex(base),'clone wrapper',label,flush=True)
 return dict(image_base=hex(base),operation='clone_wrapper',case=label,actual_wrapper=True,original_returned=True,
  full_guest_payload_and_clone_return_match=True,allocator_order_and_heap_match=True,existing_clone_owner_reused=True,native_snapshot_input=False)


def fresh_advance(library,base,label):
 keys=[b'a'] if label=='one_last' else [b'd',b'b',b'f',b'a',b'c',b'e',b'g']
 query={'right_subtree':b'b','deep_right_min':b'd','ancestor_left_child':b'a',
  'ancestor_climb_right':b'c','maximum_last':b'g'}.get(label,keys[0])
 p,blocks,addresses=fixture(library,base,keys);services=Services(blocks)
 registry.construct_configuration_tree(p,container_address=CONTAINER,descriptor_address=DESCRIPTOR,image_base=base,allocate=services.malloc)
 for obj,_,value in addresses:registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=obj,value_address=value,
  image_base=base,allocate=services.malloc,free=services.free)
 tree=registry._ConfigurationTree(p,CONTAINER,base,4096,0x100000)
 key=addresses[keys.index(query)][0];node=tree.find(key)
 iterator=G+0x8FF8 if label=='cross_page' else G+0x1500
 table=0 if label=='NULL_table' else (1<<64)-1 if label=='full_u64_table' else base+0x381B20
 _write_span(p,iterator,table.to_bytes(8,'little')+node.to_bytes(8,'little'))
 _write_span(p,PACKED,b''.join(v.to_bytes(8,'little') for v in (base+0x24C5B8,iterator,0xA5A5A5A5A5A5A5A5,0xA5A5A5A5A5A5A5A5)))
 return p,iterator,node


def native_advance(library,base,p,iterator,wrapper):
 from unicorn import arm64_const as arm
 final=[]
 def watch(c,a):
  if a==base+(0x285B6C if wrapper else 0x24C5D8):final.append(c.reg_read(arm.UC_ARM64_REG_X1))
 result,memory,_,_=oracle.native(library,base,0x285B54 if wrapper else 0x24C5B8,
  [PACKED] if wrapper else [iterator],p,instruction_observer=watch)
 assert len(final)==1
 return result,final[0],memory


def compare_advance(library,base,label,wrapper):
 p,iterator,_=fresh_advance(library,base,label)
 table,node,memory=native_advance(library,base,p,iterator,wrapper)
 pair=registry.advance_configuration_tree_iterator(p,iterator_address=iterator)
 if wrapper:_write_span(p,PACKED+16,b''.join(v.to_bytes(8,'little') for v in pair))
 assert pair==(table,node) and _read_span(p,G,0xA000)==memory
 print('PASS',hex(base),'advance iterator',label,'wrapper' if wrapper else 'direct',flush=True)
 return dict(image_base=hex(base),operation='iterator_advance',case=label,actual_wrapper=wrapper,original_returned=True,
  full_guest_payload_and_iterator_pair_return_match=True,actual_mutated_iterator_node_match=True,native_snapshot_input=False)


def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
 ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','cleanup','iterator_pair','clone','advance','guards','entry','all'),default='all')
 args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
 from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
 assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
 cases=[];guards=[];entries=[]
 if args.group in ('native','all'):
  for base in BASES:
   for profile in PROFILES:
    for wrapper in (False,True):cases.append(compare(args.library,base,profile,wrapper))
 if args.group in ('cleanup','all'):
  for base in BASES:
   for label in ('nonempty_old','empty_old','embedded_NUL','binary','NULL_old','same_old_value','reload_raw_cleanup'):
    for wrapper in (False,True):cases.append(compare_replacement(args.library,base,label,wrapper))
 if args.group in ('iterator_pair','all'):
  for base in BASES:
   for label in ('pair','NULL_pair','full_u64_pair','unmapped_pair_pointer','cross_page','unmapped_table_word'):
    for wrapper in (False,True):cases.append(compare_iterator_pair(args.library,base,label,wrapper))
 if args.group in ('clone','all'):
  for base in BASES:
   for label in ('empty','nonempty','embedded_NUL','negative_min','negative_all_ones','malloc_NULL','cross_page','self_alias'):
    cases.append(compare_clone_wrapper(args.library,base,label))
 if args.group in ('advance','all'):
  for base in BASES:
   for label in ('one_last','right_subtree','deep_right_min','ancestor_left_child','ancestor_climb_right','maximum_last','cross_page','NULL_table','full_u64_table'):
    for wrapper in (False,True):cases.append(compare_advance(args.library,base,label,wrapper))
 if args.group in ('guards','all'):
  for base in BASES:
   for label in ('invalid_container_word','unmapped_container','NULL_controller','unmapped_count'):
    p,obj,control=fresh(args.library,base,PROFILES[1])
    if label=='invalid_container_word':obj=1<<64
    elif label=='unmapped_container':obj=0x66000000
    elif label=='NULL_controller':_write_span(p,obj+32,bytes(8))
    else:_write_span(p,obj+32,(0x66000000).to_bytes(8,'little'))
    before={k:bytes(v) for k,v in p.items()}
    try:registry.configuration_tree_size(p,container_address=obj)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS tree size rollback',hex(base),label,flush=True)
   for label in ('unmapped_old_value','value_free_exception','unknown_value_callback','unknown_callback_after_key_free'):
    p,key,value,pair,blocks,next_address=fresh_replacement(args.library,base,'nonempty_old')
    actual=ReplacementServices(base,blocks,next_address,key,label)
    if label=='unmapped_old_value':_write_span(p,pair+8,(0x66000000).to_bytes(8,'little'))
    elif label=='unknown_value_callback':_write_span(p,CONTAINER+16,bytes(8))
    def free(p,pointer):
     if label=='value_free_exception' and pointer==G+0x3800:
      _write_span(p,PACKED,b'\xa5');raise RefillUnsupported('injected string-value free failure')
     return actual.free(p,pointer)
    before={k:bytes(v) for k,v in p.items()}
    try:registry.insert_configuration_pair(p,container_address=CONTAINER,key_address=key,value_address=value,image_base=base,
     allocate=actual.malloc,free=free)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),operation='string_value_replacement',case=label,rejected=True,
     all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS string value rollback',hex(base),label,flush=True)
   for label in ('unmapped_iterator_node_word','NULL_iterator_node'):
    p,iterator,pair=fresh_iterator_pair(args.library,base,'pair')
    if label=='unmapped_iterator_node_word':iterator=0x66000000
    else:_write_span(p,iterator+8,bytes(8))
    before={k:bytes(v) for k,v in p.items()}
    try:registry.configuration_tree_iterator_pair(p,iterator_address=iterator)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),operation='iterator_pair',case=label,rejected=True,
     all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS iterator pair rollback',hex(base),label,flush=True)
   for label in ('unmapped_advance_iterator','NULL_advance_node','right_cycle','unmapped_advance_parent','advance_node_bound'):
    p,iterator,node=fresh_advance(args.library,base,'ancestor_climb_right');kw={}
    if label=='unmapped_advance_iterator':iterator=0x66000000
    elif label=='NULL_advance_node':_write_span(p,iterator+8,bytes(8))
    elif label=='right_cycle':_write_span(p,node+24,node.to_bytes(8,'little'));_write_span(p,node+16,node.to_bytes(8,'little'))
    elif label=='unmapped_advance_parent':_write_span(p,node+8,(0x66000000).to_bytes(8,'little'))
    else:kw['max_nodes']=1
    before={k:bytes(v) for k,v in p.items()}
    try:registry.advance_configuration_tree_iterator(p,iterator_address=iterator,**kw)
    except (RefillUnsupported,ValueError):pass
    else:raise AssertionError('guard completed '+label)
    assert before=={k:bytes(v) for k,v in p.items()}
    guards.append(dict(image_base=hex(base),operation='iterator_advance',case=label,rejected=True,
     all_pages_unchanged=True,external_effects_rolled_back=False))
    print('PASS iterator advance rollback',hex(base),label,flush=True)
 if args.group in ('entry','all'):
  from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
  entries,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
 args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=entries,
  native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
  physical_register_spills_verified=False,live_Android_JVM_verified=False,whole_request_native_differential_verified=False,
  complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS',len(cases),'native controls,',len(guards),'guards,',len(entries),'request entry checks')


if __name__=='__main__':main()
