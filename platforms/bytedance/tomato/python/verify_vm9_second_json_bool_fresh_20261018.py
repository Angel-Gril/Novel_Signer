"""Fresh original boolean insertion, bit masking, ownership and cleanup."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_request_287474_vm as second
G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)
PROFILES=('false','true','even_byte','odd_byte','all_bits','empty_key','long_key',
    'binary_key','NUL_key','NULL_parent','NULL_key','node_failure','key_failure',
    'parent_is_node','single_child','scan_tail','cross_key','cross_packed','cross_node','live_key')
GUARDS=('wrong_target','unaligned_stack','missing_allocator','missing_free','unmapped_parent',
    'unmapped_key','unterminated_key','custom_malloc','custom_free','provider_failure','invalid_allocation',
    'packed_spill','receiver_spill','parent_spill','key_spill','allocation_spill','key_tail_spill',
    'node_mutation','free_failure','cyclic_list','list_bound','missing_receiver')
def w(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def fixture(library,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    block=G+(0x1FF0 if label=='cross_packed' else 0x1000);obj=G+0x1800
    parent=0 if label=='NULL_parent' else G+0x2000
    if label=='cross_packed':parent=G+0x6000
    if label=='parent_is_node':parent=G+0x4000
    key=0 if label=='NULL_key' else G+(0x2FFF if label=='cross_key' else 0x2800)
    data={'empty_key':b'','long_key':b'k'*300,'binary_key':b'\x80\xffk','NUL_key':b'a\0tail'}.get(label,b'field')
    if key:_write_span(p,key,data+b'\0')
    w(p,obj,image+0x35BA58);w(p,obj+8,parent)
    if parent:
        _write_span(p,parent,bytes(64));w(p,parent+24,64,4)
        if label in ('single_child','scan_tail'):
            first,last=G+0x3100,G+0x3200
            _write_span(p,first,bytes(64));_write_span(p,last,bytes(64));w(p,parent+16,first)
            if label=='single_child':w(p,first+8,first)
            else:w(p,first,last);w(p,last+8,first)
    value={'false':0,'even_byte':254,'odd_byte':3,'all_bits':255}.get(label,1)
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x261580,obj,key))+bytes([value])+b'\x5A'*15)
    w(p,image+0x381AA0,image+0x347FD0);w(p,image+0x381AA8,image+0x347FA0)
    return p,block
def services(label):
    s=Services(failures=(0,) if label=='node_failure' else (1,) if label=='key_failure' else ())
    if label=='cross_node':s.effects.next=G+0x4FE0
    if label=='live_key':
        def mutate(kind,index,read,write):
            if kind=='malloc' and index==1:write(G+0x2800,b'other\0')
        s.effects.mutate=mutate
    return s
def original(library,image,p,block,s):
    steps=[0];seen=set();watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,a):
        steps[0]+=1
        if a-image in (0x288968,0x261580,0x24A2C4,0x24A320,0x2493E8,0x24A214,0x2490E0):seen.add(a-image)
    _,memory,allocations,ledger=oracle.native(library,image,0x288968,[block],p,
        malloc_handler=s.native_malloc,host_imports={0x347FA0:s.native_free},
        instruction_observer=observe,observed_memory=watch,instruction_limit=100000)
    assert {0x288968,0x261580,0x24A2C4,0x24A320,0x2493E8,0x24A214}<=seen and not allocations and not ledger
    return memory,watch,steps[0]
def compare(library,image,label):
    p,block=fixture(library,image,label);before=_read_span(p,block,40)
    expected=services(label);actual=services(label)
    memory,watch,steps=original(library,image,p,block,expected)
    callback=getattr(second,'apply_request_287474_json_bool_callback',None)
    assert callable(callback),'original inserts a low-bit boolean, but the second callback is missing'
    result=callback(p,argument_block_address=block,entry_stack_address=SP,image_base=image,allocate=actual.malloc,free=actual.free)
    ours=_read_span(p,G,0xA000)
    assert ours==memory,(label,next((hex(i) for i,(a,b) in enumerate(zip(ours,memory)) if a!=b),None))
    assert all(_read_span(p,a,n)==data for (a,n),data in watch.items())
    assert actual.events==expected.events and actual.freed==expected.freed and actual.effects.blocks==expected.effects.blocks
    assert result==bool(memory[block-G+25]) and _read_span(p,block,25)==before[:25] and _read_span(p,block+26,14)==before[26:]
    if result:
        node=u(p,u(p,block+8)+8)
        first=u(p,node+16);tail=u(p,first+8)
        assert u(p,tail+24,4)==1+(before[24]&1)
    print('PASS JSON bool',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,original_boolean_wrapper_create_key_append_cleanup_returned=True,
        all_guest_and_image_bytes_equal=True,ordered_allocation_free_and_prefree_bytes_equal=True,
        low_bit_type_and_single_result_byte_equal=True,native_snapshot_input=False,synthetic_allocation_services=True,
        complete_physical_ABI_verified=False)
def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block=fixture(library,image,'true');s=services('true')
        kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,allocate=s.malloc,free=s.free)
        if label=='wrong_target':w(p,block,image+1)
        elif label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_free':kw['free']=None
        elif label=='unmapped_parent':w(p,G+0x1808,0x66000000)
        elif label=='unmapped_key':w(p,block+16,0x66000000)
        elif label=='unterminated_key':w(p,block+16,G+0x9000);_write_span(p,G+0x9000,b'k'*4096)
        elif label=='custom_malloc':w(p,image+0x381AA0,image+0x347FA0)
        elif label=='custom_free':w(p,image+0x381AA8,image+0x347FD0)
        elif label in ('provider_failure','free_failure'):
            def fail(tx,*args):_write_span(tx,G+0x5000,b'effect');raise RefillUnsupported('provider failure')
            kw['allocate' if label=='provider_failure' else 'free']=fail
            if label=='free_failure':w(p,G+0x1808,0)
        elif label=='invalid_allocation':kw['allocate']=lambda tx,n:True
        elif label=='packed_spill':kw['argument_block_address']=SP-0x100;_write_span(p,SP-0x100,_read_span(p,block,40))
        elif label=='receiver_spill':w(p,block+8,SP-0x100)
        elif label=='parent_spill':w(p,G+0x1808,SP-0x100)
        elif label=='key_spill':w(p,block+16,SP-0x100)
        elif label=='allocation_spill':kw['allocate']=lambda tx,n:SP-0x100
        elif label=='key_tail_spill':w(p,block+16,SP-0x1001);_write_span(p,SP-0x1001,b'kk\0')
        elif label=='node_mutation':
            def mutate(kind,index,read,write):
                if kind=='malloc' and index==1:write(G+0x4000+24,(0x102).to_bytes(4,'little'))
            s.effects.mutate=mutate
        elif label in ('cyclic_list','list_bound'):
            w(p,G+0x2010,G+0x3100);_write_span(p,G+0x3100,bytes(64));_write_span(p,G+0x3200,bytes(64))
            w(p,G+0x3100,G+0x3200);w(p,G+0x3200,G+0x3100 if label=='cyclic_list' else 0)
            if label=='list_bound':kw['max_nodes']=1
        elif label=='missing_receiver':w(p,block+8,0x66000000)
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_json_bool_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,external_provider_effect_rollback_verified=False))
    return rows
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES:
            for label in (('even_byte',) if a.mode=='red' else PROFILES):
                e['cases'].append(compare(a.library,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
