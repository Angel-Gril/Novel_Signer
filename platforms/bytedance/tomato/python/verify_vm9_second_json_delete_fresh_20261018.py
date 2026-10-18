"""Fresh original JSON deleting destructor: flags, live reloads and free order."""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from vm9_allocator import _read_span, _write_span, RefillUnsupported
import vm9_request_287474_vm as second

G=oracle.GUEST; SP=G+0xEF00; BASES=(0x122C0000,0x775C205000)
PROFILES=('null_tree','empty','number','false','true','string','raw','array','nested',
    'siblings','reference','constant_key','reference_constant','reserved_flags',
    'cross_packed','cross_object','cross_node','child_changes_flags','value_changes_flags',
    'value_changes_key','child_changes_next','reference_unmapped_child','constant_unmapped_key',
    'no_hook_null_tree','non_string_value','depth64')
GUARDS=('wrong_target','NULL_object','unmapped_object','wrapped_object','invalid_packed',
    'wrapped_packed','unaligned_stack','wrapped_stack','missing_free','custom_free',
    'unmapped_root','wrapped_root','node_cycle','child_cycle','shared_node','node_bound',
    'depth_bound','invalid_node_bound','invalid_depth_bound','packed_spill','object_spill',
    'node_spill','value_spill','key_spill','wrapper_node_alias','packed_node_alias',
    'shared_payload','child_changes_hook','free_failure','final_free_failure')

def w(p,a,v,n=8): _write_span(p,a,v.to_bytes(n,'little'))
def u(p,a,n=8): return int.from_bytes(_read_span(p,a,n),'little')

def fixture(library,image,label):
    p=oracle.fresh_pages(); p.update(oracle.image_pages(library,image))
    block=G+(0x1FF8 if label=='cross_packed' else 0x1000)
    obj=G+(0x2FF8 if label=='cross_object' else 0x1800)
    root=0 if label in ('null_tree','no_hook_null_tree') else G+(0x3FE0 if label=='cross_node' else 0x3000)
    if label=='cross_object':root=G+0x3800
    blocks={obj:16}
    def node(a,kind=64,child=0,following=0,value=0,key=0):
        _write_span(p,a,bytes(64)); w(p,a,following); w(p,a+8,0xDEADBEEF)
        w(p,a+16,child); w(p,a+24,kind,4); w(p,a+32,value); w(p,a+56,key)
        blocks[a]=64
    value,key,replacement=G+0x6800,G+0x6900,G+0x6A00
    for a,data in ((value,b'value\0'),(key,b'key\0'),(replacement,b'replacement\0')):
        _write_span(p,a,data); blocks[a]=len(data)
    if root:
        kind={'number':8,'false':1,'true':2,'string':16,'raw':128,
            'reference':0x140,'constant_key':0x240,'reference_constant':0x340,
            'reserved_flags':0xFFFFFC40,'reference_unmapped_child':0x140,
            'constant_unmapped_key':0x240}.get(label,64)
        owns=label in ('string','raw','reference','constant_key','reference_constant',
            'child_changes_flags','value_changes_flags','value_changes_key','non_string_value')
        node(root,kind,value=value if owns else 0,key=key if owns else 0)
        if label in ('array','nested','siblings','child_changes_flags','child_changes_next'):
            child=G+0x4000; node(child,8,key=key if label=='nested' else 0)
            if label=='siblings':w(p,root,child)
            else:w(p,root+16,child)
            if label=='nested':node(G+0x4100,16,value=value);w(p,child+16,G+0x4100)
            if label=='child_changes_next':node(G+0x4200,2);w(p,root,G+0x4200)
        if label=='reference_unmapped_child':w(p,root+16,0x66000000);w(p,root+32,0x66001000)
        if label=='constant_unmapped_key':w(p,root+56,0x66000000)
        if label=='depth64':
            for i in range(64):node(root+i*64,child=root+(i+1)*64 if i<63 else 0)
    w(p,obj,0xBAD0BAD0);w(p,obj+8,root)
    _write_span(p,block,(image+0x2614EC).to_bytes(8,'little')+obj.to_bytes(8,'little')+b'\xA5'*24)
    w(p,image+0x381AA8,0 if label=='no_hook_null_tree' else image+0x347FA0)
    return p,block,obj,root,blocks

def services(blocks,label,root):
    s=Services(blocks);free_count=[0]
    def mutate(kind,index,read,write):
        if kind!='free':return
        free_count[0]+=1
        if free_count[0]!=1:return
        if label=='child_changes_flags':write(root+24,(0x140).to_bytes(4,'little'))
        elif label=='value_changes_flags':write(root+24,(0x240).to_bytes(4,'little'))
        elif label=='value_changes_key':write(root+56,(G+0x6A00).to_bytes(8,'little'))
        elif label=='child_changes_next':write(root,bytes(8))
    s.effects.mutate=mutate
    return s

def original(library,image,p,block,s):
    steps=[0];seen=set();minimum=[SP]
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,a):
        steps[0]+=1;seen.add(a-image);minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP))
    _,memory,allocations,ledger=oracle.native(library,image,0x288A24,[block],p,
        host_imports={0x347FA0:s.native_free},instruction_observer=observe,observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP:SP},instruction_limit=100000)
    assert {0x288A24,0x2614EC,0x2614D4,0x2490E0,0x32A264,0x347FA0}<=seen
    assert not allocations and not ledger and SP-0x1000<=minimum[0]<SP
    return memory,watch,steps[0],SP-minimum[0]

def compare(library,image,label):
    p,block,obj,root,blocks=fixture(library,image,label);before=_read_span(p,block,40)
    expected=services(blocks,label,root);actual=services(blocks,label,root)
    memory,watch,steps,stack=original(library,image,p,block,expected)
    callback=getattr(second,'apply_request_287474_json_delete_callback',None)
    assert callable(callback),'original JSON deleting destructor returned, but the second callback is missing'
    result=callback(p,argument_block_address=block,entry_stack_address=SP,image_base=image,free=actual.free)
    assert result is None and _read_span(p,G,0xA000)==memory,label
    assert all(_read_span(p,a,n)==v for (a,n),v in watch.items()),label
    assert actual.events==expected.events and actual.freed==expected.freed and actual.effects.blocks==expected.effects.blocks,label
    assert actual.events[-1]==['free',obj] and actual.freed[-1][1][:8]==(image+0x35BA58).to_bytes(8,'little')
    assert _read_span(p,block,40)==before
    print('PASS JSON delete',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,native_stack_bytes=stack,
        original_wrapper_tree_and_deleting_destructor_returned=True,all_guest_and_image_bytes_equal=True,
        ordered_frees_and_prefree_bytes_equal=True,wrapper_vtable_before_final_free_equal=True,
        packed_bytes_unchanged=True,native_snapshot_input=False,synthetic_free_service=True,
        native_physical_X0_compared=False,complete_physical_ABI_verified=False)

def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,obj,root,blocks=fixture(library,image,'string');s=services(blocks,'string',root)
        kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,free=s.free)
        if label=='wrong_target':w(p,block,image+1)
        elif label in ('NULL_object','unmapped_object','wrapped_object'):
            w(p,block+8,{'NULL_object':0,'unmapped_object':0x66000000,'wrapped_object':(1<<64)-8}[label])
        elif label=='invalid_packed':kw['argument_block_address']=0
        elif label=='wrapped_packed':kw['argument_block_address']=(1<<64)-8
        elif label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='wrapped_stack':kw['entry_stack_address']=1<<64
        elif label=='missing_free':kw['free']=None
        elif label=='custom_free':w(p,image+0x381AA8,image+0x347FD0)
        elif label=='unmapped_root':w(p,obj+8,0x66000000)
        elif label=='wrapped_root':w(p,obj+8,(1<<64)-32)
        elif label=='node_cycle':w(p,root,root)
        elif label=='child_cycle':w(p,root+16,root)
        elif label=='shared_node':
            child=G+0x4000;_write_span(p,child,bytes(64));blocks[child]=64
            w(p,root+16,child);w(p,root,child);s=services(blocks,'string',root);kw['free']=s.free
        elif label=='node_bound':w(p,root+16,G+0x4000);_write_span(p,G+0x4000,bytes(64));kw['max_nodes']=1
        elif label=='depth_bound':w(p,root+16,G+0x4000);kw['max_depth']=1
        elif label=='invalid_node_bound':kw['max_nodes']=True
        elif label=='invalid_depth_bound':kw['max_depth']=65
        elif label=='packed_spill':kw['argument_block_address']=SP-16;_write_span(p,SP-16,_read_span(p,block,16))
        elif label=='object_spill':w(p,block+8,SP-16);_write_span(p,SP-16,_read_span(p,obj,16))
        elif label=='node_spill':w(p,obj+8,SP-64)
        elif label=='value_spill':w(p,root+32,SP-1)
        elif label=='key_spill':w(p,root+56,SP-0x1000)
        elif label=='wrapper_node_alias':w(p,obj+8,obj)
        elif label=='packed_node_alias':w(p,obj+8,block)
        elif label=='shared_payload':w(p,root+56,u(p,root+32))
        elif label=='child_changes_hook':
            def mutate(kind,index,read,write):write(image+0x381AA8,bytes(8))
            s.effects.mutate=mutate
        elif label in ('free_failure','final_free_failure'):
            def fail(tx,a):
                s.free(tx,a)
                if label=='free_failure' or a==obj:raise RefillUnsupported('free provider failed after mutation')
            kw['free']=fail
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_json_delete_callback(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,
            external_provider_effect_rollback_verified=False))
        print('PASS JSON delete refusal',label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES:
            for label in (('string',) if a.mode=='red' else PROFILES):
                e['cases'].append(compare(a.library,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
