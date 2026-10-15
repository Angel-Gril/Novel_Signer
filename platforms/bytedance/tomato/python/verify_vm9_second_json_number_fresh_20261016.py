"""Fresh original JSON number wrapper, ownership and append controls.

Allocator failures are explicit synthetic services. The separate owning
request control uses matching libc allocation. No captured output is input.
"""
from pathlib import Path
import argparse, hashlib, json, struct
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
import vm9_request_287474_vm as second
from vm9_allocator import _read_span, _write_span, RefillUnsupported

G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)
VALUES=(('zero',0),('negative_zero',0x8000000000000000),('one',0x3FF0000000000000),
    ('fraction',0x3FFC000000000000),('negative_fraction',0xBFFC000000000000),
    ('int_max',0x41DFFFFFFFC00000),('above_int_max',0x41E0000000000000),
    ('int_min',0xC1E0000000000000),('below_int_min',0xC1E0000000200000),
    ('positive_inf',0x7FF0000000000000),('negative_inf',0xFFF0000000000000),
    ('quiet_nan',0x7FF8000000001234),('negative_nan',0xFFF8000000004321),
    ('signaling_nan',0x7FF0000000000001),('subnormal',1),
    ('negative_subnormal',0x8000000000000001),('large_uint',0x41EFFFFFFFE00000))
PROFILES=tuple(k for k,v in VALUES)+('empty_key','long_key','binary_key','NUL_key',
    'NULL_parent','NULL_key','node_failure','key_failure','parent_is_node',
    'single_child','two_children','scan_tail','cross_key','cross_object',
    'cross_parent','cross_packed','cross_allocation')
GUARDS=('wrong_target','unaligned_stack','unmapped_object','unmapped_parent',
    'unmapped_key','unterminated_key','custom_malloc','custom_free','missing_allocator',
    'provider_failure','packed_stack_alias','object_stack_alias','key_stack_alias',
    'parent_stack_alias','allocation_stack_alias','cyclic_tail')


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


def fresh(library,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    packed=G+(0x1FF0 if label=='cross_packed' else 0x1000)
    obj=G+(0x2FF8 if label=='cross_object' else 0x1800)
    parent=0 if label=='NULL_parent' else G+(0x6FE0 if label=='cross_parent' else 0x2000)
    if label=='parent_is_node':parent=G+0x4000
    if label=='cross_packed':parent=G+0x6000
    key=0 if label=='NULL_key' else G+(0x2FFF if label=='cross_key' else 0x2800)
    payload={'empty_key':b'','long_key':b'k'*300,'binary_key':b'\x80\xffx',
        'NUL_key':b'a\0ignored'}.get(label,b'field')
    if key:_write_span(p,key,payload+b'\0')
    w(p,obj,image+0x35BA58);w(p,obj+8,parent)
    if parent:
        _write_span(p,parent,bytes(64));w(p,parent+24,64,4)
        if label in ('single_child','two_children','scan_tail'):
            first,last=G+0x3100,G+0x3200
            _write_span(p,first,bytes(64));_write_span(p,last,bytes(64))
            w(p,parent+16,first)
            if label=='single_child':w(p,first+8,first)
            else:
                w(p,first,last);w(p,last+8,first)
                w(p,first+8,last if label=='two_children' else 0)
    bits=dict(VALUES).get(label,0x4170000000000000)
    _write_span(p,packed,b''.join(v.to_bytes(8,'little') for v in (image+0x261350,obj,key,bits))+b'\x5A'*8)
    w(p,image+0x381AA0,image+0x347FD0);w(p,image+0x381AA8,image+0x347FA0)
    failures=(0,) if label=='node_failure' else (1,) if label=='key_failure' else ()
    return p,packed,failures


def services(label,failures):
    s=Services(failures=failures)
    if label=='cross_allocation':s.effects.next=G+0x4FE0
    return s


def original(library,image,p,packed,effects):
    steps=[0];seen=set();watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,a):
        steps[0]+=1
        if a-image in (0x288854,0x261350,0x24A35C,0x24A3B4,0x24A214,0x24A1B0,0x249168,0x2490E0):seen.add(a-image)
    _,memory,allocations,ledger=oracle.native(library,image,0x288854,[packed],p,
        malloc_handler=effects.native_malloc,host_imports={0x347FA0:effects.native_free},
        instruction_observer=observe,observed_memory=watch,instruction_limit=100000)
    assert {0x288854,0x261350,0x24A35C,0x24A3B4,0x24A214}<=seen and not allocations and not ledger
    return memory,watch,steps[0]


def red(library):
    assert not hasattr(second,'apply_request_287474_json_number_callback');rows=[]
    for image in BASES:
        p,packed,failures=fresh(library,image,'quiet_nan');effects=services('quiet_nan',failures)
        memory,watch,steps=original(library,image,p,packed,effects)
        assert memory[packed-G+32]==1
        node=int.from_bytes(memory[G+0x2010-G:G+0x2018-G],'little')
        integer=int.from_bytes(memory[node-G+40:node-G+44],'little',signed=True)
        assert integer==0,('native NaN integer',integer)
        assert memory[node-G+48:node-G+56]==dict(VALUES)['quiet_nan'].to_bytes(8,'little')
        rows.append(dict(image_base=hex(image),previous_number_callback_missing=True,
            original_wrapper_number_append_returned=True,native_NaN_integer_is_zero=True,
            native_NaN_payload_preserved=True,steps=steps,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,packed,failures=fresh(library,image,label);before=_read_span(p,packed,40)
    expected=services(label,failures);actual=services(label,failures)
    memory,watch,steps=original(library,image,p,packed,expected)
    result=second.apply_request_287474_json_number_callback(p,argument_block_address=packed,
        entry_stack_address=SP,image_base=image,allocate=actual.malloc,free=actual.free)
    ours=_read_span(p,G,0xA000)
    assert ours==memory,(label,'guest',next((hex(i) for i,(a,b) in enumerate(zip(ours,memory)) if a!=b),None))
    for (a,n),data in watch.items():assert _read_span(p,a,n)==data,(label,hex(a))
    assert actual.events==expected.events and actual.freed==expected.freed,(label,'ordered effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert _read_span(p,packed,32)==before[:32] and _read_span(p,packed+33,7)==before[33:]
    assert result==bool(memory[packed-G+32])
    print('PASS JSON number',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,original_wrapper_number_append_returned=True,
        all_guest_and_image_bytes_equal=True,ordered_allocation_free_and_prefree_bytes_equal=True,
        result_is_one_byte_and_padding_preserved=True,native_snapshot_input=False,
        synthetic_allocator_services=True,complete_physical_ABI_verified=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,packed,failures=fresh(library,image,'zero');s=services('zero',failures)
        kw=dict(argument_block_address=packed,entry_stack_address=SP,image_base=image,allocate=s.malloc,free=s.free)
        if label=='wrong_target':w(p,packed,image+0x261404)
        elif label=='unaligned_stack':kw['entry_stack_address']-=1
        elif label=='unmapped_object':w(p,packed+8,0x66000000)
        elif label=='unmapped_parent':w(p,G+0x1808,0x66000000)
        elif label=='unmapped_key':w(p,packed+16,0x66000000)
        elif label=='unterminated_key':_write_span(p,G+0x2800,b'k'*4096)
        elif label=='custom_malloc':w(p,image+0x381AA0,image+0x347FA0)
        elif label=='custom_free':w(p,image+0x381AA8,image+0x347FD0)
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='provider_failure':
            def fail(tx,n):_write_span(tx,G+0x5000,b'effect');raise RuntimeError('allocation failed')
            kw['allocate']=fail
        elif label=='packed_stack_alias':_write_span(p,SP-0x20,_read_span(p,packed,40));kw['argument_block_address']=SP-0x20
        elif label=='object_stack_alias':w(p,packed+8,SP-0x20)
        elif label=='key_stack_alias':w(p,packed+16,SP-0x20)
        elif label=='parent_stack_alias':w(p,G+0x1808,SP-0x20)
        elif label=='allocation_stack_alias':kw['allocate']=lambda tx,n:SP-0x100
        elif label=='cyclic_tail':
            w(p,G+0x2010,G+0x3100);_write_span(p,G+0x3100,bytes(64));w(p,G+0x3100,G+0x3100)
        before={k:bytes(v) for k,v in p.items()}
        try:second.apply_request_287474_json_number_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError('accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_JSON_parser_verified=False,
        complete_second_vm_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,live_Android_JVM_verified=False,actual_URL_header_JNI_conversion_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in BASES:
            for label in a.case or PROFILES:
                e['cases'].append(compare(a.library,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
