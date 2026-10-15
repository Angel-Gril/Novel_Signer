"""Fresh +2884cc/+2484fc deleting destructor through existing object owner.

Explicit component free effects verify lifecycle ordering. Real matching-libc
payload and object deallocation are checked separately on the request path.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as second
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x2800;OBJECT=G+0x1800
PROFILES=('binary','NULL_payload','negative_length','cross_object','cross_packed',
    'payload_object_alias','provider_rewrites_fields','provider_writes_payload')
GUARDS=('wrong_target','unmapped_object','partial_object','payload_free_failure','object_free_failure','missing_provider')


def equivalent_wrappers(library):
    p=oracle.image_pages(library,BASES[0])
    assert _read_span(p,BASES[0]+0x2884CC,12)==_read_span(p,BASES[0]+0x288B68,12)


def fresh(library,image,label):
    p={**oracle.image_pages(library,image),**oracle.fresh_pages()}
    obj=G+0x1FF8 if label=='cross_object' else OBJECT
    packed=G+0x2FFC if label=='cross_packed' else PACKED
    pointer=0 if label=='NULL_payload' else obj if label=='payload_object_alias' else G+0x4500
    length=0x80000000 if label=='negative_length' else 6
    _write_span(p,G+0x4500,b'a\x00b\xFFCD\x00')
    _write_span(p,obj,(image+0x34F5F8).to_bytes(8,'little')+b'\xCC'*4+
        length.to_bytes(4,'little')+pointer.to_bytes(8,'little'))
    _write_span(p,packed,(image+0x2484FC).to_bytes(8,'little')+obj.to_bytes(8,'little')+b'\x5A'*16)
    return p,packed,obj,pointer


def effect(label,obj,pointer,events,read,write):
    events.append([pointer,read(obj,24).hex(),read(pointer,24).hex()])
    if len(events)==1:
        if label=='provider_rewrites_fields':write(obj,b'\x79'*24)
        elif label=='provider_writes_payload':write(pointer,b'freed\x00payload')


def original(library,image,p,packed,obj,label):
    events=[];steps=[0];seen=set()
    def free(cpu):
        pointer=cpu.reg_read(arm.UC_ARM64_REG_X0)
        effect(label,obj,pointer,events,lambda a,n:bytes(cpu.mem_read(a,n)),cpu.mem_write);return 0xBADC0DE
    def observe(cpu,a):
        steps[0]+=1
        if a-image in (0x2884CC,0x2484FC,0x2484B8,0x32A264,0x347FA0):seen.add(a-image)
    watch={(page<<12,4096):None for page in p if not G+0xD000<=page<<12<G+0xF000}
    _,_,allocations,services=oracle.native(library,image,0x2884CC,[packed],p,
        host_imports={0x347FA0:free},instruction_observer=observe,observed_memory=watch)
    assert seen=={0x2884CC,0x2484FC,0x2484B8,0x32A264,0x347FA0} and not allocations and not services
    return watch,events,steps[0]


def model(p,image,packed,free):
    def no_allocate(*args):raise AssertionError('deleting destructor allocated')
    return second.apply_request_287474_consumer(p,wrapper_offset=0x2884CC,
        argument_block_address=packed,image_base=image,allocate=no_allocate,free=free)


def red(library):
    rows=[]
    for image in BASES:
        p,packed,obj,pointer=fresh(library,image,'binary');watch,events,steps=original(library,image,p,packed,obj,'binary')
        calls=[]
        try:model(p,image,packed,lambda p,a:calls.append(a))
        except RefillUnsupported:pass
        else:raise AssertionError('second deleting destructor already supported')
        assert not calls and [r[0] for r in events]==[pointer,obj]
        assert watch[(obj>>12)<<12,4096][(obj&4095)+16:(obj&4095)+24]==bytes(8)
        rows.append(dict(image_base=hex(image),previous_second_delete_dispatch_missing=True,
            original_new_wrapper_and_deleting_destructor_returned=True,steps=steps,
            payload_then_object_free_and_reset_observed=True,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,packed,obj,pointer=fresh(library,image,label);watch,expected,steps=original(library,image,p,packed,obj,label);events=[]
    def free(tx,a):effect(label,obj,a,events,lambda a,n:_read_span(tx,a,n),lambda a,b:_write_span(tx,a,b));return 0x1234
    result=model(p,image,packed,free)
    assert result is None and events==expected
    assert [e[0] for e in events]==([pointer] if pointer else [])+[obj]
    assert all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    print('PASS second delete',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,
        original_new_wrapper_and_deleting_destructor_returned=True,declared_pages_and_packed_bytes_equal=True,
        ordered_payload_and_object_free_with_prefree_bytes_equal=True,no_packed_result_store=True,
        component_free_provider_explicit=True,native_snapshot_input=False,native_physical_X0_compared=False)


def guards(library):
    rows=[]
    for image in BASES:
        for label in GUARDS:
            p,packed,obj,pointer=fresh(library,image,'binary');calls=[]
            def free(tx,a):
                calls.append(a)
                if (label=='payload_free_failure' and len(calls)==1) or (label=='object_free_failure' and len(calls)==2):
                    _write_span(tx,G+0x4500,b'effect');raise RuntimeError('explicit free provider failed')
            if label=='wrong_target':_write_span(p,packed,(image+0x248520).to_bytes(8,'little'))
            elif label=='unmapped_object':_write_span(p,packed+8,(0x66000000).to_bytes(8,'little'))
            elif label=='partial_object':_write_span(p,packed+8,(G+0xFFEC).to_bytes(8,'little'))
            elif label=='missing_provider':free=None
            before={k:bytes(v) for k,v in p.items()}
            try:model(p,image,packed,free)
            except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
            else:raise AssertionError('delete guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()},label
            assert len(calls)=={'payload_free_failure':1,'object_free_failure':2}.get(label,0)
            rows.append(dict(image_base=hex(image),case=label,rejected=True,all_pages_unchanged=True,
                external_provider_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    ap.add_argument('--case',action='append',choices=PROFILES);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256;equivalent_wrappers(a.library)
    e=dict(cases=[],negative_cases=[],red_cases=[],native_snapshot_input=False,complete_second_vm_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_physical_ABI_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,image,label) for image in BASES for label in a.case or PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
