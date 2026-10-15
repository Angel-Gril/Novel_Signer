"""New +288610 tail deallocation callback with an explicit free provider.

Native physical X0 after void free is not compared. Matching-libc owning
allocation state is checked separately; no accepted token group is rerun.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as second
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=(0x122C0000,0x775C205000);G=oracle.GUEST;PACKED=G+0x2800
PROFILES=('pointer','NULL','high_pointer','unaligned_pointer','cross_packed',
    'packed_alias','provider_rewrites_packed','provider_writes_payload')
GUARDS=('wrong_wrapper','wrong_target','partial_packed','missing_provider','provider_failure','provider_removes_page')


def equivalent_wrappers(library):
    p=oracle.image_pages(library,BASES[0])
    assert _read_span(p,BASES[0]+0x288610,12)==_read_span(p,BASES[0]+0x288B5C,12)


def fresh(library,image,label):
    p={**oracle.image_pages(library,image),**oracle.fresh_pages()}
    packed=G+0x2FFC if label=='cross_packed' else PACKED
    pointer={'NULL':0,'high_pointer':0xFEDCBA9876543210,'unaligned_pointer':G+0x4503,
        'packed_alias':packed}.get(label,G+0x4500)
    _write_span(p,packed,(image+0x32A264).to_bytes(8,'little')+pointer.to_bytes(8,'little')+b'\x5A'*16)
    return p,packed,pointer


def effect(label,packed,pointer,events,write):
    events.append(['free',pointer])
    if label=='provider_rewrites_packed':write(packed,b'\x39'*32)
    elif label=='provider_writes_payload':write(pointer,b'freed\x00payload')


def original(library,image,p,packed,label):
    events=[];steps=[0];seen=set()
    def free(cpu):
        pointer=cpu.reg_read(arm.UC_ARM64_REG_X0)
        effect(label,packed,pointer,events,cpu.mem_write);return 0xBADC0DE
    def observe(cpu,a):
        steps[0]+=1
        if a-image in (0x288610,0x32A264,0x347FA0):seen.add(a-image)
    watch={(page<<12,4096):None for page in p}
    _,_,allocations,services=oracle.native(library,image,0x288610,[packed],p,
        host_imports={0x347FA0:free},instruction_observer=observe,observed_memory=watch)
    assert seen=={0x288610,0x32A264,0x347FA0} and not allocations and not services
    return watch,events,steps[0]


def model(p,image,packed,free,wrapper=0x288610):
    def no_allocate(*args):raise AssertionError('free callback allocated')
    return second.apply_request_287474_consumer(p,wrapper_offset=wrapper,
        argument_block_address=packed,image_base=image,allocate=no_allocate,free=free)


def red(library):
    assert not hasattr(second,'RequestVm287474FreePrefix');rows=[]
    for image in BASES:
        p,packed,pointer=fresh(library,image,'pointer');watch,events,steps=original(library,image,p,packed,'pointer')
        calls=[]
        try:model(p,image,packed,lambda p,a:calls.append(a))
        except RefillUnsupported:pass
        else:raise AssertionError('second free callback already supported')
        assert not calls and events==[['free',pointer]] and all(_read_span(p,a,n)==b for (a,n),b in watch.items())
        rows.append(dict(image_base=hex(image),previous_second_free_dispatch_missing=True,
            original_new_wrapper_and_operator_delete_returned=True,steps=steps,
            explicit_free_pointer_and_no_packed_result_observed=True,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    p,packed,pointer=fresh(library,image,label);watch,expected,steps=original(library,image,p,packed,label);events=[]
    def free(tx,a):effect(label,packed,a,events,lambda a,b:_write_span(tx,a,b));return 0x1234
    result=model(p,image,packed,free)
    assert result is None and events==expected==[['free',pointer]]
    assert all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    print('PASS second free',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,
        original_new_wrapper_and_operator_delete_returned=True,all_pages_and_packed_bytes_equal=True,
        ordered_explicit_free_effects_equal=True,no_packed_result_store=True,
        component_free_provider_explicit=True,native_snapshot_input=False,native_physical_X0_compared=False)


def guards(library):
    rows=[]
    for image in BASES:
        for label in GUARDS:
            p,packed,_=fresh(library,image,'pointer');wrapper=0x288610;calls=[]
            def free(tx,a):calls.append(a)
            if label=='wrong_wrapper':wrapper=0x28861C
            elif label=='wrong_target':_write_span(p,packed,(image+0x32A26C).to_bytes(8,'little'))
            elif label=='partial_packed':
                packed=G+0xFFF4;_write_span(p,packed,(image+0x32A264).to_bytes(8,'little'))
            elif label=='missing_provider':free=None
            elif label in ('provider_failure','provider_removes_page'):
                def free(tx,a):
                    calls.append(a);_write_span(tx,G+0x4500,b'effect')
                    if label=='provider_removes_page':del tx[(G+0x5000)>>12]
                    raise RuntimeError('explicit free provider failed')
            before={k:bytes(v) for k,v in p.items()}
            try:model(p,image,packed,free,wrapper)
            except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
            else:raise AssertionError('free guard accepted '+label)
            assert before=={k:bytes(v) for k,v in p.items()},label
            assert len(calls)==(1 if label in ('provider_failure','provider_removes_page') else 0)
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
