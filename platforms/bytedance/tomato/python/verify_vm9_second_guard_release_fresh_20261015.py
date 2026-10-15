"""Original +28854c/+32d4f8 nonbroadcast static guard release controls."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256
import vm9_objects as objects
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;BLOCK=G+0x1200;GUARD=G+0x1400
BASES=(0x122C0000,0x775C205000)
PROFILES=('pending','clear','complete','other_flag','high_flag','byte0_even','shared_mutex',
    'cross_page_guard','guard_two_bytes','packed_guard_alias','packed_receiver_alias','packed_two_words')

def write(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))

def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x9FF0 if label=='packed_two_words' else BLOCK
    guard=G+0x2FFF if label=='cross_page_guard' else GUARD
    if label=='guard_two_bytes':guard=G+0x9FFE
    elif label=='packed_guard_alias':guard=block+16
    elif label=='packed_receiver_alias':guard=block+8
    raw=bytearray(b'\0\x02\xa6\x79\x44\x33\x22\x11')
    if label in ('clear','complete','other_flag','high_flag'):raw[1]={'clear':0,'complete':1,'other_flag':8,'high_flag':128}[label]
    if label=='complete':raw[0]=1
    elif label=='byte0_even':raw[0]=254
    _write_span(p,guard,raw[:2] if label=='guard_two_bytes' else raw)
    _write_span(p,block,(image+0x32D4F8).to_bytes(8,'little')+guard.to_bytes(8,'little'))
    if label!='packed_two_words':_write_span(p,block+16,b'\xb5'*16)
    if label=='packed_guard_alias':_write_span(p,guard,raw)
    if label in ('guard_two_bytes','packed_two_words'):p.pop((G+0xA000)>>12)
    if label=='shared_mutex':write(p,image+0x3E2F40,0x2000,4)
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image)

def original(library,libc,image,p,kw):
    steps=[0];seen=set();events=[]
    missing=[page for page in range(G>>12,(G+oracle.GUEST_SIZE)>>12) if page not in p]
    native_pages=dict(p);native_pages.update({page:bytearray(4096) for page in missing})
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,address):
        if not steps[0]:
            for page in missing:cpu.mem_unmap(page<<12,4096)
        steps[0]+=1;off=address-image
        if off in (0x28854C,0x32D4F8):seen.add(off)
        if off in (0x347F00,0x347F10):events.append(['pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0)])
        assert off!=0x3485A0,'unexpected broadcast in bounded release control'
    result,memory,allocations,ledger=oracle.native(library,image,0x28854C,[kw['argument_block_address']],native_pages,
        libc=libc,real_singletons=True,real_mutexes=True,instruction_limit=10000,
        instruction_observer=observe,observed_memory=watch,extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert seen=={0x28854C,0x32D4F8} and not allocations and result==0
    assert [e[0] for e in ledger]==['pthread_mutex_lock','pthread_mutex_unlock']
    return result,memory,watch,events,steps[0]

def red(library,libc):
    assert not hasattr(objects,'release_static_initialization_guard') and not hasattr(model,'apply_request_287474_guard_release_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'pending');result,memory,watch,events,steps=original(library,libc,image,p,kw)
        assert memory[GUARD-G:GUARD-G+8]==b'\x01\x01\xa6\x79\x44\x33\x22\x11'
        assert memory[BLOCK-G+16:BLOCK-G+32]==b'\xb5'*16
        rows.append(dict(image_base=hex(image),previous_guard_owner_and_wrapper_missing=True,original_wrapper_and_guard_returned=True,
            guard_publication_and_no_packed_store_observed=True,native_instructions=steps,native_snapshot_input=False))
    return rows

def compare(library,libc,image,label):
    p,kw=fixture(library,image,label);result,memory,watch,expected,steps=original(library,libc,image,p,kw)
    events=[];actual=model.apply_request_287474_guard_release_callback(p,**kw,observer=lambda *a:events.append(list(a)))
    assert actual==result and expected==events and _read_span(p,G,0xA000)==memory,label
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    print('PASS second guard release',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,original_wrapper_and_guard_returned=True,
        all_declared_guest_and_image_fields_equal=True,ordered_mutex_effects_equal=True,
        guard_publication_packed_alias_and_no_result_store_equal=True,no_broadcast_or_tid_or_allocator_or_JNI_effects=True,
        native_snapshot_input=False,physical_padding_and_register_spills_compared=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','unmapped_block','NULL_guard','unmapped_guard','unaligned_stack','busy_mutex',
            'broadcast_flag','pending_broadcast_flag','missing_mutex','observer_failure_after_publication','guard_spill_alias','packed_spill_alias'):
        image=BASES[0];p,kw=fixture(library,image,'pending')
        if label=='wrong_target':write(p,BLOCK,image+0x32D3A0)
        elif label=='unmapped_block':kw['argument_block_address']=0x66000000
        elif label=='NULL_guard':write(p,BLOCK+8,0)
        elif label=='unmapped_guard':write(p,BLOCK+8,0x66000000)
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='busy_mutex':write(p,image+0x3E2F40,1,4)
        elif label in ('broadcast_flag','pending_broadcast_flag'):write(p,GUARD+1,4 if label=='broadcast_flag' else 6,1)
        elif label=='missing_mutex':p.pop((image+0x3E2000)>>12)
        elif label=='observer_failure_after_publication':
            def fail(kind,*args):
                if kind=='pthread_mutex_unlock':raise RuntimeError('synthetic observer failure')
            kw['observer']=fail
        elif label=='guard_spill_alias':write(p,BLOCK+8,SP-0x20)
        elif label=='packed_spill_alias':
            a=SP-0x20;_write_span(p,a,_read_span(p,BLOCK,16));kw['argument_block_address']=a
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_guard_release_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_observer_effects_rolled_back=False))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,a.libc,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
