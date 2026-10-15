"""Original +2884ec/+32d3a0 serial guard acquisition versus Python."""
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
PROFILES=('cold','byte0_one','byte0_even','byte0_max','byte1_complete','byte1_broadcast_mark',
    'byte1_other_flag','byte1_high_flags','tid_zero','tid_max','cross_page_guard',
    'packed_guard_alias','packed_receiver_alias','guard_one_byte','result_cross_page','shared_mutex')

def write(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))

def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x1FEE if label=='result_cross_page' else BLOCK
    guard=G+0x2FFD if label=='cross_page_guard' else GUARD
    if label=='packed_guard_alias':guard=block+16
    elif label=='packed_receiver_alias':guard=block
    elif label=='guard_one_byte':guard=G+0x9FFF
    raw=bytearray(b'\0\0\xa6\x79\x44\x33\x22\x11')
    if label.startswith('byte0'):raw[0]={'byte0_one':1,'byte0_even':2,'byte0_max':255}[label]
    elif label.startswith('byte1'):raw[1]={'byte1_complete':1,'byte1_broadcast_mark':4,'byte1_other_flag':8,'byte1_high_flags':252}[label]
    if label=='guard_one_byte':raw[0]=2;_write_span(p,guard,raw[:1]);p.pop((G+0xA000)>>12,None)
    else:_write_span(p,guard,raw)
    _write_span(p,block,(image+0x32D3A0).to_bytes(8,'little')+guard.to_bytes(8,'little')+b'\xb5'*16)
    if label=='packed_guard_alias':_write_span(p,guard,raw)
    if label=='shared_mutex':write(p,image+0x3E2F40,0x2000,4)
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image,
        thread_id=0 if label=='tid_zero' else 0xFFFFFFFF if label=='tid_max' else 137)

def original(library,libc,image,p,kw):
    steps=[0];seen=set();events=[]
    # The shared oracle initially flattens its guest window. Restore missing
    # pages for setup, then unmap them before the first original instruction.
    missing=[page for page in range(G>>12,(G+oracle.GUEST_SIZE)>>12) if page not in p]
    native_pages=dict(p,**{})
    native_pages.update({page:bytearray(4096) for page in missing})
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    def observe(cpu,address):
        if not steps[0]:
            for page in missing:cpu.mem_unmap(page<<12,4096)
        steps[0]+=1;off=address-image
        if off in (0x2884EC,0x32D3A0):seen.add(off)
        if off in (0x347F00,0x347F10):
            events.append(['pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0)])
        elif off==0x348310:events.append(['gettid',kw['thread_id']])
    result,memory,allocations,ledger=oracle.native(library,image,0x2884EC,[kw['argument_block_address']],native_pages,
        libc=libc,real_singletons=True,real_mutexes=True,thread_id=kw['thread_id'],
        instruction_limit=10000,instruction_observer=observe,observed_memory=watch,
        extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert seen=={0x2884EC,0x32D3A0} and not allocations
    assert all(e[0] in ('pthread_mutex_lock','pthread_mutex_unlock','gettid') for e in ledger)
    return result,memory,watch,events,steps[0]

def red(library,libc):
    assert not hasattr(objects,'acquire_static_initialization_guard')
    assert not hasattr(model,'apply_request_287474_guard_acquire_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'cold');result,memory,_,events,steps=original(library,libc,image,p,kw)
        assert result==1 and memory[BLOCK-G+16:BLOCK-G+24]==b'\x01\0\0\0'+b'\xb5'*4
        assert [e[0] for e in events]==['pthread_mutex_lock','gettid','pthread_mutex_unlock']
        rows.append(dict(image_base=hex(image),previous_guard_owner_and_wrapper_missing=True,
            original_wrapper_and_guard_returned=True,W_result_and_padding_observed=True,
            original_mutex_and_tid_observed=True,native_instructions=steps,native_snapshot_input=False))
    return rows

def compare(library,libc,image,label):
    p,kw=fixture(library,image,label);result,memory,watch,expected,steps=original(library,libc,image,p,kw)
    events=[]
    actual=model.apply_request_287474_guard_acquire_callback(p,**kw,observer=lambda *a:events.append(list(a)))
    assert actual==result and events==expected,(label,actual,result,events,expected)
    assert _read_span(p,G,0xA000)==memory,label
    for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,hex(a))
    block=kw['argument_block_address'];padding=memory[block-G+20:block-G+24]
    assert padding==(kw['thread_id'].to_bytes(4,'little') if label=='packed_guard_alias' else b'\xb5'*4)
    print('PASS second guard acquire',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,W_result=result,
        original_wrapper_and_guard_returned=True,all_declared_guest_and_image_fields_equal=True,
        ordered_mutex_and_tid_equal=True,packed_result_W32_and_alias_effects_equal=True,
        result_padding_preserved_unless_guard_alias=label!='packed_guard_alias',native_snapshot_input=False,
        physical_padding_and_register_spills_compared=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','unmapped_block','NULL_guard','unmapped_guard','unaligned_stack',
            'missing_tid','negative_tid','wide_tid','recursive_guard','contended_guard',
            'busy_mutex','observer_failure_after_lock','guard_spill_alias','packed_spill_alias'):
        image=BASES[0];p,kw=fixture(library,image,'cold')
        if label=='wrong_target':write(p,BLOCK,image+0x32D4F8)
        elif label=='unmapped_block':kw['argument_block_address']=0x66000000
        elif label=='NULL_guard':write(p,BLOCK+8,0)
        elif label=='unmapped_guard':write(p,BLOCK+8,0x66000000)
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_tid':kw['thread_id']=None
        elif label=='negative_tid':kw['thread_id']=-1
        elif label=='wide_tid':kw['thread_id']=1<<32
        elif label in ('recursive_guard','contended_guard'):write(p,GUARD+1,2,1);write(p,GUARD+4,137 if label=='recursive_guard' else 138,4)
        elif label=='busy_mutex':write(p,image+0x3E2F40,1,4)
        elif label=='guard_spill_alias':write(p,BLOCK+8,SP-0x48)
        elif label=='packed_spill_alias':
            _write_span(p,SP-0x30,_read_span(p,BLOCK,24));kw['argument_block_address']=SP-0x30
        elif label=='observer_failure_after_lock':
            def fail(kind,*args):
                if kind=='gettid':raise RuntimeError('synthetic observer failure')
            kw['observer']=fail
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_guard_acquire_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_observer_effects_rolled_back=False))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
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
