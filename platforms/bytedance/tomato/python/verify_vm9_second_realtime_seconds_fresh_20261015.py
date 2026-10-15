"""Actual +28876c/+26cc64 signed-millisecond then unsigned-second wrapper."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=G+0xEF00;BLOCK=G+0x1200
BASES=(0x122C0000,0x775C205000)
PROFILES={'zero':(0,0),'submillisecond':(0,999999),'subsecond':(0,999999999),
    'positive':(1791023800,500123456),'negative':(-1,0),'signed_overflow':((1<<63)-1,999999999),
    'cross_page_result':(1234,567890123)}

def fixture(library,image,label):
    p=oracle.image_pages(library,image);p.update(oracle.fresh_pages())
    block=G+0x6FF8 if label=='cross_page_result' else BLOCK
    _write_span(p,block,(image+0x26CC64).to_bytes(8,'little')+b'\xa6'*16)
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image)

def original(library,image,p,kw,seconds,nanoseconds):
    steps=[0];seen=set();calls=[]
    def clock(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0
        destination=cpu.reg_read(arm.UC_ARM64_REG_X1)
        cpu.mem_write(destination,seconds.to_bytes(8,'little',signed=True)+nanoseconds.to_bytes(8,'little',signed=True))
        calls.append(['clock_gettime',0]);return 0
    def observe(cpu,address):
        steps[0]+=1
        if address-image in (0x28876C,0x26CC64,0x291958,0x329404):seen.add(address-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    result,memory,allocations,ledger=oracle.native(library,image,0x28876C,[kw['argument_block_address']],p,
        host_imports={0x348450:clock},instruction_observer=observe,observed_memory=watch,
        instruction_limit=10000,extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert seen=={0x28876C,0x26CC64,0x291958,0x329404} and not allocations and not ledger and calls==[['clock_gettime',0]]
    return result,memory,watch,steps[0],calls

def red(library):
    assert not hasattr(model,'apply_request_287474_realtime_seconds_callback')
    rows=[]
    for image in BASES:
        p,kw=fixture(library,image,'negative');result,memory,watch,steps,calls=original(library,image,p,kw,-1,0)
        assert result==(((1<<64)-1000)//1000)
        offset=kw['argument_block_address']-G
        assert memory[offset+8:offset+16]==result.to_bytes(8,'little') and memory[offset+16:offset+24]==b'\xa6'*8
        rows.append(dict(image_base=hex(image),previous_second_wrapper_missing=True,original_wrapper_and_clock_helpers_returned=True,
            unsigned_division_after_negative_signed_milliseconds_observed=True,X64_store_and_following_bytes_observed=True,
            native_instructions=steps,native_snapshot_input=False))
    return rows

def compare(library,image,label):
    p,kw=fixture(library,image,label);sec,nsec=PROFILES[label]
    result,memory,watch,steps,expected=original(library,image,p,kw,sec,nsec);events=[]
    def provider(p,clock_id):events.append(['clock_gettime',clock_id]);return 0,sec,nsec
    actual=model.apply_request_287474_realtime_seconds_callback(p,**kw,read_clock=provider)
    assert actual==result and expected==events and _read_span(p,G,0xA000)==memory,label
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()),label
    print('PASS second realtime seconds',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,native_instructions=steps,original_wrapper_and_clock_helpers_returned=True,
        all_declared_guest_and_image_fields_equal=True,signed_millisecond_then_unsigned_second_arithmetic_equal=True,
        X64_result_and_following_bytes_equal=True,explicit_realtime_provider_call_equal=True,
        no_allocator_or_JNI_or_mutex_services=True,native_snapshot_input=False,physical_spills_and_PAC_compared=False)

def guards(library):
    rows=[]
    for label in ('wrong_target','missing_packed','unaligned_stack','missing_provider','clock_failure','malformed_clock',
            'invalid_seconds','invalid_nanoseconds','final_store_failure_after_provider','packed_spill_alias'):
        p,kw=fixture(library,BASES[0],'positive')
        kw['read_clock']=lambda p,c:(0,1234,567890123)
        if label=='wrong_target':_write_span(p,BLOCK,(kw['image_base']+0x26CC60).to_bytes(8,'little'))
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_provider':kw['read_clock']=None
        elif label=='clock_failure':kw['read_clock']=lambda p,c:(-1,0,0)
        elif label=='malformed_clock':kw['read_clock']=lambda p,c:(0,0)
        elif label=='invalid_seconds':kw['read_clock']=lambda p,c:(0,1<<63,0)
        elif label=='invalid_nanoseconds':kw['read_clock']=lambda p,c:(0,0,1000000000)
        elif label=='final_store_failure_after_provider':
            block=G+0x9FF8;_write_span(p,block,(kw['image_base']+0x26CC64).to_bytes(8,'little'))
            p.pop((G+0xA000)>>12);kw['argument_block_address']=block
            def provider(p,c):_write_span(p,G+0x1800,b'changed');return 0,1234,0
            kw['read_clock']=provider
        elif label=='packed_spill_alias':
            kw['argument_block_address']=SP-0x20;_write_span(p,SP-0x20,(kw['image_base']+0x26CC64).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_realtime_seconds_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('red','native','guards'),default='native');a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library)
    elif a.mode=='guards':e['negative_cases']=guards(a.library)
    else:e['cases']=[compare(a.library,image,label) for image in BASES for label in PROFILES]
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
