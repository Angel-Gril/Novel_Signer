"""Original raw-millisecond trampoline and second VM X64 result writeback."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_second_realtime_seconds_fresh_20261015 as seconds_fixture
import vm9_request_287474_vm as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;SP=seconds_fixture.SP;BASES=seconds_fixture.BASES
PROFILES=seconds_fixture.PROFILES
GUARDS=('wrong_target','NULL_packed','wrapped_packed','missing_packed','unaligned_stack','wrapped_stack',
    'missing_provider','clock_failure','malformed_clock','invalid_seconds','invalid_nanoseconds',
    'provider_failure','partial_store_after_provider','packed_spill_alias')

def fixture(library,image,label):
    p,kw=seconds_fixture.fixture(library,image,label)
    _write_span(p,kw['argument_block_address'],(image+0x26CC60).to_bytes(8,'little'))
    return p,kw

def original(library,image,p,kw,sec,nsec):
    steps=[0];seen=set();calls=[];minimum=[SP]
    def clock(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0
        address=cpu.reg_read(arm.UC_ARM64_REG_X1)
        cpu.mem_write(address,sec.to_bytes(8,'little',signed=True)+nsec.to_bytes(8,'little',signed=True))
        calls.append(['clock_gettime',0]);return 0
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP))
        if a-image in (0x28876C,0x26CC60,0x291958,0x329404):seen.add(a-image)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    result,memory,allocations,ledger=oracle.native(library,image,0x28876C,[kw['argument_block_address']],p,
        host_imports={0x348450:clock},instruction_observer=observe,observed_memory=watch,
        instruction_limit=1000,extra_registers={arm.UC_ARM64_REG_SP:SP})
    assert seen=={0x28876C,0x26CC60,0x291958,0x329404} and not allocations and not ledger
    assert calls==[['clock_gettime',0]] and minimum[0]>=SP-0x1000
    return result,memory,watch,steps[0],calls,SP-minimum[0]

def compare(library,image,label):
    p,kw=fixture(library,image,label);sec,nsec=PROFILES[label]
    result,memory,watch,steps,expected,stack_bytes=original(library,image,p,kw,sec,nsec)
    callback=getattr(model,'apply_request_287474_realtime_milliseconds_callback',None)
    assert callable(callback),'original raw realtime milliseconds wrapper returned, but the second callback is missing'
    events=[]
    def provider(p,clock_id):events.append(['clock_gettime',clock_id]);return 0,sec,nsec
    actual=callback(p,**kw,read_clock=provider)
    assert actual==result and events==expected and _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==v for (a,n),v in watch.items())
    print('PASS realtime milliseconds',hex(image),label,flush=True)
    return dict(image_base=hex(image),case=label,steps=steps,native_stack_bytes=stack_bytes,
        original_wrapper_and_clock_helpers_returned=True,all_declared_guest_and_image_bytes_equal=True,
        signed_milliseconds_X64_bits_equal=True,exact_eight_byte_store_and_tail_equal=True,
        explicit_realtime_provider_call_equal=True,native_snapshot_input=False,
        physical_spills_and_PAC_compared=False,external_provider_effect_rollback_verified=False)

def guards(library):
    rows=[]
    for label in GUARDS:
        p,kw=fixture(library,BASES[0],'positive');block=kw['argument_block_address']
        kw['read_clock']=lambda p,c:(0,1234,567890123)
        if label=='wrong_target':_write_span(p,block,(BASES[0]+0x26CC64).to_bytes(8,'little'))
        elif label=='NULL_packed':kw['argument_block_address']=0
        elif label=='wrapped_packed':kw['argument_block_address']=(1<<64)-8
        elif label=='missing_packed':kw['argument_block_address']=0x66000000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='wrapped_stack':kw['entry_stack_address']=1<<64
        elif label=='missing_provider':kw['read_clock']=None
        elif label=='clock_failure':kw['read_clock']=lambda p,c:(-1,0,0)
        elif label=='malformed_clock':kw['read_clock']=lambda p,c:(0,0)
        elif label=='invalid_seconds':kw['read_clock']=lambda p,c:(0,1<<63,0)
        elif label=='invalid_nanoseconds':kw['read_clock']=lambda p,c:(0,0,1000000000)
        elif label=='provider_failure':
            def provider(tx,c):_write_span(tx,G+0x1800,b'changed');raise RefillUnsupported('provider failure')
            kw['read_clock']=provider
        elif label=='partial_store_after_provider':
            kw['argument_block_address']=G+0x9FF4
            _write_span(p,G+0x9FF4,(BASES[0]+0x26CC60).to_bytes(8,'little'));p.pop((G+0xA000)>>12)
            def provider(tx,c):_write_span(tx,G+0x1800,b'changed');return 0,1234,0
            kw['read_clock']=provider
        elif label=='packed_spill_alias':
            kw['argument_block_address']=SP-0x100;_write_span(p,SP-0x100,(BASES[0]+0x26CC60).to_bytes(8,'little'))
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_287474_realtime_milliseconds_callback(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_model_pages_unchanged=True,external_provider_effect_rollback_verified=False))
        print('PASS realtime milliseconds refusal',label,flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--mode',choices=('red','native','guards'),default='native')
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    e=dict(cases=[],negative_cases=[])
    if a.mode=='guards':e['negative_cases']=guards(a.library)
    else:
        for image in (BASES[:1] if a.mode=='red' else BASES):
            for label in (('negative',) if a.mode=='red' else PROFILES):
                e['cases'].append(compare(a.library,image,label))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    a.output.write_text(json.dumps(dict(e,native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']),
        native_input_snapshot_used=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
