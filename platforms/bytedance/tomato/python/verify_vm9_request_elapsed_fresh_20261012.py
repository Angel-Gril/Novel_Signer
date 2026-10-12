"""Fresh original elapsed request wrapper versus independent state arithmetic.

Clock results and mutex state are explicit inputs. The original wrapper,
elapsed body and matching libc reader transitions execute in the oracle.
The physical stack and Android clock implementation are outside this check.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import vm9_state as state
import vm9_objects as objects
import verify_vm9_state_service_fresh_20261012 as dependency
import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OBJECT=G+0x1800;PACKED=G+0x1A00;M64=(1<<64)-1


def fresh(library,libc,base,profile):
    p,sdk=dependency.fresh(library,libc,base,'cold')
    _write_span(p,OBJECT,b'\xD3'*0xA0)
    objects.construct_mutex_state(p,object_address=OBJECT,image_base=base)
    if profile.get('shared_mutex'):_write_span(p,OBJECT+8,(0x2000).to_bytes(2,'little'))
    _write_span(p,OBJECT+0x90,profile.get('readers',0).to_bytes(4,'little'))
    _write_span(p,OBJECT+0x94,bytes([profile.get('flag',0)]))
    _write_span(p,OBJECT+0x98,(profile['start']&M64).to_bytes(8,'little'))
    _write_span(p,PACKED,(base+0x26BF90).to_bytes(8,'little')+OBJECT.to_bytes(8,'little')+b'\xA5'*16)
    return p,sdk


def native(library,libc,base,p,profile):
    calls=[];observed={}
    for page in p:
        if base<=page<<12<base+0x400000:observed[page<<12,4096]=None
    observed[dependency.root.TLS,0xB00]=None
    def clock(cpu):
        assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0
        readers=int.from_bytes(cpu.mem_read(OBJECT+0x90,4),'little')
        assert readers==profile.get('readers',0)+1
        assert bytes(cpu.mem_read(OBJECT+0x94,1))==b'\x01'
        calls.append(0)
        if 'new_start' in profile:cpu.mem_write(OBJECT+0x98,(profile['new_start']&M64).to_bytes(8,'little'))
        cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),profile['seconds'].to_bytes(8,'little',signed=True)
            +profile.get('nanoseconds',0).to_bytes(8,'little',signed=True))
        return 0
    inputs={page:data for page,data in p.items() if not dependency.root.LIBC_BASE<=page<<12<dependency.root.LIBC_BASE+0x200000}
    result,memory,allocations,ledger=oracle.native(library,base,0x285D80,[PACKED],inputs,libc=libc,
        real_mutexes=True,thread_id=137,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.root.TLS},
        host_imports={0x348450:clock},observed_memory=observed,instruction_limit=10000)
    assert not allocations and calls==[0]
    return result,memory,observed


def compare(library,libc,base,label,profile):
    p,sdk=fresh(library,libc,base,profile)
    returned,memory,observed=native(library,libc,base,p,profile)
    calls=[]
    def clock(p,clock_id):
        assert clock_id==0
        assert int.from_bytes(_read_span(p,OBJECT+0x90,4),'little')==profile.get('readers',0)+1
        assert _read_span(p,OBJECT+0x94,1)==b'\x01'
        calls.append(clock_id)
        if 'new_start' in profile:_write_span(p,OBJECT+0x98,(profile['new_start']&M64).to_bytes(8,'little'))
        return 0,profile['seconds'],profile.get('nanoseconds',0)
    value=state.read_request_elapsed_seconds(p,object_address=OBJECT,read_clock=clock)
    _write_span(p,PACKED+16,value.to_bytes(8,'little'))
    assert calls==[0]
    current=_read_span(p,G,0xA000)
    if current!=memory:
        i=next(i for i,(a,b) in enumerate(zip(current,memory)) if a!=b)
        raise AssertionError((label,'guest',hex(i),hex(current[i]),hex(memory[i])))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert value==int.from_bytes(memory[0x1A10:0x1A18],'little')
    assert int.from_bytes(_read_span(p,OBJECT+0x90,4),'little')==profile.get('readers',0)
    print('PASS request elapsed',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_request_wrapper_returned=True,
        full_guest_ELF_TLS_and_uint64_packed_result_match=True,clock_inside_reader_scope=True,
        reader_count_restored_and_shared_flag_retained=True,actual_matching_libc_mutexes=True,
        saved_start_read_before_clock_verified='new_start' in profile,native_snapshot_input=False)


def profiles():
    now=1791023800500
    return (
        ('default',dict(start=0,seconds=1791023800,nanoseconds=500000000)),
        ('past',dict(start=now-1700,seconds=1791023800,nanoseconds=500000000)),
        ('subsecond',dict(start=now-999,seconds=1791023800,nanoseconds=500000000)),
        ('exact_second',dict(start=now-1000,seconds=1791023800,nanoseconds=500000000)),
        ('zero_delta',dict(start=now,seconds=1791023800,nanoseconds=500000000)),
        ('future',dict(start=now+1,seconds=1791023800,nanoseconds=500000000)),
        ('negative_start',dict(start=-1700,seconds=1791023800,nanoseconds=500000000)),
        ('negative_now_fallback',dict(start=0,seconds=-2,nanoseconds=500000000)),
        ('negative_now_positive_delta',dict(start=-3500,seconds=-2,nanoseconds=500000000)),
        ('negative_fraction_truncation',dict(start=0,seconds=-1,nanoseconds=999999999)),
        ('signed_delta_max',dict(start=(now-((1<<63)-1))&M64,seconds=1791023800,nanoseconds=500000000)),
        ('signed_delta_min',dict(start=(now-(1<<63))&M64,seconds=1791023800,nanoseconds=500000000)),
        ('wrapped_subtraction',dict(start=M64-500,seconds=0,nanoseconds=500000000)),
        ('micros_signed_wrap',dict(start=0,seconds=9223372036855,nanoseconds=999999999)),
        ('micros_unsigned_wrap',dict(start=0,seconds=18446744073710,nanoseconds=123456789)),
        ('clock_changes_start',dict(start=now-1700,new_start=now+1000,seconds=1791023800,nanoseconds=500000000)),
        ('existing_readers',dict(start=now-1700,readers=7,flag=0xCC,seconds=1791023800,nanoseconds=500000000)),
        ('normal_mutex_shared_bit',dict(start=now-1700,shared_mutex=True,seconds=1791023800,nanoseconds=500000000)),
    )


def guards(library,libc):
    rows=[]
    for label in ('missing_provider','malformed_result','clock_error','invalid_nanoseconds','invalid_seconds',
            'provider_failure','writer_count','saturated_readers','contended_mutex','unmapped_saved_word',
            'reader_underflow_after_clock','writer_mode_after_clock'):
        p,sdk=fresh(library,libc,dependency.BASES[0],dict(start=1000,seconds=3))
        object_address=OBJECT
        def clock(p,clock_id):
            _write_span(p,OBJECT+0x98,(9000).to_bytes(8,'little'))
            if label=='malformed_result':return (0,)
            if label=='clock_error':return -1,3,0
            if label=='invalid_nanoseconds':return 0,3,1000000000
            if label=='invalid_seconds':return 0,1<<63,0
            if label=='provider_failure':raise RefillUnsupported('explicit clock unavailable')
            if label=='reader_underflow_after_clock':_write_span(p,OBJECT+0x90,bytes(4))
            if label=='writer_mode_after_clock':_write_span(p,OBJECT+0x94,bytes(1))
            return 0,3,0
        provider=clock
        if label=='missing_provider':provider=None
        elif label=='writer_count':_write_span(p,OBJECT+0x90,(1<<31).to_bytes(4,'little'))
        elif label=='saturated_readers':_write_span(p,OBJECT+0x90,((1<<31)-1).to_bytes(4,'little'))
        elif label=='contended_mutex':_write_span(p,OBJECT+8,(1).to_bytes(2,'little'))
        elif label=='unmapped_saved_word':
            object_address=G+0x4F68
            objects.construct_mutex_state(p,object_address=object_address,image_base=dependency.BASES[0])
            del p[(G+0x5000)>>12]
        before={k:bytes(v) for k,v in p.items()}
        try:state.read_request_elapsed_seconds(p,object_address=object_address,read_clock=provider)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request elapsed guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    cases=[];negative=[]
    if args.group in ('native','all'):
        cases=[compare(args.library,args.libc,base,label,profile) for base in dependency.BASES for label,profile in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library,args.libc)
    args.output.write_text(json.dumps(dict(component='Actual request elapsed seconds',cases=cases,
        native_Python_controls=len(cases),native_input_snapshot_used=False,negative_cases=negative,rollback_guards=len(negative),
        whole_physical_stack_bytes_compared=False,whole_request_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
