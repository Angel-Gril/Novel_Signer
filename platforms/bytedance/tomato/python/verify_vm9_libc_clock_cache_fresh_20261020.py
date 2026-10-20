"""Matching bionic clock cache effects through the shared allocator session."""
from pathlib import Path
import argparse,hashlib,json
from vm9_allocator import RefillUnsupported,_read_span,_write_span
from vm9_outer_allocator import ActualAllocatorSession


def verify(library,libc):
    import verify_vm9_signer_objects as oracle
    from unicorn import arm64_const as arm
    assert hashlib.sha256(library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(libc.read_bytes()).hexdigest()=='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'
    L=0x51000000;G=oracle.GUEST;SP=G+0xEF00;OUT=G+0x3300
    cases=[]
    for image in (0x122C0000,0x775C205000):
        for name,guard,clock_id,seconds,nanoseconds in (
                ('cold',0,0,1700000000,123456789),
                ('cold_highword',0xAABBCCDD00000000,1,321,987654321),
                ('warm',1,0,-123,1000),
                ('warm_lowbit',0x9988776600000003,1,0,0)):
            p=oracle.image_pages(libc,L);p.update(oracle.image_pages(library,image));p.update(oracle.fresh_pages())
            def word(a,v):_write_span(p,a,v.to_bytes(8,'little'))
            word(L+0xDE810,guard);word(L+0xDE820,L+0x6A864 if guard&1 else 0xBAD0)
            word(L+0xD9048,0xBAD4 if guard&1 else L+0x6A864)
            original={k:bytes(v) for k,v in p.items()};model={k:bytearray(v) for k,v in original.items()}
            events=[]
            def provider(tx,clock):
                events.append((clock,_read_span(tx,L+0xDE810,8).hex(),_read_span(tx,L+0xDE820,8).hex()))
                return (0,seconds,nanoseconds)
            session=ActualAllocatorSession.__new__(ActualAllocatorSession)
            session.libc_base=L;session._read_clock_provider=provider
            status,sec,nsec=session.read_clock(model,clock_id)
            _write_span(model,OUT,sec.to_bytes(8,'little',signed=True)+nsec.to_bytes(8,'little',signed=True))
            expected_events=list(events);events.clear()
            def syscall(cpu,number):
                assert number==113
                clock=cpu.reg_read(arm.UC_ARM64_REG_X0);out=cpu.reg_read(arm.UC_ARM64_REG_X1)
                events.append((clock,bytes(cpu.mem_read(L+0xDE810,8)).hex(),bytes(cpu.mem_read(L+0xDE820,8)).hex()))
                assert out==OUT
                cpu.mem_write(out,seconds.to_bytes(8,'little',signed=True)+nanoseconds.to_bytes(8,'little',signed=True))
                return 0
            observed={(L+0xDE000,4096):None,(L+0xD9000,4096):None,(OUT,32):None}
            result,memory,allocations,ledger=oracle.native(library,image,L+0x1D854-image,[clock_id,OUT],p,
                libc=libc,syscall_handler=syscall,observed_memory=observed,instruction_limit=5000,
                extra_registers={arm.UC_ARM64_REG_SP:SP})
            assert result==status==0 and not allocations and not ledger
            assert observed[L+0xDE000,4096]==_read_span(model,L+0xDE000,4096), 'matching clock guard/cache missing from session'
            assert all(raw==_read_span(model,a,n) for (a,n),raw in observed.items())
            assert memory==oracle.flatten(model)[:0xA000]
            assert events==expected_events and original=={k:bytes(v) for k,v in p.items()}
            cases.append(dict(image_base=hex(image),case=name,clock_id=clock_id,native_return_equal=True,
                full_cache_and_source_pages_equal=True,timespec_and_padding_equal=True,provider_observed_ready_cache=True,
                independent_input_unchanged=True))
    from vm9_libc_clock import prepare_bionic_clock_cache
    guards=[]
    fresh=oracle.image_pages(libc,L)
    def rejected(label,edit=lambda p:None,base=L,provider=provider):
        p={k:bytearray(v) for k,v in fresh.items()};edit(p)
        before={k:bytes(v) for k,v in p.items()};calls=[]
        session=ActualAllocatorSession.__new__(ActualAllocatorSession)
        session.libc_base=base
        session._read_clock_provider=(lambda *args:calls.append(args) or (0,0,0)) if provider else provider
        try:session.read_clock(p,0)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('clock cache accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()} and not calls
        guards.append(label)
    def setword(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))
    rejected('unaligned_base',base=L+1)
    rejected('boolean_base',base=True)
    rejected('overflowing_base',base=1<<64)
    for value in (0x100,0x200,2):
        rejected('guard_wait_'+hex(value),lambda p,value=value:setword(p,L+0xDE810,value))
    for value in (0,L+0x6A868):
        rejected('cold_target_'+hex(value),lambda p,value=value:setword(p,L+0xD9048,value))
        def warm(p,value=value):setword(p,L+0xDE810,1);setword(p,L+0xDE820,value)
        rejected('warm_target_'+hex(value),warm)
    rejected('cold_source_unmapped',lambda p:p.pop((L+0xD9000)>>12))
    rejected('guard_unmapped',lambda p:p.pop((L+0xDE000)>>12))
    rejected('missing_provider',provider=None)
    rejected('noncallable_provider',provider=False)
    # The fast path does not access the source table at all.
    warm={k:bytearray(v) for k,v in fresh.items()}
    setword(warm,L+0xDE810,1);setword(warm,L+0xDE820,L+0x6A864)
    warm.pop((L+0xD9000)>>12);before={k:bytes(v) for k,v in warm.items()}
    assert prepare_bionic_clock_cache(warm,libc_base=L)==L+0x6A864
    assert before=={k:bytes(v) for k,v in warm.items()}
    return dict(native_Python_controls=len(cases),cases=cases,refusal_guards=len(guards),guards=guards,
        rollback_guards=0,warm_source_page_not_read=True,historical_native_groups_replayed=False,
        complete_physical_ABI_verified=False,external_provider_effect_rollback_verified=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path);args=parser.parse_args();result=verify(args.library,args.libc)
    if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
if __name__=='__main__':main()
