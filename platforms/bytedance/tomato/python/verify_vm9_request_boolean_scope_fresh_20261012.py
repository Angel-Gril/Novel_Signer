"""Actual elapsed scope, atomic counter and warm logger lifecycle controls.

Original ELF, matching-libc strings/mutexes and explicit clock/allocator inputs.
Compare final guest/image pages and service order; native output never seeds
Python. Host concurrency, physical spills and the complete signer are separate.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_request_mode_format_fresh_20261007 as f
import verify_vm9_request_event_emission_fresh_20261007 as e
import vm9_request_leaf_prefixes as leaf
import vm9_objects as objects
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=e.GUEST;SCOPE=G+0x9400;START=G+0x9500;SP=e.STACK;NOW=(1791023800,123456789)
BASES=(0x122C0000,0x775C205000);MASK64=(1<<64)-1


def fresh(library,base,profile):
    p=e.fresh(library,base);capacity=profile.get('capacity',0);count=profile.get('count',0)
    old=G+0x1800 if capacity else 0
    seed=f.Effects(blocks={old:capacity*96} if capacity else {})
    if capacity>=200:seed.next=G+0x7000
    if capacity:_write_span(p,old,bytes(capacity*96))
    _write_span(p,e.LOGGER,bytes(64));e.w(p,base+0x3E1B08,e.LOGGER)
    for offset,value in ((40,old),(48,old+count*96),(56,old+capacity*96)):e.w(p,e.LOGGER+offset,value)
    e.w(p,SCOPE,START);_write_span(p,SCOPE+8,bytes([profile.get('flag',1)]))
    e.w(p,START,profile.get('start',NOW[0]*1000000000+100000000)&MASK64)
    e.w(p,base+0x3E1620,profile.get('counter',0));e.w(p,base+0x3839E8,profile.get('divisor',10))
    if profile.get('warm_names'):
        for n,flag,s,m in ((0x3E1A10,0x3E1A30,0x11F140,0x11F260),(0x3E1A40,0x3E1A60,0x11F160,0x11F240)):
            objects.decode_masked_bytes(p,source_address=base+s,destination_address=base+n,mask_address=base+m)
            _write_span(p,base+flag,(7).to_bytes(4,'little'))
    return p,seed


def compare(library,libc,base,label,profile,entries):
    p,seed=fresh(library,base,profile);expected=e.duplicate(seed);actual=e.duplicate(seed)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    native_clocks=[];model_clocks=[]
    def clock(c):
        assert c.reg_read(arm.UC_ARM64_REG_X0)==1;sec,ns=profile.get('now',NOW)
        native_clocks.append([1,0,sec,ns])
        c.mem_write(c.reg_read(arm.UC_ARM64_REG_X1),sec.to_bytes(8,'little',signed=True)+ns.to_bytes(8,'little'))
        if 'clock_counter' in profile:c.mem_write(base+0x3E1620,profile['clock_counter'].to_bytes(8,'little'))
        return 0
    def read_clock(p,identifier):
        sec,ns=profile.get('now',NOW);model_clocks.append([identifier,0,sec,ns])
        if 'clock_counter' in profile:e.w(p,base+0x3E1620,profile['clock_counter'])
        return 0,sec,ns
    imports=f.services(entries,expected);imports[0x348450]=clock
    direct=profile.get('direct',False)
    args=[profile.get('elapsed_word',23),profile.get('counter',0),profile.get('mode',1)] if direct else [SCOPE]
    _,memory,_,ledger=e.native(library,base,0x28E204 if direct else 0x28C09C,args,p,libc=libc,
        real_mutexes=True,host_imports=imports,malloc_handler=lambda c,n:expected.native(c,'malloc',n),
        observed_memory=observed,instruction_limit=700000)
    if direct:
        emitted=leaf.execute_elapsed_event(p,image_base=base,entry_stack_address=SP,
            elapsed_word=args[0],sequence_word=args[1],mode=args[2],allocate=actual.malloc,free=actual.free)
    else:
        emitted=leaf.leave_boolean_scope(p,image_base=base,entry_stack_address=SP,scope_address=SCOPE,
            read_clock=read_clock,allocate=actual.malloc,free=actual.free)
    assert expected.calls==actual.calls and expected.blocks==actual.blocks,('effects',label)
    assert _read_span(p,G,0xA000)==memory,('payload',label)
    assert all(_read_span(p,a,n)==v for (a,n),v in observed.items()),('ELF',label)
    assert native_clocks==model_clocks,('clocks',label)
    assert len(ledger)==2*emitted
    print('PASS scope',hex(base),label,'emissions',emitted,flush=True)
    return dict(image_base=hex(base),case=label,native_entry_offset='0x28e204' if direct else '0x28c09c',
        original_returned=True,full_guest_payload_and_ELF_pages_match=True,payload_padding_mask_used=False,
        counter_wrap_and_sampling_match=True,clock_and_allocator_cleanup_order_match=True,
        warm_logger_records_and_mutex_state_match=True,emission_calls=emitted,
        logical_scope_and_final_heap_match=True,native_snapshot_input=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','entry','all'),default='all')
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==e.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==e.LIBC_SHA256
    entries=f.imports(args.library,args.libc)
    profiles=[('sampled',{}),('disabled',dict(flag=0)),('nonzero_flag',dict(flag=2)),
        ('zero_elapsed',dict(start=NOW[0]*1000000000+NOW[1])),
        ('negative_elapsed_uint64',dict(start=NOW[0]*1000000000+200000000)),
        ('positive_submicrosecond',dict(start=NOW[0]*1000000000+NOW[1]-999)),
        ('negative_submicrosecond',dict(start=NOW[0]*1000000000+NOW[1]+999)),
        ('unsampled',dict(counter=1)),('sampled_tenth',dict(counter=10)),
        ('wrap_counter',dict(counter=MASK64)),('sampled_max_words',dict(counter=MASK64,divisor=1,start=1<<63)),
        ('zero_divisor_selected',dict(divisor=0)),('zero_divisor_skipped',dict(divisor=0,counter=1)),
        ('counter_load_after_clock',dict(clock_counter=20)),('warm_names',dict(warm_names=True)),
        ('spare_capacity',dict(capacity=2)),('existing_record_growth',dict(capacity=1,count=1)),
        ('existing_spare_capacity',dict(capacity=2,count=1)),('record199',dict(capacity=200,count=199)),
        ('drop_record200',dict(capacity=200,count=200)),('two_event_names',dict(direct=True,mode=1)),
        ('signed_mode',dict(direct=True,mode=0xFFFFFFFF)),('unsampled_two_names',dict(direct=True,counter=1))]
    cases=[];guards=[];request=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label,profile in profiles:cases.append(compare(args.library,args.libc,base,label,profile,entries))
    if args.group in ('guards','all'):
        for base in BASES:
            for label in ('missing_clock','missing_allocator','missing_free','clock_error','NULL_start',
                          'cold_logger','contended_logger','alternate_publication','unaligned_stack',
                          'unsupported_format','allocation0','allocation1','allocation5'):
                p,seed=fresh(args.library,base,{});effects=e.duplicate(seed)
                kw=dict(image_base=base,entry_stack_address=SP,scope_address=SCOPE,
                    read_clock=lambda *a:(0,*NOW),allocate=effects.malloc,free=effects.free)
                if label=='missing_clock':kw['read_clock']=None
                elif label=='missing_allocator':kw['allocate']=None
                elif label=='missing_free':kw['free']=None
                elif label=='clock_error':kw['read_clock']=lambda *a:(1,*NOW)
                elif label=='NULL_start':e.w(p,SCOPE,0)
                elif label=='cold_logger':e.w(p,base+0x3E1B08,0)
                elif label=='contended_logger':_write_span(p,e.LOGGER,b'\1\0')
                elif label=='alternate_publication':_write_span(p,base+0x3E1B20,b'\1')
                elif label=='unaligned_stack':kw['entry_stack_address']=SP+1
                elif label=='unsupported_format':_write_span(p,base+0x6E9C7,b'{2}\0')
                else:effects.failures={int(label[len('allocation'):])}
                before=e.snapshot(p)
                try:leaf.leave_boolean_scope(p,**kw)
                except (RefillUnsupported,ValueError) as exc:
                    if isinstance(exc,ValueError):
                        assert label=='NULL_start' and str(exc)=='missing checkpoint page 0x0'
                else:raise AssertionError('guard completed '+label)
                assert e.snapshot(p)==before,label
                guards.append(dict(image_base=hex(base),case=label,rejected=True,
                    all_pages_unchanged=True,external_effects_rolled_back=False))
                print('PASS scope rollback',hex(base),label,flush=True)
    if args.group in ('entry','all'):
        from verify_vm9_request_stack_evaluator_fresh_20261012 import request_entry
        request,entry_guards=request_entry(args.library,args.libc);guards.extend(entry_guards)
    args.output.write_text(json.dumps(dict(cases=cases,negative_cases=guards,request_entry_cases=request,
        native_Python_controls=len(cases),rollback_guards=len(guards),native_input_snapshot_used=False,
        controlled_warm_logger=True,physical_register_spills_verified=False,concurrent_atomicity_verified=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
    print('PASS',len(cases),'native controls,',len(guards),'guards,',len(request),'request entry checks')


if __name__=='__main__':main()
