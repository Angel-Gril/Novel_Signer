"""Original state-service final reference constructor and public composition.

Direct25728C controls compare full payload/image/scope and allocator/lock effects.
Original26A3AC controls compare complete guest payload/image/TLS, return and
allocation/free effects plus the final constructor's full live scope. Other
state scopes and physical spills have their separate evidence boundaries.
"""
from pathlib import Path
import argparse,hashlib,inspect,json,os
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_state_service_fresh_20261012 as service
from verify_vm9_jni_byte_array_fresh_20261011 import fresh,w,TP,SP
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
import vm9_libc_stdio as mutex
BASES=service.BASES;OUT=oracle.GUEST+0x1000;OBJ=oracle.GUEST+0x1800
EXTRA=0x73000000


def factory_input(library,libc,image,label):
    # Supply the same fully initialized diagnostic table to both executions.
    # Cold-table environment scopes are a known separate recovery boundary;
    # their pending allocation differences stay in the whole-request probe.
    p,sdk=service.fresh(library,libc,image,label)
    for a in range(EXTRA,EXTRA+0x6000,4096):p[a>>12]=bytearray(4096)
    lock,table,entries=EXTRA+0x800,EXTRA+0x1000,EXTRA+0x2000
    w(p,image+diagnostics.GUARD,0x101);w(p,image+diagnostics.GLOBAL_LOCK,lock)
    w(p,lock,image+0x34C738);w(p,image+diagnostics.TABLE,table)
    for i in range(256):
        entry=entries+i*48;w(p,table+i*8,entry);w(p,entry,image+0x34C738)
        mutex.initialize_recursive_mutex(p,mutex_address=entry+8)
    return p,sdk


def direct(library,libc,image,warm,null,dirty):
    pointer=0 if null else OBJ;p=fresh(library,image,warm=warm,referenced=pointer)
    if dirty:_write_span(p,SP-0x50,bytes([0xA7])*24)
    observed={(k<<12,4096):None for k in p if image<=k<<12<image+0x400000};observed[SP-0x50,24]=None
    expected=Services();actual=Services()
    def see(c,a):
        off=a-image
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x25728C,[OUT,pointer],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP},thread_id=137,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_observer=see,instruction_limit=100000)
    references.construct_scoped_string_reference(p,reference_address=OUT,string_address=pointer,
        entry_stack_address=SP,image_base=image,thread_pointer=TP,thread_id=137,
        allocate=actual.malloc,diagnostic_observer=actual.diagnostic)
    assert _read_span(p,oracle.GUEST,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    print('PASS final reference direct',hex(image),warm,null,dirty,flush=True)
    return dict(image_base=hex(image),kind='direct25728C',warm_locks=warm,NULL_object=null,dirty_padding=dirty,
        original_returned=True,all_guest_image_and_full24_scope_equal=True,ordered_allocation_locks_equal=True,native_snapshot_input=False)


def factory(library,libc,image,label):
    p,sdk=factory_input(library,libc,image,label);expected_scopes=[];target_entries=[]
    final_scope=service.SP-0xB0
    def observe(c,a):
        if a-image==0x25728C:target_entries.append(c.reg_read(arm.UC_ARM64_REG_SP))
        if target_entries and a-image==0x26C9D0 and c.reg_read(arm.UC_ARM64_REG_X0)==final_scope:
            expected_scopes.append(bytes(c.mem_read(final_scope,24)))
    source=inspect.getsource(service.native).replace('real_mutexes=True,thread_id=137','real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,thread_id=137')
    source=source.replace('        if not cpus:cpus.append(c)','        observe(c,a)\n        if not cpus:cpus.append(c)')
    source=source.replace('real_singletons=True,','real_singletons=True,map_extra_input_pages=True,')
    source=source.replace('    observed[root.TLS,0xB00]=None',
        '    observed[root.TLS,0xB00]=None\n    for k in p:\n        if 0x73000000<=k<<12<0x73006000:observed[k<<12,4096]=None')
    namespace={**vars(service),'observe':observe};exec(compile(source,'native-state-final-reference','exec'),namespace)
    returned,memory,allocations,frees,registrations,wakes,clocks,observed=namespace['native'](library,libc,image,p,sdk)
    actual=service.Services(image);context={};scopes=[];leave=diagnostics.leave_diagnostic_scope
    def record(tx,**kw):
        if kw['object_address']==final_scope:scopes.append(_read_span(tx,final_scope,24))
        return leave(tx,**kw)
    try:
        diagnostics.leave_diagnostic_scope=record
        result=actual.execute(p,diagnostic_scope=context)
    finally:diagnostics.leave_diagnostic_scope=leave
    assert len(target_entries)==len(scopes)==len(expected_scopes)==1 and target_entries==[service.SP-0x60],('final constructor missing',label,target_entries,scopes)
    assert scopes==expected_scopes,('final constructor full24byte scope',label,scopes,expected_scopes)
    assert result.wrapper_address==returned and _read_span(p,oracle.GUEST,0xA000)==memory,('state payload',label)
    assert actual.allocator.calls==allocations and actual.frees==frees,('state allocation/free effects',label)
    assert actual.registrations==registrations and actual.wakes==wakes
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),('state image/TLS',label)
    print('PASS final reference factory',hex(image),label,flush=True)
    return dict(image_base=hex(image),kind='factory26A3AC',case=label,original_returned=True,
        final_constructor_entry_stack_offset=-0x60,final_live24byte_scope_equal=True,
        complete_guest_image_TLS_return_and_allocation_free_effects_equal=True,
        diagnostic_table_all_buckets_warm=True,all_diagnostic_table_pages_equal=True,
        other_state_scope_bytes_compared=False,physical_spills_compared=False,native_snapshot_input=False)


def guards(library,libc):
    rows=[];image=BASES[0]
    for label in ('scope_writes_then_raises','unmapped_scope','counter_NULL','unaligned_stack'):
        p,_=factory_input(library,libc,image,'cold');actual=service.Services(image)
        before={k:bytes(v) for k,v in p.items()};saved=references.construct_scoped_string_reference
        def provider(tx,**kw):
            if kw['entry_stack_address']==SP-0x60:
                if label=='scope_writes_then_raises':
                    _write_span(tx,kw['reference_address'],bytes(16));raise RefillUnsupported('final constructor failure')
                if label=='unmapped_scope':kw['entry_stack_address']=0x66001000
                elif label=='unaligned_stack':kw['entry_stack_address']=SP-0x61
                else:kw['allocate']=lambda *a:0
            return saved(tx,**kw)
        try:
            references.construct_scoped_string_reference=provider
            try:actual.execute(p,diagnostic_scope={})
            except (RefillUnsupported,ValueError,TypeError):pass
            else:raise AssertionError('final constructor failure accepted '+label)
        finally:references.construct_scoped_string_reference=saved
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve())
    if a.red:
        factory(a.library,a.libc,BASES[0],'cold');raise AssertionError('missing final scope unexpectedly matched')
    cases=[direct(a.library,a.libc,image,warm,null,dirty) for image in BASES for warm in (False,True) for null in (False,True) for dirty in (False,True)]
    cases += [factory(a.library,a.libc,image,label) for image in BASES for label in ('cold','decoded_key')]
    negative=guards(a.library,a.libc)
    report=dict(schema='vm9-state-final-reference-scope-fresh/v1',native_Python_controls=len(cases),
        new_refusal_or_page_rollback_guards=len(negative),cases=cases,negative_cases=negative,
        native_snapshot_input=False,historical_native_groups_replayed=False,complete_state_memory_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native final-reference controls and',len(negative),'rollback guards')


if __name__=='__main__':main()
