"""Original environment-service getter with explicit reference diagnostics.

Fresh ELF/libc and synthetic allocation services. Real libc mutex instructions
execute. Complete C++ guard event traces are retained, including differences.
"""
from pathlib import Path
import argparse,hashlib,inspect,json,os
from unicorn import arm64_const as arm
import verify_vm9_shared_factory_scope_fresh_20261021 as shared
import verify_vm9_signer_objects as oracle
import vm9_configuration_init as configuration
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
import verify_vm9_environment_release_scope_fresh_20261021 as environment
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=shared.BASES;SP=shared.SP;TP=shared.TP
PROFILES=('dirty_A7','dirty_3C','warm_service','warm_NULL_slot','guard_byte0_2','guard_byte1_1')


def fixture(library,libc,image,profile,warm):
    p,sdk=shared.fixture(library,libc,image,'cold_constants',warm)
    for a in range((SP-0x5000)&~4095,(SP+0x1000)&~4095,4096):p.setdefault(a>>12,bytearray(4096))
    _write_span(p,SP-0x800,bytes([0x3C if profile=='dirty_3C' else 0xA7])*0x800)
    if profile=='warm_service':
        configuration.get_environment_service_reference(p,image_base=image,allocate=shared.Services(image).allocate,thread_id=137)
    elif profile in ('warm_NULL_slot','guard_byte0_2','guard_byte1_1'):
        _write_span(p,image+0x3D18D8,{'warm_NULL_slot':b'\x01\x01','guard_byte0_2':b'\x02\x00','guard_byte1_1':b'\x00\x01'}[profile])
    return p,sdk


def original(library,libc,image,p,sdk,observe):
    source=inspect.getsource(shared.original).replace("'state':0x26A3AC","'state':0x26A3AC,'service':0x172D40")
    namespace={**vars(shared),'SP':SP}
    exec(compile(source,'original-environment-service-scope','exec'),namespace)
    return namespace['original'](library,libc,image,p,sdk,'service',observe)


def execute(p,image,s,*,scoped=True,**options):
    def constructor(tx,**kw):return references.construct_scoped_string_reference(tx,**kw,
        image_base=image,thread_pointer=TP,allocate=s.allocate,thread_id=137,diagnostic_observer=s.diagnostic)
    kw=dict(image_base=image,allocate=s.allocate,thread_id=137)
    if scoped:kw.update(entry_stack_address=SP,reference_constructor=constructor)
    kw.update(options)
    return configuration.get_environment_service_reference(p,**kw)


def compare(library,libc,image,profile,warm,*,red=False):
    p,sdk=fixture(library,libc,image,profile,warm);expected_scopes=[];entries=[];expected_events=[];expected_reference_events=[];returns=[]
    scope=SP-0x70
    def observe(c,a):
        off=a-image
        if returns and a==returns[-1]:returns.pop()
        if off in (0x26C858,0x26C9D0):returns.append(c.reg_read(arm.UC_ARM64_REG_X30))
        if off==0x172EB0:entries.append(c.reg_read(arm.UC_ARM64_REG_SP))
        if off==0x26C9D0 and c.reg_read(arm.UC_ARM64_REG_X0)==scope:expected_scopes.append(bytes(c.mem_read(scope,24)))
        event=None
        if off in (0x347F00,0x347F10):event=['pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0)]
        if off==0x348310:event=['gettid',137]
        if event is not None:
            expected_events.append(event)
            if returns:expected_reference_events.append(event)
    returned,memory,allocations,frees,registrations,wakes,clocks,observed=original(library,libc,image,p,sdk,observe)
    actual=shared.Services(image);scopes=[];leave=diagnostics.leave_diagnostic_scope
    def record(tx,**kw):
        if kw['object_address']==scope:scopes.append(_read_span(tx,scope,24))
        return leave(tx,**kw)
    try:
        diagnostics.leave_diagnostic_scope=record;result=execute(p,image,actual,scoped=not red)
    finally:diagnostics.leave_diagnostic_scope=leave
    cold=profile.startswith('dirty_')
    assert entries==([SP-0x20] if cold else []),('native constructor entry',entries)
    assert scopes==expected_scopes and len(scopes)==int(cold),('missing or different environment-service scope',scopes,expected_scopes)
    assert result.wrapper_address==returned,('return',result.wrapper_address,returned)
    assert actual.allocator.calls==allocations and actual.frees==frees,('allocation/free',actual.allocator.calls,allocations)
    assert actual.reference_events==expected_reference_events,('reference diagnostic events',actual.reference_events,expected_reference_events)
    assert actual.registrations==registrations and actual.wakes==wakes
    assert _read_span(p,oracle.GUEST,0xA000)==memory,('guest payload',profile)
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),('image/TLS/table',profile)
    print('PASS environment service scope',hex(image),profile,warm,hex(SP),flush=True)
    return dict(image_base=hex(image),case=profile,warm_diagnostics=warm,entry_stack_address=hex(SP),
        original_helper_returned=True,constructor_entry_offset_from_getter=-0x20,full24byte_live_scope_equal=True,
        return_guest_payload_image_TLS_and_table_equal=True,ordered_allocation_free_registration_wake_and_reference_diagnostics_equal=True,
        complete_context_mutex_trace_equal=actual.diagnostic_events==expected_events,
        native_context_mutex_and_gettid_events=expected_events,model_context_mutex_and_gettid_events=actual.diagnostic_events,
        native_snapshot_input=False,physical_spills_compared=False)


def guards(library,libc):
    rows=[];image=BASES[0]
    for label in ('provider_writes_then_raises','unmapped_scope','unaligned_stack','missing_stack','counter_NULL','noncallable_constructor'):
        p,_=fixture(library,libc,image,PROFILES[0],False);s=shared.Services(image)
        def constructor(tx,**kw):
            if label=='provider_writes_then_raises':
                _write_span(tx,kw['reference_address'],bytes(16));raise RefillUnsupported('environment-service constructor failed')
            return references.construct_scoped_string_reference(tx,**kw,image_base=image,thread_pointer=TP,
                allocate=(lambda *a:0) if label=='counter_NULL' else s.allocate,thread_id=137)
        options=dict(reference_constructor=0 if label=='noncallable_constructor' else constructor)
        if label=='unmapped_scope':options['entry_stack_address']=0x66001000
        if label=='unaligned_stack':options['entry_stack_address']=SP-1
        if label=='missing_stack':options['entry_stack_address']=None
        before={k:bytes(v) for k,v in p.items()}
        try:execute(p,image,s,**options)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows


def compare_environment(library,libc,image,profile,warm):
    p,sdk=environment.fixture(library,libc,image,profile,warm)
    _write_span(p,image+0x3D18D0,bytes(16));scope=environment.SP-0xD0
    expected=[];entries=[];events=[];reference_events=[];returns=[]
    def observe(c,a):
        off=a-image
        if returns and a==returns[-1]:returns.pop()
        if off in (0x26C858,0x26C9D0):returns.append(c.reg_read(arm.UC_ARM64_REG_X30))
        if off==0x172EB0:entries.append(c.reg_read(arm.UC_ARM64_REG_SP))
        if off==0x26C9D0 and c.reg_read(arm.UC_ARM64_REG_X0)==scope:expected.append(bytes(c.mem_read(scope,24)))
        event=None
        if off in (0x347F00,0x347F10):event=['pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0)]
        if off==0x348310:event=['gettid',137]
        if event is not None:
            events.append(event)
            if returns:reference_events.append(event)
    _,memory,allocations,frees,registrations,wakes,clocks,observed=environment.original(library,libc,image,p,sdk,observe)
    s=environment.Services(image,profile);scopes=[];leave=diagnostics.leave_diagnostic_scope
    def record(tx,**kw):
        if kw['object_address']==scope:scopes.append(_read_span(tx,scope,24))
        return leave(tx,**kw)
    def constructor(tx,**kw):return references.construct_scoped_string_reference(tx,**kw,
        image_base=image,thread_pointer=TP,allocate=s.allocate,thread_id=137,diagnostic_observer=s.diagnostic)
    try:
        diagnostics.leave_diagnostic_scope=record;environment.execute(p,image,s,reference_constructor=constructor)
    finally:diagnostics.leave_diagnostic_scope=leave
    assert entries==[environment.SP-0x80] and len(expected)==len(scopes)==1
    assert scopes==expected,('environment parent constructor padding',scopes,expected)
    assert s.effects.calls==allocations and s.frees==frees and s.registrations==registrations and s.wakes==wakes
    assert s.diagnostic_events==reference_events,('environment reference diagnostic events',s.diagnostic_events,reference_events)
    assert _read_span(p,oracle.GUEST,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items())
    print('PASS environment parent service scope',hex(image),profile[0],warm,flush=True)
    return dict(image_base=hex(image),case=profile[0],warm_diagnostics=warm,kind='environment_parent',
        original_helper_returned=True,full24byte_live_scope_equal=True,return_guest_payload_image_TLS_and_table_equal=True,
        ordered_allocation_free_registration_wake_and_reference_diagnostics_equal=True,
        complete_context_mutex_trace_equal=s.diagnostic_events==events,
        native_context_mutex_and_gettid_events=events,model_context_mutex_and_gettid_events=s.diagnostic_events,
        native_snapshot_input=False,physical_spills_compared=False)


def main():
    global SP
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==shared.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve())
    if a.red:compare(a.library,a.libc,BASES[0],PROFILES[0],False,red=True);raise AssertionError('missing scope unexpectedly matched')
    cases=[compare(a.library,a.libc,image,profile,warm) for image in BASES for profile in PROFILES for warm in (False,True)]
    saved=SP
    try:
        SP=shared.HIGH_SP
        cases += [compare(a.library,a.libc,image,profile,False) for image in BASES for profile in PROFILES[:2]]
    finally:SP=saved
    cases += [compare_environment(a.library,a.libc,image,profile,warm) for image in BASES for profile in environment.PROFILES[1:3] for warm in (False,True)]
    negative=guards(a.library,a.libc)
    report=dict(schema='vm9-environment-service-scope-fresh/v1',native_Python_controls=len(cases),cases=cases,
        new_refusal_or_page_rollback_guards=len(negative),negative_cases=negative,
        native_snapshot_input=False,historical_native_groups_replayed=False,complete_state_request_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native environment-service controls and',len(negative),'rollback guards',flush=True)


if __name__=='__main__':main()
