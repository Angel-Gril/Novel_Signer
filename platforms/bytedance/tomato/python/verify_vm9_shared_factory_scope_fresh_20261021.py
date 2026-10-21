"""Original default shared factory and getter with a scoped final reference.

Fresh ELF/TLS/guest inputs; synthetic allocation/property/filesystem services.
Matching libc mutex instructions execute. JNI factory remains unsupported.
"""
from pathlib import Path
import argparse,hashlib,inspect,json,os
from unicorn import arm64_const as arm
import verify_vm9_state_service_fresh_20261012 as service
import verify_vm9_signer_objects as oracle
import vm9_configuration_init as configuration
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
import vm9_libc_stdio as mutex
import vm9_objects as objects
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=service.BASES;SP=service.SP;TP=service.root.TLS;OUT=oracle.GUEST+0x1800
HIGH_SP=0x760010EF00
PROFILES=('cold_constants','warm_constants','empty_payload','one_byte','text19')
LAYOUT=((0x3DEDC0,0xA55A0,0x3DEDB8,0xA5648),(0x3DEDF8,0xA55B0,0x3DEDD0,0xA5620),(0x3DEE18,0xA55E0,0x3DEE00,0xA5600))


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))


def fixture(library,libc,image,profile,warm):
    p,sdk=service.fresh(library,libc,image,'cold')
    for a in range((SP-0x5000)&~4095,(SP+0x1000)&~4095,4096):p.setdefault(a>>12,bytearray([0xA7])*4096)
    _write_span(p,SP-0x800,bytes([0xA7])*0x800);w(p,TP+0x28,0x123456789ABCDEF0)
    if profile!='cold_constants':
        for row in LAYOUT:configuration._lazy_constant(p,image,*row)
        if profile not in ('cold_constants','warm_constants'):
            length={'empty_payload':0,'one_byte':1,'text19':19}[profile]
            _write_span(p,image+0x3DEE00,b'x'*length+b'\0')
    if warm:
        lock,table,entries=0x73000800,0x73001000,0x73002000
        for a in range(0x73000000,0x73006000,4096):p[a>>12]=bytearray(4096)
        w(p,image+diagnostics.GUARD,0x101);w(p,image+diagnostics.GLOBAL_LOCK,lock);w(p,lock,image+0x34C738)
        w(p,image+diagnostics.TABLE,table)
        for i in range(256):
            entry=entries+i*48;w(p,table+i*8,entry);w(p,entry,image+0x34C738)
            mutex.initialize_recursive_mutex(p,mutex_address=entry+8)
    return p,sdk


class Services(service.Services):
    def __init__(self,image):super().__init__(image);self.diagnostic_events=[];self.reference_events=[]
    def diagnostic(self,*event):self.diagnostic_events.append(list(event));self.reference_events.append(list(event))


def execute(p,image,s,kind,*,scoped=True,**options):
    def constructor(tx,**kw):return references.construct_scoped_string_reference(tx,**kw,
        image_base=image,thread_pointer=TP,allocate=s.allocate,thread_id=137,diagnostic_observer=s.diagnostic)
    def copier(tx,**kw):return references.copy_scoped_string_reference(tx,**kw,
        image_base=image,thread_pointer=TP,allocate=s.allocate,thread_id=137,diagnostic_observer=s.diagnostic)
    kw=dict(entry_stack_address=SP,image_base=image,allocate=s.allocate,free=s.free,
        read_property=lambda *a:None,syscall=s.syscall,errno_address=TP+0x100)
    if scoped:kw['reference_constructor']=constructor
    if kind=='getter':kw.update(output_reference_address=OUT,reference_copier=copier,thread_id=137,register_destructor=s.register)
    kw.update(options)
    owner=configuration.construct_default_shared_reference if kind=='factory' else configuration.get_inline_shared_reference
    return owner(p,**kw)


def original(library,libc,image,p,sdk,kind,observe):
    function={'factory':0x26CDC4,'getter':0x26CD0C,'state':0x26A3AC}[kind]
    source=inspect.getsource(service.native)
    old='real_mutexes=True,thread_id=137';assert old in source
    source=source.replace(old,'real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,thread_id=137')
    old='base,0x26A3AC,[]';assert old in source;source=source.replace(old,'base,function,[]')
    source=source.replace('real_singletons=True,','real_singletons=True,map_extra_input_pages=True,')
    if kind=='getter':source=source.replace('extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:root.TLS}',
        'extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:root.TLS,arm.UC_ARM64_REG_X8:OUT}')
    source=source.replace('extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:root.TLS',
        'extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:root.TLS')
    old='        if not cpus:cpus.append(c)';assert old in source;source=source.replace(old,'        observe(c,a)\n'+old)
    source=source.replace('    observed[root.TLS,0xB00]=None',
        '    observed[root.TLS,0xB00]=None\n    for k in p:\n        if 0x73000000<=k<<12<0x73006000:observed[k<<12,4096]=None')
    namespace={**vars(service),'function':function,'observe':observe,'OUT':OUT,'SP':SP}
    exec(compile(source,'original-shared-factory-scope','exec'),namespace)
    return namespace['native'](library,libc,image,p,sdk)


def compare(library,libc,image,kind,profile,warm,*,red=False):
    p,sdk=fixture(library,libc,image,profile,warm);expected_scopes=[];entries=[];expected_events=[];active=[]
    diagnostic_returns=[];expected_reference_events=[]
    factory_sp=SP-(0x40 if kind=='getter' else 0);scope=factory_sp-0xC0
    def observe(c,a):
        off=a-image
        if diagnostic_returns and a==diagnostic_returns[-1]:diagnostic_returns.pop()
        if off in (0x26C858,0x26C9D0):diagnostic_returns.append(c.reg_read(arm.UC_ARM64_REG_X30))
        if off==0x1625A4 and c.reg_read(arm.UC_ARM64_REG_X30)==image+0x26CF50:
            entries.append(c.reg_read(arm.UC_ARM64_REG_SP));active.append(True)
        if active and off==0x26C9D0 and c.reg_read(arm.UC_ARM64_REG_X0)==scope:
            expected_scopes.append(bytes(c.mem_read(scope,24)));active.clear()
        event=None
        if off in (0x347F00,0x347F10):event=['pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0)]
        if off==0x348310:event=['gettid',137]
        if event is not None:
            expected_events.append(event)
            if diagnostic_returns:expected_reference_events.append(event)
    _,memory,allocations,frees,registrations,wakes,clocks,observed=original(library,libc,image,p,sdk,kind,observe)
    actual=Services(image);scopes=[];leave=diagnostics.leave_diagnostic_scope
    lock,unlock=objects.lock_uncontended_mutex,objects.unlock_uncontended_mutex
    # Diagnostic observers cover reference locks. Record the logger's actual
    # owning mutex operations too: native sees both sets at the app PLT.
    def logger_lock(tx,**kw):
        if kw['mutex_address']==image+0x3DF1EC:actual.diagnostic_events.append(['pthread_mutex_lock',kw['mutex_address']])
        return lock(tx,**kw)
    def logger_unlock(tx,**kw):
        if kw['mutex_address']==image+0x3DF1EC:actual.diagnostic_events.append(['pthread_mutex_unlock',kw['mutex_address']])
        return unlock(tx,**kw)
    def record(tx,**kw):
        if kw['object_address']==scope:scopes.append(_read_span(tx,scope,24))
        return leave(tx,**kw)
    try:
        diagnostics.leave_diagnostic_scope=record
        objects.lock_uncontended_mutex=logger_lock;objects.unlock_uncontended_mutex=logger_unlock
        execute(p,image,actual,kind,scoped=not red)
    finally:
        diagnostics.leave_diagnostic_scope=leave
        objects.lock_uncontended_mutex=lock;objects.unlock_uncontended_mutex=unlock
    assert entries==[factory_sp-0x70] and len(expected_scopes)==len(scopes)==1,('missing shared factory scope',kind,entries,scopes)
    assert scopes==expected_scopes,('full shared factory scope',kind,profile,scopes,expected_scopes)
    assert actual.allocator.calls==allocations and actual.frees==frees,('allocation/free',kind,profile,actual.allocator.calls,allocations)
    assert actual.reference_events==expected_reference_events,('reference diagnostic events',kind,profile,actual.reference_events,expected_reference_events)
    # Serial getter guard flag effects are modeled without its PLT observer.
    # Retain both COMPLETE traces and the inequality; do not call them equal.
    if kind=='factory':assert actual.diagnostic_events==expected_events,('complete factory mutex trace',profile)
    assert actual.registrations==registrations and actual.wakes==wakes
    own=_read_span(p,oracle.GUEST,0xA000)
    assert own==memory,('guest payload',kind,profile,[(hex(i),x,y) for i,(x,y) in enumerate(zip(own,memory)) if x!=y][:20])
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),('image/TLS/table',kind,profile)
    print('PASS shared factory scope',hex(image),kind,profile,warm,flush=True)
    return dict(image_base=hex(image),kind=kind,case=profile,warm_diagnostics=warm,original_helper_returned=True,
        entry_stack_address=hex(SP),
        constructor_entry_offset_from_factory=-0x70,full24byte_live_scope_equal=True,
        all_guest_payload_image_TLS_and_table_pages_equal=True,ordered_allocation_free_registration_wake_and_reference_diagnostics_equal=True,
        complete_context_mutex_trace_equal=actual.diagnostic_events==expected_events,
        native_context_mutex_and_gettid_events=expected_events,model_context_mutex_and_gettid_events=actual.diagnostic_events,
        native_snapshot_input=False,physical_spills_compared=False)


def guards(library,libc):
    rows=[];image=BASES[0]
    for label in ('scope_writes_then_raises','unmapped_scope','unaligned_scope','counter_NULL',
            'noncallable_factory','noncallable_getter','state_provider_raises'):
        kind='getter' if label=='noncallable_getter' else 'factory'
        p,_=fixture(library,libc,image,PROFILES[0],True);actual=Services(image)
        def provider(tx,**kw):
            if label in ('scope_writes_then_raises','state_provider_raises'):
                _write_span(tx,kw['reference_address'],bytes(16));raise RefillUnsupported('shared factory constructor failed')
            if label=='unmapped_scope':kw['entry_stack_address']=0x66001000
            if label=='unaligned_scope':kw['entry_stack_address']-=1
            return references.construct_scoped_string_reference(tx,**kw,image_base=image,thread_pointer=TP,
                allocate=(lambda *args:0) if label=='counter_NULL' else actual.allocate,thread_id=137)
        before={k:bytes(v) for k,v in p.items()}
        if label=='state_provider_raises':
            original_constructor=references.construct_scoped_string_reference
            def state_constructor(tx,**kw):
                if kw['reference_address']==image+0x3DEE28:
                    _write_span(tx,kw['reference_address'],bytes(16));raise RefillUnsupported('state shared constructor failed')
                return original_constructor(tx,**kw)
            try:
                references.construct_scoped_string_reference=state_constructor
                try:actual.execute(p,diagnostic_scope={})
                except (RefillUnsupported,ValueError):pass
                else:raise AssertionError('state constructor failure accepted')
            finally:references.construct_scoped_string_reference=original_constructor
        else:
            kw=dict(reference_constructor=1 if label.startswith('noncallable_') else provider)
            try:execute(p,image,actual,kind,**kw)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('constructor failure accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows


def main():
    global SP
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve())
    if a.red:compare(a.library,a.libc,BASES[0],'factory',PROFILES[0],False,red=True);raise AssertionError('missing scope unexpectedly matched')
    cases=[compare(a.library,a.libc,image,kind,profile,warm) for image in BASES for kind in ('factory','getter') for profile in PROFILES for warm in (False,True)]
    saved=SP
    try:
        SP=HIGH_SP
        cases += [compare(a.library,a.libc,image,kind,PROFILES[0],False) for image in BASES for kind in ('factory','getter')]
    finally:SP=saved
    negative=guards(a.library,a.libc)
    report=dict(schema='vm9-shared-factory-scope-fresh/v1',native_Python_controls=len(cases),cases=cases,
        new_refusal_or_page_rollback_guards=len(negative),negative_cases=negative,
        native_snapshot_input=False,historical_native_groups_replayed=False,complete_state_request_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native shared factory scope controls and',len(negative),'rollback guards')


if __name__=='__main__':main()
