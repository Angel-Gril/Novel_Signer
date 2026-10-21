"""Original environment25EE84 with its final15E1A8 diagnostic release.

The inline reference and environment-service singleton are explicit warm input.
Their independent cold constructor scope gaps are outside this helper fixture.
Actual matching libc locks, formatting and filesystem instructions execute;
host allocation and unavailable environment services are synthetic inputs.
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
from verify_vm9_strings import Effects
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported
BASES=service.BASES;SP=service.SP;TP=service.root.TLS
CARRY_BASE=0x7FFFD00000
OUT=oracle.GUEST+0x1800;OBJ=oracle.GUEST+0x3400;COUNT=oracle.GUEST+0x3480;DATA=oracle.GUEST+0x3500
PROFILES=(('NULL_shared',0,None),('empty',0,2),('text',19,2),('long',165,2),('zero_count',7,0),('wrap_count',7,0xFFFFFFFF),
    ('exists_empty',0,2),('exists_text',19,2),('exists_long',165,2))


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def fixture(library,libc,image,profile,warm):
    p,sdk=service.fresh(library,libc,image,'cold');label,length,count=profile
    ref=image+0x3DEE28;w(p,ref-8,0x101);w(p,ref,0 if count is None else OBJ);w(p,ref+8,0 if count is None else COUNT)
    if count is not None:w(p,COUNT,count,4)
    w(p,OBJ,image+0x34F5F8);w(p,OBJ+8,length+1,4);w(p,OBJ+12,length,4);w(p,OBJ+16,DATA)
    _write_span(p,DATA,b'x'*length+b'\0')
    w(p,image+0x3D18D8,0x101);w(p,image+0x3D18D0,oracle.GUEST+0x3800);w(p,oracle.GUEST+0x3800,oracle.GUEST+0x3900)
    _write_span(p,SP-0x500,bytes([0xA7])*0x500);w(p,TP+0x28,0x123456789ABCDEF0)
    if warm:
        lock,table,entries=0x73000800,0x73001000,0x73002000
        for a in range(0x73000000,0x73006000,4096):p[a>>12]=bytearray(4096)
        w(p,image+diagnostics.GUARD,0x101);w(p,image+diagnostics.GLOBAL_LOCK,lock);w(p,lock,image+0x34C738)
        w(p,image+diagnostics.TABLE,table)
        for i in range(256):
            entry=entries+i*48;w(p,table+i*8,entry);w(p,entry,image+0x34C738)
            mutex.initialize_recursive_mutex(p,mutex_address=entry+8)
    return p,sdk


def execute(p,image,s,*,scoped_release=True,**options):
    def copier(tx,**kw):return references.copy_scoped_string_reference(tx,**kw,image_base=image,
        thread_pointer=TP,allocate=s.allocate,thread_id=137,diagnostic_observer=s.diagnostic)
    def assigner(tx,**kw):return references.assign_scoped_owned_string_reference(tx,**kw,image_base=image,
        thread_pointer=TP,allocate=s.allocate,free=s.free,thread_id=137,diagnostic_observer=s.diagnostic)
    def releaser(tx,**kw):return references.release_scoped_string_reference(tx,**kw,image_base=image,
        thread_pointer=TP,allocate=s.allocate,free=s.free,thread_id=137,diagnostic_observer=s.diagnostic)
    kw=dict(output_reference_address=OUT,entry_stack_address=SP,image_base=image,
        allocate=s.allocate,reallocate=s.reallocate,free=s.free,read_property=lambda *a:None,
        syscall=s.syscall,errno_address=TP+0x100,mkdir=s.mkdir,thread_id=137,
        register_destructor=s.register,prepare_format=s.prepare,reference_copier=copier,reference_assigner=assigner)
    if scoped_release:kw.update(reference_releaser=releaser,thread_pointer=TP)
    kw.update(options);return configuration.construct_environment_reference(p,**kw)


class Services(service.Services):
    def __init__(self,image,profile):
        super().__init__(image);self.diagnostic_events=[];self.path_exists=profile[0].startswith('exists_')
        self.effects=Effects(blocks=((OBJ,24),(COUNT,4),(DATA,profile[1]+1)))
    def allocate(self,p,n):return self.effects.malloc(p,n)
    def reallocate(self,p,a,n):return self.effects.realloc(p,a,n)
    def free(self,p,a):self.frees.append(a);return self.effects.free(p,a)
    def syscall(self,p,n,args):
        if self.path_exists and n==48:return 0
        return super().syscall(p,n,args)
    def diagnostic(self,*event):self.diagnostic_events.append(list(event))


def original(library,libc,image,p,sdk,observe,*,path_exists=False):
    source=inspect.getsource(service.native)
    effects=Effects(blocks=((OBJ,24),(COUNT,4),(DATA,int.from_bytes(_read_span(p,OBJ+8,4),'little'))))
    source=source.replace('        if n in (48,56,79):return -2',
        '        if path_exists and n==48:return 0\n        if n in (48,56,79):return -2')
    old='    def free(c):frees.append(c.reg_read(arm.UC_ARM64_REG_X0));return 0'
    assert old in source
    source=source.replace(old,'    def free(c):\n        a=c.reg_read(arm.UC_ARM64_REG_X0);frees.append(a)\n        return effects.native(c,"free",pointer=a)')
    old='    for offset,name in ('
    assert source.count(old)==1
    source=source.replace(old,'    imports[0x348320]=lambda c:effects.native(c,"realloc",c.reg_read(arm.UC_ARM64_REG_X1),c.reg_read(arm.UC_ARM64_REG_X0))\n'+old)
    source=source.replace('host_imports=imports,','malloc_handler=lambda c,n:effects.native(c,"malloc",n),host_imports=imports,')
    source=source.replace('return result,memory,allocations,frees,','return result,memory,effects.calls,frees,')
    source=source.replace('real_mutexes=True,thread_id=137','real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,thread_id=137')
    source=source.replace("base,0x26A3AC,[]","base,0x25EE84,[]")
    source=source.replace('real_singletons=True,','real_singletons=True,map_extra_input_pages=True,')
    source=source.replace('extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:root.TLS}',
        'extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:root.TLS,arm.UC_ARM64_REG_X8:OUT}')
    source=source.replace('        if not cpus:cpus.append(c)','        observe(c,a)\n        if not cpus:cpus.append(c)')
    source=source.replace('    observed[root.TLS,0xB00]=None',
        '    observed[root.TLS,0xB00]=None\n    for k in p:\n        if 0x73000000<=k<<12<0x73006000:observed[k<<12,4096]=None')
    namespace={**vars(service),'observe':observe,'OUT':OUT,'effects':effects,'path_exists':path_exists}
    exec(compile(source,'original-environment-scoped-release','exec'),namespace)
    return namespace['native'](library,libc,image,p,sdk)


def compare(library,libc,image,profile,warm,*,red=False):
    p,sdk=fixture(library,libc,image,profile,warm);expected_scopes=[];entries=[];expected_events=[]
    def observe(c,a):
        off=a-image
        if off==0x15E1A8 and c.reg_read(arm.UC_ARM64_REG_X30)==image+0x25EF84:entries.append(c.reg_read(arm.UC_ARM64_REG_SP))
        if entries and off==0x26C9D0 and c.reg_read(arm.UC_ARM64_REG_X0)==SP-0xA0:
            expected_scopes.append(bytes(c.mem_read(SP-0xA0,24)))
        if off in (0x347F00,0x347F10):expected_events.append(['pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',c.reg_read(arm.UC_ARM64_REG_X0)])
        if off==0x348310:expected_events.append(['gettid',137])
    _,memory,allocations,frees,registrations,wakes,clocks,observed=original(library,libc,image,p,sdk,observe,path_exists=profile[0].startswith('exists_'))
    actual=Services(image,profile);leave=diagnostics.leave_diagnostic_scope;scopes=[]
    def record(tx,**kw):
        if kw['object_address']==SP-0xA0:scopes.append(_read_span(tx,SP-0xA0,24))
        return leave(tx,**kw)
    try:
        diagnostics.leave_diagnostic_scope=record
        execute(p,image,actual,scoped_release=not red)
    finally:diagnostics.leave_diagnostic_scope=leave
    assert entries==[SP-0x60] and len(expected_scopes)==len(scopes)==1,('missing environment release scope',profile[0],entries,scopes)
    assert scopes==expected_scopes,('full release scope',profile[0],scopes,expected_scopes)
    assert actual.diagnostic_events==expected_events,('diagnostic events',profile[0],actual.diagnostic_events,expected_events)
    assert actual.effects.calls==allocations and actual.frees==frees,('allocator effects',profile[0],actual.effects.calls,allocations)
    assert actual.registrations==registrations and actual.wakes==wakes
    own=_read_span(p,oracle.GUEST,0xA000)
    assert own==memory,('guest payload',profile[0],[(hex(i),x,y) for i,(x,y) in enumerate(zip(own,memory)) if x!=y][:20])
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),('image/TLS',profile[0])
    print('PASS environment release',hex(image),profile[0],warm,flush=True)
    return dict(image_base=hex(image),case=profile[0],warm_diagnostics=warm,original_helper_returned=True,
        release_entry_stack_offset=-0x60,full24byte_release_scope_equal=True,
        all_guest_image_TLS_and_warm_table_pages_equal=True,allocation_free_registration_wake_and_diagnostic_events_equal=True,
        native_snapshot_input=False,other_cold_reference_scopes_verified=False,physical_spills_compared=False)


def guards(library,libc):
    rows=[];image=BASES[0]
    for label in ('scope_writes_then_raises','unmapped_scope','unaligned_scope','noncallable_provider',
            'missing_TP','unmapped_canary','free_provider_raises'):
        profile=PROFILES[4] if label=='free_provider_raises' else PROFILES[0]
        p,_=fixture(library,libc,image,profile,False);actual=Services(image,profile);kw={}
        def release(tx,**args):
            if label=='scope_writes_then_raises':
                _write_span(tx,args['reference_address'],bytes(16));raise RefillUnsupported('release failure')
            if label=='unmapped_scope':args['entry_stack_address']=0x66001000
            if label=='unaligned_scope':args['entry_stack_address']-=1
            return references.release_scoped_string_reference(tx,**args,image_base=image,
                thread_pointer=TP,allocate=actual.allocate,free=actual.free,thread_id=137)
        kw['reference_releaser']=release
        if label=='noncallable_provider':kw['reference_releaser']=1
        if label=='missing_TP':kw['thread_pointer']=None
        if label=='unmapped_canary':kw['thread_pointer']=0x66001000
        if label=='free_provider_raises':
            original_free=actual.free
            def free(tx,a):original_free(tx,a);raise RefillUnsupported('free failed after page writes')
            actual.free=free
        before={k:bytes(v) for k,v in p.items()}
        try:execute(p,image,actual,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('release failure accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(a.library.resolve())
    if a.red:compare(a.library,a.libc,BASES[0],PROFILES[0],False,red=True);raise AssertionError('missing release unexpectedly matched')
    cases=[compare(a.library,a.libc,image,profile,warm) for image in BASES for profile in PROFILES for warm in (False,True)]
    cases += [compare(a.library,a.libc,CARRY_BASE,profile,False) for profile in (PROFILES[2],PROFILES[7])]
    negative=guards(a.library,a.libc)
    report=dict(schema='vm9-environment-release-scope-fresh/v1',native_Python_controls=len(cases),cases=cases,
        new_refusal_or_page_rollback_guards=len(negative),negative_cases=negative,
        native_snapshot_input=False,historical_native_groups_replayed=False,complete_state_request_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native environment release controls')


if __name__=='__main__':main()
