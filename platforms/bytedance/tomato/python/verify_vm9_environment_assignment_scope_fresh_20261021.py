"""Original environment prefix through its owned-reference assignment.

Native stops at +0x25ef1c. Python is observed at its first environment service
getter, before later formatting/filesystem/cleanup. No prefix pages are
published and no native output initializes the model. Physical spills and
the later reference release are outside this prefix contract.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_configuration_init as configuration
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_byte_array_fresh_20261011 import fresh,TP,SP,w
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000)
OUT=oracle.GUEST+0x1000;OBJ=oracle.GUEST+0x1800;COUNT=oracle.GUEST+0x1C00;DATA=oracle.GUEST+0x2000
PROFILES=(('empty',0,2),('one',1,2),('text',33,2),('long',165,2),
    ('count_zero',7,0),('count_wrap',7,0xFFFFFFFF),('high_output',7,2))


class PrefixObserved(BaseException):pass


def fixture(library,image,profile,warm):
    _,length,count=profile;p=fresh(library,image,warm=warm,referenced=OBJ)
    ref=image+0x3DEE28;w(p,ref-8,0x101);w(p,ref,OBJ);w(p,ref+8,COUNT);w(p,COUNT,count,4)
    w(p,OBJ,image+0x34F5F8);w(p,OBJ+8,length+1,4);w(p,OBJ+12,length,4);w(p,OBJ+16,DATA)
    _write_span(p,DATA,bytes(i%251+1 for i in range(length))+b'\0')
    return p


def copier(image,services):
    return lambda p,**kw:references.copy_scoped_string_reference(p,**kw,
        image_base=image,thread_pointer=TP,allocate=services.malloc,
        thread_id=137,diagnostic_observer=services.diagnostic)


def assigner(image,services):
    return lambda p,**kw:references.assign_scoped_owned_string_reference(p,**kw,
        image_base=image,thread_pointer=TP,allocate=services.malloc,free=services.free,
        thread_id=137,diagnostic_observer=services.diagnostic)


def execute(p,image,services,*,output=OUT,**options):
    return configuration.construct_environment_reference(p,output_reference_address=output,
        entry_stack_address=SP,image_base=image,allocate=services.malloc,
        reallocate=services.effects.realloc,free=services.free,read_property=lambda *a:None,
        syscall=lambda *a:-2,errno_address=TP+0x900,mkdir=lambda *a:-1,thread_id=137,
        reference_copier=copier(image,services),**options)


def observe_prefix(p,image,services,**options):
    saved=configuration.get_environment_service_reference;captured=[]
    def observe(tx,**kw):
        captured.append({k:bytearray(tx[k]) for k in tx});raise PrefixObserved()
    try:
        configuration.get_environment_service_reference=observe
        try:execute(p,image,services,**options)
        except PrefixObserved:pass
        else:raise AssertionError('environment prefix was not reached')
    finally:configuration.get_environment_service_reference=saved
    assert len(captured)==1
    return captured[0]


def check(library,libc,image,profile,warm,*,red=False):
    p=fixture(library,image,profile,warm);initial={k:bytearray(v) for k,v in p.items()}
    output=image+0x3DFF00 if profile[0]=='high_output' else OUT
    actual=Services();expected=Services()
    observed={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    observed[SP-0xB0,24]=None
    def see(cpu,address):
        off=address-image
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x25EE84,[],initial,libc=libc,stop_offset=0x25EF1C,
        real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        real_diagnostics=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_X8:output},
        malloc_handler=expected.native_malloc,instruction_observer=see,
        observed_memory=observed,instruction_limit=100000)
    options={} if red else dict(reference_assigner=assigner(image,actual))
    prefix=observe_prefix(p,image,actual,output=output,**options)
    assert actual.events==expected.events,(profile[0],'environment owned-reference allocation/lock order')
    assert _read_span(prefix,oracle.GUEST,0xA000)==memory,(profile[0],'payload')
    for (address,size),raw in observed.items():
        own=_read_span(prefix,address,size)
        assert own==raw,(profile[0],'image/scope',hex(address),[i for i,(x,y) in enumerate(zip(own,raw)) if x!=y])
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert p==initial,'prefix observation must not publish pages'
    return dict(image_base=hex(image),case=profile[0],warm_diagnostics=warm,
        original_environment_prefix_reached_25EF1C=True,all_guest_payload_and_library_pages_equal=True,
        scope_bytes_equal=True,allocation_and_lock_effects_equal=True,Python_prefix_pages_unpublished=True,
        native_snapshot_input=False,full_environment_cleanup_verified=False)


def guards(library):
    image=BASES[0];rows=[]
    for label in ('invalid_provider','provider_raises','provider_writes_then_raises',
            'unmapped_output','unaligned_assignment_stack','unmapped_assignment_scope','diagnostic_guard_wait','counter_NULL'):
        p=fixture(library,image,PROFILES[0],False);actual=Services();provider=assigner(image,actual)
        if label=='invalid_provider':provider=42
        elif label in ('provider_raises','provider_writes_then_raises'):
            def provider(tx,**kw):
                if label=='provider_writes_then_raises':_write_span(tx,kw['reference_address'],bytes(16))
                raise RefillUnsupported('explicit assignment provider failure')
        elif label in ('unaligned_assignment_stack','unmapped_assignment_scope'):
            original=provider
            def provider(tx,**kw):return original(tx,**dict(kw,entry_stack_address=SP-1 if label=='unaligned_assignment_stack' else 0x64001000))
        elif label=='unmapped_output':p.pop(OUT>>12)
        elif label=='diagnostic_guard_wait':w(p,image+diagnostics.GUARD+1,2,1)
        else:
            def provider(tx,**kw):return references.assign_scoped_owned_string_reference(tx,**kw,
                image_base=image,thread_pointer=TP,allocate=lambda tx,n:0 if n==4 else actual.malloc(tx,n),
                free=actual.free,thread_id=137)
        before={k:bytes(v) for k,v in p.items()}
        try:execute(p,image,actual,reference_assigner=provider)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('negative accepted: '+label)
        assert before=={k:bytes(v) for k,v in p.items()},label+' page rollback'
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--red',action='store_true');a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    if a.red:
        check(a.library,a.libc,BASES[0],PROFILES[0],False,red=True)
        raise AssertionError('bare assignment unexpectedly matched actual diagnostic scope')
    cases=[check(a.library,a.libc,image,profile,warm) for image in BASES for warm in (False,True) for profile in PROFILES]
    negative=guards(a.library)
    report=dict(schema='vm9-environment-assignment-scope-fresh/v1',native_Python_controls=len(cases),
        new_refusal_or_page_rollback_guards=len(negative),cases=cases,negative_cases=negative,
        allocation_provider_is_synthetic=True,native_snapshot_input=False,
        historical_native_groups_replayed=False,full_state_request_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native environment prefixes and',len(negative),'rollback controls')


if __name__=='__main__':main()
