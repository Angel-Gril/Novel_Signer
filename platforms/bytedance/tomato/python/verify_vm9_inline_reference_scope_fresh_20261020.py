"""Original inline getter with real diagnostic reference-copy scopes.

Shared initialization is warm; diagnostic locks are independently cold/warm.
Native output is compared only. Physical spills and cold shared factory
diagnostic composition are outside these bounded controls.
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
OUT=oracle.GUEST+0x1000;OBJ=oracle.GUEST+0x1800;COUNT=oracle.GUEST+0x1C00
PROFILES=(('ordinary',2,None,False),('count_NULL',None,None,False),
    ('count_zero',0,None,False),('count_max',0xFFFFFFFF,None,False),
    ('object_NULL',2,None,True),('self_alias',2,0,False),
    ('destination_before',2,-8,False),('destination_after',2,8,False),
    ('signed_count',0x80000000,None,False))


def fixture(library,image,profile,warm):
    _,count,delta,null=profile
    pointer=0 if null else OBJ
    p=fresh(library,image,warm=warm,referenced=0 if delta in (-8,0) else pointer)
    ref=image+0x3DEE28
    w(p,ref-8,0x101);w(p,ref,pointer);w(p,ref+8,0 if count is None else COUNT)
    if count is not None:w(p,COUNT,count,4)
    return p,OUT if delta is None else ref+delta


def provider(image,services):
    def copy(p,*,destination_address,source_address,entry_stack_address):
        return references.copy_scoped_string_reference(p,destination_address=destination_address,
            source_address=source_address,entry_stack_address=entry_stack_address,
            image_base=image,thread_pointer=TP,allocate=services.malloc,
            thread_id=137,diagnostic_observer=services.diagnostic)
    return copy


def execute(p,image,output,services,**options):
    return configuration.get_inline_shared_reference(p,output_reference_address=output,
        entry_stack_address=SP,image_base=image,allocate=services.malloc,free=services.free,
        read_property=lambda *a:None,syscall=lambda *a:-2,errno_address=TP+0x900,
        thread_id=137,**options)


def check(library,libc,image,profile,warm,*,red=False):
    p,output=fixture(library,image,profile,warm);initial={k:bytearray(v) for k,v in p.items()}
    actual=Services();expected=Services()
    observed={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    observed[SP-0x90,24]=None
    def see(cpu,address):
        off=address-image
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    _,memory,_,_=oracle.native(library,image,0x26CD0C,[],initial,libc=libc,
        real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        real_diagnostics=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_X8:output},
        malloc_handler=expected.native_malloc,instruction_observer=see,
        observed_memory=observed,instruction_limit=100000)
    options={} if red else dict(reference_copier=provider(image,actual))
    result=execute(p,image,output,actual,**options)
    assert actual.events==expected.events,(profile[0],'scoped getter allocation/lock order')
    assert result==output and _read_span(p,oracle.GUEST,0xA000)==memory,(profile[0],'payload')
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),(profile[0],'image/scope')
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    return dict(image_base=hex(image),case=profile[0],warm_diagnostics=warm,
        original_getter_returned=True,all_guest_payload_and_library_pages_equal=True,
        scope_bytes_equal=True,allocation_and_lock_effects_equal=True,native_snapshot_input=False)


def guards(library):
    image=BASES[0];rows=[]
    for label in ('invalid_provider','provider_raises','provider_writes_then_raises',
            'unmapped_output','unaligned_stack','unmapped_scope','diagnostic_guard_wait','allocation_NULL'):
        p,output=fixture(library,image,PROFILES[0],False);actual=Services(failures=(0,) if label=='allocation_NULL' else ())
        copier=provider(image,actual)
        if label=='invalid_provider':copier=42
        elif label in ('provider_raises','provider_writes_then_raises'):
            def copier(tx,**kw):
                if label=='provider_writes_then_raises':_write_span(tx,kw['destination_address'],bytes(16))
                raise RefillUnsupported('explicit copy provider failure')
        elif label in ('unaligned_stack','unmapped_scope'):
            original=copier
            def copier(tx,**kw):return original(tx,**dict(kw,entry_stack_address=SP-1 if label=='unaligned_stack' else 0x64001000))
        elif label=='diagnostic_guard_wait':w(p,image+diagnostics.GUARD+1,2,1)
        before={k:bytes(v) for k,v in p.items()}
        try:execute(p,image,0x64000000 if label=='unmapped_output' else output,actual,reference_copier=copier)
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
        raise AssertionError('bare reference unexpectedly matched real diagnostic getter')
    cases=[check(a.library,a.libc,image,profile,warm) for image in BASES for warm in (False,True) for profile in PROFILES]
    negative=guards(a.library)
    report=dict(schema='vm9-inline-reference-scope-fresh/v1',native_Python_controls=len(cases),
        new_refusal_or_page_rollback_guards=len(negative),cases=cases,negative_cases=negative,
        allocation_provider_is_synthetic=True,native_snapshot_input=False,
        historical_native_groups_replayed=False,full_state_request_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native getters and',len(negative),'rollback controls')


if __name__=='__main__':main()
