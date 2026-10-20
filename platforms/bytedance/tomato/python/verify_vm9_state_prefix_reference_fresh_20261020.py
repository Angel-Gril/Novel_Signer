"""Fresh original state prefix with its actual scoped string reference.

Matching libc locks execute naturally; allocation is an explicit service.
Native output is compared only. The state VM body and physical spills are
outside these component controls.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import vm9_objects as objects
import vm9_reference_scopes as references
import verify_vm9_signer_objects as oracle
from verify_vm9_jni_byte_array_fresh_20261011 import fresh,TP,SP,w
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_worker_allocator import LIBC_SHA256
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=(0x122C0000,0x775C205000)
OWNER=oracle.GUEST+0x1000;SOURCE=oracle.GUEST+0x1800;DATA=oracle.GUEST+0x2000
PROFILES=(('empty',0,0,False,()),('one',1,1,False,()),('text',32,255,False,()),
    ('long',165,256,False,()),('warm',7,1,True,()),('warm_empty',0,0,True,()),
    ('warm_long',165,255,True,()),('payload_NULL',7,1,False,(1,)))


def fixture(library,image,length,warm):
    p=fresh(library,image,warm=warm,referenced=oracle.GUEST+0x4000)
    w(p,SOURCE,image+0x34F5F8);w(p,SOURCE+8,length+1,4);w(p,SOURCE+12,length,4);w(p,SOURCE+16,DATA)
    _write_span(p,DATA,bytes(i%251+1 for i in range(length))+b'\0')
    return p


def provider(image,services):
    def construct(p,*,reference_address,string_address):
        return references.construct_scoped_string_reference(p,
            reference_address=reference_address,string_address=string_address,
            entry_stack_address=SP-0x40,image_base=image,thread_pointer=TP,
            allocate=services.malloc,thread_id=137,diagnostic_observer=services.diagnostic)
    return construct


def compare(library,libc,image,profile,*,red=False):
    label,length,flag,warm,failures=profile;p=fixture(library,image,length,warm)
    initial={k:bytearray(v) for k,v in p.items()};actual=Services(failures=failures);expected=Services(failures=failures)
    observed={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    observed[SP-0x90,24]=None
    def see(cpu,address):
        off=address-image
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:expected.diagnostic('gettid',137)
    returned,memory,_,_=oracle.native(library,image,0x2698F0,[OWNER,SOURCE,flag],initial,
        libc=libc,stop_offset=0x269988,real_singletons=True,real_mutexes=True,
        real_recursive_mutexes=True,real_diagnostics=True,thread_id=137,
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:TP,arm.UC_ARM64_REG_SP:SP},
        malloc_handler=expected.native_malloc,instruction_observer=see,
        observed_memory=observed,instruction_limit=100000)
    options={} if red else dict(reference_constructor=provider(image,actual))
    result=objects.construct_mutex_backed_string_owner_prefix(p,object_address=OWNER,
        source_object_address=SOURCE,flag=flag,image_base=image,allocate=actual.malloc,**options)
    assert actual.events==expected.events,(label,'scoped reference allocation/lock order')
    assert result.object_address==returned and _read_span(p,oracle.GUEST,0xA000)==memory,(label,'payload')
    assert all(_read_span(p,a,n)==raw for (a,n),raw in observed.items()),(label,'image/scope')
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert _read_span(p,OWNER+0x29,7)==b'\xA5'*7
    return dict(image_base=hex(image),case=label,original_state_prefix_returned=True,
        real_scoped_reference_constructor_used=True,all_guest_payload_and_library_pages_equal=True,
        scope_bytes_equal=True,allocation_and_lock_effects_equal=True,owner_padding_preserved=True,
        native_snapshot_input=False)


def guards(library):
    image=BASES[0];rows=[]
    for label in ('invalid_provider','provider_raises','provider_writes_then_raises',
            'unmapped_owner','unmapped_source','length_bound','object_NULL','counter_NULL'):
        p=fixture(library,image,7,False);actual=Services(failures=(0,) if label=='object_NULL' else ())
        construct=provider(image,actual)
        if label=='invalid_provider':construct=42
        elif label in ('provider_raises','provider_writes_then_raises'):
            def construct(tx,**kw):
                if label=='provider_writes_then_raises':_write_span(tx,kw['reference_address'],bytes(16))
                raise RefillUnsupported('explicit reference provider failure')
        elif label=='counter_NULL':
            def construct(tx,**kw):
                return references.construct_scoped_string_reference(tx,**kw,entry_stack_address=SP-0x40,
                    image_base=image,thread_pointer=TP,
                    allocate=lambda pages,size:0 if size==4 else actual.malloc(pages,size),thread_id=137)
        before={k:bytes(v) for k,v in p.items()}
        try:
            objects.construct_mutex_backed_string_owner_prefix(p,
                object_address=0x64000000 if label=='unmapped_owner' else OWNER,
                source_object_address=0x64000000 if label=='unmapped_source' else SOURCE,
                flag=1,image_base=image,allocate=actual.malloc,
                max_payload_bytes=1 if label=='length_bound' else 0x100000,
                reference_constructor=construct)
        except (RefillUnsupported,ValueError):pass
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
        compare(a.library,a.libc,BASES[0],PROFILES[0],red=True)
        raise AssertionError('prior bare reference unexpectedly matched real diagnostic prefix')
    cases=[compare(a.library,a.libc,image,profile) for image in BASES for profile in PROFILES]
    negative=guards(a.library)
    report=dict(schema='vm9-state-prefix-reference-fresh/v1',native_Python_controls=len(cases),
        new_refusal_or_page_rollback_guards=len(negative),cases=cases,negative_cases=negative,
        allocation_provider_is_synthetic=True,native_snapshot_input=False,
        historical_native_groups_replayed=False,full_state_request_or_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS',len(cases),'native prefixes and',len(negative),'rollback controls')


if __name__=='__main__':main()
