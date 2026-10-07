"""Actual .init_array +0x271940 cache mutex constructor versus Python.

Allocator and __cxa_atexit registration are explicit services. Matching-libc
mutex init runs; this does not execute all ELF constructors or full JNI_OnLoad.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn import arm64_const as arm
import vm9_jni_environment as environment
from vm9_allocator import RefillUnsupported,_read_span,_write_span
from verify_vm9_signer_objects import GUEST,LIBRARY_SHA256,fresh_pages,image_pages,native
from verify_vm9_strings import Effects
from verify_vm9_jni_initialization_fresh_20261007 import LIBC_SHA256


def u(p,a):return int.from_bytes(_read_span(p,a,8),'little')
def w(p,a,v):_write_span(p,a,v.to_bytes(8,'little'))


def fixture(lib,base,profile):
    p=fresh_pages();p.update(image_pages(lib,base))
    _write_span(p,base+0x3DF118,b'\xA5'*48)
    if profile.get('warm'):
        w(p,base+0x3DF0A8,GUEST+0x3000)
        w(p,base+0x3DF0C0,0x515151);w(p,base+0x3DF0C8,0x616161)
    return p


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    cases=[];negatives=[]
    for base in (0x122C0000,0x775C205000):
        for label,profile in [('cold',{}),('warm_cache',dict(warm=True)),('registration_nonzero',dict(status=7)),
                ('alternate_allocation',dict(alternate=True))]:
            p=fixture(a.library,base,profile);expected,actual=Effects(blocks={}),Effects(blocks={})
            if profile.get('alternate'):expected.next=actual.next=GUEST+0x5000
            events=[];model_events=[];entries=[]
            def register_native(cpu):
                args=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
                assert args==[base+0x165388,base+0x3DF118,base+0x34C700]
                events.append([*args,profile.get('status',0)]);return profile.get('status',0)
            def register_model(p,fn,obj,dso):
                model_events.append([fn,obj,dso,profile.get('status',0)]);return profile.get('status',0)
            def observe(cpu,address):
                if address-base in (0x271940,0x32A1F0,0x15DEA8,0x347EE0):entries.append(hex(address-base))
            observed={(k<<12,4096):None for k in p if base<=k<<12<base+0x400000}
            result,memory,alloc,ledger=native(a.library,base,0x271940,[],p,libc=a.libc,
                real_mutexes=True,host_imports={0x347EA0:register_native},instruction_observer=observe,
                malloc_handler=lambda cpu,n:expected.native(cpu,'malloc',n),observed_memory=observed)
            model=environment.initialize_java_cache_mutexes(p,image_base=base,
                allocate=actual.malloc,register_exit=register_model)
            assert result==model.registration_status==profile.get('status',0)
            assert memory==_read_span(p,GUEST,0xA000) and not alloc and not ledger
            assert expected.calls==actual.calls==[['malloc',48,0]] and events==model_events
            assert all(data==_read_span(p,address,n) for (address,n),data in observed.items())
            assert u(p,base+0x3DF0A8)==model.allocated_mutex_object
            assert model.inline_mutex_object==base+0x3DF118
            cases.append(dict(label=label,image_base=hex(base),native_entries=entries,
                allocator_effects=expected.calls,exit_registration=events,registration_status=result,
                guest_payload_match=True,all_main_image_pages_match=True,cache_pointer_published=True,
                preexisting_class_method_cache_preserved=True,native_input_snapshot_used=False,
                actual_all_ELF_init_array_executed=False,actual_destructor_executed=False,
                full_JNI_OnLoad_recovered=False))
    base=0x122C0000
    def reject(label,change=lambda p:None,**kwargs):
        p=fixture(a.library,base,{});change(p);before={k:bytes(v) for k,v in p.items()}
        effects=Effects(blocks={});options=dict(image_base=base,allocate=effects.malloc,register_exit=lambda *args:0)
        options.update(kwargs)
        try:environment.initialize_java_cache_mutexes(p,**options)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('accepted negative '+label)
        assert before=={k:bytes(v) for k,v in p.items()};negatives.append(dict(label=label,pages_unchanged=True))
    reject('missing_allocator',allocate=None)
    reject('allocation_NULL',allocate=lambda *args:0)
    reject('unmapped_allocation',allocate=lambda *args:GUEST+0x100000)
    reject('missing_exit_service',register_exit=None)
    reject('exit_status_overflow',register_exit=lambda *args:1<<64)
    reject('late_exit_refusal',register_exit=lambda *args:(_ for _ in ()).throw(RefillUnsupported('explicit registration refuses')))
    evidence=dict(schema='vm9-jni-cache-mutex-fresh-differential-v1',evidence_date='2026-10-07',sample_sha256=LIBRARY_SHA256,
        matching_libc_sha256=LIBC_SHA256,constructor_controls=len(cases),negative_controls=len(negatives),
        constructor_cases=cases,negative_checks=negatives,native_input_snapshot_used=False,
        explicit_allocator_and_exit_registration_services_used=True,matching_libc_mutex_init_body_executed=True,
        cache_mutex_constructor_recovered=True,all_ELF_constructors_recovered=False,actual_destructor_executed=False,
        full_JNI_OnLoad_recovered=False,actual_android_jvm_executed=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('JNI cache mutex constructor:',len(cases),'native/Python;',len(negatives),'negative passed')

if __name__=='__main__':main()
