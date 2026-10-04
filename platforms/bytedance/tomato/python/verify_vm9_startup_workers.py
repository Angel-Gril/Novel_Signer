"""Fresh native worker TLS/support prefixes, with explicit dispatch boundaries.

Fixtures construct logical ownership inputs independently for both models.
No native entry snapshots, host threads or actual worker dispatch are used.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_TPIDR_EL0
import vm9_startup as startup
import vm9_allocator as allocator
import verify_vm9_startup_init as main_fixture
import verify_vm9_root_configuration as fixture
from verify_vm9_signer_objects import native, GUEST, LIBRARY_SHA256


def inputs(library, libc, base, warm):
    p=main_fixture.fresh_inputs(library,libc,base)
    w=allocator._write_span
    w(p,GUEST+0x3000,(GUEST+0x3040).to_bytes(8,'little'))
    w(p,GUEST+0x3040,bytes(48))
    w(p,GUEST+0x3100,bytes(64))
    w(p,GUEST+0x3100,(GUEST+0x3000).to_bytes(8,'little'))
    w(p,GUEST+0x3108,(GUEST+0x3600).to_bytes(8,'little'))
    w(p,GUEST+0x3110,(base+0x372600).to_bytes(8,'little'))
    w(p,GUEST+0x3118,(GUEST+0x3800).to_bytes(8,'little'))
    w(p,GUEST+0x3130,(GUEST+0x3110).to_bytes(8,'little'))
    w(p,GUEST+0x3600,bytes(256))
    w(p,GUEST+0x3608,(GUEST+0x3618).to_bytes(8,'little'))
    table=fixture.LIBC_BASE+fixture.LIBC_PTHREAD_GENERATION_OFFSET
    w(p,table,bytes(141*16))
    # Two occupied keys make cold initialization skip indices 0 and 1.
    for index in (0,1):w(p,table+index*16,(1).to_bytes(8,'little'))
    if warm:
        w(p,base+0x3E2F30,(0x80000009).to_bytes(4,'little'))
        w(p,base+0x3E2F38,b'\1\1')
        w(p,table+9*16,(3).to_bytes(8,'little')+(base+0x32CE6C).to_bytes(8,'little'))
    return p


def probe(library,libc,*,base,kind,warm,thread_id):
    model=inputs(library,libc,base,warm)
    native_seed=inputs(library,libc,base,warm)
    oracle={p:v for p,v in native_seed.items()
        if not fixture.LIBC_BASE<=p<<12<fixture.LIBC_BASE+0x400000}
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={s.name:fixture.LIBC_BASE+s['st_value'] for sec in elf.iter_sections()
            if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    table=fixture.LIBC_BASE+fixture.LIBC_PTHREAD_GENERATION_OFFSET
    observed={(fixture.TLS,0xB00):None,(table,141*16):None}
    observed.update({(p<<12,4096):None for p in model if base<=p<<12<base+0x400000})
    events=[];actual_events=[]
    entry=0x326A2C if kind=='executor' else 0x3260A4
    initial_generations=allocator._read_span(native_seed,table,141*16)
    def observe(cpu,address):
        if address==base+entry:cpu.mem_write(table,initial_generations)
    def key(cpu):
        events.append(['key_create']);cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_key_create'])
    def specific(cpu):
        events.append(['set_specific']);cpu.reg_write(UC_ARM64_REG_PC,exports['pthread_setspecific'])
    result,memory,allocations,_=native(library,base,0x326A2C if kind=='executor' else 0x3260A4,
        [GUEST+0x3100],oracle,libc=libc,real_singletons=True,thread_id=thread_id,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:fixture.TLS},host_imports={0x348620:key,0x348580:specific},
        stop_offset=0x326B18 if kind=='executor' else 0x291934,observed_memory=observed,
        instruction_observer=observe)
    def create_key(p,address,destructor):
        actual_events.append(['key_create'])
        return allocator.pthread_key_create(p,key_address=address,destructor=destructor,generation_table=table)
    def set_specific(p,key,value):
        actual_events.append(['set_specific'])
        return allocator.pthread_setspecific(p,key=key,value=value,thread_pointer=fixture.TLS,generation_table=table)
    output=startup.attach_worker_support(model,argument_address=GUEST+0x3100,worker_kind=kind,
        image_base=base,thread_id=thread_id,create_key=create_key,set_specific=set_specific)
    assert result==output, 'dispatch argument'
    assert allocator._read_span(model,GUEST,0xA000)==memory, 'guest memory'
    for (address,width),expected in observed.items():
        actual=allocator._read_span(model,address,width)
        assert actual==expected, ('image/TLS/generation',hex(address),
            [hex(i) for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:12])
    assert actual_events==events==([['set_specific']] if warm else [['key_create'],['set_specific']])
    assert not allocations
    return dict(image_base=hex(base),worker_kind=kind,warm_key=warm,thread_id=thread_id,
        dispatch_argument_match=True,guest_objects_match=True,all_main_image_pages_match=True,
        tls_match=True,generation_table_match=True,key_publication_order_match=True,
        support_ownership_transferred=True,allocations=0,
        native_input_snapshot_used=False,dispatch_executed=False)


def negative_cases(library,libc):
    base=0x122c0000;cases=[]
    for label in ('unknown_worker','missing_support','unknown_callable','key_create_error','set_specific_error','recursive_guard'):
        p=inputs(library,libc,base,False)
        if label=='missing_support':allocator._write_span(p,GUEST+0x3100,bytes(8))
        if label=='unknown_callable':allocator._write_span(p,GUEST+0x3110,bytes(8))
        if label=='recursive_guard':allocator._write_span(p,base+0x3E2F38,b'\0\2')
        before={k:bytes(v) for k,v in p.items()};events=[]
        def key(p,address,destructor):
            events.append('key_create');return 11 if label=='key_create_error' else 0
        def specific(p,key,value):
            events.append('set_specific');return 22 if label=='set_specific_error' else 0
        try:
            startup.attach_worker_support(p,argument_address=GUEST+0x3100,
                worker_kind='invalid' if label=='unknown_worker' else 'queue',image_base=base,
                thread_id=137,create_key=key,set_specific=specific)
        except allocator.RefillUnsupported:
            assert {k:bytes(v) for k,v in p.items()}==before, label+' rollback'
            if label in ('unknown_worker','missing_support','unknown_callable','recursive_guard'):assert not events
            cases.append(dict(case=label,rejected=True,guest_page_rollback=True,
                environment_effect_count=len(events),external_effects_rolled_back=False))
        else:raise AssertionError(label+' accepted')
    return cases


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases=[probe(args.library,args.libc,base=base,kind=kind,warm=warm,thread_id=tid)
        for base in (0x122c0000,0x775c205000) for kind in ('executor','queue')
        for warm in (False,True) for tid in (137,271)]
    negatives=negative_cases(args.library,args.libc)
    report=dict(library_sha256=LIBRARY_SHA256,libc_sha256=hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        native_runs=len(cases),cases=cases,negative_count=len(negatives),negative_cases=negatives,
        native_input_snapshot_used=False,fresh_logical_worker_inputs=True,
        native_code_used_by_python_model=False,worker_dispatch_executed=False,
        complete_thread_runtime=False,complete_allocator_boot=False,complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_count=len(negatives),worker_tls_prefix_match=True)))


if __name__=='__main__':main()
