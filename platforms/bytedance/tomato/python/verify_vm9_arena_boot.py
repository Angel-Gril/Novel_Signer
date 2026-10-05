"""Fresh native comparisons for arena publication prefix and explicit once gate."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0
import vm9_startup as startup
import verify_vm9_startup_init as fixture
from verify_vm9_signer_objects import native,GUEST,LIBRARY_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported


def probe(library,libc,*,base,region,once):
    model=fixture.fresh_inputs(library,libc,base)
    oracle=fixture.fresh_inputs(library,libc,base)
    events=[];actual=[]
    def allocate(p,size):events.append([size,region]);return region
    def native_allocate(cpu,size):return region
    def allocation_effect(cpu,size,ptr):actual.append([size,ptr])
    observed={(base+0x3E09A8,0x48):None,(base+0x3E2EB8,8):None}
    _,memory,_,_=native(library,base,0x32A0A0 if once else 0x280890,
        [base+0x3E09E8,GUEST+0x1000,base+0x280890] if once else [0],oracle,
        stop_offset=0x280970,libc=libc,real_mutexes=once,
        allocation_effect=allocation_effect,malloc_handler=native_allocate,
        instruction_limit=200000,observed_memory=observed)
    result=(startup.begin_once_arena_boot if once else startup.initialize_arena_boot_prefix)(
        model,image_base=base,allocate=allocate)
    assert _read_span(model,GUEST,0xA000)==memory
    assert _read_span(model,base+0x3E09A8,0x48)==observed[base+0x3E09A8,0x48]
    assert _read_span(model,base+0x3E2EB8,8)==observed[base+0x3E2EB8,8]
    assert events==actual==[[0x4000,region]]
    assert result.region_address==region and result.once_initialization_pending==once
    assert int.from_bytes(_read_span(model,base+0x3E09E8,8),'little')==int(once)
    return dict(image_base=hex(base),case='once_prefix' if once else 'initializer_prefix',
        allocation_region_offset=hex(region-GUEST),allocation_size=0x4000,
        unaligned_allocator_output_allowed=True,allocation_sequence_match=True,
        full_guest_heap_match=True,zero_fill_match=True,eight_published_pointers_match=True,
        once_state_match=True,once_state_at_boundary=int(once),mutex_match=True,
        next_native_caller_offset='0x280970',initializer_completed=False,
        native_input_snapshot_used=False)


def gate(library,libc,base,state):
    model=fixture.fresh_inputs(library,libc,base);oracle=fixture.fresh_inputs(library,libc,base)
    control=base+0x3E09E8;mutex=base+0x3E2EB8;condition=base+0x3E2EE0
    for pages in (model,oracle):_write_span(pages,control,state.to_bytes(8,'little'))
    expected=[];events=[];marker=GUEST+0x1200
    def observe(pages):return [int.from_bytes(_read_span(pages,a,n),'little') for a,n in ((control,8),(mutex,2))]
    def native_init(cpu):
        expected.append(['initializer',*[int.from_bytes(cpu.mem_read(a,n),'little') for a,n in ((control,8),(mutex,2))]])
        cpu.mem_write(marker,(37).to_bytes(8,'little'));return 0
    def native_broadcast(cpu):
        expected.append(['broadcast',cpu.reg_read(UC_ARM64_REG_X0),*[int.from_bytes(cpu.mem_read(a,n),'little') for a,n in ((control,8),(mutex,2))]])
        return 0
    observed={(control,8):None,(mutex,8):None}
    _,memory,allocations,_=native(library,base,0x32A0A0,[control,GUEST+0x1000,base+0x280890],oracle,
        libc=libc,real_mutexes=True,host_imports={0x280890:native_init,0x3485A0:native_broadcast},
        observed_memory=observed,instruction_limit=10000)
    def initializer(pages):events.append(['initializer',*observe(pages)]);_write_span(pages,marker,(37).to_bytes(8,'little'));return 0
    def broadcast(pages,address):events.append(['broadcast',address,*observe(pages)]);return 0
    startup.call_once_arena_boot(model,image_base=base,initializer=initializer,broadcast=broadcast)
    assert events==expected
    assert _read_span(model,GUEST,0xA000)==memory
    assert _read_span(model,control,8)==observed[control,8]
    assert _read_span(model,mutex,8)==observed[mutex,8] and not allocations
    return dict(image_base=hex(base),case='once_gate_with_explicit_provider',initial_state=hex(state),
        ordered_initializer_broadcast_states_match=True,full_guest_heap_match=True,
        once_and_mutex_match=True,initializer_is_explicit_oracle_boundary=True,
        actual_nested_arena_initializer_executed=False,native_input_snapshot_used=False)


def negative_cases(library,libc):
    cases=[];base=0x122C0000
    for label in ('null_allocator','unmapped_allocator','busy_once','locked_mutex','initializer_failure','broadcast_failure','partial_initializer'):
        pages=fixture.fresh_inputs(library,libc,base)
        if label=='busy_once':_write_span(pages,base+0x3E09E8,(1).to_bytes(8,'little'))
        if label=='locked_mutex':_write_span(pages,base+0x3E2EB8,(1).to_bytes(2,'little'))
        before={k:bytes(v) for k,v in pages.items()}
        def initializer(p):
            _write_span(p,GUEST+0x1000,bytes(8))
            if label=='initializer_failure':raise RefillUnsupported('synthetic failure')
            if label=='partial_initializer':return startup.ArenaBootPrefixResult(GUEST+0x4300)
        try:
            if label in ('initializer_failure','broadcast_failure','partial_initializer'):
                startup.call_once_arena_boot(pages,image_base=base,initializer=initializer,
                    broadcast=lambda *_:5 if label=='broadcast_failure' else 0)
            else:startup.begin_once_arena_boot(pages,image_base=base,
                allocate=lambda *_:0 if label=='null_allocator' else 0x60000000)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label+' accepted')
        assert {k:bytes(v) for k,v in pages.items()}==before
        cases.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            external_provider_effects_rolled_back=False))
    return cases


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases=[]
    for base in (0x122C0000,0x775C205000):
        for region in (GUEST+0x4000,GUEST+0x4300):
            for once in (False,True):cases.append(probe(a.library,a.libc,base=base,region=region,once=once))
        for state in (0,(1<<64)-1,37):cases.append(gate(a.library,a.libc,base,state))
    negatives=negative_cases(a.library,a.libc)
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=negatives,
        correction_of_commit='1b8aa32',earlier_complete_once_claim_with_partial_initializer_retracted=True,
        fresh_elf_inputs=True,native_input_snapshot_used=False,native_code_used_by_python_model=False,
        complete_nested_initializer=False,complete_real_allocator_boot=False,complete_python_medusa=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_checks=len(negatives),arena_prefix_and_explicit_once_gate_match=True)))
if __name__=='__main__':main()
