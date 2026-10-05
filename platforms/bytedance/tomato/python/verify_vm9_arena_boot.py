"""Fresh +0x280890 arena initializer and +0x32a0a0 once gate."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_X0
import vm9_startup as startup
import verify_vm9_startup_init as fixture
import verify_vm9_root_configuration as root
from verify_vm9_signer_objects import native,GUEST,LIBRARY_SHA256
from vm9_allocator import _read_span,RefillUnsupported

def probe(library,*,base):
    libc=Path(r'C:\AI\6\_vlibc.so')
    model=fixture.fresh_inputs(library,libc,base)
    oracle=fixture.fresh_inputs(library,libc,base)
    events=[];actual=[];nextptr=GUEST+0x4000
    def alloc(p,size):
        nonlocal nextptr
        ptr=nextptr;nextptr+=(size+15)&~15;events.append(['allocate',size,ptr]);return ptr
    def native_alloc(cpu,size,ptr):actual.append(['allocate',size,ptr])
    observed={(base+0x3E09A8,0x40):None}
    _,memory,allocations,_=native(library,base,0x280890,[0],oracle,stop_offset=0x280970,
        allocation_effect=native_alloc,libc=libc,instruction_limit=200000,observed_memory=observed)
    region=startup.call_once_arena_boot(model,image_base=base,allocate=alloc)
    assert _read_span(model,GUEST,0xA000)==memory
    assert _read_span(model,base+0x3E09A8,0x40)==observed[(base+0x3E09A8,0x40)]
    assert int.from_bytes(_read_span(model,base+0x3E09E8,8),'little')==(1<<64)-1
    native_region=memory[actual[0][2]-GUEST:actual[0][2]-GUEST+0x4000]
    assert _read_span(model,region,0x4000)==native_region
    assert actual==events
    assert allocations==[[0x4000,actual[0][2]]]
    return dict(image_base=hex(base),native_runs=1,arena_allocation_size=0x4000,
        arena_region_offset=hex(actual[0][2]-GUEST),region_zero_fill_match=True,
        published_table_words=8,table_match=True,once_state_transition=True,
        guest_bytes_match=True,allocation_sequence_match=True,native_input_snapshot_used=False,
        complete_real_allocator_boot=False,complete_python_medusa=False)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases=[probe(a.library,base=b) for b in (0x122c0000,0x775c205000)]
    negatives=[];base=0x122c0000
    p=fixture.fresh_inputs(a.library,Path(r'C:\AI\6\_vlibc.so'),base)
    before={k:bytes(v) for k,v in p.items()}
    try:startup.call_once_arena_boot(p,image_base=base,allocate=lambda *args:0)
    except RefillUnsupported:pass
    else:raise AssertionError('bad arena allocation accepted')
    assert {k:bytes(v) for k,v in p.items()}==before
    negatives.append(dict(case='bad_allocator',rejected=True,guest_pages_unchanged=True))
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,negative_cases=negatives,
        fresh_synthetic_inputs=True,native_input_snapshot_used=False,native_code_used_by_python_model=False,
        complete_real_allocator_boot=False,complete_python_medusa=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(dict(native_runs=len(cases),negative_checks=len(negatives),arena_boot_match=True)))
if __name__=='__main__':main()

