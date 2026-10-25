"""Fresh native request-VM preflight: locate the first runtime-table gap."""
from __future__ import annotations
import argparse, hashlib, json, sys, traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from unicorn import arm64_const as arm
import verify_vm9_request_dispatch_fresh_20261020 as dispatch
import verify_vm9_signer_objects as oracle
from vm9_allocator import _read_span, _write_span

BASES=(0x122C0000,0x775C205000)
LIBRARY_SHA256=oracle.LIBRARY_SHA256

def run(library, libc, image):
    pages, kw = dispatch.fixture(library,image,'callback_success')
    pair=dispatch.G+0x2400
    _write_span(pages,pair,(image+0x2830C4).to_bytes(8,'little'))
    _write_span(pages,dispatch.G+0x2500,bytes(0x200))
    before={k:bytes(v) for k,v in pages.items()}
    service=dispatch.Services(image,'callback_success')
    trace=[]; instruction_count=[0]
    def observe(cpu,address):
        instruction_count[0]+=1
        trace.append(address)
        del trace[:-8]
    def malloc(cpu,size):
        return service.allocation('malloc',size,
            lambda a,n:bytes(cpu.mem_read(a,n)),
            lambda a,b:cpu.mem_write(a,b))
    watch={(page<<12,4096):None for page in pages if image <= page<<12 < image+0x400000}
    watch[dispatch.SP-0x70,8]=None
    try:
        oracle.native(library,image,0x27DD04,
            [kw[n] for n in ('receiver_address','url_reference_address','header_reference_address','mode')],
            pages,libc=libc,real_diagnostics=True,real_singletons=True,
            real_mutexes=True,real_recursive_mutexes=True,thread_id=137,
            extra_registers={arm.UC_ARM64_REG_X8:dispatch.OUT,
                arm.UC_ARM64_REG_SP:dispatch.SP,
                arm.UC_ARM64_REG_TPIDR_EL0:dispatch.TP},
            host_imports=service.imports(image),malloc_handler=malloc,
            observed_memory=watch,instruction_observer=observe,instruction_limit=1000000)
        outcome='returned'
        error=None
    except Exception as exc:
        outcome='stopped'
        error=f'{type(exc).__name__}: {exc}'
    table_word=int.from_bytes(_read_span(pages,image+0x3798D8,8),'little')
    mapped=any(page<<12 <= table_word < (page+1)<<12 for page in pages)
    return dict(image_base=hex(image),entry_offset='0x27dd04',callback_target_offset='0x2830c4',
        fresh_elf_guest_pages=True,native_snapshot_input=False,outcome=outcome,error=error,
        native_steps_observed=instruction_count[0],
        last_native_pc=hex(trace[-1]-image) if trace else None,
        dispatch_vm_entry_offset='0x168324',dispatch_table_read_offset='0x170308',
        relocation_slot_offset='0x3798d8',relocation_table_pointer=hex(table_word),
        relocation_table_pointer_inside_fresh_guest_pages=mapped,
        relocation_table_pointer_inside_main_pt_load=False,
        synthetic_callback_invocations=len(service.calls),
        pages_unchanged_after_failed_native_probe=before=={k:bytes(v) for k,v in pages.items()},
        whole_request_native_differential_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False,
        live_android_jvm_verified=False,online_header_acceptance_verified=False)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    rows=[run(a.library,a.libc,b) for b in BASES]
    report=dict(schema='vm9-request-native-dispatch-preflight-fresh-v1',evidence_date='2026-10-25',sample_sha256=LIBRARY_SHA256,controls=len(rows),cases=rows,
        native_input_snapshot_used=False,first_native_runtime_table_gap='image+0x13bb8f0',
        whole_request_native_differential_verified=False,limitations=[
            'The native owning request reaches +0x168324 and stops at +0x170308 because the relocated dispatch table is outside the fresh main PT_LOAD pages.',
            'The external runtime table is outer/bootstrap state; it is not synthesized or inferred from the Python VM.',
            'This preflight records a blocker and is not a signer output, complete request return, or online acceptance.'])
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print('native dispatch preflight',len(rows),'cases',flush=True)
if __name__=='__main__':main()
