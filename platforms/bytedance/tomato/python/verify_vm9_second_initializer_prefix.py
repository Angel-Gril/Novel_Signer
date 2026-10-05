"""Fresh entry/return controls for the second table's two nested callers."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from verify_vm9_default_task_prefix import prelude,boundary,fresh
from verify_vm9_signer_objects import GUEST,STOP,LIBRARY_SHA256
from vm9_allocator import _write_span,RefillUnsupported
import vm9_startup as startup


def negative_checks(library,libc,vm_module):
    checks=[];base=0x122C0000
    for label in ('invalid_table','busy_second_once','locked_mutex','null_allocator',
            'unmapped_allocator','broadcast_failure','tagged_return','unmapped_stack',
            'canary_mismatch'):
        pages=fresh(library,libc,base,0x3C)
        if label=='busy_second_once':
            _write_span(pages,base+0x3E0A30,(1).to_bytes(8,'little'))
        if label=='locked_mutex':
            _write_span(pages,base+0x3E2EB8,(1).to_bytes(2,'little'))
        before={key:bytes(value) for key,value in pages.items()};old=vm_module.B
        def allocate(staged,size):
            if label=='null_allocator':return 0
            if label=='unmapped_allocator':return GUEST+0x200000
            if label=='canary_mismatch':
                _write_span(staged,GUEST+0xD028,(0x22).to_bytes(8,'little'))
            return GUEST+0x4300
        try:
            startup.run_default_initialization_caller(pages,
                table_index=6 if label=='invalid_table' else 1,allocate=allocate,
                broadcast=lambda *_:1 if label=='broadcast_failure' else 0,
                vm_module=vm_module,
                entry_stack_address=GUEST+0x200000 if label=='unmapped_stack' else GUEST+0xEF00,
                return_address=1<<63 if label=='tagged_return' else STOP,
                thread_pointer=GUEST+0xD000,image_base=base)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label+' accepted')
        assert {key:bytes(value) for key,value in pages.items()}==before,label
        assert vm_module.B==old,label
        checks.append(dict(case=label,rejected=True,guest_pages_unchanged=True,
            vm_base_restored=True,external_provider_effects_rolled_back=False))
    return checks


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    cases=[]
    for base in (0x122C0000,0x775C205000):
        for caller in (0x280B54,0x280BDC):
            for fill in (0x3C,0xA5):
                cases.append(prelude(args.library,args.libc,vm_full,base,caller,fill))
            cases.append(boundary(args.library,args.libc,vm_full,base,caller,0x3C))
    negatives=negative_checks(args.library,args.libc,vm_full)
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,
        negative_checks=len(negatives),negative_cases=negatives,
        fresh_elf_stack_tls_inputs=True,native_input_snapshot_used=False,
        all_six_default_callers_complete=False,complete_real_allocator_boot=False,
        complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),negative_checks=len(negatives),second_nested_preludes_and_returns_match=True)))


if __name__=='__main__':main()
