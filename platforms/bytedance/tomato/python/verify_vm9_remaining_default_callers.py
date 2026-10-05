"""Fresh prelude/first-callback controls for the five remaining default callers.

This stops before each unknown initializer; it does not execute the six-caller
body or provide a captured native initialization state to Python.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
from verify_vm9_default_task_prefix import DEFAULT_CALLERS, prelude, boundary
from verify_vm9_signer_objects import LIBRARY_SHA256


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
        for caller in DEFAULT_CALLERS[1:]:
            for fill in (0x3C,0xA5):
                cases.append(prelude(args.library,args.libc,vm_full,base,caller,fill))
                cases.append(boundary(args.library,args.libc,vm_full,base,caller,fill))
    report=dict(library_sha256=LIBRARY_SHA256,native_runs=len(cases),cases=cases,
        fresh_elf_stack_tls_inputs=True,native_input_snapshot_used=False,
        remaining_five_initializer_bodies_complete=False,
        all_six_default_callers_complete=False,complete_real_allocator_boot=False,
        complete_python_medusa=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_runs=len(cases),remaining_five_preludes_and_first_callbacks_match=True)))


if __name__=='__main__':main()
