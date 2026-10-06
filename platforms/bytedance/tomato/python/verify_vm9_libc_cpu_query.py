"""Same-fresh get_nprocs controls through actual FILE/allocator lifecycle."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from verify_vm9_libc_stdio import case,CPU_CASE_LABELS
from verify_vm9_signer_objects import LIBRARY_SHA256
from verify_vm9_libc_mapping import LIBC_SHA256


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,required=True);ap.add_argument("--libc",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True);ap.add_argument("--case",action="append",choices=CPU_CASE_LABELS)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    rows=[]
    for image in (0x122C0000,0x775C205000):
        for label in args.case or CPU_CASE_LABELS:
            rows.append(case(args.library,args.libc,image,label))
            print("fresh libc CPU query",hex(image),label,"PASS",flush=True)
    report=dict(schema="vm9-libc-fresh-cpu-query-v1",sample_sha256=LIBRARY_SHA256,libc_sha256=LIBC_SHA256,
        cases=rows,full_case_set_verified=set(args.case or CPU_CASE_LABELS)==set(CPU_CASE_LABELS),
        cpu_count_read_from_file_bytes=True,native_input_snapshot_used=False,explicit_virtual_os=True,
        python_malloc_cold_boot_complete=False,standalone_medusa_complete=False,current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__":main()
