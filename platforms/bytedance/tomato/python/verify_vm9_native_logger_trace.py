"""Capture native outer logger register arguments for descriptor comparison."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import verify_vm9_outer_signer_native as native
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker

LIBRARY = Path(r"C:\AI\6\libmetasec_ml_71332.so")
LIBC = Path(r"C:\AI\6\_vlibc.so")
PROFILES = {"absent": None, "sdk_30": b"30"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=LIBRARY)
    parser.add_argument("--libc", type=Path, default=LIBC)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())

    rows = []
    for image in (0x122C0000, 0x775C205000):
        for label, value in PROFILES.items():
            trace = []
            result = native.case(args.library, args.libc, image, value, trace=trace)
            logger = [item for item in trace if item["offset"] == "0x26e9e0"]
            if len(logger) != 1:
                raise AssertionError("native outer logger trace count changed")
            row = {
                "image_base": hex(image),
                "property_profile": label,
                "native_outer_getter_returned": result["native_outer_getter_returned"],
                "logger_entry": logger[0],
                "logger_return_offset": "0x26cf0c",
                "logger_downstream_offsets": [
                    item["offset"] for item in trace if item["offset"] in
                    ("0x271ec8", "0x271ddc")],
                "actual_allocator_counts": result["actual_allocator_counts"],
                "native_input_snapshot_used": False,
                "fresh_medusa_output_verified": False,
            }
            rows.append(row)
            print("native logger", hex(image), label, "PASS", flush=True)

    report = {
        "schema": "vm9-native-logger-register-trace-v1",
        "sample_sha256": oracle.LIBRARY_SHA256,
        "libc_sha256": worker.LIBC_SHA256,
        "cases": rows,
        "controls": len(rows),
        "logger_entry_offset": "0x26e9e0",
        "logger_downstream_offsets": ["0x271ec8", "0x271ddc"],
        "logger_return_offset": "0x26cf0c",
        "native_input_snapshot_used": False,
        "python_descriptor_comparison_complete": False,
        "fresh_medusa_output_verified": False,
        "current_online_header_matrix_verified": False,
        "complete_python_medusa": False,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("native logger trace", len(rows), "PASS; Python descriptor comparison remains open", flush=True)


if __name__ == "__main__":
    main()
