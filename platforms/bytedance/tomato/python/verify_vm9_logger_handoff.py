"""Compare the fresh post-VM logger handoff boundary.

The native path calls +0x26cf08 after the root VM returns and enters
+0x26e9e0 with a stack-local short-string object and fixed arguments. The
Python path generates only the address/argument relation and fails closed at
this boundary; the bounded fallback object and formatter payload are modeled, while sink dispatch remains unimplemented.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import verify_vm9_outer_constructor_boundary as boundary
import verify_vm9_outer_signer_native as native
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker

LIBRARY = Path(r"C:\AI\6\libmetasec_ml_71332.so")
LIBC = Path(r"C:\AI\6\_vlibc.so")
BASES = (0x122C0000, 0x775C205000)
PROFILES = {"absent": None, "sdk_30": b"30"}


def _int(value):
    return int(value, 16) if isinstance(value, str) else value


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, default=LIBRARY)
    ap.add_argument("--libc", type=Path, default=LIBC)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--apply-logger-model", action="store_true")
    args = ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == worker.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full

    rows = []
    for image in BASES:
        for label, value in PROFILES.items():
            trace: list[dict] = []
            native_result = native.case(args.library, args.libc, image, value, trace=trace)
            native_entry = [item for item in trace if item.get("offset") == "0x26cf08"]
            prelude = [item for item in trace
                       if item.get("offset") == "0x1684f0"
                       and item.get("register_backing_words_after_prelude")]
            if len(native_entry) != 1 or len(prelude) != 1:
                raise AssertionError("native handoff/prelude boundary count changed")
            native_entry = native_entry[0]
            native_vm_stack = _int(prelude[0]["virtual_stack"]) - 0x570
            native_object = _int(native_entry["x0"])
            native_first = _int(native_entry["x1"])
            native_x2 = _int(native_entry["x2"])
            native_x3 = _int(native_entry["x3"])
            python_result = boundary.case(
                args.library, args.libc, image, label, value, vm_full,
                apply_logger_model=False, capture_logger_handoff=True,
                apply_handoff_model=args.apply_logger_model)
            handoffs = python_result.get("logger_handoffs", [])
            if len(handoffs) != 1:
                raise AssertionError("Python logger handoff boundary count changed")
            handoff = handoffs[0]
            python_vm_stack = _int(handoff["vm_stack"])
            python_object = _int(handoff["object_address"])
            python_source = _int(handoff["source_object_address"])
            python_first = _int(handoff["first_argument"])
            python_x2 = _int(handoff["second_argument"])
            python_x3 = _int(handoff["width"])
            checks = {
                "vm_stack_match": python_vm_stack == native_vm_stack,
                "object_relative_offset_match": (native_object - native_vm_stack == -0xAE0
                                                  and python_object - python_vm_stack == -0xAE0),
                "native_object_relative_offset": native_object - native_vm_stack,
                "python_object_relative_offset": python_object - python_vm_stack,
                "static_source_offset_match": python_source - image == 0x3DEDB8,
                "first_argument_offset_match": (native_first - image == 0x3DEDD0
                                                  and python_first - image == 0x3DEDD0),
                "x2_match": native_x2 == python_x2 == 8,
                "x3_match": native_x3 == python_x3 == 3,
            }
            if not all(value for key, value in checks.items() if key.endswith("match")):
                raise AssertionError(f"handoff mismatch: {checks}")
            model_rows = python_result.get("logger_models", [])
            model_checks = {}
            if args.apply_logger_model:
                if len(model_rows) != 1:
                    raise AssertionError("Python logger model did not materialize exactly once")
                model = model_rows[0]
                native_logger_entry = next(item for item in trace if item.get("offset") == "0x26e9e0")
                native_formatter = next(item for item in trace if item.get("offset") == "0x271ec8")
                native_sink = next(item for item in trace if item.get("offset") == "0x271ddc")
                native_tag = bytes.fromhex(native_formatter["x1_bytes_0x80"])
                native_output = bytes.fromhex(native_sink["x2_bytes_0x420"])
                python_tag = bytes.fromhex(model["tag_bytes_0x40"])
                python_output = bytes.fromhex(model["output_bytes_0x420"])
                model_checks = {
                    "logger_object_0x80_match": model["object_bytes_0x80"] == native_logger_entry["x0_bytes_0x80"],
                    "tag_payload_prefix_match": python_tag[:8] == native_tag[:8] == b"METASEC\0",
                    "format_object_payload_prefix_match": model["format_bytes_0x80"][:0x50] == native_formatter["x2_bytes_0x420"][:0x50],
                    "formatted_message_match": python_output.split(b"\0", 1)[0] == native_output.split(b"\0", 1)[0] == b"Invalid JavaVM, fallback to test path.",
                    "sink_entry_level_match": native_sink["x0"] == "0x6",
                    "sink_entry_tag_match": native_sink["x1"] == model["tag_address"],
                }
                if not all(model_checks.values()):
                    raise AssertionError(f"logger model mismatch: {model_checks}")
            rows.append({
                "image_base": hex(image),
                "property_profile": label,
                "fresh_elf_inputs": True,
                "native_input_snapshot_used": False,
                "native_entry_offset": "0x26cf08",
                "native_logger_offset": "0x26e9e0",
                "native_formatter_offset": "0x271ec8",
                "native_sink_offset": "0x271ddc",
                "native_vm_return_offset": "0x99f04",
                "python_vm_return_offset": "0x99f04",
                "checks": checks,
                "logger_model_checks": model_checks,
                "logger_model": model_rows,
                "python_rejected_at": None if args.apply_logger_model else "0x26cf08",
                "native_outer_getter_returned": native_result["native_outer_getter_returned"],
                "logger_object_fields_recovered": bool(args.apply_logger_model),
                "formatter_payload_recovered": bool(args.apply_logger_model),
                "logger_sink_dispatch_recovered": False,
                "logger_semantics_complete": False,
                "fresh_medusa_output_verified": False,
            })
            print("logger handoff", hex(image), label, "PASS", flush=True)

    report = {
        "schema": "vm9-logger-handoff-boundary-v1",
        "sample_sha256": oracle.LIBRARY_SHA256,
        "libc_sha256": worker.LIBC_SHA256,
        "controls": len(rows),
        "cases": rows,
        "native_path": ["0x257084", "0x257308", "0x168324", "0x1684f0", "0x99f04", "0x26cf08", "0x26e9e0"],
        "python_path": ["construct_root_caller", "0x99f04", "logger_handoff_provider", "logger_object_model", "formatter_payload_model"],
        "native_input_snapshot_used": False,
        "all_controls_handoff_relation_match": True,
        "logger_model_requested": args.apply_logger_model,
        "logger_object_fields_recovered": bool(args.apply_logger_model),
        "formatter_payload_recovered": bool(args.apply_logger_model),
        "logger_sink_dispatch_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
        "limitations": [
            "The bounded model matches the four fresh object/tag/formatter entry controls but does not recover the final sink callback or file/socket writes.",
            "The Python model remains a logger boundary model; it does not invoke an unproven native callback or publish a descriptor trampoline.",
            "No online signature, Rust download, or other-platform result is implied.",
        ],
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("logger handoff", len(rows), "fresh controls PASS; logger semantics remain open", flush=True)


if __name__ == "__main__":
    main()
