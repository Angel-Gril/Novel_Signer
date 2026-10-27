"""Record the native outer graph object relationships at cold getter return.

This is a read-only provenance probe.  It does not feed native bytes into the
Python object model and does not interpret any field as a signer result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import verify_vm9_outer_signer_native as outer
import verify_vm9_signer_objects as oracle


BASES = (0x122C0000, 0x775C205000)


def _run(library: Path, libc: Path, image: int) -> dict:
    captured = {}

    def terminal_observer(cpu, *, root, **_kwargs):
        def u(address, width=8):
            return int.from_bytes(bytes(cpu.mem_read(address, width)), "little")

        def words(address, width):
            return [hex(u(address + index * 8)) for index in range(width // 8)]

        root_words = words(root, 0x28)
        if root_words[0] != "0x0":
            raise AssertionError("root +0x00 is unexpectedly written")
        if any(int(root_words[index], 16) == 0 for index in (1, 2, 3, 4)):
            raise AssertionError("outer root dependencies are incomplete")

        children = []
        expected = (
            (0x18, 0x2830C4, 0x35DC50, 0x80),
            (0x20, 0x289190, 0x35F7E0, 0xE8),
        )
        for field, target_offset, handler_vtable_offset, handler_width in expected:
            child = u(root + field)
            child_vtable = u(child)
            callback_pair = u(child + 0x20)
            callback_target = u(callback_pair)
            handler = u(callback_pair + 8)
            if child_vtable != image + 0x35D5F0:
                raise AssertionError((hex(field), hex(child_vtable)))
            if callback_target != image + target_offset:
                raise AssertionError((hex(field), hex(callback_target)))
            if u(handler) != image + handler_vtable_offset:
                raise AssertionError((hex(field), hex(u(handler))))
            record = {
                "root_field_offset": hex(field),
                "child_address": hex(child),
                "child_vtable_offset": hex(child_vtable - image),
                "child_words": words(child, 0x28),
                "callback_pair_address": hex(callback_pair),
                "callback_target_offset": hex(callback_target - image),
                "handler_address": hex(handler),
                "handler_vtable_offset": hex(u(handler) - image),
                "handler_words_0x80_or_0xe8": words(handler, handler_width),
            }
            if handler_vtable_offset == 0x35DC50:
                # The service_refs context has both the outer callback
                # reference members and the service singleton references.
                record["callback_reference_members"] = {
                    "+0x30": [hex(u(handler + 0x30)), hex(u(handler + 0x38))],
                    "+0x40": [hex(u(handler + 0x40)), hex(u(handler + 0x48))],
                }
                record["service_reference_members"] = {
                    "+0x50": [hex(u(handler + 0x50)), hex(u(handler + 0x58))],
                    "+0x60": [hex(u(handler + 0x60)), hex(u(handler + 0x68))],
                }
                if any(u(handler + offset) == 0 for offset in (0x30, 0x40, 0x50, 0x60)):
                    raise AssertionError("service handler reference member is null")
            children.append(record)

        captured.update({
            "root_address": hex(root),
            "root_words": root_words,
            "children": children,
        })

    outer.case(library, libc, image, None, terminal_observer=terminal_observer)
    return {
        "image_base": hex(image),
        "outer_function_offset": "0x1658e4",
        "root_and_children_verified": True,
        **captured,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256(args.library.read_bytes()).hexdigest()
    if digest != oracle.LIBRARY_SHA256:
        raise AssertionError(digest)
    cases = [_run(args.library, args.libc, image) for image in BASES]
    report = {
        "schema": "vm9-outer-graph-object-provenance-20261028-v1",
        "sample_sha256": digest,
        "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "cases": cases,
        "fresh_native_controls": len(cases),
        "root_and_children_verified": all(
            case["root_and_children_verified"] for case in cases
        ),
        "native_snapshot_used_as_python_input": False,
        "signer_result_interpretation": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "comparison_note": (
            "At cold outer getter return, both image bases expose the same 40-byte "
            "root dependency fields, child vtable/target pairs, and derived handler "
            "vtables. The service_refs handler contains non-null callback and service "
            "reference members. Root +0x00 remains an observed untouched field, not a "
            "synthesized clearing rule."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("outer graph object provenance", len(cases), "fresh cases PASS", flush=True)


if __name__ == "__main__":
    main()
