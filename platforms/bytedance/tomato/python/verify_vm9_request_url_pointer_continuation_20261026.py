"""Trace the request VM after binding the URL object to a real-format fixture.

This is a read-only continuation probe.  It reuses the accepted native owner
probe, supplies the two words that ``+0x15f5bc/+0x15f5c4`` actually consume
(``char *`` and refcount pointer), and supplies a frozen clock result.  It
does not synthesize a runtime dispatch table or a callback vtable.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_request_dispatch_fresh_20261020 as dispatch
import verify_vm9_request_runtime_table_owner_20261025 as owner
import verify_vm9_signer_objects as oracle
from vm9_allocator import _write_span


URL = (
    b"https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/"
    b"?aid=1967&book_id=7373660003258862617"
)
URL_POINTER = dispatch.G + 0x1D00
REFCOUNT = dispatch.G + 0x1D80


def _install_fixture():
    original = dispatch.fixture

    def fixture(library, image, label):
        pages, kwargs = original(library, image, label)
        _write_span(pages, URL_POINTER, URL + b"\0")
        _write_span(pages, REFCOUNT, (1).to_bytes(4, "little"))
        _write_span(pages, dispatch.URL, URL_POINTER.to_bytes(8, "little"))
        _write_span(pages, dispatch.URL + 8, REFCOUNT.to_bytes(8, "little"))
        return pages, kwargs

    dispatch.fixture = fixture


def _install_clock():
    original = dispatch.Services.imports

    def imports(self, image):
        result = original(self, image)

        def clock(cpu):
            timespec = cpu.reg_read(arm.UC_ARM64_REG_X1)
            cpu.mem_write(
                timespec,
                (1791023800).to_bytes(8, "little", signed=True)
                + (500000000).to_bytes(8, "little", signed=True),
            )
            return 0

        result[0x348450] = clock
        return result

    dispatch.Services.imports = imports


def run(library: Path, libc: Path) -> dict:
    _install_fixture()
    _install_clock()
    original_native = oracle.native
    cases = []
    try:
        for image in owner.BASES:
            trace = []
            # The owner probe is intentionally unchanged; this private kwarg
            # only reaches the wrapper above and is removed before Unicorn.
            def native_with_trace(*args, _trace=trace, **kwargs):
                previous = kwargs.get("instruction_observer")

                def observe(cpu, address):
                    offset = address - args[1]
                    if offset in (0x2858A8, 0x2858AC, 0x2858B0,
                                  0x2858B4, 0x2858B8):
                        row = {
                            "pc_offset": hex(offset),
                            "x0": hex(cpu.reg_read(arm.UC_ARM64_REG_X0)),
                            "x1": hex(cpu.reg_read(arm.UC_ARM64_REG_X1)),
                            "x2": hex(cpu.reg_read(arm.UC_ARM64_REG_X2)),
                            "x3": hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
                            "x8": hex(cpu.reg_read(arm.UC_ARM64_REG_X8)),
                        }
                        object_address = cpu.reg_read(arm.UC_ARM64_REG_X0)
                        try:
                            row["object_bytes"] = bytes(
                                cpu.mem_read(object_address, 0x30)
                            ).hex()
                        except Exception:
                            row["object_bytes"] = None
                        _trace.append(row)
                    if previous:
                        previous(cpu, address)

                kwargs["instruction_observer"] = observe
                return original_native(*args, **kwargs)

            oracle.native = native_with_trace
            row = owner.run(library, libc, image)
            callback = trace[-1] if trace else None
            cases.append(
                {
                    "image_base": row["image_base"],
                    "outcome": row["outcome"],
                    "error": row["error"],
                    "native_instructions_observed": row["native_instructions_observed"],
                    "vm_handler_event_count": len(row["vm_handler_semantics"]),
                    "clock_gettime_calls": sum(
                        event.get("name") == "clock_gettime" for event in row["import_calls"]
                    ),
                    "runtime_table_reads": len(row["runtime_table_reads"]),
                    "first_relocation_slot_read": row["first_relocation_slot_read"],
                    "callback_object_trace": trace,
                    "callback_object_final_observation": callback,
                }
            )
    finally:
        oracle.native = original_native
    return {
        "schema": "vm9-request-url-pointer-continuation-fresh-20261026-v1",
        "evidence_date": "2026-10-26",
        "sample_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "matching_libc_sha256": hashlib.sha256(libc.read_bytes()).hexdigest(),
        "url_fixture": {
            "format": "NUL-terminated URL bytes plus native two-word reference",
            "byte_length": len(URL),
            "sha256": hashlib.sha256(URL).hexdigest(),
            "pointer_word_address": hex(URL_POINTER),
            "refcount_word_address": hex(REFCOUNT),
        },
        "cases": cases,
        "runtime_table_content_reconstructed": False,
        "synthetic_dispatch_table_used": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "Binding the URL reference moves both image bases beyond the prior "
            "+0x170308 read-at-0xc stop. The replay reaches the clock import and "
            "then the existing callback-object trampoline at +0x2858a8; its "
            "object field 0 remains NULL, so +0x2858b4 branches to zero. No "
            "callback vtable, dispatch page, or signer result was synthesized."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if hashlib.sha256(args.library.read_bytes()).hexdigest() != oracle.LIBRARY_SHA256:
        raise SystemExit("unexpected native sample")
    report = run(args.library, args.libc)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("request URL continuation", len(report["cases"]), "cases", flush=True)


if __name__ == "__main__":
    main()
