"""Capture the fresh outer-constructor logger/trampoline boundary.

This verifier deliberately stops at the active +0x2584ac descriptor trampoline.
It records the logger callback arguments and descriptor fields without replacing
that trampoline with a guessed no-op or callback implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import vm9_objects as objects
import vm9_outer_allocator as outer_allocator
import vm9_outer_constructor as outer_constructor
import vm9_registry as registry
import vm9_root as root_model
import vm9_startup as startup
import vm9_startup_allocator as startup_model
from vm9_allocator import RefillUnsupported
from vm9_libc_boot import _w
import verify_vm9_libc_stdio as io
import verify_vm9_outer_prefix_allocator as prefix
import verify_vm9_root_configuration as config_fixture
import verify_vm9_root_allocator as root_fixture
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker_fixture

LIBRARY = Path(r"C:\AI\6\libmetasec_ml_71332.so")
LIBC = Path(r"C:\AI\6\_vlibc.so")
PROFILES = {"absent": None, "sdk_30": b"30"}


def _hex(value):
    return hex(value) if isinstance(value, int) else value


def case(library: Path, libc: Path, image: int, label: str, property_value: bytes | None,
         vm_module):
    pages, _, _ = root_fixture.fresh(library, libc, image, property_value)
    environment = worker_fixture.Environment(pages, 2)
    threads: list[list[int]] = []
    destructor_calls: list[list[int]] = []
    wake_calls: list[list[int]] = []
    logger_calls: list[dict] = []
    trampoline_calls: list[dict] = []

    def create_thread(staged, output, _attr, entry, argument):
        handle = io.GUEST + 0xC800 + len(threads) * 0x100
        _w(staged, output, handle)
        threads.append([handle, entry, argument])
        return 0

    def register_destructor(_staged, destructor, obj, dso):
        destructor_calls.append([destructor, obj, dso])
        return 0

    def signal_condition(staged, address):
        return startup.signal_condition_no_waiters(
            staged, condition_address=address,
            wake=lambda _p, pointer, operation, count:
                wake_calls.append([pointer, operation, count]) or 0)

    startup_model.initialize_main_startup(
        environment.os, vm_module=vm_module, image_base=image,
        entry_stack_address=worker_fixture.TOP, return_address=oracle.STOP,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        libc_base=io.LIBC, brk=environment.brk, os_call=environment.service,
        create_thread=create_thread, register_destructor=register_destructor,
        thread_id=137, signal_condition=signal_condition)

    session = outer_allocator.make_session(
        environment.os, image_base=image, libc_base=io.LIBC,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        brk=environment.brk, os_call=environment.service,
        once_wake=lambda _p, pointer, operation, count:
            wake_calls.append([pointer, operation, count]) or 0,
        register_destructor=register_destructor, thread_id=137,
        read_clock=lambda _p, _clock_id: (0, 1791023800, 500000000))

    def get_registry(entry_stack_address):
        return registry.get_registry320_reference(
            session.pages, entry_stack_address=entry_stack_address,
            image_base=image, allocate=session.allocate, free=session.free,
            read_clock=session.read_clock, get_tls=session.get_tls,
            initialize_registry=session.initialize_registry,
            broadcast=session.broadcast, thread_id=137)

    def mkdir(staged, _path, _mode):
        _w(staged, config_fixture.TLS + 0x100, 17, 4)
        return 0xFFFFFFFF

    def prefix_stack_effect(staged, stack):
        for delta, value in ((-0x150, stack - 0x140),
                             (-0x148, image + 0x32A210),
                             (-0xF8, image + 0x32A210)):
            _w(staged, stack + delta, value)

    class BoundaryCallbacks(root_model.RootCallbacks):
        def __init__(self, *args, **kwargs):
            kwargs["logger_callback"] = self.capture_logger
            super().__init__(*args, **kwargs)

        def capture_logger(self, vm, *, argument, object_address, first_argument,
                           second_argument, width, register_values):
            logger_calls.append({
                "argument": _hex(argument),
                "object_address": _hex(object_address),
                "first_argument": _hex(first_argument),
                "second_argument": _hex(second_argument),
                "width": _hex(width),
                "register_values": [_hex(value) for value in register_values],
                "argument_words": [_hex(vm.m.u64(argument + i * 8)) for i in range(8)],
            })
            # The logger side effect is intentionally not guessed here. The
            # purpose of this control is to reach and record the next boundary.

        def __call__(self, vm, function, argument):
            wrapper = function - self.base
            if wrapper == 0x2584AC:
                descriptor = argument + 8
                fields = [vm.m.u64(descriptor + i * 8) for i in range(8)]
                trampoline_calls.append({
                    "function": _hex(function),
                    "argument": _hex(argument),
                    "descriptor": _hex(descriptor),
                    "fields": [_hex(value) for value in fields],
                    "branch_target": _hex(fields[0]),
                    "x0_object": _hex(fields[1]),
                    "vm_registers_0_8": [_hex(value) for value in vm.R[:9]],
                })
                raise RefillUnsupported(
                    "native +0x2584ac descriptor trampoline is not recovered")
            return super().__call__(vm, function, argument)

    previous = root_model.RootCallbacks
    root_model.RootCallbacks = BoundaryCallbacks
    try:
        try:
            outer_constructor.construct_default_outer(
                session.pages, outer_root_address=io.GUEST + 0x1800,
                entry_stack_address=worker_fixture.TOP,
                thread_pointer=config_fixture.TLS, image_base=image,
                vm_module=vm_module, allocate=session.allocate,
                reallocate=session.reallocate, free=session.free,
                get_registry=get_registry,
                get_singleton=lambda p, sp: session.singleton(p, sp),
                get_tls=session.get_tls,
                initialize_registry=session.initialize_registry,
                broadcast=session.broadcast,
                read_property=lambda _p, _name: property_value,
                syscall=prefix._syscall,
                errno_address=config_fixture.TLS + 0x100,
                mkdir=mkdir, register_destructor=register_destructor,
                thread_id=137, prepare_format=session.prepare_format,
                prefix_stack_effect=prefix_stack_effect,
                logger_callback=lambda *args, **kwargs: None, logger_callback_required=True,
                root_output_address=io.GUEST + 0x1800)
        except RefillUnsupported as exc:
            error = str(exc)
        else:
            raise AssertionError("outer constructor crossed an unrecovered boundary")
    finally:
        root_model.RootCallbacks = previous

    if not logger_calls:
        raise AssertionError("logger callback boundary was not reached")
    if not trampoline_calls:
        raise AssertionError("descriptor trampoline boundary was not reached")
    return {
        "image_base": hex(image),
        "property_profile": label,
        "fresh_elf_inputs": True,
        "native_input_snapshot_used": False,
        "rejected_at_boundary": True,
        "rejection": error,
        "logger_calls": logger_calls,
        "descriptor_trampoline": trampoline_calls,
        "logger_model_applied": False,
        "descriptor_trampoline_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=LIBRARY)
    parser.add_argument("--libc", type=Path, default=LIBC)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == io.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full

    rows = []
    for image in (0x122C0000, 0x775C205000):
        for label, value in PROFILES.items():
            row = case(args.library, args.libc, image, label, value, vm_full)
            rows.append(row)
            print("outer constructor boundary", hex(image), label, "PASS", flush=True)
    report = {
        "schema": "vm9-outer-constructor-boundary-v1",
        "sample_sha256": oracle.LIBRARY_SHA256,
        "libc_sha256": io.LIBC_SHA256,
        "cases": rows,
        "controls": len(rows),
        "fresh_elf_inputs": True,
        "native_input_snapshot_used": False,
        "logger_callback_arguments_captured": True,
        "active_descriptor_trampoline_captured": True,
        "logger_model_applied": False,
        "descriptor_trampoline_recovered": False,
        "fresh_medusa_output_verified": False,
        "current_online_header_matrix_verified": False,
        "complete_python_medusa": False,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("outer constructor boundary", len(rows), "PASS; descriptor trampoline remains open", flush=True)


if __name__ == "__main__":
    main()
