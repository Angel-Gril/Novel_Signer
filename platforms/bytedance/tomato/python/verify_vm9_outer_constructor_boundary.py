"""Observe the fresh Python outer constructor, including return or rejection.

Optional observers receive independently generated Python state. Captured callback
boundaries and constructor completion are reported from this run; standalone
wrapper evidence is not promoted to a current-path observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import vm9_objects as objects
import vm9_callbacks as callbacks
import vm9_configuration_init as configuration
import vm9_outer_allocator as outer_allocator
import vm9_outer_constructor as outer_constructor
import vm9_registry as registry
import vm9_root as root_model
import vm9_startup as startup
import vm9_startup_allocator as startup_model
import vm9_logger as logger_model
from vm9_allocator import RefillUnsupported, _read_span
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
         vm_module, apply_logger_model=False, capture_logger_handoff=False,
         apply_handoff_model=False, logger_observer=None, terminal_observer=None,
         constructor_counter=None, apply_publication=False):
    pages, _, _ = root_fixture.fresh(library, libc, image, property_value)
    if constructor_counter is not None:
        if not isinstance(constructor_counter, int) or not 0 <= constructor_counter <= 0xFFFFFFFF:
            raise ValueError("constructor counter must fit u32")
        _w(pages, image + 0x3D1994, constructor_counter, 4)
    environment = worker_fixture.Environment(pages, 2)
    threads: list[list[int]] = []
    destructor_calls: list[list[int]] = []
    wake_calls: list[list[int]] = []
    logger_calls: list[dict] = []
    logger_errors: list[str] = []
    allocation_calls: list[list[int]] = []
    allocation_sites: list[list[str]] = []
    free_calls: list[int] = []
    allocator_events: list[list[int | str]] = []
    trampoline_calls: list[dict] = []
    logger_handoffs: list[dict] = []
    logger_models: list[dict] = []
    logger_observations: list[dict] = []
    python_vm_entries: list[dict] = []
    python_vm_runs: list[dict] = []
    logger_applied: list[bool] = []
    constructor_result = None
    publication_ledger: list[list] = []
    publication_observations: list[dict] = []

    def publish(staged, *, root_address):
        # Services match the native control's explicit opaque reference profile.
        refs = iter((io.GUEST + 0x8000, io.GUEST + 0x8010))
        types = {io.GUEST + 0x8000: 2, io.GUEST + 0x8010: 3}
        def invoke(*values):
            publication_ledger.append(["invoke", *values])
            return next(refs)
        def get_type(environment, reference):
            publication_ledger.append(["get_type", environment, reference])
            return types[reference]
        def delete(kind, environment, reference):
            publication_ledger.append(["delete", kind, environment, reference])
        def u(address):
            return int.from_bytes(_read_span(staged, address, 8), "little")
        children = [u(root_address + offset) for offset in (0x18, 0x20)]
        publication_observations.append({
            "root_address": root_address,
            "children": children,
            "callback_pairs": [
                _read_span(staged, u(child + 0x20), 16) for child in children],
            "allocation_count": len(allocation_calls),
            "free_count": len(free_calls),
        })
        return callbacks.publish_signer_handle(root_address=root_address,
            environment=io.GUEST + 0x7800, invoke=invoke,
            get_reference_type=get_type, delete_reference=delete)

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

    # Native +0x1658e4 cold getter allocates its 16-byte wrapper and 40-byte
    # outer object before entering +0x27c930/+0x28040c. Keep those allocations
    # in the same allocator transaction so all later pointers and object fields
    # use the native order. The wrapper's 4-byte count is constructed only after
    # the body returns, matching +0x165968.
    prefix_session = outer_allocator.make_session(
        environment.os, image_base=image, libc_base=io.LIBC,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        brk=environment.brk, os_call=environment.service,
        once_wake=lambda _p, pointer, operation, count:
            wake_calls.append([pointer, operation, count]) or 0,
        register_destructor=register_destructor, thread_id=137,
        read_clock=lambda _p, _clock_id: (0, 1791023800, 500000000),
        allocation_effect=lambda _p, size, pointer: (allocation_calls.append([size, pointer]), allocator_events.append(["alloc", size, pointer]), allocation_sites.append([f"{f.filename}:{f.lineno}:{f.function}" for f in __import__("inspect").stack()[1:9]])),
        free_effect=lambda _p, pointer: (free_calls.append(pointer), allocator_events.append(["free", pointer])))
    singleton_wrapper = prefix_session.allocate(prefix_session.pages, 16)
    outer_root = prefix_session.allocate(prefix_session.pages, 40)
    if not singleton_wrapper or not outer_root:
        raise RefillUnsupported("outer singleton prefix allocation failed")
    decoded_global_lengths = outer_constructor.initialize_outer_global_strings(
        prefix_session.pages, image_base=image)
    prefix_session.commit()

    startup_model.initialize_main_startup(
        environment.os, vm_module=vm_module, image_base=image,
        entry_stack_address=worker_fixture.TOP, return_address=oracle.STOP,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        libc_base=io.LIBC, brk=environment.brk, os_call=environment.service,
        create_thread=create_thread, register_destructor=register_destructor,
        thread_id=137, signal_condition=signal_condition,
        allocation_effect=lambda _p, size, pointer: (allocation_calls.append([size, pointer]), allocator_events.append(["alloc", size, pointer]), allocation_sites.append([f"{f.filename}:{f.lineno}:{f.function}" for f in __import__("inspect").stack()[1:9]])))

    session = outer_allocator.make_session(
        environment.os, image_base=image, libc_base=io.LIBC,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        brk=environment.brk, os_call=environment.service,
        once_wake=lambda _p, pointer, operation, count:
            wake_calls.append([pointer, operation, count]) or 0,
        register_destructor=register_destructor, thread_id=137,
        read_clock=lambda _p, _clock_id: (0, 1791023800, 500000000),
        allocation_effect=lambda _p, size, pointer: (allocation_calls.append([size, pointer]), allocator_events.append(["alloc", size, pointer]), allocation_sites.append([f"{f.filename}:{f.lineno}:{f.function}" for f in __import__("inspect").stack()[1:9]])),
        free_effect=lambda _p, pointer: (free_calls.append(pointer), allocator_events.append(["free", pointer])))

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

    def observe_logger(pages, *, phase, **fields):
        row = {"phase": phase}
        for key, value in fields.items():
            row[key] = _hex(value) if isinstance(value, int) else value
        if "tag_address" in fields:
            try:
                row["tag_bytes_0x40"] = _read_span(pages, fields["tag_address"], 0x40).hex()
            except Exception:
                row["tag_bytes_0x40"] = None
        if "output_address" in fields:
            try:
                row["output_bytes_0x420"] = _read_span(pages, fields["output_address"], 0x420).hex()
            except Exception:
                row["output_bytes_0x420"] = None
        if "object_address" in fields:
            try:
                row["object_bytes_0x80"] = _read_span(pages, fields["object_address"], 0x80).hex()
            except Exception:
                row["object_bytes_0x80"] = None
        try:
            row["logger_global_0x40"] = _read_span(pages, image + 0x382600, 0x40).hex()
        except Exception:
            row["logger_global_0x40"] = None
        logger_observations.append(row)
        if logger_observer is not None:
            logger_observer(pages, **fields, phase=phase)

    def capture_logger_handoff(pages, **fields):
        logger_handoffs.append({key: _hex(value) if isinstance(value, int) else value
                                for key, value in fields.items()})
        if apply_handoff_model:
            try:
                tag = logger_model._read_cstring(pages, image + 0x3DEDB8, 0x100)
                tag_address = logger_model.choose_tag_payload(
                    allocation_calls, allocation_sites, free_calls,
                    tag_length=len(tag), allocator_events=allocator_events)
                model = logger_model.materialize_post_vm_logger(
                    pages, vm_stack=fields['vm_stack'], image_base=image,
                    object_address=fields['object_address'],
                    format_object_address=image + 0x3DEDD0,
                    tag_address=tag_address,
                    thread_pointer=config_fixture.TLS)
                logger_models.append(model)
            except RefillUnsupported as exc:
                logger_errors.append(str(exc))
                raise
            return
        raise RefillUnsupported('native +0x26cf08 logger handoff is not recovered')

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
            if apply_logger_model:
                try:
                    configuration.initialize_unavailable_logger(
                        vm.m.pages, image_base=self.base,
                        read_property=lambda _p, _name: property_value,
                        syscall=prefix._syscall,
                        errno_address=config_fixture.TLS + 0x100,
                        property_buffer_address=argument + 0x100)
                    logger_applied.append(True)
                except RefillUnsupported as exc:
                    logger_errors.append(str(exc))
                    raise
            # The default control intentionally does not guess the logger side effect.

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
                    "native +0x2584ac wrapper is verified, but the current callback object graph is not recovered")
            return super().__call__(vm, function, argument)

    previous = root_model.RootCallbacks
    previous_vm = vm_module.VM
    class ObservedVM(previous_vm):
        def run(self):
            if self.pc - vm_module.B == 0x991C0:
                stack = self.R[4]
                def safe_span(address, width):
                    try:
                        return self.m.rd(address, width).hex()
                    except Exception:
                        return None
                root_object = self.m.u64(stack)
                python_vm_entries.append({
                    "entry_offset": "0x991c0",
                    "root_object": hex(root_object),
                    "root_object_bytes_0x120": safe_span(root_object, 0x120),
                    "registers_0_8": [hex(value) for value in self.R[:9]],
                    "stack": hex(stack),
                    "stack_bytes_0x800": safe_span(stack - 0x400, 0x800),
                    "register_backing_bytes_0x100": safe_span(stack + 0x458, 0x100),
                    "register_backing_words": [hex(value) for value in self.R],
                })
            start = self.pc - vm_module.B
            try:
                return super().run()
            finally:
                python_vm_runs.append({
                    "entry_offset": hex(start),
                    "stop_offset": hex(self.pc - vm_module.B),
                    "steps": self.steps,
                    "callback_wrapper_offsets": [
                        item["wrapper_offset"] for item in
                        getattr(self.native_hook, "modeled", [])
                        if "wrapper_offset" in item],
                })
    root_model.RootCallbacks = BoundaryCallbacks
    vm_module.VM = ObservedVM
    try:
        try:
            constructor_result = outer_constructor.construct_default_outer(
                session.pages, outer_root_address=outer_root,
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
                root_output_address=io.GUEST + 0x1800,
                singleton_wrapper_address=singleton_wrapper,
                logger_handoff_callback=(capture_logger_handoff if capture_logger_handoff else None),
                logger_observer=observe_logger,
                publication_callback=publish if apply_publication else None,
                publication_required=apply_publication)
        except RefillUnsupported as exc:
            error = str(exc)
        else:
            error = None
    finally:
        root_model.RootCallbacks = previous
        vm_module.VM = previous_vm

    if constructor_result is not None and terminal_observer is not None:
        terminal_observer(session.pages, result=constructor_result,
                          singleton_wrapper=singleton_wrapper,
                          allocation_sequence=allocation_calls,
                          free_sequence=free_calls,
                          allocator_events=allocator_events)
    return {
        "image_base": hex(image),
        "property_profile": label,
        "fresh_elf_inputs": True,
        "native_input_snapshot_used": False,
        "rejected_at_boundary": error is not None,
        "python_constructor_returned": constructor_result is not None,
        "python_outer_native_state_complete": False,
        "constructor_hash_generated": None if constructor_result is None else constructor_result.constructor_hash,
        "publication_applied": bool(publication_observations),
        "publication_result": None if constructor_result is None else constructor_result.publication_result,
        "publication_ledger": publication_ledger,
        "publication_observations": publication_observations,
        "logger_record_state_complete": False,
        "rejection": error,
        "logger_calls": logger_calls,
        "python_vm_entries": python_vm_entries,
        "python_vm_runs": python_vm_runs,
        "allocation_sequence": allocation_calls,
        "allocation_sites": allocation_sites,
        "free_calls": [hex(value) for value in free_calls],
        "allocator_events": allocator_events,
        "singleton_wrapper_address": _hex(singleton_wrapper),
        "outer_root_prefix_address": _hex(outer_root),
        "decoded_outer_global_lengths": list(decoded_global_lengths),
        "descriptor_trampoline": trampoline_calls,
        "logger_handoffs": logger_handoffs,
        "logger_models": logger_models,
        "logger_observations": logger_observations,
        "logger_model_requested": apply_logger_model,
        "logger_model_errors": logger_errors,
        "logger_model_applied": bool(logger_applied),
        "descriptor_trampoline_wrapper_verified": False,
        "standalone_wrapper_verifier_executed": False,
        "descriptor_trampoline_current_graph_recovered": False,
        "descriptor_trampoline_recovered": False,
        "fresh_medusa_output_verified": False,
        "complete_python_medusa": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, default=LIBRARY)
    parser.add_argument("--libc", type=Path, default=LIBC)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply-logger-model", action="store_true")
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest() == io.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full

    rows = []
    for image in (0x122C0000, 0x775C205000):
        for label, value in PROFILES.items():
            row = case(args.library, args.libc, image, label, value, vm_full, args.apply_logger_model)
            rows.append(row)
            status = "RETURNED" if row["python_constructor_returned"] else "REJECTED"
            print("outer constructor boundary", hex(image), label, status, flush=True)
    report = {
        "schema": "vm9-outer-constructor-boundary-v2",
        "sample_sha256": oracle.LIBRARY_SHA256,
        "libc_sha256": io.LIBC_SHA256,
        "cases": rows,
        "controls": len(rows),
        "fresh_elf_inputs": True,
        "native_input_snapshot_used": False,
        "logger_callback_arguments_captured": any(row["logger_calls"] for row in rows),
        "active_descriptor_trampoline_captured": any(row["descriptor_trampoline"] for row in rows),
        "python_vm_entry_captured": all(row["python_vm_entries"] for row in rows),
        "python_constructor_returned": all(row["python_constructor_returned"] for row in rows),
        "python_vm_entry_offset": "0x991c0",
        "logger_model_requested": args.apply_logger_model,
        "logger_model_applied": bool(args.apply_logger_model and all(row["logger_model_applied"] for row in rows)),
        "descriptor_trampoline_wrapper_verified": False,
        "standalone_wrapper_verifier_executed": False,
        "descriptor_trampoline_current_graph_recovered": False,
        "descriptor_trampoline_recovered": False,
        "fresh_medusa_output_verified": False,
        "current_online_header_matrix_verified": False,
        "complete_python_medusa": False,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("outer constructor observations", len(rows), "recorded; object graph and signing require differential verification", flush=True)


if __name__ == "__main__":
    main()
