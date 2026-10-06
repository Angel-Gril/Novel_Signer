"""Compose fresh main startup, registry string input and root on one allocator/TLS state.

This is a Python-only composition checkpoint. The startup and root components
have separate native controls, while this verifier proves that their guest
state can be carried through one actual matching-libc allocator transaction.
It does not claim a native whole-prefix comparison or a fresh Medusa output.
"""
from __future__ import annotations
from pathlib import Path
import argparse, hashlib, json, os
import vm9_objects as objects
import vm9_callbacks as callbacks
import vm9_registry as registry
import vm9_root as root
import vm9_startup as startup
import vm9_startup_allocator as startup_model
import vm9_outer_allocator as outer
from vm9_allocator import RefillUnsupported, _write_span
from vm9_libc_boot import _w
import verify_vm9_root_allocator as root_fixture
import verify_vm9_root_configuration as config_fixture
import verify_vm9_worker_allocator as worker_fixture
import verify_vm9_libc_stdio as io
import verify_vm9_signer_objects as oracle


LIBRARY = Path(r"C:\AI\6\libmetasec_ml_71332.so")
LIBC = Path(r"C:\AI\6\_vlibc.so")
PROFILES = {"absent": None, "sdk_30": b"30"}


def _syscall(_pages, number, _args):
    if number in (48, 56, 79):
        return -2
    if number in (57, 63):
        return -9
    if number == 198:
        return -97
    raise RefillUnsupported(f"unknown outer-prefix syscall {number}")


def case(library: Path, libc: Path, image: int, property_value: bytes | None,
         vm_module):
    pages, _strings, _sdk = root_fixture.fresh(library, libc, image, property_value)
    environment = worker_fixture.Environment(pages, 2)
    threads: list[list[int]] = []
    destructor_calls: list[list[int]] = []
    allocation_calls: list[list[int]] = []
    free_calls: list[list[int]] = []
    wake_calls: list[list[int]] = []

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
            wake=lambda _p, pointer, operation, count: wake_calls.append(
                [pointer, operation, count]) or 0)

    startup_result = startup_model.initialize_main_startup(
        environment.os, vm_module=vm_module, image_base=image,
        entry_stack_address=worker_fixture.TOP, return_address=oracle.STOP,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        libc_base=io.LIBC, brk=environment.brk, os_call=environment.service,
        create_thread=create_thread, register_destructor=register_destructor,
        thread_id=137, signal_condition=signal_condition)

    session = outer.make_session(
        environment.os, image_base=image, libc_base=io.LIBC,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        brk=environment.brk, os_call=environment.service,
        once_wake=lambda _p, pointer, operation, count: wake_calls.append(
            [pointer, operation, count]) or 0,
        register_destructor=register_destructor, thread_id=137,
        read_clock=lambda _p, _clock_id: (0, 1791023800, 500000000),
        allocation_effect=lambda _p, size, pointer: allocation_calls.append(
            [size, pointer]),
        free_effect=lambda _p, pointer: free_calls.append([pointer]))

    # Build the registry and source object on the same actual allocator state.
    registry_object = session.allocate(session.pages, 320)
    objects.construct_registry_layout320(
        session.pages, object_address=registry_object, image_base=image,
        allocate=session.allocate)
    source_object = session.allocate(session.pages, 24)
    value = b"alpha"
    payload = session.allocate(session.pages, len(value) + 1)
    _write_span(session.pages, source_object,
        (image + 0x34F5F8).to_bytes(8, "little") +
        (len(value) + 1).to_bytes(4, "little") +
        len(value).to_bytes(4, "little") + payload.to_bytes(8, "little"))
    _write_span(session.pages, payload, value + b"\0")

    string_result = registry.append_registry_string_caller(
        session.pages, registry_address=registry_object,
        source_object_address=source_object, entry_stack_address=worker_fixture.TOP,
        return_address=oracle.STOP, thread_pointer=config_fixture.TLS,
        image_base=image, vm_module=vm_module, allocate=session.allocate,
        reallocate=session.reallocate, free=session.free,
        get_tls=session.get_tls, initialize_registry=session.initialize_registry,
        broadcast=session.broadcast)

    def mkdir(staged, _path, _mode):
        _w(staged, config_fixture.TLS + 0x100, 17, 4)
        return 0xFFFFFFFF

    def prefix_stack_effect(staged, stack):
        for delta, value in ((-0x150, stack - 0x140),
                             (-0x148, image + 0x32A210),
                             (-0xF8, image + 0x32A210)):
            _w(staged, stack + delta, value)

    root_result = root.construct_root_reference(
        session.pages, output_reference_address=io.GUEST + 0x1800,
        first_reference_address=io.GUEST + 0x1000,
        second_reference_address=io.GUEST + 0x1010,
        initializer_reference_address=io.GUEST + 0x1020, flag=5,
        entry_stack_address=worker_fixture.TOP, thread_pointer=config_fixture.TLS,
        image_base=image, vm_module=vm_module, allocate=session.allocate,
        reallocate=session.reallocate, free=session.free,
        get_singleton=session.singleton, get_tls=session.get_tls,
        initialize_registry=session.initialize_registry, broadcast=session.broadcast,
        read_property=lambda _p, _name: property_value, syscall=_syscall,
        errno_address=config_fixture.TLS + 0x100, mkdir=mkdir,
        register_destructor=register_destructor, thread_id=137,
        prepare_format=session.prepare_format,
        prefix_stack_effect=prefix_stack_effect)

    # Continue the same state through the measured child/handler assembly and
    # callback publication. These owners are input-driven; JNI invoke/delete
    # effects remain explicit providers.
    configuration_reference = objects.construct_configuration_reference(
        session.pages, image_base=image, allocate=session.allocate, thread_id=137)
    service_reference = objects.construct_service_reference(
        session.pages, image_base=image, kind="service",
        allocate=session.allocate, thread_id=137)
    flag_reference = objects.construct_service_reference(
        session.pages, image_base=image, kind="flag",
        allocate=session.allocate, thread_id=137)
    outer_root = session.allocate(session.pages, 0x28)
    child_a = session.allocate(session.pages, 0x28)
    child_b = session.allocate(session.pages, 0x28)
    child_a_layout = objects.construct_signer_child(
        session.pages, object_address=child_a, image_base=image,
        allocate=session.allocate)
    child_b_layout = objects.construct_signer_child(
        session.pages, object_address=child_b, image_base=image,
        allocate=session.allocate)
    handler_a = session.allocate(session.pages, 0xE8)
    handler_b = session.allocate(session.pages, 0x80)
    objects.construct_signer_handler(
        session.pages, object_address=handler_a, image_base=image,
        allocate=session.allocate, kind="embedded_state")
    objects.construct_signer_handler(
        session.pages, object_address=handler_b, image_base=image,
        allocate=session.allocate, kind="service_refs",
        service_reference_address=service_reference.wrapper_address,
        flag_reference_address=flag_reference.wrapper_address)
    signer_root = objects.construct_signer_root(
        session.pages, object_address=outer_root,
        configuration_a=root_result.object_address,
        configuration_b=configuration_reference.wrapper_address,
        child_a=child_a, child_b=child_b)
    pair_a = objects.bind_signer_child_callback(
        session.pages, child_address=child_a, handler_address=handler_a,
        image_base=image, kind="embedded_state")
    pair_b = objects.bind_signer_child_callback(
        session.pages, child_address=child_b, handler_address=handler_b,
        image_base=image, kind="service_refs")
    ledger = []
    returned_references = iter((io.GUEST + 0x9000, io.GUEST + 0x9010))
    reference_types = {io.GUEST + 0x9000: 2, io.GUEST + 0x9010: 3}
    def invoke(*values):
        ledger.append(["invoke", *values])
        return next(returned_references)
    def get_reference_type(environment, reference):
        ledger.append(["get_type", environment, reference])
        return reference_types.get(reference, 0)
    def delete_reference(kind, environment, reference):
        ledger.append(["delete", kind, environment, reference])
    published = callbacks.publish_signer_handle(
        root_address=signer_root.object_address, environment=io.GUEST + 0x7800,
        invoke=invoke, get_reference_type=get_reference_type,
        delete_reference=delete_reference)
    assert published and pair_a and pair_b
    session.commit()

    output_reference = int.from_bytes(
        bytes(environment.os.pages[(io.GUEST + 0x1800) >> 12][
              (io.GUEST + 0x1800) & 0xFFF:(io.GUEST + 0x1808) & 0xFFF]),
        "little")
    count = int.from_bytes(
        bytes(environment.os.pages[root_result.reference_count_address >> 12][
              root_result.reference_count_address & 0xFFF:
              (root_result.reference_count_address & 0xFFF) + 4]), "little")
    assert output_reference == root_result.object_address
    assert count == 1
    assert len(threads) == 3
    assert startup_result.registers
    return {
        "image_base": hex(image),
        "property_profile": "absent" if property_value is None else "sdk_30",
        "startup_thread_descriptors": len(threads),
        "startup_destructor_registrations": len(destructor_calls),
        "registry_string_vm_steps": string_result.steps,
        "registry_string_stop_offset": hex(string_result.stop_offset),
        "root_vm_steps": root_result.vm_result.steps,
        "root_vm_stop_offset": hex(root_result.vm_result.stop_offset),
        "root_reference_count": count,
        "outer_signer_root": signer_root.object_address,
        "child_callback_pairs": [pair_a, pair_b],
        "callback_publication_entries": len(ledger),
        "actual_allocator_allocations": len(allocation_calls),
        "actual_allocator_frees": len(free_calls),
        "wake_callbacks": len(wake_calls),
        "same_guest_state_startup_registry_string_root": True,
        "python_outer_assembly_composed": True,
        "callback_publication_verified": True,
        "fresh_elf_inputs": True,
        "native_input_snapshot_used": False,
        "native_whole_prefix_comparison": False,
        "fresh_medusa_output_verified": False,
    }


def rejection_case(library: Path, libc: Path, image: int, vm_module):
    pages, _strings, _sdk = root_fixture.fresh(library, libc, image, None)
    environment = worker_fixture.Environment(pages, 2)
    threads = []

    def create_thread(staged, output, _attr, entry, argument):
        handle = io.GUEST + 0xC800 + len(threads) * 0x100
        _w(staged, output, handle)
        threads.append([handle, entry, argument])
        return 0

    startup_model.initialize_main_startup(
        environment.os, vm_module=vm_module, image_base=image,
        entry_stack_address=worker_fixture.TOP, return_address=oracle.STOP,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        libc_base=io.LIBC, brk=environment.brk, os_call=environment.service,
        create_thread=create_thread, register_destructor=lambda *args: 0,
        thread_id=137,
        signal_condition=lambda staged, address: startup.signal_condition_no_waiters(
            staged, condition_address=address, wake=lambda *args: 0))
    session = outer.make_session(
        environment.os, image_base=image, libc_base=io.LIBC,
        thread_pointer=config_fixture.TLS, scratch_address=worker_fixture.SCRATCH,
        brk=environment.brk, os_call=environment.service, once_wake=lambda *a: 0,
        register_destructor=lambda *args: 0, thread_id=137,
        read_clock=lambda _p, _clock_id: (0, 1791023800, 500000000))
    before = {key: bytes(value) for key, value in session.pages.items()}
    try:
        registry.append_registry_string_caller(
            session.pages, registry_address=io.GUEST + 0x100000,
            source_object_address=io.GUEST + 0x100010,
            entry_stack_address=worker_fixture.TOP,
            return_address=oracle.STOP, thread_pointer=config_fixture.TLS,
            image_base=image, vm_module=vm_module, allocate=session.allocate,
            reallocate=session.reallocate, free=session.free,
            get_tls=session.get_tls, initialize_registry=session.initialize_registry,
            broadcast=session.broadcast)
    except (RefillUnsupported, ValueError):
        assert before == {key: bytes(value) for key, value in session.pages.items()}
        return {"case": "missing_registry_pages", "rejected": True,
                "guest_state_rolled_back": True, "vm_base_restored": True}
    raise AssertionError("missing registry pages were accepted")


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
            row = case(args.library, args.libc, image, value, vm_full)
            rows.append(row)
            print("outer prefix", hex(image), label, "PASS", flush=True)
    rejected = [rejection_case(args.library, args.libc, 0x122C0000, vm_full)]
    report = {
        "schema": "vm9-outer-prefix-actual-allocator-v1",
        "sample_sha256": oracle.LIBRARY_SHA256,
        "libc_sha256": io.LIBC_SHA256,
        "cases": rows,
        "rejection_cases": rejected,
        "python_actual_allocator_prefix_composed": True,
        "same_guest_state_startup_registry_string_root": True,
        "fresh_elf_inputs": True,
        "native_input_snapshot_used": False,
        "native_whole_prefix_comparison": False,
        "python_outer_assembly_composed": True,
        "callback_publication_verified": True,
        "matching_libc_realloc_restored": False,
        "formatting_callback_restored": False,
        "fresh_medusa_output_verified": False,
        "current_online_header_matrix_verified": False,
        "complete_python_medusa": False,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("outer prefix actual allocator", len(rows), "PASS; native whole-prefix comparison remains open", flush=True)


if __name__ == "__main__":
    main()
