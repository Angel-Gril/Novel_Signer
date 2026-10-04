"""Same-fresh-native-run differences for bounded root and parser VM phases.

Each VM starts from that run's native prelude snapshot for differential testing.
No external captured pages or trace/branch/opaque hooks are used. This does not
prove a fully Python constructor/prelude or complete Medusa initialization.
Only offsets, counts and comparison booleans are exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X8, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
)

import vm9_objects as objects
import vm9_protobuf as protobuf
import vm9_registry as registry
import vm9_cipher_callback as cipher_callback
import vm9_stream_cipher as stream_cipher
import verify_vm9_root_configuration as oracle
from vm9_allocator import _read_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256


class PrefixBoundary(Exception):
    pass


def probe(library, libc, *, base, property_value, vm_module):
    vm_full = vm_module
    snapshots, boundaries, allocations, registrations = {}, {}, [], []
    native_frees, native_wakes = [], []
    native_effects, model_effects = [], []
    emutls_returns = {}
    tls_registry_return = None
    scoped_returns = {}
    registry_returns = {}
    stack_writer_counts = {"libc:0x68d5c": 0, "image:0x2694f4": 0}
    clock_seconds = 1791023800
    pending_visits, pending_active, pending_finished = {}, False, False

    def boundary(cpu, key, argument=None, width=0):
        boundaries[key] = {
            "guest": bytes(cpu.mem_read(GUEST, 0xA000)),
            "image": {page: bytes(cpu.mem_read(page << 12, 4096))
                      for page in snapshots[key]["pages"] if base <= page << 12 < base + 0x400000},
            "allocations": list(allocations[snapshots[key]["allocation_index"]:]),
            "descriptor": bytes(cpu.mem_read(argument, width)) if width else None,
            "tls": bytes(cpu.mem_read(oracle.TLS, 0xB00)),
            "pthread_generations": bytes(cpu.mem_read(
                oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET, 141 * 16)),
            "registrations": list(registrations[snapshots[key].get("registration_index", 0):]),
            "frees": list(native_frees[snapshots[key].get("free_index", 0):]),
            "wakes": list(native_wakes[snapshots[key].get("wake_index", 0):]),
            "effects": list(native_effects[snapshots[key].get("effect_index", 0):]),
        }

    def constructor_snapshot(cpu, key):
        pages = {page >> 12: bytearray(cpu.mem_read(page, 4096))
                 for begin, end, _ in cpu.mem_regions() for page in range(begin, end + 1, 4096)}
        snapshots[key] = {"object_address": cpu.reg_read(UC_ARM64_REG_X0), "pages": pages,
            "secondary_address": cpu.reg_read(UC_ARM64_REG_X1),
            "third_argument": cpu.reg_read(UC_ARM64_REG_X2),
            "fourth_argument": cpu.reg_read(UC_ARM64_REG_X3),
            "output_reference": cpu.reg_read(UC_ARM64_REG_X8),
            "stack_pointer": cpu.reg_read(UC_ARM64_REG_SP),
            "allocation_index": len(allocations),
            "registration_index": len(registrations),
            "free_index": len(native_frees), "wake_index": len(native_wakes),
            "effect_index": len(native_effects),
            "allocation_next": max(pointer + ((size + 15) & ~15) for size, pointer in allocations)}

    def observe(cpu, address):
        nonlocal pending_active, pending_finished, tls_registry_return
        offset = address - base
        if offset == 0x348450:
            native_effects.append(["clock", cpu.reg_read(UC_ARM64_REG_X0)])
        if offset == 0x259DBC and not pending_finished:
            pending_active = True
        elif offset == 0x26354C and pending_active:
            pending_active, pending_finished = False, True
        if pending_active and offset in (0x259DBC, 0x276B9C, 0x161068, 0x166370, 0x25AB1C, 0x242640):
            key = hex(offset)
            pending_visits[key] = pending_visits.get(key, 0) + 1
        constructor_key = {0x166370: "singleton136", 0x2566EC: "registry320"}.get(offset)
        if constructor_key and constructor_key not in snapshots:
            constructor_snapshot(cpu, constructor_key)
        registry_key = {0x2566EC: "registry320_full", 0x2568C8: "configuration_set",
                        0x166370: "singleton136_full", 0x15E694: "registry320_getter",
                        0x161068: "singleton136_getter", 0x259DBC: "cipher_callback",
                        0x276B9C: "checked_copy", 0x25AA48: "cipher_context",
                        0x2592B8: "stream_reference", 0x256088: "configuration_unpack"}.get(offset)
        if registry_key and registry_key not in snapshots:
            constructor_snapshot(cpu, registry_key)
            registry_returns[registry_key] = cpu.reg_read(UC_ARM64_REG_X30)
        for registry_key, return_address in registry_returns.items():
            if address == return_address and registry_key not in boundaries:
                state = snapshots[registry_key]
                if registry_key in ("cipher_callback", "stream_reference"):
                    boundary(cpu, registry_key, state["output_reference"], 16)
                elif registry_key == "cipher_context":
                    boundary(cpu, registry_key, state["output_reference"], 0x210)
                elif registry_key == "checked_copy":
                    boundary(cpu, registry_key, state["object_address"], state["third_argument"])
                else:
                    boundary(cpu, registry_key)
                boundaries[registry_key]["return_value"] = cpu.reg_read(UC_ARM64_REG_X0)
        constructor_end = {0x166544: "singleton136", 0x256808: "registry320"}.get(offset)
        if constructor_end and constructor_end in snapshots and constructor_end not in boundaries:
            boundary(cpu, constructor_end)
        if offset == 0x34377C:
            tls_key = {base + 0x382470: "emutls_cold", base + 0x382450: "emutls_ready"}.get(
                cpu.reg_read(UC_ARM64_REG_X0))
            if tls_key and tls_key not in snapshots:
                once = int.from_bytes(cpu.mem_read(base + 0x3E31F8, 4), "little")
                assert once == (0 if tls_key == "emutls_cold" else 2)
                constructor_snapshot(cpu, tls_key)
                emutls_returns[tls_key] = cpu.reg_read(UC_ARM64_REG_X30)
        for tls_key, return_address in emutls_returns.items():
            if address == return_address and tls_key not in boundaries:
                boundary(cpu, tls_key)
                boundaries[tls_key]["return_pointer"] = cpu.reg_read(UC_ARM64_REG_X0)
        if offset == 0x269880 and "tls_registry" not in snapshots:
            constructor_snapshot(cpu, "tls_registry")
            tls_registry_return = cpu.reg_read(UC_ARM64_REG_X30)
        if address == tls_registry_return and "tls_registry" not in boundaries:
            boundary(cpu, "tls_registry")
        scoped_key = {0x268EB0: "scoped_acquire", 0x268FBC: "scoped_release"}.get(offset)
        if scoped_key and scoped_key not in snapshots:
            constructor_snapshot(cpu, scoped_key)
            scoped_returns[scoped_key] = cpu.reg_read(UC_ARM64_REG_X30)
        for scoped_key, return_address in scoped_returns.items():
            if address == return_address and scoped_key not in boundaries:
                boundary(cpu, scoped_key, snapshots[scoped_key]["object_address"], 20)
        if offset == 0x168324:
            values = [cpu.reg_read(reg) for reg in (
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4)]
            key = {base + 0x991C0: "root", base + 0x9A6F0: "parser"}.get(values[0])
            if key and key not in snapshots:
                descriptor = [int.from_bytes(cpu.mem_read(values[4] + i * 8, 8), "little") for i in range(3)]
                pages = {page >> 12: bytearray(cpu.mem_read(page, 4096))
                         for begin, end, _ in cpu.mem_regions() for page in range(begin, end + 1, 4096)}
                snapshots[key] = {"values": values, "descriptor": descriptor, "pages": pages,
                    "entry_stack_pointer": cpu.reg_read(UC_ARM64_REG_SP),
                    "return_address": cpu.reg_read(UC_ARM64_REG_X30),
                    "register_backing": descriptor[1] - 0x118,
                    "registration_index": len(registrations), "effect_index": len(native_effects),
                    "allocation_index": len(allocations),
                    "free_index": len(native_frees), "wake_index": len(native_wakes),
                    "allocation_next": max(pointer + ((size + 15) & ~15) for size, pointer in allocations)}
        elif offset == 0x261A1C and "root" in snapshots and "root" not in boundaries:
            boundary(cpu, "root")
        elif "parser" in snapshots and address == snapshots["parser"]["return_address"] and "parser" not in boundaries:
            boundary(cpu, "parser")
            boundaries["parser"]["registers"] = [int.from_bytes(cpu.mem_read(snapshots["parser"]["register_backing"] + i * 8, 8), "little") for i in range(32)]

    def allocation_effect(cpu, size, pointer):
        allocations.append([size, pointer])
        native_effects.append(["allocate", size, pointer])
    def registration_effect(cpu, destructor, obj, dso):
        registrations.append([destructor, obj, dso])
        native_effects.append(["register", destructor, obj, dso])
    def free_effect(cpu, pointer):
        native_frees.append(pointer)
        native_effects.append(["free", pointer])
    def wake_effect(cpu, pointer, operation, count):
        native_wakes.append([pointer, operation, count])
        native_effects.append(["wake", pointer, operation, count])
    def stack_write(cpu, address, width):
        pc = cpu.reg_read(UC_ARM64_REG_PC)
        label = {oracle.LIBC_BASE + 0x68D5C: "libc:0x68d5c",
                 base + 0x2694F4: "image:0x2694f4"}.get(pc)
        if label:
            stack_writer_counts[label] += 1
    control = oracle.probe(library, libc, base=base, property_value=property_value, seconds=clock_seconds,
        instruction_observer=observe,
        allocation_effect=allocation_effect, registration_effect=registration_effect,
        free_effect=free_effect, wake_effect=wake_effect, memory_write_observer=stack_write)
    assert control["returned"] and set(snapshots) == set(boundaries) == {
        "root", "parser", "singleton136", "registry320", "emutls_cold", "emutls_ready", "tls_registry",
        "scoped_acquire", "scoped_release", "registry320_full", "configuration_set",
        "singleton136_full", "registry320_getter", "singleton136_getter",
        "cipher_callback", "checked_copy", "cipher_context", "stream_reference", "configuration_unpack"}
    assert pending_finished and pending_visits.get("0x166370") == 1 and pending_visits.get("0x242640", 0) > 0
    assert all(stack_writer_counts.values())

    class StrictMem(vm_full.Mem):
        def __init__(self, pages):
            self.pages = pages
        def _pg(self, address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported("unmapped fresh guest page")
            return self.pages[address >> 12]

    from vm9_allocator import pthread_getspecific, pthread_setspecific, pthread_key_create
    def get_specific(pages, key):
        return pthread_getspecific(pages, key=key, thread_pointer=oracle.TLS,
            generation_table=oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET)
    def set_specific(pages, key, pointer):
        return pthread_setspecific(pages, key=key, value=pointer, thread_pointer=oracle.TLS,
            generation_table=oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET)
    def create_key(pages, key_address, destructor):
        return pthread_key_create(pages, key_address=key_address, destructor=destructor,
            generation_table=oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET)
    results = []
    vm_full.B = base
    for key in ("root", "parser"):
        state, expected = snapshots[key], boundaries[key]
        values, descriptor = state["values"], state["descriptor"]
        vm = vm_full.VM(StrictMem(state["pages"]), values[0] - base,
            values[1], values[2], values[3], descriptor[0], descriptor[2], maxsteps=100000)
        # Native initializes only slots 0,4..7,29,31; other slots retain
        # bytes from the same run's input backing, not forced host zeros.
        vm.R = [int.from_bytes(_read_span(state["pages"], state["register_backing"] + i * 8, 8), "little") for i in range(32)]
        vm.R[0] = 0
        vm.R[4:8] = [values[1], values[2], values[3], descriptor[0]]
        vm.R[29], vm.R[31] = (descriptor[1] - 0x130) & ~15, descriptor[2]
        allocation_next = state["allocation_next"]
        model_allocations, modeled, frees = [], [], []
        unpack_results = []
        vm_registrations, vm_wakes, vm_effects = [], [], []

        def allocate(pages, size):
            nonlocal allocation_next
            pointer = allocation_next
            allocation_next += (size + 15) & ~15
            if allocation_next >= GUEST + 0x9000:
                raise RefillUnsupported("bounded VM allocation arena exhausted")
            _read_span(pages, pointer, size)
            model_allocations.append([size, pointer])
            vm_effects.append(["allocate", size, pointer])
            return pointer

        def free(pages, pointer):
            # Exactly the nonreusing free boundary used by the native oracle.
            frees.append(pointer)
            vm_effects.append(["free", pointer])

        def reallocate(pages, pointer, size):
            raise RefillUnsupported("this native prefix has no realloc boundary")

        def vm_wake(pages, pointer, operation, count):
            vm_wakes.append([pointer, operation, count])
            vm_effects.append(["wake", pointer, operation, count])
            return 0
        def vm_get_tls(pages, control):
            return objects.get_emulated_tls_address(pages, control_address=control, image_base=base,
                allocate=allocate, reallocate=reallocate, get_specific=get_specific,
                set_specific=set_specific, create_key=create_key, once_wake=vm_wake)
        def vm_atexit(pages, destructor, obj, dso):
            vm_registrations.append([destructor, obj, dso])
            vm_effects.append(["register", destructor, obj, dso])
            return 0
        def vm_thread_destructor(pages, destructor, obj, dso):
            assert dso == base + 0x34C700
            return objects.register_emulated_thread_destructor(pages, destructor_address=destructor,
                object_address=obj, image_base=base, allocate=allocate, get_tls=vm_get_tls,
                create_key=create_key, set_specific=set_specific, register_atexit=vm_atexit, thread_id=137)
        def vm_initialize_registry(pages):
            objects.initialize_scoped_tls_registry(pages, image_base=base, get_tls=vm_get_tls,
                register_destructor=vm_thread_destructor)
        def vm_clock(pages, clock_id):
            vm_effects.append(["clock", clock_id])
            return 0, clock_seconds, 500000000
        def vm_broadcast(pages, pointer):
            return objects.broadcast_condition_no_waiters(pages, condition_address=pointer, wake=vm_wake)
        def vm_singleton(pages, sp):
            return registry.get_singleton136_reference(pages, entry_stack_address=sp,
                image_base=base, allocate=allocate, free=free, read_clock=vm_clock,
                get_tls=vm_get_tls, initialize_registry=vm_initialize_registry,
                broadcast=vm_broadcast, thread_id=137).wrapper_address

        def callback(current, function, argument):
            wrapper = function - base
            words = [current.m.u64(argument + i * 8) for i in range(4)]
            target = words[0] - base
            handled = True
            if (wrapper, target) in ((0x258444, 0x26C858), (0x258454, 0x26C9D0),
                                     (0x26346C, 0x26C858), (0x263498, 0x26C9D0)):
                pass  # Explicit diagnostic-scope exclusion, shared with native oracle.
            elif (wrapper, target) in ((0x2584C4, 0x32A1F0), (0x26347C, 0x32A1F0)):
                current.m.w64(argument + 0x10, allocate(current.m.pages, words[1]))
            elif (wrapper, target) == (0x258478, 0x248344):
                objects.construct_string_object(current.m.pages, object_address=words[1],
                    source_address=words[2], allocate=allocate, vtable_address=base + 0x34F5F8,
                    empty_descriptor_address=base + 0x6E168)
            elif (wrapper, target) == (0x2634C4, 0x2481AC):
                objects.construct_string_object(current.m.pages, object_address=words[1],
                    source_address=0, allocate=allocate, vtable_address=base + 0x34F5F8,
                    empty_descriptor_address=base + 0x6E168)
            elif wrapper == 0x2584B8 and target in (0x32A444, 0x32A4FC):
                model = objects.acquire_uncontended_shared_reader if target == 0x32A444 else objects.release_uncontended_shared_reader
                model(current.m.pages, mutex_address=words[1])
            elif (wrapper, target) == (0x258430, 0x167E54):
                objects.decode_masked_bytes(current.m.pages, source_address=words[1],
                    destination_address=words[2], mask_address=words[3])
            elif (wrapper, target) == (0x2634A4, 0x258E7C):
                objects.construct_decoded_configuration_reference(current.m.pages,
                    object_address=words[1], source_object_address=words[2], image_base=base,
                    allocate=allocate, free=free)
            elif (wrapper, target) == (0x2634D0, 0x248684):
                result = objects.append_string_object(current.m.pages, object_address=words[1],
                    source_object_address=words[2], allocate=allocate, reallocate=reallocate, free=free)
                current.m.w64(argument + 24, result)
            elif (wrapper, target) == (0x2634F0, 0x2481FC):
                objects.construct_sized_string_object(current.m.pages, object_address=words[1],
                    source_address=words[2], length=words[3] & 0xFFFFFFFF,
                    image_base=base, allocate=allocate)
            elif wrapper == 0x2634C4 and target in (0x2484B8, 0x2484FC):
                objects.destroy_string_object(current.m.pages, object_address=words[1],
                    image_base=base, free=free, delete_object=target == 0x2484FC)
            elif wrapper == 0x263504 and target in (0x25874C, 0x258780):
                objects.construct_digest_reference(current.m.pages, object_address=words[1],
                    source_object_address=words[2], algorithm="md5" if target == 0x25874C else "sha1",
                    flag=words[3] & 255, image_base=base, allocate=allocate, reallocate=reallocate, free=free)
            elif (wrapper, target) == (0x263524, 0x248344):
                objects.construct_string_object(current.m.pages, object_address=words[1],
                    source_address=words[2], allocate=allocate, vtable_address=base + 0x34F5F8,
                    empty_descriptor_address=base + 0x6E168)
            elif (wrapper, target) == (0x263534, 0x259DBC):
                cipher_callback.decrypt_configuration_reference(current.m.pages,
                    output_reference_address=words[1], data_object_address=words[2], key_object_address=words[3],
                    iv_object_address=current.m.u64(argument + 32), mode_address=current.m.u64(argument + 40),
                    entry_stack_address=state["entry_stack_pointer"] - 0x190,
                    image_base=base, allocate=allocate, free=free, get_singleton=vm_singleton)
            elif (wrapper, target) == (0x263554, 0x2483E0):
                objects.clone_string_object(current.m.pages, object_address=words[1],
                    source_object_address=words[2], image_base=base, allocate=allocate)
            elif (wrapper, target) == (0x263564, 0x276B9C):
                returned = cipher_callback.checked_forward_copy(current.m.pages,
                    output_address=words[1], source_address=words[2], length=words[3],
                    entry_stack_address=state["entry_stack_pointer"] - 0x190, get_singleton=vm_singleton)
                current.m.w64(argument + 32, returned)
            elif (wrapper, target) == (0x263584, 0x2592B8):
                stream_cipher.transform_configuration_reference(current.m.pages,
                    output_reference_address=words[1], data_object_address=words[2], key_object_address=words[3],
                    entry_stack_address=state["entry_stack_pointer"] - 0x190,
                    image_base=base, allocate=allocate, free=free)
            elif (wrapper, target) == (0x2635A0, 0x32A264):
                free(current.m.pages, words[1])
            elif (wrapper, target) == (0x2635AC, 0x248DD8):
                objects.fill_string_object(current.m.pages, object_address=words[1],
                    length=current.m.u32(argument + 0x10), fill=current.m.rd(argument + 0x14, 1)[0],
                    allocate=allocate, reallocate=reallocate, free=free)
            elif (wrapper, target) == (0x2635C0, 0x256088):
                returned = protobuf.unpack_configuration_message(current.m.pages,
                    allocator_address=words[1], length=words[2], data_address=words[3],
                    image_base=base, allocate=allocate, free=free)
                current.m.w64(argument + 32, returned)
                unpack_results.append({"input_length": words[2], "returned_null": returned == 0})
            elif key == "root" and (wrapper, target) == (0x2584E0, 0x26194C):
                objects.construct_configuration_object_layout(current.m.pages,
                    object_address=words[1], first_string_address=words[2], second_string_address=words[3],
                    image_base=base, allocate=allocate)
                raise PrefixBoundary()
            else:
                handled = False
            if not handled:
                raise vm_full.NativeCall(function, argument)
            modeled.append({"wrapper_offset": hex(wrapper), "target_offset": hex(target)})

        vm.native_hook = callback
        descriptor_match = None
        try:
            vm.run()
        except PrefixBoundary:
            assert key == "root"
            stop = "0x261a1c"
            pending = "0x261c54"
        except vm_full.VMExit:
            assert key == "parser"
            assert vm.R == expected["registers"], ("parser VM registers", [i for i, (a,b) in enumerate(zip(vm.R, expected["registers"])) if a != b])
            stop, pending = "vm_return", None
        except vm_full.NativeCall as exc:
            raise RefillUnsupported(f"unmodeled callback +{exc.f-base:#x} -> +{vm.m.u64(exc.arg)-base:#x}") from exc
        else:
            raise AssertionError("VM ended without the explicit native exit boundary")
        assert vm.m.rd(GUEST, 0xA000) == expected["guest"]
        assert all(vm.m.rd(page << 12, 4096) == data for page, data in expected["image"].items())
        assert model_allocations == expected["allocations"]
        assert frees == expected["frees"]
        assert vm_registrations == expected["registrations"], key + " registrations"
        assert vm_wakes == expected["wakes"], key + " wakes"
        assert vm_effects == expected["effects"], key + " ordered VM effects"
        assert vm.m.rd(oracle.TLS, 0xB00) == expected["tls"], key + " VM TLS"
        assert vm.m.rd(oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET, 141 * 16) == expected["pthread_generations"], key + " VM generations"
        results.append({"phase": key, "vm_entry_offset": hex(values[0] - base),
            "steps": vm.steps, "stop_bytecode_offset": hex(vm.pc - base), "boundary_offset": stop,
            "pending_target_offset": pending, "vm_path_returned": key == "parser",
            "all_32_vm_slots_match": key == "parser", "unpack_results": unpack_results,
            "guest_objects_match": True, "all_image_pages_match": True,
            "allocation_sequence_match": True, "allocations": len(model_allocations),
            "descriptor_match": descriptor_match, "modeled_callbacks": modeled, "explicit_free_calls": len(frees),
            "free_sequence_match": True, "tls_and_generation_state_match": True,
            "registration_and_wake_order_match": True, "all_ordered_effects_match": True,
            "native_prelude_snapshot_used": True, "complete_initializer": False})
    constructors = []
    for key, model, start, stop in (
        ("singleton136", objects.construct_singleton_layout136, 0x166370, 0x166544),
        ("registry320", objects.construct_registry_layout320, 0x2566EC, 0x256808),
    ):
        state, expected = snapshots[key], boundaries[key]
        allocation_next, model_allocations = state["allocation_next"], []
        def allocate_prefix(pages, size):
            nonlocal allocation_next
            pointer = allocation_next
            allocation_next += (size + 15) & ~15
            if allocation_next >= GUEST + 0x9000:
                raise RefillUnsupported("bounded constructor arena exhausted")
            _read_span(pages, pointer, size)
            model_allocations.append([size, pointer])
            model_effects.append(["allocate", size, pointer])
            return pointer
        model(state["pages"], object_address=state["object_address"], image_base=base, allocate=allocate_prefix)
        assert _read_span(state["pages"], GUEST, 0xA000) == expected["guest"], key + " guest"
        assert all(_read_span(state["pages"], page << 12, 4096) == data for page, data in expected["image"].items()), key + " image"
        assert model_allocations == expected["allocations"], key + " allocations"
        constructors.append({"phase": key, "entry_offset": hex(start), "boundary_offset": hex(stop),
            "guest_objects_match": True, "all_image_pages_match": True, "allocation_sequence_match": True,
            "allocations": len(model_allocations), "native_prelude_snapshot_used": True,
            "complete_initializer": False})
    # Both actual calls use the recovered bionic generation checks. The first
    # also allocates its key through the Python generation-table scanner.
    def once_wake(pages, pointer, operation, count):
        model_wakes.append([pointer, operation, count])
        model_effects.append(["wake", pointer, operation, count])
        return 0
    emutls = []
    for key in ("emutls_cold", "emutls_ready"):
        state, expected = snapshots[key], boundaries[key]
        allocation_next, model_allocations, model_wakes = state["allocation_next"], [], []
        pointer = objects.get_emulated_tls_address(state["pages"], control_address=state["object_address"],
            image_base=base, allocate=allocate_prefix, reallocate=reallocate,
            get_specific=get_specific, set_specific=set_specific, create_key=create_key, once_wake=once_wake)
        assert pointer == expected["return_pointer"], key + " pointer"
        assert _read_span(state["pages"], GUEST, 0xA000) == expected["guest"], key + " guest"
        assert _read_span(state["pages"], oracle.TLS, 0xB00) == expected["tls"], key + " TLS"
        assert _read_span(state["pages"], oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET,
                          141 * 16) == expected["pthread_generations"], key + " generations"
        assert all(_read_span(state["pages"], page << 12, 4096) == data for page, data in expected["image"].items()), key + " image"
        assert model_allocations == expected["allocations"], key + " allocations"
        assert model_wakes == expected["wakes"], key + " once wake"
        emutls.append({"phase": key, "entry_offset": "0x34377c",
            "control_offset": hex(state["object_address"] - base), "return_pointer_match": True,
            "guest_objects_match": True, "tls_generation_state_match": True, "all_image_pages_match": True,
            "pthread_generation_table_match": True, "pthread_generation_table_bytes": 141 * 16,
            "allocation_sequence_match": True, "allocations": len(model_allocations),
            "once_wake_sequence_match": True,
            "native_prelude_snapshot_used": True, "once_key_already_initialized": key == "emutls_ready",
            "python_key_creation": key == "emutls_cold", "complete_python_pthread_boot": False})
    state, expected = snapshots["tls_registry"], boundaries["tls_registry"]
    allocation_next, model_allocations, model_registrations, model_wakes = state["allocation_next"], [], [], []
    def get_tls(pages, control):
        return objects.get_emulated_tls_address(pages, control_address=control, image_base=base,
            allocate=allocate_prefix, reallocate=reallocate, get_specific=get_specific,
            set_specific=set_specific, create_key=create_key, once_wake=once_wake)
    def register_atexit(pages, destructor, obj, dso):
        model_registrations.append([destructor, obj, dso])
        model_effects.append(["register", destructor, obj, dso])
        return 0
    def register_destructor(pages, destructor, obj, dso):
        assert dso == base + 0x34C700
        return objects.register_emulated_thread_destructor(pages, destructor_address=destructor,
            object_address=obj, image_base=base, allocate=allocate_prefix, get_tls=get_tls,
            create_key=create_key, set_specific=set_specific, register_atexit=register_atexit, thread_id=137)
    objects.initialize_scoped_tls_registry(state["pages"], image_base=base, get_tls=get_tls,
                                          register_destructor=register_destructor)
    assert _read_span(state["pages"], GUEST, 0xA000) == expected["guest"], "TLS registry guest"
    assert _read_span(state["pages"], oracle.TLS, 0xB00) == expected["tls"], "TLS registry thread"
    assert _read_span(state["pages"], oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET,
                      141 * 16) == expected["pthread_generations"], "TLS registry generations"
    assert all(_read_span(state["pages"], page << 12, 4096) == data for page, data in expected["image"].items()), "TLS registry image"
    assert model_allocations == expected["allocations"], "TLS registry allocations"
    assert model_registrations == expected["registrations"], "TLS registry registrations"
    assert model_wakes == expected["wakes"], "TLS registry once wake"
    tls_registry = {"entry_offset": "0x269880", "guest_objects_match": True, "tls_state_match": True,
        "pthread_generation_table_match": True, "all_image_pages_match": True,
        "allocation_sequence_match": True, "registration_sequence_match": True,
        "once_wake_sequence_match": True,
        "allocations": len(model_allocations), "process_destructor_registrations": len(model_registrations),
        "native_prelude_snapshot_used": True, "complete_scoped_lock": False}
    scoped_locks = []
    for key, entry in (("scoped_acquire", 0x268EB0), ("scoped_release", 0x268FBC)):
        state, expected = snapshots[key], boundaries[key]
        allocation_next, model_allocations, model_registrations, model_frees, model_wakes = state["allocation_next"], [], [], [], []
        def initialize_registry(pages):
            objects.initialize_scoped_tls_registry(pages, image_base=base, get_tls=get_tls,
                                                  register_destructor=register_destructor)
        if key == "scoped_acquire":
            status = objects.construct_single_scoped_lock(state["pages"], object_address=state["object_address"],
                mutex_address=state["secondary_address"], scratch_address=state["stack_pointer"] - 0x48,
                image_base=base, allocate=allocate_prefix, get_tls=get_tls, initialize_registry=initialize_registry)
            assert status == 0
        else:
            objects.destroy_single_scoped_lock(state["pages"], object_address=state["object_address"],
                image_base=base, free=lambda pages, pointer: model_frees.append(pointer), get_tls=get_tls,
                initialize_registry=initialize_registry,
                broadcast=lambda pages, pointer: objects.broadcast_condition_no_waiters(
                    pages, condition_address=pointer,
                    wake=lambda pages, ptr, op, count: model_wakes.append([ptr, op, count]) or 0))
        assert _read_span(state["pages"], state["object_address"], 20) == expected["descriptor"], key + " guard"
        assert _read_span(state["pages"], GUEST, 0xA000) == expected["guest"], key + " guest"
        assert _read_span(state["pages"], oracle.TLS, 0xB00) == expected["tls"], key + " TLS"
        assert _read_span(state["pages"], oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET,
                          141 * 16) == expected["pthread_generations"], key + " generations"
        assert all(_read_span(state["pages"], page << 12, 4096) == data for page, data in expected["image"].items()), key + " image"
        assert model_allocations == expected["allocations"], key + " allocations"
        assert model_registrations == expected["registrations"], key + " registrations"
        assert model_frees == expected["frees"], key + " frees"
        assert model_wakes == expected["wakes"], (key, "wakes", [[hex(p - base), op, count] for p, op, count in expected["wakes"]])
        scoped_locks.append({"phase": key, "entry_offset": hex(entry), "guard_bytes_match": True,
            "guest_objects_match": True, "tls_state_match": True, "pthread_generation_table_match": True,
            "all_image_pages_match": True, "allocation_sequence_match": True, "registration_sequence_match": True,
            "free_sequence_match": True, "wake_sequence_match": True,
            "allocations": len(model_allocations), "explicit_free_calls": len(model_frees),
            "native_prelude_snapshot_used": True, "single_live_mutex_only": True, "full_scoped_lock_tree": False})
    registry_initialization = []
    for key in ("configuration_set", "registry320_full", "registry320_getter", "singleton136_full", "singleton136_getter",
                "cipher_callback", "checked_copy", "cipher_context", "stream_reference", "configuration_unpack"):
        state, expected = snapshots[key], boundaries[key]
        allocation_next, model_allocations, model_registrations, model_frees, model_wakes = state["allocation_next"], [], [], [], []
        model_effects = []
        def free_registry(pages, pointer):
            model_frees.append(pointer)
            model_effects.append(["free", pointer])
        def broadcast_registry(pages, pointer):
            return objects.broadcast_condition_no_waiters(pages, condition_address=pointer,
                wake=once_wake)
        def read_clock_registry(pages, clock_id):
            model_effects.append(["clock", clock_id])
            return 0, clock_seconds, 500000000
        common = dict(image_base=base, entry_stack_address=state["stack_pointer"],
            allocate=allocate_prefix, free=free_registry, get_tls=get_tls,
            initialize_registry=initialize_registry, broadcast=broadcast_registry)
        def get_singleton_cipher(pages, sp):
            return registry.get_singleton136_reference(pages, read_clock=read_clock_registry,
                thread_id=137, **(common | {"entry_stack_address": sp})).wrapper_address
        if key == "configuration_unpack":
            returned = protobuf.unpack_configuration_message(state["pages"],
                allocator_address=state["object_address"], length=state["secondary_address"],
                data_address=state["third_argument"], image_base=base, allocate=allocate_prefix, free=free_registry)
            assert returned == expected["return_value"], key + " return"
        elif key == "stream_reference":
            stream_cipher.transform_configuration_reference(state["pages"],
                output_reference_address=state["output_reference"], data_object_address=state["object_address"],
                key_object_address=state["secondary_address"], entry_stack_address=state["stack_pointer"],
                image_base=base, allocate=allocate_prefix, free=free_registry)
        elif key == "cipher_callback":
            cipher_callback.decrypt_configuration_reference(state["pages"],
                output_reference_address=state["output_reference"], data_object_address=state["object_address"],
                key_object_address=state["secondary_address"], iv_object_address=state["third_argument"],
                mode_address=state["fourth_argument"], entry_stack_address=state["stack_pointer"],
                image_base=base, allocate=allocate_prefix, free=free_registry, get_singleton=get_singleton_cipher)
        elif key == "checked_copy":
            cipher_callback.checked_forward_copy(state["pages"], output_address=state["object_address"],
                source_address=state["secondary_address"], length=state["third_argument"],
                entry_stack_address=state["stack_pointer"], get_singleton=get_singleton_cipher)
        elif key == "cipher_context":
            cipher_callback.initialize_cipher_context(state["pages"], descriptor_address=state["object_address"],
                context_address=state["output_reference"], image_base=base)
        elif key == "configuration_set":
            returned = registry.set_configuration_u32(state["pages"], registry_address=state["object_address"],
                key_address=state["secondary_address"], value=state["third_argument"] & 0xFFFFFFFF, **common)
            assert returned == expected["return_value"] & 0xFFFFFFFF, key + " return"
        elif key == "registry320_full":
            registry.construct_registry320(state["pages"], object_address=state["object_address"],
                read_clock=read_clock_registry, **common)
        elif key == "singleton136_full":
            registry.construct_singleton136(state["pages"], object_address=state["object_address"],
                read_clock=read_clock_registry, thread_id=137, **common)
        else:
            operation = registry.get_registry320_reference if key == "registry320_getter" else registry.get_singleton136_reference
            reference = operation(state["pages"], read_clock=read_clock_registry, thread_id=137, **common)
            assert reference.wrapper_address == expected["return_value"], key + " returned wrapper"
        if key in ("cipher_callback", "cipher_context", "checked_copy", "stream_reference"):
            pointer = state["object_address"] if key == "checked_copy" else state["output_reference"]
            assert _read_span(state["pages"], pointer, len(expected["descriptor"])) == expected["descriptor"], key + " explicit result bytes"
        got = _read_span(state["pages"], GUEST, 0xA000)
        if got != expected["guest"]:
            first = next(i for i, (a, b) in enumerate(zip(got, expected["guest"])) if a != b)
            raise AssertionError(f"{key} guest+{first:#x}")
        assert _read_span(state["pages"], oracle.TLS, 0xB00) == expected["tls"], key + " TLS"
        assert _read_span(state["pages"], oracle.LIBC_BASE + oracle.LIBC_PTHREAD_GENERATION_OFFSET,
                          141 * 16) == expected["pthread_generations"], key + " generations"
        assert all(_read_span(state["pages"], page << 12, 4096) == data for page, data in expected["image"].items()), key + " image"
        assert model_allocations == expected["allocations"], key + " allocations"
        assert model_registrations == expected["registrations"], key + " registrations"
        assert model_frees == expected["frees"], key + " frees"
        assert model_wakes == expected["wakes"], key + " wakes"
        assert model_effects == expected["effects"], key + " ordered effects"
        registry_initialization.append({"phase": key, "entry_offset": {
            "configuration_set": "0x2568c8", "registry320_full": "0x2566ec", "registry320_getter": "0x15e694",
            "singleton136_full": "0x166370", "singleton136_getter": "0x161068",
            "cipher_callback": "0x259dbc", "checked_copy": "0x276b9c", "cipher_context": "0x25aa48",
            "stream_reference": "0x2592b8", "configuration_unpack": "0x256088"}[key],
            "guest_objects_match": True, "tls_state_match": True, "pthread_generation_table_match": True,
            "all_image_pages_match": True, "allocation_sequence_match": True, "registration_sequence_match": True,
            "free_sequence_match": True, "wake_sequence_match": True, "allocations": len(model_allocations),
            "explicit_free_calls": len(model_frees), "native_prelude_snapshot_used": True,
            "explicit_return_value_compared": key == "configuration_unpack",
            "returned_null": returned == 0 if key == "configuration_unpack" else None,
            "recovered_python_tls_path_used": key not in ("cipher_context", "stream_reference", "configuration_unpack"),
            "ordered_allocator_clock_registration_wake_effects_match": True,
            "guard_boundary": "not_used" if key == "configuration_unpack" else "serialized_successful_single_thread_guard",
            "lazy_publication_compared": key in ("registry320_getter", "singleton136_full", "singleton136_getter"),
            "explicit_result_bytes_compared": key in ("cipher_callback", "cipher_context", "checked_copy", "stream_reference")})
    return {"image_base": hex(base), "native_control_returned": True, "phases": results,
            "constructor_prefixes": constructors,
            "emulated_tls": emutls,
            "tls_registry": tls_registry,
            "scoped_locks": scoped_locks,
            "registry_initialization": registry_initialization,
            "native_stack_writer_counts": stack_writer_counts,
            "pending_callback_native_visits": pending_visits,
            "configuration_decrypt_callback_python_implemented": True,
            "configuration_stream_callback_python_implemented": True,
            "configuration_fill_callback_python_implemented": True,
            "configuration_unpack_callback_python_implemented": True,
            "parser_observed_path_python_implemented": True,
            "independent_python_parser_prelude": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    os.environ["TOMATO_LIBMETASEC"] = str(args.library.resolve())
    import vm_full
    cases = []
    for base in (0x122C0000, 0x775C205000):
        for label, value in (("absent", None), ("sdk_30", b"30")):
            case = probe(args.library, args.libc, base=base, property_value=value, vm_module=vm_full)
            case["property_profile"] = label
            cases.append(case)
    report = {"cases": cases, "native_runs": len(cases), "vm_phase_comparisons": len(cases) * 2,
        "constructor_prefix_comparisons": len(cases) * 2,
        "emulated_tls_comparisons": len(cases) * 2,
        "tls_registry_comparisons": len(cases),
        "scoped_lock_comparisons": len(cases) * 2,
        "registry_and_cipher_comparisons": len(cases) * 10,
        "library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "fresh_elf": True, "external_captured_pages_used": False, "native_prelude_snapshot_used": True,
        "trace_branch_opaque_hooks_used": False, "jvm_used": False,
        "complete_python_prelude": False, "complete_88_byte_initializer": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"native_runs": len(cases), "vm_phase_comparisons": len(cases) * 2,
                      "constructor_prefix_comparisons": len(cases) * 2,
                      "emulated_tls_comparisons": len(cases) * 2,
                      "tls_registry_comparisons": len(cases),
                      "scoped_lock_comparisons": len(cases) * 2,
                      "registry_and_cipher_comparisons": len(cases) * 10}))


if __name__ == "__main__":
    main()
