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
    UC_ARM64_REG_X3, UC_ARM64_REG_X4,
)

import vm9_objects as objects
import verify_vm9_root_configuration as oracle
from vm9_allocator import _read_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256


class PrefixBoundary(Exception):
    pass


def probe(library, libc, *, base, property_value, vm_module):
    vm_full = vm_module
    snapshots, boundaries, allocations = {}, {}, []
    pending_visits, pending_active, pending_finished = {}, False, False

    def boundary(cpu, key, argument=None, width=0):
        boundaries[key] = {
            "guest": bytes(cpu.mem_read(GUEST, 0xA000)),
            "image": {page: bytes(cpu.mem_read(page << 12, 4096))
                      for page in snapshots[key]["pages"] if base <= page << 12 < base + 0x400000},
            "allocations": list(allocations[snapshots[key]["allocation_index"]:]),
            "descriptor": bytes(cpu.mem_read(argument, width)) if width else None,
        }

    def observe(cpu, address):
        nonlocal pending_active, pending_finished
        offset = address - base
        if offset == 0x259DBC and not pending_finished:
            pending_active = True
        elif offset == 0x26354C and pending_active:
            pending_active, pending_finished = False, True
        if pending_active and offset in (0x259DBC, 0x276B9C, 0x161068, 0x166370, 0x25AB1C, 0x242640):
            key = hex(offset)
            pending_visits[key] = pending_visits.get(key, 0) + 1
        if offset == 0x168324:
            values = [cpu.reg_read(reg) for reg in (
                UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4)]
            key = {base + 0x991C0: "root", base + 0x9A6F0: "parser"}.get(values[0])
            if key and key not in snapshots:
                descriptor = [int.from_bytes(cpu.mem_read(values[4] + i * 8, 8), "little") for i in range(3)]
                pages = {page >> 12: bytearray(cpu.mem_read(page, 4096))
                         for begin, end, _ in cpu.mem_regions() for page in range(begin, end + 1, 4096)}
                snapshots[key] = {"values": values, "descriptor": descriptor, "pages": pages,
                    "allocation_index": len(allocations),
                    "allocation_next": max(pointer + ((size + 15) & ~15) for size, pointer in allocations)}
        elif offset == 0x261A1C and "root" in snapshots and "root" not in boundaries:
            boundary(cpu, "root")
        elif offset == 0x263534 and "parser" in snapshots and "parser" not in boundaries:
            argument = cpu.reg_read(UC_ARM64_REG_X0)
            if int.from_bytes(cpu.mem_read(argument, 8), "little") == base + 0x259DBC:
                boundary(cpu, "parser", argument, 48)

    control = oracle.probe(library, libc, base=base, property_value=property_value,
        instruction_observer=observe,
        allocation_effect=lambda cpu, size, pointer: allocations.append([size, pointer]))
    assert control["returned"] and set(snapshots) == set(boundaries) == {"root", "parser"}
    assert pending_finished and pending_visits.get("0x166370") == 1 and pending_visits.get("0x242640", 0) > 0

    class StrictMem(vm_full.Mem):
        def __init__(self, pages):
            self.pages = pages
        def _pg(self, address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported("unmapped fresh guest page")
            return self.pages[address >> 12]

    results = []
    vm_full.B = base
    for key in ("root", "parser"):
        state, expected = snapshots[key], boundaries[key]
        values, descriptor = state["values"], state["descriptor"]
        vm = vm_full.VM(StrictMem(state["pages"]), values[0] - base,
            values[1], values[2], values[3], descriptor[0], descriptor[2], maxsteps=100000)
        vm.R[29], vm.R[31] = (descriptor[1] - 0x130) & ~15, descriptor[2]
        allocation_next = state["allocation_next"]
        model_allocations, modeled, frees = [], [], []

        def allocate(pages, size):
            nonlocal allocation_next
            pointer = allocation_next
            allocation_next += (size + 15) & ~15
            if allocation_next >= GUEST + 0x9000:
                raise RefillUnsupported("bounded VM allocation arena exhausted")
            _read_span(pages, pointer, size)
            model_allocations.append([size, pointer])
            return pointer

        def free(pages, pointer):
            # Exactly the nonreusing free boundary used by the native oracle.
            frees.append(pointer)

        def reallocate(pages, pointer, size):
            raise RefillUnsupported("this native prefix has no realloc boundary")

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
            elif (wrapper, target) == (0x2634C4, 0x2484B8):
                objects.destroy_string_object(current.m.pages, object_address=words[1],
                    image_base=base, free=free)
            elif wrapper == 0x263504 and target in (0x25874C, 0x258780):
                objects.construct_digest_reference(current.m.pages, object_address=words[1],
                    source_object_address=words[2], algorithm="md5" if target == 0x25874C else "sha1",
                    flag=words[3] & 255, image_base=base, allocate=allocate, reallocate=reallocate, free=free)
            elif (wrapper, target) == (0x263524, 0x248344):
                objects.construct_string_object(current.m.pages, object_address=words[1],
                    source_address=words[2], allocate=allocate, vtable_address=base + 0x34F5F8,
                    empty_descriptor_address=base + 0x6E168)
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
        except vm_full.NativeCall as exc:
            assert key == "parser" and exc.f == base + 0x263534 and vm.m.u64(exc.arg) == base + 0x259DBC
            descriptor_match = vm.m.rd(exc.arg, 48) == expected["descriptor"]
            assert descriptor_match
            stop, pending = "0x263534", "0x259dbc"
        else:
            raise AssertionError("VM unexpectedly crossed the unimplemented boundary")
        assert vm.m.rd(GUEST, 0xA000) == expected["guest"]
        assert all(vm.m.rd(page << 12, 4096) == data for page, data in expected["image"].items())
        assert model_allocations == expected["allocations"]
        results.append({"phase": key, "vm_entry_offset": hex(values[0] - base),
            "steps": vm.steps, "stop_bytecode_offset": hex(vm.pc - base), "boundary_offset": stop,
            "pending_target_offset": pending, "guest_objects_match": True, "all_image_pages_match": True,
            "allocation_sequence_match": True, "allocations": len(model_allocations),
            "descriptor_match": descriptor_match, "modeled_callbacks": modeled, "explicit_free_calls": len(frees),
            "native_prelude_snapshot_used": True, "complete_initializer": False})
    return {"image_base": hex(base), "native_control_returned": True, "phases": results,
            "pending_callback_native_visits": pending_visits,
            "pending_callback_python_implemented": False}


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
        "library_sha256": LIBRARY_SHA256, "libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
        "fresh_elf": True, "external_captured_pages_used": False, "native_prelude_snapshot_used": True,
        "trace_branch_opaque_hooks_used": False, "jvm_used": False,
        "complete_python_prelude": False, "complete_88_byte_initializer": False, "complete_python_medusa": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"native_runs": len(cases), "vm_phase_comparisons": len(cases) * 2}))


if __name__ == "__main__":
    main()
