"""Observe the actual output tree of the fresh bootstrap/request continuation.

The parent driver supplies explicit request/JNI/import services. This verifier
adds observations only, follows the native owning reference, and retains its
construction, formatting and assignment provenance. A nonzero reference is not
treated as successful signing. Native pages never initialize a Python model.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as arm

import verify_vm9_bootstrap_request_memcpy_continuation_20261026 as continuation
import verify_vm9_dispatch_table_encoding_20261026 as encoding
import verify_vm9_signer_objects as oracle


MAX_NODES = 64
MAX_BYTES = 4096


def _reg(cpu, index):
    return cpu.reg_read(getattr(arm, f"UC_ARM64_REG_X{index}"))


def _read(cpu, address, size):
    assert 0 < address <= (1 << 64) - size
    return bytes(cpu.mem_read(address, size))


def _u(cpu, address, size=8):
    return int.from_bytes(_read(cpu, address, size), "little")


def _cstring(cpu, address):
    data = bytearray()
    for index in range(MAX_BYTES):
        value = _read(cpu, address + index, 1)
        if value == b"\0":
            return bytes(data)
        data.extend(value)
    raise AssertionError("native C string exceeds the observation bound")


def _string(cpu, address, image):
    assert _u(cpu, address) == image + 0x34F5F8
    capacity, length = _u(cpu, address + 8, 4), _u(cpu, address + 12, 4)
    assert 0 <= length < capacity <= MAX_BYTES
    pointer = _u(cpu, address + 16)
    payload = _read(cpu, pointer, length)
    assert _read(cpu, pointer + length, 1) == b"\0"
    return {"object_address": hex(address), "vtable_offset": "0x34f5f8",
            "capacity": capacity, "length": length,
            "payload_address": hex(pointer),
            "payload_sha256": hashlib.sha256(payload).hexdigest()}, payload


def _tree(cpu, reference, image):
    container, counter = _u(cpu, reference), _u(cpu, reference + 8)
    assert container and counter and container != counter
    expected = (0x35B7C0, 0x182D6C, 0x182D6C, 0x188A94)
    assert tuple(_u(cpu, container + i * 8) - image for i in range(4)) == expected
    controller = _u(cpu, container + 32)
    assert _u(cpu, controller + 16) == image + 0x188A94
    assert _u(cpu, controller + 24) == image + 0x24B560
    sentinel, count = _u(cpu, controller), _u(cpu, controller + 8)
    assert count <= MAX_NODES and _u(cpu, counter, 4) == 1
    root = _u(cpu, sentinel + 8)
    nodes, seen, keys = [], set(), []

    def visit(node, parent):
        if not node:
            return
        assert node != sentinel and node not in seen and len(seen) < MAX_NODES
        seen.add(node)
        assert _u(cpu, node + 8) == parent and _u(cpu, node, 4) in (0, 1)
        visit(_u(cpu, node + 16), node)
        pair = _u(cpu, node + 32)
        key, raw_key = _string(cpu, _u(cpu, pair), image)
        value, raw_value = _string(cpu, _u(cpu, pair + 8), image)
        keys.append(raw_key)
        nodes.append({"node_address": hex(node), "pair_address": hex(pair),
                      "key": key, "value": value})
        visit(_u(cpu, node + 24), node)

    visit(root, sentinel)
    assert len(nodes) == count and keys == sorted(set(keys))
    if nodes:
        assert _u(cpu, sentinel + 16) == int(nodes[0]["node_address"], 16)
        assert _u(cpu, sentinel + 24) == int(nodes[-1]["node_address"], 16)
    else:
        assert not root and _u(cpu, sentinel + 16) == sentinel
        assert _u(cpu, sentinel + 24) == sentinel
    return {"reference_address": hex(reference), "container_address": hex(container),
            "counter_address": hex(counter), "counter_value": _u(cpu, counter, 4),
            "container_vtable_offset": "0x35b7c0", "controller_address": hex(controller),
            "sentinel_address": hex(sentinel), "node_count": count, "nodes": nodes,
            "parent_links_count_order_and_extrema_valid": True}, keys


def static_evidence(library):
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".text")
        data, start = section.data(), section["sh_addr"]
        bytecode = next(segment for segment in elf.iter_segments()
                        if segment["p_type"] == "PT_LOAD"
                        and segment["p_vaddr"] <= 0xF858C
                        and 0xF8590 <= segment["p_vaddr"] + segment["p_filesz"])
        stream.seek(bytecode["p_offset"] + 0xF858C - bytecode["p_vaddr"])
        word = int.from_bytes(stream.read(4), "little")
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    expected = {0x16AA48: ("blr", "x8"),
                0x27E804: ("str", "x8, [x19]"),
                0x27E80C: ("str", "x8, [x19, #8]")}
    rows = []
    for address, fact in expected.items():
        instruction = next(md.disasm(data[address - start:address - start + 4], address))
        assert (instruction.mnemonic, instruction.op_str) == fact
        rows.append({"offset": hex(address), "bytes": instruction.bytes.hex(),
                     "mnemonic": instruction.mnemonic, "operands": instruction.op_str})
    # Independently decode the observed MOVsxt word, without importing the
    # interpreter or using native output to choose a replacement status.
    assert word == 0x7F60F97B and word & 0x3F == 59
    source = ((word >> 17) & 0xF) | ((word >> 27) & 0x10)
    destination = ((word >> 7) & 0xF) | ((word >> 12) & 0x10)
    immediate = ((word >> 21) & 0x1F) | (((word >> 11) & 0x1F) << 5)
    immediate |= (((word >> 26) & 0x1F) << 10) | (((word >> 6) & 1) << 15)
    signed = immediate - 0x10000 if immediate & 0x8000 else immediate
    assert (source, destination, signed) == (0, 2, -5)
    return {"native_instructions": rows,
            "status_bytecode": {"offset": "0xf858c", "word": hex(word),
                                "opcode": 59, "source_slot": source,
                                "destination_slot": destination, "signed_immediate": signed}}


def run(library, libc, image, handlers):
    original_native, original_count = continuation.bootstrap.native, continuation.TABLE_PAGE_COUNT
    holder, callbacks, output_writes, status_writes, insertions, formats = {}, [], [], [], [], []
    history = deque(maxlen=20)
    root_history = deque(maxlen=48)
    guard_writes = []
    original_uc = oracle.Uc

    def cpu_factory(*args, **kwargs):
        cpu = original_uc(*args, **kwargs)
        first_hook = None

        def first_instruction(c, _address, _size, _user):
            holder["guard_before_native_bootstrap"] = _read(c, image + 0x3D1558, 8).hex()
            c.hook_del(first_hook)

        def guard_write(c, _access, address, size, value, _user):
            pc, caller = c.reg_read(arm.UC_ARM64_REG_PC), _reg(c, 30)
            guard_writes.append({"pc": hex(pc), "pc_offset": hex(pc - image),
                                 "caller_address": hex(caller), "caller_offset": hex(caller - image),
                                 "address_offset": hex(address - image), "size": size,
                                 "value": hex(value & ((1 << (size * 8)) - 1))})

        first_hook = cpu.hook_add(UC_HOOK_CODE, first_instruction)
        cpu.hook_add(UC_HOOK_MEM_WRITE, guard_write, begin=image + 0x3D1558, end=image + 0x3D155F)
        return cpu

    def native(*args, **kwargs):
        result = original_native(*args, **kwargs)
        cpu, service = result[:2]
        holder.update(cpu=cpu, service=service)

        def code(c, address, _size, _user):
            offset = address - image
            if offset in handlers:
                # Native x19 addresses the current bytecode-PC slot, rather
                # than containing the bytecode PC itself.
                slot = _reg(c, 19)
                pc = _u(c, slot)
                history.append({"handler_offset": hex(offset),
                                "bytecode_pc_slot": hex(slot),
                                "bytecode_pc_offset": hex(pc - image),
                                "instruction_word": hex(_u(c, pc, 4)),
                                "backing_address": hex(_reg(c, 28))})
            if offset == 0x2830C4:
                holder["request_entry"] = {"x" + str(i): hex(_reg(c, i)) for i in (0, 1, 2, 3, 8)}
                holder["request_entry"]["stack_address"] = hex(c.reg_read(arm.UC_ARM64_REG_SP))
                holder["request_backing"] = c.reg_read(arm.UC_ARM64_REG_SP) - 0x148
            if offset in handlers and _reg(c, 28) == holder.get("request_backing"):
                entry = dict(history[-1])
                entry["first_four_virtual_registers"] = [hex(_u(c, _reg(c, 28) + i * 8)) for i in range(4)]
                if root_history and root_history[-1]["bytecode_pc_offset"] == entry["bytecode_pc_offset"]:
                    root_history[-1] = entry
                else:
                    root_history.append(entry)
                if entry["bytecode_pc_offset"] == "0xf83f8":
                    pointer = _u(c, _reg(c, 28) + 30 * 8)
                    holder["gate_source"] = {"load_bytecode_offset": "0xf83f8",
                                             "source_address": hex(pointer),
                                             "source_image_offset": hex(pointer - image),
                                             "source_byte": _u(c, pointer, 1)}
                if entry["bytecode_pc_offset"] == "0xf8404":
                    gate = holder["gate_source"]
                    gate["branch_bytecode_offset"] = "0xf8404"
                    gate["masked_r1"] = _u(c, _reg(c, 28) + 8)
                    gate["r0"] = _u(c, _reg(c, 28))
                    assert gate["source_byte"] & 1 == gate["masked_r1"] == 1
                    assert gate["r0"] == 0
                if entry["bytecode_pc_offset"] == "0xf8554" and "gate_source" in holder:
                    holder["gate_source"]["taken_destination_observed"] = "0xf8554"
            if offset == 0x16AA48:
                argument = _reg(c, 0)
                words = [_u(c, argument + i * 8) for i in range(4)]
                row = {"wrapper_offset": hex(_reg(c, 8) - image),
                       "target_offset": hex(words[0] - image),
                       "argument_address": hex(argument), "words": [hex(v) for v in words],
                       "bytecode_pc_offset": hex(_u(c, _reg(c, 19)) - image)}
                if words[0] == image + 0x248908:
                    row["string_argument_address"] = hex(_u(c, argument + 32))
                callbacks.append(row)
            if offset == 0x248908:
                integer = _reg(c, 2) & 0xFFFFFFFF
                formats.append({"object_address": hex(_reg(c, 0)),
                                "format_hex": _cstring(c, _reg(c, 1)).hex(),
                                "signed_int32": integer - (1 << 32) if integer >> 31 else integer,
                                "string_argument_length": len(_cstring(c, _reg(c, 3)))})
            if offset == 0x25BF3C:
                key, raw_key = _string(c, _reg(c, 1), image)
                value, raw_value = _string(c, _reg(c, 2), image)
                assert raw_key == b"X-Neptune" and raw_value == b"-5|"
                insertions.append({"container_address": hex(_reg(c, 0)),
                                   "key": key, "value": value,
                                   "known_diagnostic_key": "X-Neptune"})

        def write(c, _access, address, size, value, _user):
            pc = c.reg_read(arm.UC_ARM64_REG_PC) - image
            raw_value = value & ((1 << (size * 8)) - 1)
            if continuation.dispatch.OUT <= address < continuation.dispatch.OUT + 16:
                assert address + size <= continuation.dispatch.OUT + 16
                output_writes.append({"pc_offset": hex(pc), "address": hex(address),
                                      "size": size, "value": hex(raw_value)})
            if size >= 4 and raw_value & 0xFFFFFFFF == 0xFFFFFFFB:
                row = {"pc_offset": hex(pc), "address": hex(address),
                       "size": size, "value": hex(raw_value),
                       "recent_vm_handlers": list(history)}
                if pc == 0x16DB74:
                    backing = _reg(c, 28)
                    assert _u(c, _reg(c, 19)) == image + 0xF858C
                    assert address == backing + 2 * 8 and size == 8
                    assert _u(c, backing) == 0 and _reg(c, 10) == (1 << 64) - 5
                    row["status_origin"] = {"bytecode_offset": "0xf858c",
                                            "source_slot": 0, "source_value": 0,
                                            "destination_slot": 2, "signed_immediate": -5,
                                            "native_result": -5,
                                            "recent_root_vm_handlers": list(root_history)}
                status_writes.append(row)

        cpu.hook_add(UC_HOOK_CODE, code, begin=image + 0x168324, end=image + 0x347E64)
        cpu.hook_add(UC_HOOK_MEM_WRITE, write)
        cpu.ctl_flush_tb()
        return result

    continuation.bootstrap.native = native
    continuation.TABLE_PAGE_COUNT = 0
    oracle.Uc = cpu_factory
    try:
        result = continuation.run(library, libc, image)
    finally:
        oracle.Uc = original_uc
        continuation.bootstrap.native = original_native
        continuation.TABLE_PAGE_COUNT = original_count
    assert result["request_reached_oracle_stop"] and result["unmapped_event_count"] == 0
    cpu, service = holder["cpu"], holder["service"]
    reference = int(result["output_reference_address"], 16)
    tree, keys = _tree(cpu, reference, image)
    assert tree["node_count"] == 1 and keys == [b"X-Neptune"]
    assert len(insertions) == len(formats) == 1
    insertion, node = insertions[0], tree["nodes"][0]
    assert insertion["container_address"] == tree["container_address"]
    assert insertion["key"] == node["key"] and insertion["value"] == node["value"]
    assert formats == [{"object_address": node["value"]["object_address"],
                        "format_hex": b"%d|%s".hex(), "signed_int32": -5,
                        "string_argument_length": 0}]
    assert {row["pc_offset"] for row in output_writes} >= {"0x27e804", "0x27e80c"}
    assert output_writes[-2]["value"] == tree["container_address"]
    assert output_writes[-1]["value"] == tree["counter_address"]
    assert service.sizes[int(tree["container_address"], 16)] == 40
    assert service.sizes[int(tree["counter_address"], 16)] == 4
    assert any(row["pc_offset"] == "0x16db74" for row in status_writes)
    assert any(row["target_offset"] == "0x248908" for row in callbacks)
    assert holder["gate_source"]["taken_destination_observed"] == "0xf8554"
    assert holder["gate_source"]["source_image_offset"] == "0x3d1558"
    assert holder["guard_before_native_bootstrap"] == bytes(8).hex() and guard_writes
    return {"image_base": hex(image), "continuation": result,
            "request_entry": holder["request_entry"], "output_tree": tree,
            "output_reference_writes": output_writes, "callback_ledger": callbacks,
            "format_calls": formats, "tree_insertions": insertions,
            "negative_status_writes": status_writes,
            "negative_status_gate": holder["gate_source"],
            "guard_before_native_bootstrap_hex": holder["guard_before_native_bootstrap"],
            "native_registry_guard_writes": guard_writes,
            "output_tree_and_refcount_allocations_known": True,
            "formatted_value_is_inserted_value_and_returned_value": True,
            "known_diagnostic_key": "X-Neptune",
            "only_diagnostic_header_returned": True,
            "requested_signer_headers_generated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    static = static_evidence(args.library)
    tables = encoding.static_evidence(args.library)
    handlers = {int(row["decoded_handler_offset"], 16)
                for table in tables["tables"] for row in table["entries"]}
    cases = []
    for image in continuation.BASES:
        cases.append(run(args.library, args.libc, image, handlers))
        print("native output reference", hex(image), "valid tree; one diagnostic entry", flush=True)
    report = {"schema": "vm9-request-output-reference-fresh-20261026-v1",
              "evidence_date": "2026-10-26", "sample_sha256": oracle.LIBRARY_SHA256,
              "matching_libc_sha256": hashlib.sha256(args.libc.read_bytes()).hexdigest(),
              "static": static, "cases": cases,
              "fresh_native_continuations": len(cases), "observation_only": True,
              "translation_cache_flushed_after_observer_install": True,
              "external_dispatch_canary_pages_mapped": False,
              "native_snapshot_input": False, "python_model_initialized_from_native": False,
              "synthetic_dispatch_table_used": False, "synthetic_callback_vtable_used": False,
              "output_reference_valid_tree_verified": True,
              "fresh_standalone_signer_verified": False,
              "whole_request_native_differential_verified": False,
              "online_header_acceptance_verified": False,
              "interpretation": "The continuation returns an allocated owning configuration-tree "
                  "reference with counter one. Its sole X-Neptune entry is constructed by the "
                  "signed-int32/C-string formatter with status -5 and an empty string; no other "
                  "signer header is returned. Bytecode +f8404 takes the +f8554 branch because the "
                  "registry guard +3d1558 has low bit one, then +f858c produces status -5. "
                  "Nonzero output and native return do not establish signing.",
              "limitations": ["Request, JNI and OS/import providers remain the parent's explicit synthetic fixture.",
                              "The status producer is observed; the business meaning of -5 is not inferred.",
                              "Payloads are retained as lengths/hashes, not live headers or identifiers.",
                              "No Python whole-request differential, live JVM or online acceptance is claimed."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
