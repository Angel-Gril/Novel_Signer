"""Fresh ELF/native differences for configuration comparison and RB insertion.

One native execution owns each operation sequence and its allocator. Synthetic
inputs drive both sides; native outputs are compared, never fed to the model.
Export offsets/counts only, including poisoned cleanup and preserved padding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X30

import vm9_registry as registry
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, REGS, STOP, fresh_pages, image_pages, native
from verify_vm9_strings import Effects, fields

CONTAINER, DESCRIPTOR, DISPATCH = GUEST + 0x1000, GUEST + 0x1300, GUEST + 0xF800
BASES = (0x122C0000, 0x775C205000)


def fixture(library, base, keys):
    pages = fresh_pages()
    pages.update(image_pages(library, base))
    _write_span(pages, DISPATCH, bytes.fromhex("1f2003d5"))
    _write_span(pages, DESCRIPTOR, b"".join((base + o).to_bytes(8, "little")
                for o in (0x182D6C, 0x165334, 0x188A94)))
    blocks, addresses = {}, []
    for i, key in enumerate(keys):
        obj, payload, value = GUEST + 0x2000 + i * 0x40, GUEST + 0x3000 + i * 0x40, GUEST + 0x2800 + i * 0x10
        assert len(key) < 0x40 and i < 32
        _write_span(pages, obj, (base + 0x34F5F8).to_bytes(8, "little"))
        fields(pages, obj + 8, len(key) + 1, len(key), payload)
        _write_span(pages, payload, key + b"\0")
        _write_span(pages, value, (1000 + i).to_bytes(4, "little"))
        blocks.update({obj: 24, payload: len(key) + 1, value: 4})
        addresses.append((obj, payload, value))
    return pages, blocks, addresses


def check_memory(label, pages, expected):
    got = _read_span(pages, GUEST, 0xA000)
    if got != expected:
        first = next(i for i, (a, b) in enumerate(zip(got, expected)) if a != b)
        raise AssertionError(f"{label}: guest+{first:#x}: {got[first]:#x} != {expected[first]:#x}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []
    comparisons = [(b"", b""), (b"", b"a"), (b"a", b""), (b"a", b"a"),
                   (b"a", b"aa"), (b"aa", b"a"), (b"z", b"a"), (b"a", b"z"),
                   (b"\xff", b"\x01"), (b"\x01", b"\xff"),
                   (b"a\0tail", b"a\0different"), (b"a\0", b"a\0tail"),
                   (b"\0long", b"\0"), (b"ab\0", b"ac\0"), (b"abc", b"abd")]
    for base in BASES:
        for index, (a, b) in enumerate(comparisons):
            for adapter in (False, True):
                pages, _, addresses = fixture(args.library, base, [a, b])
                first, second = addresses[0][0], addresses[1][0]
                if index == 14:  # Both fields and first payload cross page boundaries.
                    first = GUEST + 0x1FF4
                    _write_span(pages, first, _read_span(pages, addresses[0][0], 24))
                    payload = GUEST + 0x3FFE
                    _write_span(pages, payload, a + b"\0")
                    fields(pages, first + 8, len(a) + 1, len(a), payload)
                entry, operation = (0x188A94, registry.compare_string_objects) if adapter else (0x2473DC, registry.compare_string_fields)
                if not adapter:
                    first, second = first + 8, second + 8
                result, memory, _, _ = native(args.library, base, entry, [first, second], pages)
                actual = operation(pages, first_address=first, second_address=second)
                assert actual & 0xFFFFFFFF == result & 0xFFFFFFFF, (index, adapter, actual, result)
                check_memory("compare", pages, memory)
                cases.append({"case": f"compare_{index}_{adapter}", "image_base": hex(base),
                              "native_result_match": True, "guest_bytes_match": True})
        for invalid in ("null_first", "null_second", "null_payload_first", "null_payload_second",
                        "negative_first", "negative_second", "same_pointer", "empty_distinct_pointer"):
            pages, _, addresses = fixture(args.library, base, [b"a", b"b"])
            first, second = addresses[0][0] + 8, addresses[1][0] + 8
            if invalid == "null_first": first = 0
            if invalid == "null_second": second = 0
            if invalid == "null_payload_first": _write_span(pages, first + 8, bytes(8))
            if invalid == "null_payload_second": _write_span(pages, second + 8, bytes(8))
            if invalid == "negative_first": _write_span(pages, first + 4, bytes.fromhex("00000080"))
            if invalid == "negative_second": _write_span(pages, second + 4, bytes.fromhex("ffffffff"))
            if invalid == "same_pointer":
                fields(pages, first, 0, 0x7FFFFFFF, 0x80000000)
                fields(pages, second, 0, 0x7FFFFFFF, 0x80000000)
            if invalid == "empty_distinct_pointer":
                fields(pages, first, 0, 0, 0x80000000)
                fields(pages, second, 0, 0, 0x90000000)
            result, memory, _, _ = native(args.library, base, 0x2473DC, [first, second], pages)
            actual = registry.compare_string_fields(pages, first_address=first, second_address=second)
            assert actual & 0xFFFFFFFF == result & 0xFFFFFFFF
            check_memory(invalid, pages, memory)
            cases.append({"case": invalid, "image_base": hex(base), "native_result_match": True,
                          "guest_bytes_match": True})

    def sequence(base, label, keys, *, mutation=None):
        pages, blocks, addresses = fixture(args.library, base, keys + [b"missing"])
        queries = []
        for i, key in enumerate(keys + [b"missing"]):
            query, payload = GUEST + 0x1400 + i * 24, GUEST + 0x9000 + i * 0x40
            fields(pages, query + 8, len(key) + 1, len(key), payload)
            _write_span(pages, payload, key + b"\0")
            queries.append(query)
        expected, actual = Effects(blocks=blocks, mutate=mutation), Effects(blocks=blocks, mutate=mutation)
        operations = [("construct", 0x25BF14, [CONTAINER, DESCRIPTOR])]
        for (obj, _, value), query in zip(addresses[:-1], queries):
            operations.extend([("insert", 0x25BF3C, [CONTAINER, obj, value]),
                               ("lookup", 0x25C168, [CONTAINER, query])])
        for query in queries:
            operations.append(("lookup", 0x25C168, [CONTAINER, query]))
        completed = []
        def observer(cpu, address):
            if address != DISPATCH: return
            completed.append((cpu.reg_read(UC_ARM64_REG_X0), bytes(cpu.mem_read(GUEST, 0xA000)),
                              list(expected.calls), dict(expected.blocks)))
            if len(completed) == len(operations):
                cpu.reg_write(UC_ARM64_REG_PC, STOP)
                return
            _, entry, arguments = operations[len(completed)]
            for reg, value in zip(REGS, arguments): cpu.reg_write(reg, value)
            cpu.reg_write(UC_ARM64_REG_X30, DISPATCH)
            cpu.reg_write(UC_ARM64_REG_PC, base + entry)
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        native(args.library, base, operations[0][1], operations[0][2], pages,
            extra_registers={UC_ARM64_REG_X30: DISPATCH}, instruction_limit=200000,
            instruction_observer=observer, observed_memory=observed,
            malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size),
            host_imports={0x347FA0: lambda cpu: expected.native(cpu, "free", pointer=cpu.reg_read(UC_ARM64_REG_X0))})
        assert len(completed) == len(operations)
        for index, ((kind, _, arguments), (result, memory, calls, live)) in enumerate(zip(operations, completed)):
            if kind == "construct":
                registry.construct_configuration_tree(pages, container_address=CONTAINER,
                    descriptor_address=DESCRIPTOR, image_base=base, allocate=actual.malloc)
            elif kind == "insert":
                registry.insert_configuration_pair(pages, container_address=CONTAINER,
                    key_address=arguments[1], value_address=arguments[2], image_base=base,
                    allocate=actual.malloc, free=actual.free)
            else:
                got = registry.lookup_configuration_value(pages, container_address=CONTAINER,
                    key_address=arguments[1], image_base=base)
                assert got == result, (label, index, got, result)
            check_memory(f"{label}_{index}_{kind}", pages, memory)
            assert actual.calls == calls, (label, index, "effect order")
            assert actual.blocks == live, (label, index, "allocator state")
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items())
        cases.append({"case": label, "image_base": hex(base), "operation_count": len(operations),
            "all_intermediate_guest_bytes_match": True, "all_main_image_pages_match": True,
            "allocator_state_match": True, "effect_order_match": True, "lookup_returns_match": True,
            "allocation_sizes": [c[1] for c in actual.calls if c[0] != "free"],
            "free_count": sum(c[0] == "free" for c in actual.calls), "single_native_execution": True})

    sequences = {"ascending": list(b"abcdefghijklmnop"), "descending": list(b"ponmlkjihgfedcba"),
        "alternating": list(b"apbocndmelfkghij"), "left_right": list(b"cab"), "right_left": list(b"acb"),
        "duplicates": list(b"abcbacaa"), "nul_equivalent": [b"a\0x", b"a\0longer", b"b", b"a\0q"],
        "binary": [b"\xff", b"\x80", b"\x01", b"\0", b"", b"\xfe"]}
    for base in BASES:
        for label, keys in sequences.items():
            sequence(base, label, [bytes([k]) if isinstance(k, int) else k for k in keys])
        def mutate_pair(kind, index, read, write):
            if kind == "malloc" and index == 4:  # Second pair malloc, after missing-key lookup.
                write(GUEST + 0x3040, b"a\0")
        sequence(base, "pair_malloc_duplicate", [b"a", b"b"], mutation=mutate_pair)
        def mutate_side(kind, index, read, write):
            if kind == "malloc" and index == 5:  # Second node malloc, after insertion side decision.
                write(GUEST + 0x3040, b"z\0")
        sequence(base, "node_malloc_key_change", [b"m", b"a"], mutation=mutate_side)

    base = BASES[0]
    for label in ("unknown_comparator", "unknown_hook", "unknown_cleanup", "cycle", "bad_color",
                  "node_limit", "byte_limit", "null_pair", "null_node", "missing_payload", "missing_node"):
        pages, blocks, addresses = fixture(args.library, base, [b"a", b"b"])
        effects = Effects(blocks=blocks)
        controller = registry.construct_configuration_tree(pages, container_address=CONTAINER,
            descriptor_address=DESCRIPTOR, image_base=base, allocate=effects.malloc)
        registry.insert_configuration_pair(pages, container_address=CONTAINER, key_address=addresses[0][0],
            value_address=addresses[0][2], image_base=base, allocate=effects.malloc, free=effects.free)
        sentinel = int.from_bytes(_read_span(pages, controller, 8), "little")
        root = int.from_bytes(_read_span(pages, sentinel + 8, 8), "little")
        kw = {}
        key = addresses[1][0]
        if label == "unknown_comparator": _write_span(pages, CONTAINER + 24, bytes(8))
        if label == "unknown_hook": _write_span(pages, controller + 24, bytes(8))
        if label == "unknown_cleanup":
            _write_span(pages, CONTAINER + 8, bytes(8)); key = addresses[0][0]
        if label == "cycle": _write_span(pages, root + 24, root.to_bytes(8, "little"))
        if label == "bad_color": _write_span(pages, root, (7).to_bytes(4, "little"))
        if label == "node_limit": kw["max_nodes"] = 1
        if label == "byte_limit":
            kw["max_bytes"] = 0
        if label in ("null_pair", "null_node"):
            effects.failures.add(effects.allocation_index + int(label == "null_node"))
        if label == "missing_payload": _write_span(pages, key + 16, (0x80000000).to_bytes(8, "little"))
        if label == "missing_node": _write_span(pages, sentinel + 8, (0x80000000).to_bytes(8, "little"))
        before = {p: bytes(b) for p, b in pages.items()}
        try:
            registry.insert_configuration_pair(pages, container_address=CONTAINER, key_address=key,
                value_address=addresses[1][2], image_base=base, allocate=effects.malloc, free=effects.free, **kw)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else: raise AssertionError(label + " accepted")
    report = {"library_sha256": LIBRARY_SHA256, "differential_cases": len(cases),
        "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "fresh_memory": True, "captured_pages_used": False, "native_output_used_as_input": False,
        "explicit_allocator_boundary": True, "configuration_tree_deletion": False,
        "complete_registry320_initializer": False, "complete_singleton136_initializer": False,
        "complete_python_medusa": False, "jvm_used": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
