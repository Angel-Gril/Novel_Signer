"""Fresh native/independent-AES differences for guest schedules and dispatch.

Synthetic keys/data only. Native schedule output is never model input.
Sequences share one native CPU; compare every intermediate object/image byte.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from Crypto.Cipher import AES
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0, UC_ARM64_REG_X30

import vm9_cipher as cipher
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, REGS, STOP, fresh_pages, image_pages, native
from verify_vm9_registry import BASES, DISPATCH, check_memory

ENTRY_SP = GUEST + 0xEF00
DESCRIPTOR, MODE = GUEST + 0x2500, GUEST + 0x2520


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []
    rng = random.Random(0x242640)

    def fixture(base, key_size, *, key_alias=None, cross_page=False):
        pages = fresh_pages()
        pages.update(image_pages(args.library, base))
        context = GUEST + (0x1FF8 if cross_page else 0x1000)
        key_address = context + key_alias if key_alias is not None else GUEST + 0x2800
        key = bytes(rng.randrange(256) for _ in range(max(32, key_size if key_size < 64 else 32)))
        payload = bytes(rng.randrange(256) for _ in range(160))
        source, output = GUEST + (0x2FF8 if cross_page else 0x3000), GUEST + (0x3FF8 if cross_page else 0x3800)
        _write_span(pages, key_address, key)
        _write_span(pages, source, payload)
        _write_span(pages, context + 0x1E8, bytes(range(16)))
        _write_span(pages, DESCRIPTOR, MODE.to_bytes(8, "little"))
        _write_span(pages, MODE, bytes(4))
        _write_span(pages, DISPATCH, bytes.fromhex("1f2003d5"))
        return pages, context, key_address, key, source, output, payload

    def compare(base, label, pages, operations, *, independent=None):
        completed = []
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        def observer(cpu, address):
            if address != DISPATCH: return
            completed.append((cpu.reg_read(UC_ARM64_REG_X0), bytes(cpu.mem_read(GUEST, 0xA000))))
            if len(completed) == len(operations):
                cpu.reg_write(UC_ARM64_REG_PC, STOP)
                return
            _, entry, arguments = operations[len(completed)]
            for reg, value in zip(REGS, arguments): cpu.reg_write(reg, value)
            cpu.reg_write(UC_ARM64_REG_X30, DISPATCH)
            cpu.reg_write(UC_ARM64_REG_PC, base + entry)
        native(args.library, base, operations[0][1], operations[0][2], pages,
            extra_registers={UC_ARM64_REG_X30: DISPATCH}, instruction_limit=300000,
            instruction_observer=observer, observed_memory=observed)
        for index, ((kind, _, arguments), (result, memory)) in enumerate(zip(operations, completed)):
            if kind == "schedule":
                got = cipher.construct_cipher_schedule(pages, context_address=arguments[0],
                    key_address=arguments[1], key_size=arguments[2], image_base=base)
            elif kind in ("encrypt", "decrypt"):
                operation = cipher.encrypt_cipher_block if kind == "encrypt" else cipher.decrypt_cipher_block
                operation(pages, context_address=arguments[0], source_address=arguments[1],
                          output_address=arguments[2], image_base=base)
                got = None
            elif kind == "cbc":
                got = cipher.decrypt_cipher_cbc(pages, context_address=arguments[0],
                    source_address=arguments[1], output_address=arguments[2], length=arguments[3],
                    entry_stack_address=ENTRY_SP, image_base=base)
            else:
                got = cipher.process_cipher_blocks(pages, mode_descriptor_address=arguments[0],
                    context_address=arguments[1], source_address=arguments[2], output_address=arguments[3],
                    length=arguments[4], entry_stack_address=ENTRY_SP, image_base=base)
            if got is not None:
                assert got & 0xFFFFFFFF == result & 0xFFFFFFFF, (label, index, "status", got, result)
            check_memory(f"{label}_{index}", pages, memory)
        assert len(completed) == len(operations)
        assert all(_read_span(pages, a, n) == data for (a, n), data in observed.items()), label + " image"
        if independent:
            address, payload = independent
            assert _read_span(pages, address, len(payload)) == payload, label + " independent AES"
        cases.append({"case": label, "image_base": hex(base), "operation_count": len(operations),
            "all_intermediate_guest_bytes_match": True, "all_main_image_pages_match": True,
            "native_status_match": True, "independent_aes_checked": independent is not None,
            "single_native_execution": True})

    for base in BASES:
        for size in (16, 24, 32):
            for cross_page in (False, True):
                pages, ctx, key_address, key, src, dst, data = fixture(base, size, cross_page=cross_page)
                compare(base, f"schedule_{size}_{cross_page}", pages,
                        [("schedule", 0x241E9C, [ctx, key_address, size])])
            for delta in (-4, 0, 4, 0xF0, 0x1E0):
                pages, ctx, key_address, *_ = fixture(base, size, key_alias=delta)
                compare(base, f"schedule_alias_{size}_{delta}", pages,
                        [("schedule", 0x241E9C, [ctx, key_address, size])])
            for operation, entry in (("encrypt", 0x2422EC), ("decrypt", 0x242640)):
                for delta in (None, 0, -3, 5):
                    pages, ctx, key_address, key, src, dst, data = fixture(base, size, cross_page=delta is None)
                    if delta is not None: dst = src + delta
                    reference = AES.new(key[:size], AES.MODE_ECB)
                    expected = reference.encrypt(data[:16]) if operation == "encrypt" else reference.decrypt(data[:16])
                    compare(base, f"{operation}_{size}_{delta}", pages,
                        [("schedule", 0x241E9C, [ctx, key_address, size]), (operation, entry, [ctx, src, dst])],
                        independent=(dst, expected))
            for mode in (0, 1):
                for length in (0, 1, 15, 16, 17, 31, 32, 48, 64):
                    pages, ctx, key_address, key, src, dst, data = fixture(base, size)
                    _write_span(pages, MODE, mode.to_bytes(4, "little"))
                    expected = None
                    if mode == 0:
                        width = (length + 15) & ~15
                        expected = AES.new(key[:size], AES.MODE_ECB).decrypt(data[:width])
                    elif length % 16 == 0:
                        expected = AES.new(key[:size], AES.MODE_CBC, bytes(range(16))).decrypt(data[:length])
                    compare(base, f"dispatch_{mode}_{size}_{length}", pages,
                        [("schedule", 0x241E9C, [ctx, key_address, size]),
                         ("dispatch", 0x25AB1C, [DESCRIPTOR, ctx, src, dst, length])],
                        independent=(dst, expected) if expected is not None else None)
            for delta in (0, -3, 5):
                pages, ctx, key_address, key, src, dst, data = fixture(base, size)
                compare(base, f"cbc_overlap_{size}_{delta}", pages,
                    [("schedule", 0x241E9C, [ctx, key_address, size]), ("cbc", 0x242B18, [ctx, src, src + delta, 48])])
            pages, ctx, key_address, key, src, dst, data = fixture(base, size)
            expected = AES.new(key[:size], AES.MODE_CBC, bytes(range(16))).decrypt(data[:48])
            compare(base, f"cbc_split_{size}", pages,
                [("schedule", 0x241E9C, [ctx, key_address, size]), ("cbc", 0x242B18, [ctx, src, dst, 16]),
                 ("cbc", 0x242B18, [ctx, src + 16, dst + 16, 32])], independent=(dst, expected))
        for size in (0, 1, 15, 17, 23, 25, 31, 33, 0x80000000, 0xFFFFFFFF):
            pages, ctx, key_address, *_ = fixture(base, size)
            compare(base, f"invalid_size_{size}", pages, [("schedule", 0x241E9C, [ctx, key_address, size])])
        for mode in (4, 0xFFFFFFFF):
            pages, ctx, key_address, *_ = fixture(base, 16)
            _write_span(pages, MODE, mode.to_bytes(4, "little"))
            compare(base, f"ignored_mode_{mode}", pages,
                    [("dispatch", 0x25AB1C, [DESCRIPTOR, 0, 0, 0, 0xFFFFFFFF])])
        for offset, kind, entry in ((0x91750, "schedule", 0x241E9C), (0x92778, "schedule", 0x241E9C),
                                   (0x93778, "encrypt", 0x2422EC), (0x94778, "decrypt", 0x242640),
                                   (0x95778, "decrypt", 0x242640)):
            pages, ctx, key_address, key, src, dst, data = fixture(base, 16)
            _write_span(pages, base + offset, bytes(0x400))
            operations = [("schedule", 0x241E9C, [ctx, key_address, 16])]
            if kind != "schedule": operations.append((kind, entry, [ctx, src, dst]))
            compare(base, f"guest_table_mutation_{offset:x}", pages, operations)
        print(json.dumps({"base_completed": hex(base), "differential_groups": len(cases)}), flush=True)

    base = BASES[0]
    for label in ("missing_key", "missing_table", "missing_context", "bad_rounds", "missing_output",
                  "late_block_unmapped", "unsupported_stream_2", "unsupported_stream_3", "unknown_jump", "byte_bound", "length_overflow"):
        pages, ctx, key_address, key, src, dst, data = fixture(base, 16)
        cipher.construct_cipher_schedule(pages, context_address=ctx, key_address=key_address, key_size=16, image_base=base)
        if label == "missing_key": key_address = 0x80000000
        if label == "missing_table": del pages[(base + 0x94000) >> 12]
        if label == "missing_context": ctx = 0x80000000
        if label == "bad_rounds": _write_span(pages, ctx + 0x1E0, (0).to_bytes(8, "little"))
        if label == "missing_output": dst = 0x80000000
        if label == "late_block_unmapped": src = GUEST + 0xFFF0
        if label.startswith("unsupported_stream_"): _write_span(pages, MODE, int(label[-1]).to_bytes(4, "little"))
        if label == "unknown_jump": _write_span(pages, base + 0x9A0B8, bytes([255]))
        before = {p: bytes(b) for p, b in pages.items()}
        try:
            if label == "missing_key":
                cipher.construct_cipher_schedule(pages, context_address=ctx, key_address=key_address, key_size=16, image_base=base)
            else:
                cipher.process_cipher_blocks(pages, mode_descriptor_address=DESCRIPTOR, context_address=ctx,
                    source_address=src, output_address=dst, length=0xFFFFFFFF if label == "length_overflow" else 32,
                    entry_stack_address=ENTRY_SP, image_base=base, max_bytes=16 if label == "byte_bound" else 0x100000)
        except (RefillUnsupported, ValueError):
            assert before == {p: bytes(b) for p, b in pages.items()}
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else: raise AssertionError(label + " accepted")
    report = {"library_sha256": LIBRARY_SHA256, "differential_cases": len(cases),
        "negative_cases": len(negatives), "cases": cases, "negatives": negatives,
        "fresh_memory": True, "captured_pages_used": False, "native_output_used_as_input": False,
        "models_use_guest_tables": True, "independent_aes_is_verifier_only": True,
        "key_sizes": [16, 24, 32], "ecb_cbc_decryption_dispatch": True,
        "stream_dispatch_recovered": False, "complete_259dbc_callback": False,
        "complete_python_medusa": False, "jvm_used": False}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"differential_cases": len(cases), "negative_cases": len(negatives)}))


if __name__ == "__main__":
    main()
