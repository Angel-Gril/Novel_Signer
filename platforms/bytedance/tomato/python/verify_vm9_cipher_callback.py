"""Fresh synthetic native differences for configuration cipher callback.

Warm singleton state is an explicit independent component boundary. Real
+0x161068 executes twice; a separate same-run verifier covers cold startup.
No key/plaintext/ciphertext or decoded native constants are exported.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
from pathlib import Path
from Crypto.Cipher import AES
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X8
import vm9_cipher_callback as callback
import vm9_registry as registry
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects, fields
from verify_vm9_registry import BASES, check_memory

DATA, KEY, IV, MODE, OUTPUT = (GUEST + o for o in (0x1000, 0x1020, 0x1040, 0x1100, 0x1200))
REFERENCE, SINGLETON = GUEST + 0x2800, GUEST + 0x2A00
ENTRY_SP = GUEST + 0xEF00


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == LIBRARY_SHA256
    cases, negatives = [], []
    rng = random.Random(0x259DBC)

    def fixture(base, key_size, data_length, padding):
        pages = fresh_pages()
        pages.update(image_pages(args.library, base))
        key = bytes(rng.randrange(256) for _ in range(max(32, key_size)))
        plain = bytes(rng.randrange(256) for _ in range(max(16, data_length)))
        plain = plain[:-1] + bytes([padding])
        payload = AES.new(key[:key_size], AES.MODE_ECB).encrypt(plain) if key_size in (16, 24, 32) and not len(plain) & 15 else plain
        for obj, address, size, raw in ((DATA, GUEST + 0x2000, data_length, payload),
                                       (KEY, GUEST + 0x2400, key_size, key),
                                       (IV, GUEST + 0x2600, 16, bytes(16))):
            _write_span(pages, obj, (base + 0x34F5F8).to_bytes(8, "little"))
            fields(pages, obj + 8, size + 1, size, address)
            _write_span(pages, address, raw + b"\0")
        _write_span(pages, MODE, bytes(4))
        _write_span(pages, base + 0x3D1680, b"\1\1" + bytes(6))
        _write_span(pages, base + 0x3D1678, REFERENCE.to_bytes(8, "little"))
        _write_span(pages, REFERENCE, SINGLETON.to_bytes(8, "little") + bytes(8))
        _write_span(pages, SINGLETON, bytes(136))
        return pages, plain

    def compare(base, label, key_size=16, data_length=32, padding=3, *, mutation=None,
                operation="callback", copy_delta=0, check_fields=(0, 0), failures=()):
        pages, plain = fixture(base, key_size, data_length, padding)
        _write_span(pages, SINGLETON + 0x10, check_fields[0].to_bytes(8, "little") + check_fields[1].to_bytes(8, "little"))
        if operation == "copy":
            entry, arguments = 0x276B9C, [GUEST + 0x2000 + copy_delta, GUEST + 0x2000, data_length]
        elif operation == "initialize":
            _write_span(pages, OUTPUT, MODE.to_bytes(8, "little") + KEY.to_bytes(8, "little") + IV.to_bytes(8, "little"))
            entry, arguments = 0x25AA48, [OUTPUT]
        else:
            entry, arguments = 0x259DBC, [DATA, KEY, IV, MODE]
        expected, actual = Effects(blocks={}, mutate=mutation, failures=failures), Effects(blocks={}, mutate=mutation, failures=failures)
        native_freed, model_freed = [], []
        getter_visits = 0
        def observer(cpu, address):
            nonlocal getter_visits
            if address == base + 0x161068: getter_visits += 1
        def native_free(cpu):
            ptr = cpu.reg_read(UC_ARM64_REG_X0)
            if ptr: native_freed.append((ptr, bytes(cpu.mem_read(ptr, expected.blocks[ptr]))))
            return expected.native(cpu, "free", pointer=ptr)
        def model_free(staged, ptr):
            if ptr: model_freed.append((ptr, _read_span(staged, ptr, actual.blocks[ptr])))
            return actual.free(staged, ptr)
        observed = {(p << 12, 4096): None for p in pages if base <= p << 12 < base + 0x400000}
        if operation == "callback" and key_size in (16, 24, 32) and data_length and not data_length & 15:
            observed[ENTRY_SP - 0x320 + 0xA0, 0x210] = None
        returned, memory, _, _ = native(args.library, base, entry, arguments, pages,
            real_singletons=True, thread_id=137, instruction_limit=400000,
            instruction_observer=observer, observed_memory=observed,
            extra_registers={UC_ARM64_REG_X8: GUEST + 0x3000 if operation == "initialize" else OUTPUT},
            malloc_handler=lambda cpu, size: expected.native(cpu, "malloc", size=size),
            host_imports={0x347FA0: native_free, 0x348400: native_free})
        model_getters = []
        def forbidden(*args): raise AssertionError("warm singleton boundary became cold")
        def get_singleton(staged, sp):
            model_getters.append(sp)
            return registry.get_singleton136_reference(staged, entry_stack_address=sp,
                image_base=base, allocate=actual.malloc, free=model_free,
                read_clock=forbidden, get_tls=forbidden, initialize_registry=forbidden,
                broadcast=forbidden, thread_id=137).wrapper_address
        if operation == "callback":
            callback.decrypt_configuration_reference(pages, output_reference_address=OUTPUT,
                data_object_address=DATA, key_object_address=KEY, iv_object_address=IV,
                mode_address=MODE, entry_stack_address=ENTRY_SP, image_base=base,
                allocate=actual.malloc, free=model_free, get_singleton=get_singleton)
        elif operation == "copy":
            callback.checked_forward_copy(pages, output_address=arguments[0], source_address=arguments[1],
                length=data_length, entry_stack_address=ENTRY_SP, get_singleton=get_singleton)
        else:
            got = callback.initialize_cipher_context(pages, descriptor_address=OUTPUT,
                context_address=GUEST + 0x3000, image_base=base)
            assert got == (0 if key_size in (16, 24, 32) else -1), label + " constructor status"

        if operation == "initialize": assert got & 0xFFFFFFFF == returned & 0xFFFFFFFF, label + " native status"
        check_memory(label, pages, memory)
        assert all(_read_span(pages, a, n) == raw for (a, n), raw in observed.items()), label + " image/context"
        assert actual.calls == expected.calls, (label, actual.calls, expected.calls)
        assert actual.blocks == expected.blocks, label + " live allocator"
        assert native_freed == model_freed, label + " pre-free bytes"
        assert len(model_getters) == getter_visits, label + " getter calls"
        if operation == "callback" and mutation is None and 3 not in failures and key_size in (16, 24, 32) and data_length and not data_length & 15 and padding <= 16:
            string = int.from_bytes(_read_span(pages, OUTPUT, 8), "little")
            size = int.from_bytes(_read_span(pages, string + 12, 4), "little")
            ptr = int.from_bytes(_read_span(pages, string + 16, 8), "little")
            assert size == data_length - padding and _read_span(pages, ptr, size) == plain[:size], label + " independent AES"
        cases.append({"case": label, "image_base": hex(base), "entry_offset": hex(entry),
            "all_guest_bytes_match": True, "all_image_and_context_bytes_match": True,
            "allocation_free_order_match": True, "pre_free_bytes_match": True,
            "real_singleton_getter_calls_match": True, "getter_calls": getter_visits})

    for base in BASES:
        for size in (0, 1, 15, 16, 17, 24, 31, 32, 33):
            compare(base, f"context_builder_key_{size}", size, operation="initialize")
        for size in (16, 24, 32):
            for padding in range(18):
                compare(base, f"key_{size}_last_byte_{padding}", size, 32, padding)
            for length in (16, 48, 176, 256):
                compare(base, f"key_{size}_data_{length}", size, length, 3)
        for size in (0, 1, 15, 17, 23, 25, 31, 33):
            compare(base, f"invalid_key_size_{size}", size)
        for length in (0, 1, 15, 17, 31, 33):
            compare(base, f"invalid_data_length_{length}", 16, length)
        for delta in (-8, -1, 0, 1, 8, 16):
            compare(base, f"copy_overlap_{delta}", data_length=48, operation="copy", copy_delta=delta)
        compare(base, "copy_zero", data_length=0, operation="copy")
        compare(base, "copy_one_check_zero", operation="copy", check_fields=(0x1234, 0))
        # Mutation at clone allocation changes source; descriptor must use original key.
        def mutate_key(kind, index, read, write):
            if kind == "malloc" and index == 0: write(GUEST + 0x2400, bytes(range(32)))
        compare(base, "key_mutation_after_clone_malloc", mutation=mutate_key)
        compare(base, "clone_malloc_null", failures=(0,))
        compare(base, "string_payload_malloc_null", failures=(3,))

    for label in ("unknown_mode", "changed_key_jump", "changed_dispatch_a", "changed_dispatch_b", "unmapped_data", "both_environment_checks", "copy_bound", "unmapped_context", "data_bound", "null_buffer_allocation", "null_string_allocation", "null_count_allocation"):
        base = BASES[0]
        pages, _ = fixture(base, 16, 32, 3)
        if label == "unknown_mode": _write_span(pages, MODE, (2).to_bytes(4, "little"))
        if label == "changed_key_jump": _write_span(pages, base + 0x9A0B4, b"\1")
        if label == "changed_dispatch_a": _write_span(pages, base + 0x381CF0, bytes(8))
        if label == "changed_dispatch_b": _write_span(pages, base + 0x381CF8, bytes(8))
        if label == "unmapped_data": _write_span(pages, DATA + 16, (GUEST + 0x100000).to_bytes(8, "little"))
        if label == "both_environment_checks": _write_span(pages, SINGLETON + 0x10, (7).to_bytes(8, "little") * 2)
        before = {p: bytes(v) for p, v in pages.items()}
        failure = {"null_buffer_allocation": (1,), "null_string_allocation": (2,), "null_count_allocation": (4,)}.get(label, ())
        effects = Effects(blocks={}, failures=failure)
        try:
            if label in ("both_environment_checks", "copy_bound"):
                callback.checked_forward_copy(pages, output_address=GUEST+0x3000, source_address=GUEST+0x2000,
                    length=33 if label == "copy_bound" else 16, max_bytes=32,
                    entry_stack_address=ENTRY_SP, get_singleton=lambda *a: REFERENCE)
            elif label == "unmapped_context":
                callback.initialize_cipher_context(pages, descriptor_address=OUTPUT,
                    context_address=GUEST+0x100000, image_base=base)
            else:
                callback.decrypt_configuration_reference(pages, output_reference_address=OUTPUT,
                    data_object_address=DATA, key_object_address=KEY, iv_object_address=IV,
                    mode_address=MODE, entry_stack_address=ENTRY_SP, image_base=base,
                    allocate=effects.malloc, free=effects.free, get_singleton=lambda *a: REFERENCE,
                    max_bytes=16 if label == "data_bound" else 0x100000)
        except (RefillUnsupported, ValueError):
            assert {p: bytes(v) for p, v in pages.items()} == before, label + " rollback"
            negatives.append({"case": label, "rejected": True, "page_rollback": True})
        else:
            raise AssertionError(label + " did not reject")
    report = {"library_sha256": LIBRARY_SHA256, "cases": cases, "native_differences": len(cases),
        "negative_cases": negatives, "negative_count": len(negatives),
        "fresh_synthetic_inputs": True, "native_outputs_used_as_model_input": False,
        "keys_payloads_and_ciphertexts_exported": False, "jvm_used": False,
        "verified_callback_modes": [0], "complete_cipher_modes": False,
        "padding_checks_last_byte_only": True, "serialized_warm_singleton_boundary": True,
        "complete_python_medusa": False,
        "rollback_scope": "guest_pages_only; external allocator ledgers are explicit effects"}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"native_differences": len(cases), "negative_count": len(negatives)}))


if __name__ == "__main__":
    main()
