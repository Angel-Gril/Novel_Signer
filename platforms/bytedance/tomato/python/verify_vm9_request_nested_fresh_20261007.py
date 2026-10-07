"""Independent store/sub-dispatch controls and fresh request-prefix composition."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unicorn import arm64_const as arm

import verify_vm9_signer_objects as oracle
from vm9_allocator import RefillUnsupported, _read_span, _write_span
from vm9_request_caller import prepare_request_vm_caller
from vm9_request_dispatcher import prepare_request_dispatch_frame
from vm9_request_nested import (
    STORE_OFFSET, STORE_END, SUBDISPATCH_OFFSET, SUBDISPATCH_END,
    NORMAL_KEY, prepare_store64_state, store_request_word,
    subdispatch_request_word, execute_request_nested_prefix, movhi_request_word,
)

MASK64 = (1 << 64) - 1
REG_NAMES = ("x0", "x1", "x4", "x5", "x8", "x9", "x10", "x11", "x12",
             "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21",
             "x22", "x23", "x24", "x25", "x28", "x29", "x30", "sp")


class Stop(Exception):
    pass


def registers(cpu):
    return {n: cpu.reg_read(getattr(arm, "UC_ARM64_REG_" + n.upper())) for n in REG_NAMES}


def bounded_native(library, image, start, end, pages, inputs):
    state = {"writes": []}

    def observe(cpu, address):
        if not start <= address - image < end:
            state.update(target=address, regs=registers(cpu),
                         guest=bytes(cpu.mem_read(oracle.GUEST, oracle.GUEST_SIZE)))
            raise Stop

    try:
        oracle.native(library, image, start, [], pages,
            extra_registers={getattr(arm, "UC_ARM64_REG_" + n.upper()): v for n, v in inputs.items()},
            instruction_observer=observe,
            memory_write_observer=lambda cpu, a, w: state["writes"].append((a, w)),
            instruction_limit=10000)
    except Stop:
        return state
    raise AssertionError("component did not leave its verified block")


def write(pages, address, value, width=8):
    _write_span(pages, address, value.to_bytes(width, "little"))


def store_word(base_slot, source_slot, displacement):
    d = displacement & 0xFFFF
    return (26 | ((d & 0x1F) << 16) | ((d & 0x3E0) << 6)
            | (((d >> 10) & 1) << 6) | ((d & 0x7800) >> 4)
            | ((d & 0x8000) << 11) | ((base_slot & 15) << 22)
            | ((base_slot >> 4) << 31) | ((source_slot & 15) << 27)
            | ((source_slot >> 4) << 21))


def direct_store(library, image, control):
    pages = oracle.image_pages(library, image); pages.update(oracle.fresh_pages())
    base_slot, source_slot, displacement, base_offset = control[1:]
    stream, wordptr, backing = (oracle.GUEST + n for n in (0xE000, 0xE800, 0xD000))
    x1, x23, x29, scratch = (oracle.GUEST + n for n in (0xE100, 0xE200, 0xE500, 0xE600))
    word = store_word(base_slot, source_slot, displacement)
    write(pages, stream, wordptr)
    write(pages, wordptr, word, 4); write(pages, wordptr + 4, 0x01C10B11, 4)
    for i in range(32):
        write(pages, backing + i * 8, (0x1122334455667788 ^ i * 0x0101010101010101) & MASK64)
    write(pages, backing + base_slot * 8, oracle.GUEST + base_offset)
    # The table is an explicit component input; the fresh full-chain controls
    # below use the unmodified relocated ELF table.
    table = oracle.GUEST + 0xC800
    fold = (((0x00A060400A021040 | (~(image + 0x168324) & MASK64)) & 0x00A061440A061440)
            + ((image + 0x168324) & 0x0000010400040400)) & MASK64
    mask = (fold | 0x01010104) ^ NORMAL_KEY
    write(pages, image + 0x3798D8, (table - mask) & MASK64)
    key, target = 0x33DC5, image + 0x16855C
    write(pages, table + 17 * 8, target + key)
    write(pages, x29 - 8, key); write(pages, x29 - 0x10, scratch)
    write(pages, x29 - 0x38, oracle.GUEST + 0x8800)
    st = prepare_store64_state(image_base=image, x0=0x12345678, x1=x1,
        x4=0xABCDEF, x5=0x0123456789ABCDEF, x19=stream,
        x20=image + 0x379000, x23=x23, x28=backing, x29=x29)
    inputs = {k: v for k, v in vars(st).items() if k != "image_base"}
    native = bounded_native(library, image, STORE_OFFSET, STORE_END, pages, inputs)
    result = store_request_word(pages, st)
    assert result["next_handler"] == native["target"] == target
    assert oracle.flatten(pages) == native["guest"], control[0]
    assert result["writes"] == native["writes"], control[0]
    for name, value in {**inputs, **result["register_updates"]}.items():
        assert native["regs"][name] == value, (control[0], name)
    assert result["signed_displacement"] == displacement
    assert result["target_address"] == oracle.GUEST + base_offset + displacement
    return dict(image_base=hex(image), case=control[0], word=hex(word),
        base_slot=base_slot, source_slot=source_slot, signed_displacement=displacement,
        dispatch_table_kind="explicit_synthetic", registers_match=True,
        full_guest_memory_match=True, guest_bytes_compared=oracle.GUEST_SIZE,
        ordered_writes_match=True, native_write_count=len(native["writes"]),
        native_input_snapshot_used=False)


def direct_subdispatch(library, image, sub):
    pages = oracle.image_pages(library, image); pages.update(oracle.fresh_pages())
    stream, wordptr, x29, table = (oracle.GUEST + n for n in (0xE000, 0xE800, 0xE500, 0xC800))
    word = 17 | (sub << 6) | (13 << 17)
    write(pages, stream, wordptr); write(pages, wordptr, word, 4)
    x4, x5, key = 0xFFEEDDCCBBAA9988, 0x0123456789ABCDEF, 0xA5A5
    mask = (x5 | 0x01010104) ^ x4
    write(pages, image + 0x3798E0, (table - mask) & MASK64)
    target = image + 0x16A5A8
    write(pages, table + sub * 8, target + key); write(pages, x29 - 8, key)
    inputs = dict(x19=stream, x29=x29, x4=x4, x5=x5)
    native = bounded_native(library, image, SUBDISPATCH_OFFSET, SUBDISPATCH_END, pages, inputs)
    result = subdispatch_request_word(pages, image_base=image, **inputs)
    assert result["next_handler"] == native["target"] == target
    assert oracle.flatten(pages) == native["guest"]
    assert native["writes"] == []
    for name, value in {**inputs, **result["register_updates"]}.items():
        assert native["regs"][name] == value, (sub, name)
    return dict(image_base=hex(image), sub=sub, dispatch_table_kind="explicit_synthetic",
        registers_match=True, full_guest_memory_match=True, native_write_count=0,
        native_input_snapshot_used=False)



def movhi_word(dst, immediate, scratch):
    return (52 | ((immediate & 0x1F) << 16) | ((immediate & 0x3E0) << 21)
            | (((immediate >> 10) & 1) << 6) | ((immediate & 0x7800) >> 4)
            | ((immediate & 0x8000) << 6) | ((dst & 15) << 22)
            | ((dst >> 4) << 11) | ((scratch & 15) << 12) | ((scratch >> 4) << 31))


def direct_movhi(library, image, dst, immediate, scratch):
    pages = oracle.image_pages(library, image); pages.update(oracle.fresh_pages())
    stream, wordptr, backing, x22, x23, x29, x30, table = (oracle.GUEST + n for n in
        (0xE000, 0xE800, 0xD000, 0xE100, 0xE200, 0xE500, 0xE600, 0xC800))
    word = movhi_word(dst, immediate, scratch)
    write(pages, stream, wordptr); write(pages, wordptr, word, 4)
    write(pages, wordptr + 4, 0x12345678, 4)
    fold = (((0x00A060400A021040 | (~(image + 0x168324) & MASK64)) & 0x00A061440A061440)
            + ((image + 0x168324) & 0x0000010400040400)) & MASK64
    mask = (fold | 0x01010104) ^ NORMAL_KEY
    write(pages, image + 0x3798D8, (table - mask) & MASK64)
    key, target = 0x33DC5, image + 0x16E32C
    write(pages, table + (0x12345678 & 63) * 8, target + key)
    write(pages, x29 - 8, key)
    inputs = dict(x19=stream, x20=image + 0x379000, x22=x22, x23=x23,
                  x28=backing, x29=x29, x30=x30)
    native = bounded_native(library, image, 0x16E158, 0x16E32C, pages,
                            {**inputs, "x21": 0xAABBCCDD})
    result = movhi_request_word(pages, image_base=image, **inputs)
    assert result["next_handler"] == native["target"] == target
    assert oracle.flatten(pages) == native["guest"]
    assert result["writes"] == native["writes"]
    for name, value in {**inputs, **result["register_updates"], "x21": 0xAABBCCDD}.items():
        assert native["regs"][name] == value, (immediate, name)
    signed = immediate - 0x10000 if immediate & 0x8000 else immediate
    assert result["immediate"] == immediate
    assert result["dst"] == dst and result["value"] == ((signed << 16) & MASK64)
    return dict(image_base=hex(image), immediate=hex(immediate), dst=dst, scratch=scratch,
        value=hex(result["value"]), dispatch_table_kind="explicit_synthetic",
        registers_match=True, full_guest_memory_match=True, guest_bytes_compared=oracle.GUEST_SIZE,
        ordered_writes_match=True, native_write_count=len(native["writes"]), native_input_snapshot_used=False)

def fresh_caller_pages(library, image, fill):
    pages = oracle.image_pages(library, image)
    pages.update({a >> 12: bytearray([fill]) * 4096 for a in
                  range(oracle.GUEST, oracle.GUEST + oracle.GUEST_SIZE, 4096)})
    return pages


def composed_case(library, image, object_offset, preserved_x8, fill):
    pages = fresh_caller_pages(library, image, fill)
    native = {"loop_targets": [], "writes": [], "record": False, "or_entered": False, "movhi_entered": False}

    def observe(cpu, address):
        off = address - image
        if off == STORE_OFFSET:
            if native["record"]:
                native["loop_targets"].append(registers(cpu))
            native["record"] = True
        elif off == SUBDISPATCH_OFFSET and native["record"]:
            native["loop_targets"].append(registers(cpu))
        elif off == 0x16A5A8 and native["record"]:
            native["or_entry"] = registers(cpu)
            native["or_entered"] = True
        elif native["or_entered"] and not native["movhi_entered"] and not 0x16A5A8 <= off < 0x16A614:
            assert off == 0x16E158
            native["post_or"] = dict(target=address, regs=registers(cpu))
            native["movhi_entered"] = True
        elif native["movhi_entered"] and not 0x16E158 <= off < 0x16E32C:
            native.update(target=address, regs=registers(cpu),
                          guest=bytes(cpu.mem_read(oracle.GUEST, oracle.GUEST_SIZE)))
            raise Stop

    def record_write(cpu, address, width):
        if native["record"]:
            native["writes"].append((address, width))

    try:
        oracle.native(library, image, 0x256ED4, [oracle.GUEST + object_offset], pages,
            extra_registers={arm.UC_ARM64_REG_X8: preserved_x8,
                arm.UC_ARM64_REG_X29: oracle.GUEST + 0xDE00,
                arm.UC_ARM64_REG_X28: 0x123456789ABCDEF0,
                arm.UC_ARM64_REG_X19: oracle.GUEST + 0x2200},
            instruction_observer=observe, memory_write_observer=record_write,
            instruction_limit=1000000)
    except Stop:
        pass
    else:
        raise AssertionError("fresh caller did not reach the post-OR64 boundary")
    model_pages = fresh_caller_pages(library, image, fill)
    frame = prepare_request_dispatch_frame(entry_stack_address=oracle.GUEST + 0xEF00,
                                           image_base=image)
    prepare_request_vm_caller(model_pages, entry_stack_address=oracle.GUEST + 0xEF00,
        return_address=oracle.STOP, thread_pointer=oracle.GUEST + 0xD000,
        image_base=image, object_address=oracle.GUEST + object_offset,
        preserved_x8=preserved_x8, saved_frame_pointer=oracle.GUEST + 0xDE00,
        saved_x28=0x123456789ABCDEF0, saved_x19=oracle.GUEST + 0x2200)
    result = execute_request_nested_prefix(model_pages, frame)
    assert len(result["stores"]) == len(native["loop_targets"]) == 10
    assert result["next_handler"] == native["post_or"]["target"] == image + 0x16E158
    for store, target_regs in zip(result["stores"], native["loop_targets"]):
        for name, value in store["register_updates"].items():
            assert target_regs[name] == value, ("store", name)
    for name, value in result["subdispatch"]["register_updates"].items():
        assert native["or_entry"][name] == value, ("subdispatch", name)
    x5 = (((0x00A060400A021040 | (~(image + 0x168324) & MASK64)) & 0x00A061440A061440)
          + ((image + 0x168324) & 0x0000010400040400)) & MASK64
    expected = dict(x0=frame.x0, x1=frame.x1, x4=NORMAL_KEY, x5=x5,
        x19=frame.x19, x20=frame.x20, x22=frame.x22, x23=frame.x23,
        x24=frame.x24, x25=frame.x24 - 0x10, x28=frame.x28, x29=frame.x29,
        x30=frame.x30, sp=frame.sp)
    for component in (result["stores"][-1], result["subdispatch"], result["or64"]):
        expected.update(component["register_updates"])
    assert set(expected) == set(REG_NAMES)
    assert expected == native["post_or"]["regs"]
    movhi = movhi_request_word(model_pages, image_base=image, x19=frame.x19,
        x20=frame.x20, x22=frame.x22, x23=frame.x23, x28=frame.x28, x29=frame.x29, x30=frame.x30)
    assert movhi["next_handler"] == native["target"] == image + 0x16E32C
    expected.update(movhi["register_updates"])
    assert expected == native["regs"]
    model_writes = [event for store in result["stores"] for event in store["writes"]]
    model_writes += result["or64"]["writes"] + movhi["writes"]
    assert model_writes == native["writes"]
    # Full caller backing and every changed range are compared. Unmodeled
    # generic prelude spills are not passed to Python or claimed as recovered.
    ranges = set(model_writes)
    ranges.update({(frame.x28, 0x100), (frame.x19, 8), (frame.x29 - 8, 8),
        (frame.x29 - 0x10, 8), (frame.x29 - 0x38, 8), (frame.x30, 2),
        (oracle.GUEST + 0xEF00 - 0x3B0, 0x28)})
    for address, width in ranges:
        start = address - oracle.GUEST
        assert _read_span(model_pages, address, width) == native["guest"][start:start + width], hex(address)
    return dict(image_base=hex(image), object_offset=hex(object_offset),
        preserved_x8=hex(preserved_x8), fresh_page_fill=hex(fill),
        store_iterations=len(result["stores"]), stream_final_offset="0x99054",
        operation_sequence=["0x16d7d0", "0x171138 x10", "0x16855c", "0x16a5a8", "0x16e158"],
        prefix_post_or_offset=hex(result["next_handler_offset"]),
        next_handler_offset=hex(movhi["next_handler_offset"]),
        or64_word=hex(result["or64"]["word"]), or64_result=hex(result["or64"]["result"]),
        movhi_word=hex(movhi["word"]), movhi_immediate=hex(movhi["immediate"]),
        movhi_dst=movhi["dst"], movhi_value=hex(movhi["value"]),
        native_write_count=len(model_writes), compared_memory_ranges=len(ranges),
        all_component_registers_match=True, defined_memory_ranges_match=True,
        ordered_writes_match=True, dispatch_table_kind="unmodified_relocated_ELF",
        native_input_snapshot_used=False)


def negative_cases(library):
    image = 0x122C0000
    pages = fresh_caller_pages(library, image, 0xA5)
    frame = prepare_request_dispatch_frame(entry_stack_address=oracle.GUEST + 0xEF00, image_base=image)
    prepare_request_vm_caller(pages, entry_stack_address=oracle.GUEST + 0xEF00,
        return_address=oracle.STOP, thread_pointer=oracle.GUEST + 0xD000, image_base=image,
        object_address=oracle.GUEST + 0x1800, preserved_x8=0x7004EDD8)
    initial = {k: bytes(v) for k, v in pages.items()}
    for budget in (0, 1):
        try:
            execute_request_nested_prefix(pages, frame, max_store_words=budget)
        except RefillUnsupported:
            pass
        else:
            raise AssertionError("invalid/exhausted loop budget accepted")
        assert all(bytes(pages[k]) == v for k, v in initial.items())
    stream, wordptr = oracle.GUEST + 0xE000, oracle.GUEST + 0xE800
    write(pages, stream, wordptr); write(pages, wordptr, 0, 4)
    component_initial = {k: bytes(v) for k, v in pages.items()}
    store_state = prepare_store64_state(image_base=image, x0=0, x1=oracle.GUEST + 0xE100,
        x4=0, x5=0, x19=stream, x20=image + 0x379000, x23=oracle.GUEST + 0xE200,
        x28=oracle.GUEST + 0xD000, x29=oracle.GUEST + 0xE500)
    for action in (
        lambda: store_request_word(pages, store_state),
        lambda: subdispatch_request_word(pages, image_base=image, x19=stream,
            x29=oracle.GUEST + 0xE500, x4=0, x5=0),
        lambda: movhi_request_word(pages, image_base=image, x19=stream, x20=image + 0x379000,
            x22=oracle.GUEST + 0xE100, x23=oracle.GUEST + 0xE200,
            x28=oracle.GUEST + 0xD000, x29=oracle.GUEST + 0xE500, x30=oracle.GUEST + 0xE600),
    ):
        try:
            action()
        except RefillUnsupported:
            pass
        else:
            raise AssertionError("unrecognized component opcode accepted")
        assert all(bytes(pages[k]) == v for k, v in component_initial.items())
    return ["nonpositive_budget_refused", "exhausted_budget_refused_without_publication",
            "wrong_store_opcode_refused", "wrong_subdispatch_opcode_refused", "wrong_movhi_opcode_refused"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest() == oracle.LIBRARY_SHA256
    stores, subdispatches, movhis, chains = [], [], [], []
    store_controls = (
        ("positive", 29, 31, 136, 0x8000),
        ("negative", 17, 16, -152, 0x8000),
        ("min_signed", 3, 31, -32768, 0x9000),
        ("max_signed", 31, 2, 32767, 0x1000),
        ("stream_next_word_alias", 29, 16, 4, 0xE800),
        ("base_source_same", 4, 4, 0, 0x8000),
    )
    for image in (0x122C0000, 0x775C205000):
        for control in store_controls:
            stores.append(direct_store(args.library, image, control))
            print("nested store", hex(image), control[0], "PASS", flush=True)
        for sub in (0, 44, 63):
            subdispatches.append(direct_subdispatch(args.library, image, sub))
            print("subdispatch", hex(image), sub, "PASS", flush=True)
        for dst, immediate, scratch in ((0, 0, 0), (31, 0x7FFF, 31), (16, 0x8000, 19),
                                         (7, 0xFFFF, 2), (3, 0x1234, 0), (29, 0x58F3, 31)):
            movhis.append(direct_movhi(args.library, image, dst, immediate, scratch))
            print("MOVhi", hex(image), hex(immediate), "PASS", flush=True)
        for offset, x8, fill in ((0x1800, 0x7004EDD8, 0xA5), (0x1FF8, 0x64000000, 0x5A),
                                  (0x2800, image + 0x257050, 0x3C)):
            chains.append(composed_case(args.library, image, offset, x8, fill))
            print("fresh caller prefix", hex(image), hex(offset), "PASS", flush=True)
    negatives = negative_cases(args.library)
    report = dict(schema="vm9-request-nested-fresh-differential-v1", evidence_date="2026-10-07",
        sample_sha256=oracle.LIBRARY_SHA256, store_controls=len(stores), store_cases=stores,
        subdispatch_controls=len(subdispatches), subdispatch_cases=subdispatches,
        movhi_controls=len(movhis), movhi_cases=movhis,
        composed_controls=len(chains), composed_cases=chains, negative_cases=negatives,
        store_loop_python_implementation_verified=True, subdispatch_python_implementation_verified=True,
        fresh_caller_to_post_or64_prefix_verified=True, fresh_caller_to_post_movhi_prefix_verified=True,
        movhi_python_implementation_verified=True, next_handler_offset="0x16e32c",
        complete_python_medusa=False, fresh_input_signer_output_verified=False,
        current_online_header_matrix_verified=False, no_jvm_rust_signer_complete=False,
        limitations=[
            "The composed fresh caller is a synthetic native object/x8 input, not URL/headers/JNI conversion.",
            "Defined backing slots, required prelude pointers and changed ranges are compared. "
            "Other generic frame spills remain outside the contract.",
            "Normal +0x171138 stores and +0x16e158 MOVhi are modeled; repair paths and +0x16e32c body are not.",
            "No JVM, captured input snapshot, online request or signature output is used.",
        ])
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("nested", len(stores), "store +", len(subdispatches), "subdispatch +",
          len(movhis), "MOVhi +", len(chains), "fresh caller +", len(negatives), "negative controls PASS")


if __name__ == "__main__":
    main()
