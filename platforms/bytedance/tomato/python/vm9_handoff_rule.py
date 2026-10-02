"""Learn a captured-state NEXT#1 rule from two paired VM9 captures.

This is a research diagnostic, not a signer. It replays a rule over trusted
local pickle checkpoints and captured native-memory images. Never load a
pickle checkpoint from an untrusted source. The held-out capture's NEXT#1
is not read by this program, allowing an independent comparison afterwards.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from pathlib import Path

REGIONS = (
    (0x12100000, "vm9_libc.bin"),
    (0x12290000, "vm9_m0.bin"),
    (0x12800000, "vm9_m1.bin"),
    (0xE4FF0000, "vm9_m2.bin"),
    (0x11EC0000, "vm9_copy2.bin"),
)


def read_bytes(pages: dict[int, bytes | bytearray], address: int, size: int) -> bytes:
    page, offset = address >> 12, address & 4095
    if offset + size > 4096:
        raise ValueError("structural field crosses a page boundary")
    return bytes(pages[page][offset:offset + size])


def read_word(pages: dict[int, bytes | bytearray], address: int) -> int:
    return int.from_bytes(read_bytes(pages, address, 8), "little")


def write_bytes(pages: dict[int, bytearray], address: int, value: bytes) -> None:
    page, offset = address >> 12, address & 4095
    if offset + len(value) > 4096:
        raise ValueError("structural field crosses a page boundary")
    pages[page][offset:offset + len(value)] = value


def write_word(pages: dict[int, bytearray], address: int, value: int) -> None:
    write_bytes(pages, address, value.to_bytes(8, "little"))


def freelist_object(pages: dict[int, bytes | bytearray]) -> tuple[int, int]:
    count = read_word(pages, 0x12282070)
    pointer = read_word(pages, 0x12282078)
    if not 0 < count < 100:
        raise ValueError("unsupported size-class count; the refill path is not modeled")
    result = read_word(pages, pointer + (count - 1) * 8)
    if not 0x12290000 <= result < 0x12750000 or result % 8:
        raise ValueError("unsupported allocator object pointer")
    return result, count


def apply_allocator_model(
    before: dict[int, bytes | bytearray],
    predicted: dict[int, bytearray],
    training: tuple[tuple[dict[int, bytearray], dict[int, bytes]], ...],
) -> dict:
    """Relocate the trained object and apply shared whole-word state deltas.

    This retains trained target bytes and a captured baseline. It has only been
    validated on the documented homepage/detail captures; it is not a general
    allocator, host implementation, or current Medusa signer.
    """
    training_objects = [freelist_object(source)[0] for source, _ in training]
    if len(set(training_objects)) != 1:
        raise ValueError("training object locations differ; no relocation rule is claimed")
    trained_object = training_objects[0]
    object_pointer, count = freelist_object(before)
    modeled_object = read_bytes(predicted, trained_object, 24)
    write_bytes(predicted, trained_object, read_bytes(before, trained_object, 24))
    write_bytes(predicted, object_pointer, modeled_object)
    for address in (0xe4ffbc80, 0xe4ffbca0, 0xe4ffbd08, 0xe4ffcaa0):
        write_word(predicted, address, object_pointer)
    deltas = []
    for address in (0x12240730, 0x12282060, 0x12282070, 0x12296018, 0x12296020):
        shared = [read_word(target, address) - read_word(source, address)
                  for source, target in training]
        if len(set(shared)) != 1:
            raise ValueError(f"training word deltas differ at {address:#x}")
        write_word(predicted, address, read_word(before, address) + shared[0])
        deltas.append({"address": f"0x{address:08x}", "delta": shared[0]})
    # A full store clears source-dependent low bytes left by the byte mask.
    scratch = [read_word(target, 0xe4ffb9e0) for _, target in training]
    if len(set(scratch)) != 1:
        raise ValueError("training scratch values differ")
    write_word(predicted, 0xe4ffb9e0, scratch[0])
    return {
        "trained_object": f"0x{trained_object:08x}",
        "object_pointer": f"0x{object_pointer:08x}",
        "source_bin_count": count,
        "word_deltas": deltas,
        "still_uses_training_target_bytes": True,
        "scratch_byte_0xe4ffbb78": "unmodeled; do not substitute a trace value",
    }


def load_training(capture: Path) -> tuple[dict[int, bytearray], dict[int, bytes]]:
    with (capture / "mem_after_seg1_offline.pkl").open("rb") as stream:
        before = pickle.load(stream)
    after = {}
    for base, name in REGIONS:
        blob = (capture / "handoff" / "next_1" / name).read_bytes()
        for offset in range(0, len(blob), 4096):
            after[(base + offset) >> 12] = blob[offset:offset + 4096]
    return before, after


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("training_a", type=Path)
    parser.add_argument("training_b", type=Path)
    parser.add_argument("heldout_checkpoint", type=Path)
    parser.add_argument("patched_checkpoint", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--allocator-model", action="store_true",
                        help="diagnostic object relocation and shared whole-word state deltas")
    args = parser.parse_args()
    old_before, old_after = load_training(args.training_a)
    new_before, new_after = load_training(args.training_b)

    with args.heldout_checkpoint.open("rb") as stream:
        heldout = pickle.load(stream)
    source = {page: bytes(data) for page, data in heldout.items()} if args.allocator_model else None
    fixed_count = dynamic_count = 0
    changed_pages = set()
    dynamic_locations = []
    for page in sorted(set(old_after) & set(new_after)):
        oa = bytes(old_before.get(page, b"\0" * 4096))
        na = bytes(new_before.get(page, b"\0" * 4096))
        ob, nb = old_after[page], new_after[page]
        old_mask = {i for i in range(4096) if oa[i] != ob[i]}
        new_mask = {i for i in range(4096) if na[i] != nb[i]}
        if old_mask != new_mask:
            raise ValueError(f"training masks differ on page {page:#x}")
        if not old_mask:
            continue
        dest = heldout.setdefault(page, bytearray(b"\0" * 4096))
        for i in old_mask:
            if ob[i] == nb[i]:
                dest[i] = ob[i]
                fixed_count += 1
                continue
            delta_a = (ob[i] - oa[i]) & 0xff
            delta_b = (nb[i] - na[i]) & 0xff
            if delta_a != delta_b:
                raise ValueError(f"no shared byte rule at {(page << 12) + i:#x}")
            dest[i] = (dest[i] + delta_a) & 0xff
            dynamic_count += 1
            dynamic_locations.append({
                "address": f"0x{(page << 12) + i:08x}",
                "delta": f"0x{delta_a:02x}",
            })
        changed_pages.add(page)

    allocator_model = None
    if args.allocator_model:
        allocator_model = apply_allocator_model(source, heldout,
            ((old_before, old_after), (new_before, new_after)))
    with args.patched_checkpoint.open("wb") as stream:
        pickle.dump(heldout, stream, protocol=pickle.HIGHEST_PROTOCOL)
    summary = {
        "rule_pages": len(changed_pages),
        "fixed_target_bytes": fixed_count,
        "arithmetic_bytes": dynamic_count,
        "dynamic_locations": dynamic_locations,
        "source_checkpoint_sha256": hashlib.sha256(args.heldout_checkpoint.read_bytes()).hexdigest(),
        "patched_checkpoint_sha256": hashlib.sha256(args.patched_checkpoint.read_bytes()).hexdigest(),
        "heldout_handoff_read": False,
    }
    if allocator_model is not None:
        summary["allocator_model"] = allocator_model
    if args.summary:
        args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
