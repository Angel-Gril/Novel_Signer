"""Fresh-input checks for the measured VM9 service singleton boundaries.

This verifier covers guard/slot publication, allocation order, the exact
2-byte flag payload, and transactional failure behavior.  The 0x2d0-byte
service payload is supplied by an explicit initializer because its nested
string/configuration graph is still an open native boundary.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _read_span, _write_span


IMAGE_BASE = 0x122C0000
GUEST = 0x70000000
GUEST_SIZE = 0x10000


class Allocator:
    def __init__(self):
        self.next = GUEST + 0x4000
        self.calls = []

    def take(self, pages, size):
        pointer = self.next
        self.next += (size + 15) & ~15
        if self.next >= GUEST + 0x9000:
            return 0
        self.calls.append([size, pointer])
        _read_span(pages, pointer, size)
        return pointer


def fresh_pages():
    pages = {
        address >> 12: bytearray(b"\xa5" * 4096)
        for address in range(GUEST, GUEST + GUEST_SIZE, 4096)
    }
    for offset in (
        objects.SERVICE_A_GUARD_OFFSET, objects.SERVICE_A_SLOT_OFFSET,
        objects.SERVICE_B_GUARD_OFFSET, objects.SERVICE_B_SLOT_OFFSET,
    ):
        address = IMAGE_BASE + offset
        pages[address >> 12] = bytearray(b"\xa5" * 4096)
    for offset in (objects.SERVICE_A_GUARD_OFFSET,
                   objects.SERVICE_A_SLOT_OFFSET,
                   objects.SERVICE_B_GUARD_OFFSET,
                   objects.SERVICE_B_SLOT_OFFSET):
        address = IMAGE_BASE + offset
        width = 1 if offset in (objects.SERVICE_A_GUARD_OFFSET,
                                objects.SERVICE_B_GUARD_OFFSET) else 8
        _write_span(pages, address, bytes(width))
    return pages


def flatten(pages):
    return {key: bytes(value) for key, value in pages.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = []

    pages = fresh_pages()
    alloc = Allocator()
    service = objects.construct_service_reference(
        pages, image_base=IMAGE_BASE, kind="service", allocate=alloc.take,
        initialize_payload=lambda staged, address: _write_span(
            staged, address, bytes((index * 17 + 3) & 0xFF
                                   for index in range(objects.SERVICE_A_PAYLOAD_SIZE))))
    assert service.payload_size == objects.SERVICE_A_PAYLOAD_SIZE
    assert alloc.calls == [[16, GUEST + 0x4000],
                           [objects.SERVICE_A_PAYLOAD_SIZE, GUEST + 0x4010],
                           [4, GUEST + 0x42E0]]
    assert int.from_bytes(_read_span(
        pages, IMAGE_BASE + objects.SERVICE_A_SLOT_OFFSET, 8), "little") == service.wrapper_address
    assert _read_span(pages, IMAGE_BASE + objects.SERVICE_A_GUARD_OFFSET, 1) == b"\x01"
    cases.append({"case": "service_payload_explicit_initializer",
                  "payload_size": service.payload_size,
                  "allocation_sequence": alloc.calls, "published": True})

    before_calls = list(alloc.calls)
    again = objects.construct_service_reference(
        pages, image_base=IMAGE_BASE, kind="service", allocate=alloc.take,
        initialize_payload=lambda staged, address: (_ for _ in ()).throw(
            AssertionError("guarded getter reinitialized payload")))
    assert again.wrapper_address == service.wrapper_address
    assert alloc.calls == before_calls
    cases.append({"case": "service_guarded_second_getter", "allocation_skipped": True})

    flag_pages = fresh_pages()
    flag_alloc = Allocator()
    flag = objects.construct_service_reference(
        flag_pages, image_base=IMAGE_BASE, kind="flag", allocate=flag_alloc.take)
    assert flag.payload_size == 2
    assert _read_span(flag_pages, flag.payload_address, 2) == b"\0\0"
    assert flag_alloc.calls == [[16, GUEST + 0x4000], [2, GUEST + 0x4010],
                                [4, GUEST + 0x4020]]
    cases.append({"case": "flag_zero_payload", "payload_size": 2,
                  "allocation_sequence": flag_alloc.calls})

    ready_pages = fresh_pages()
    ready_slot = IMAGE_BASE + objects.SERVICE_B_SLOT_OFFSET
    _write_span(ready_pages, ready_slot, (GUEST + 0x3F00).to_bytes(8, "little"))
    _write_span(ready_pages, IMAGE_BASE + objects.SERVICE_B_GUARD_OFFSET, b"\x01")
    ready_alloc = Allocator()
    ready = objects.construct_service_reference(
        ready_pages, image_base=IMAGE_BASE, kind="flag", allocate=ready_alloc.take)
    assert ready.wrapper_address == GUEST + 0x3F00 and not ready_alloc.calls
    cases.append({"case": "prepublished_slot", "allocation_skipped": True})

    negatives = []
    for label, initializer in (
        ("missing_service_initializer", None),
        ("initializer_failure", lambda staged, address: (_ for _ in ()).throw(
            RefillUnsupported("test failure"))),
    ):
        pages = fresh_pages()
        before = flatten(pages)
        alloc = Allocator()
        try:
            objects.construct_service_reference(
                pages, image_base=IMAGE_BASE, kind="service", allocate=alloc.take,
                initialize_payload=initializer)
        except (RefillUnsupported, ValueError):
            assert flatten(pages) == before
        else:
            raise AssertionError(label)
        negatives.append({"case": label, "rejected": True, "pages_unchanged": True})

    result = {
        "evidence_id": "vm9_service_singletons_python_20261003",
        "image_base": hex(IMAGE_BASE),
        "fresh_memory": True,
        "jvm_required": False,
        "native_execution_used_for_verification_only": False,
        "guards_and_slots": {
            "service": [hex(objects.SERVICE_A_GUARD_OFFSET),
                        hex(objects.SERVICE_A_SLOT_OFFSET)],
            "flag": [hex(objects.SERVICE_B_GUARD_OFFSET),
                     hex(objects.SERVICE_B_SLOT_OFFSET)],
        },
        "cases": cases,
        "negative_cases": negatives,
        "service_payload_constructor_complete": False,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(cases), "negative_cases": len(negatives),
                      "service_payload_constructor_complete": False}))


if __name__ == "__main__":
    main()
