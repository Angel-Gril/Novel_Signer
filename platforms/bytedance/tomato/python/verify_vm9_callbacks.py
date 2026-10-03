"""Verify the parameterized callback boundary primitives."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import vm9_allocator as allocator
import vm9_callbacks as callbacks


def digest_pages(pages) -> str:
    digest = hashlib.sha256()
    for page in sorted(pages):
        digest.update(page.to_bytes(8, "little"))
        digest.update(bytes(pages[page]))
    return digest.hexdigest()


def put(pages, address, data):
    page = pages[address >> 12]
    page[address & 0xFFF:(address & 0xFFF) + len(data)] = data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()

    pages = {index: bytearray(0x1000) for index in range(4)}
    wrapper = 0x0000_1000
    timespec = 0x0000_2000
    descriptor = 0x0000_3000
    put(pages, wrapper + 8, timespec.to_bytes(8, "little"))
    put(pages, descriptor + 0x10, b"preserve")

    clock = callbacks.clock_callback(
        pages,
        wrapper_address=wrapper,
        clock_id=1,
        seconds=1790261112,
        nanoseconds=123456789,
    )
    assert clock.return_code == 0
    assert allocator.read_u64(pages, timespec) == 1790261112
    assert allocator.read_u64(pages, timespec + 8) == 123456789
    assert allocator.read_u64(pages, wrapper + 0x10) == 0

    descriptor_result = callbacks.publish_callback_descriptor(
        pages,
        descriptor_address=descriptor,
        branch_target=0x125EA444,
        object_address=0x1284A288,
    )
    assert descriptor_result.branch_target == 0x125EA444
    assert allocator.read_u64(pages, descriptor) == 0x125EA444
    assert allocator.read_u64(pages, descriptor + 8) == 0x1284A288
    assert bytes(pages[descriptor >> 12][0x10:0x18]) == b"preserve"

    negative = []
    before = digest_pages(pages)
    for label, kwargs in (
        ("clock_id", {"clock_id": 7, "seconds": 1, "nanoseconds": 0}),
        ("nanoseconds", {"clock_id": 1, "seconds": 1, "nanoseconds": 1_000_000_000}),
    ):
        try:
            callbacks.clock_callback(pages, wrapper_address=wrapper, **kwargs)
        except allocator.RefillUnsupported:
            pass
        else:
            raise AssertionError(label)
        assert digest_pages(pages) == before
        negative.append({"case": label, "rejected": True, "unchanged": True})
    try:
        callbacks.compose_packed_callback_x8(upper_word=1, lower_word=2)
    except allocator.RefillUnsupported:
        negative.append({"case": "packed_callback_x8", "rejected": True, "unchanged": True})
    else:
        raise AssertionError("packed_callback_x8")

    result = {
        "evidence_id": "vm9_callbacks_parameterized_20261003",
        "status": "proven_callback_boundaries_parameterized",
        "clock_wrapper": {
            "timespec_pointer_field": "+0x08",
            "result_slot": "+0x10",
            "clock_id": clock.clock_id,
            "return_code": clock.return_code,
        },
        "descriptor_writer": {
            "writes": ["descriptor+0x00", "descriptor+0x08"],
            "branch_target": hex(descriptor_result.branch_target),
            "object_address": hex(descriptor_result.object_address),
            "trampoline": "ldp x1,x8,[x0]; mov x0,x8; br x1",
        },
        "negative_cases": negative,
        "unsupported": [
            "packed callback-object x8 composition",
            "remaining native constructor/destructor object graph",
        ],
        "fresh_input_signer": False,
    }
    options.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
