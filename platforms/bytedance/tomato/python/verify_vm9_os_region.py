"""Verify the explicit guest OS region owner and bounded global boot contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from pathlib import Path

import vm9_allocator as model


def digest_pages(pages) -> str:
    digest = hashlib.sha256()
    for page in sorted(pages):
        digest.update(page.to_bytes(8, "little"))
        digest.update(bytes(pages[page]))
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()

    baseline = pickle.load(options.checkpoint.open("rb"))
    baseline = {key: bytearray(value) for key, value in baseline.items()}
    state = model.read_global_boot_state(baseline)
    assert state.ready
    inventory = model.global_boot_inventory()
    assert len(inventory) == 8
    assert sum(item.status == "captured-input" for item in inventory) == 4

    boot_pages = {key: bytearray(value) for key, value in baseline.items()}
    boot = model.initialize_global_boot(
        boot_pages,
        config=model.GlobalBootConfig(
            arena_zero=state.arena_zero,
            arena_table=state.arena_table,
            arena_count=state.arena_count,
            arena_capacity=state.arena_capacity,
            cache_enabled=state.cache_enabled,
        ),
    )
    assert boot.ready and boot.arena_zero == state.arena_zero

    pages = {key: bytearray(value) for key, value in baseline.items()}
    arena = model.create_arena(pages, arena_index=1)
    guest_os = model.GuestOS(pages, next_address=0x1360_0000)
    registration = model.register_os_region(
        pages,
        arena_address=arena,
        guest_os=guest_os,
        base=0x1360_0000,
        anonymous_name=b"vm9-region",
    )
    pointer = model.allocate_arena_small(
        pages, arena_address=arena, request_size=0x2C
    )
    assert pointer == 0x1360_2000
    assert [model.read_u64(pages, 0x1360_0000 + offset) for offset in
            (0x68, 0x70, 0x78, 0x80, 0x250)] == [0x31, 0x1031, 0x2031, 0x3BFF0, 0x3BFF0]
    assert registration.free_node == 0x1360_0258
    assert guest_os.mapping_for(pointer) == registration.mapping

    full_pages = {key: bytearray(value) for key, value in baseline.items()}
    full_arena = model.create_arena(full_pages, arena_index=1)
    full_cache = model.create_tcache(full_pages, arena_address=full_arena)
    thread = 0x12F0_0000
    for offset in range(0, 0x80, 8):
        model.write_u64(full_pages, thread + offset, 0)
    model.write_u32(full_pages, thread + 8, 1)
    model.write_u64(full_pages, thread + 0x10, full_cache)
    model.write_u64(full_pages, thread + 0x30, full_arena)
    model.write_u32(full_pages, thread + 0x48, 1)
    full_os = model.GuestOS(full_pages, next_address=0x1360_0000)
    full_result = model.allocate_small_object(
        full_pages,
        thread_state_address=thread,
        request_size=0x2C,
        guest_os=full_os,
    )
    assert full_result.free_list.object_address == 0x1360_2000

    negative = []
    inactive_pages = {key: bytearray(value) for key, value in baseline.items()}
    key_pointer = model.read_u64(inactive_pages, 0x121C8F98)
    key = model.read_u32(inactive_pages, key_pointer)
    model.write_u64(inactive_pages, 0x121D0200 + (key & 0x7FFF_FFFF) * 16, 0)
    before_pages = digest_pages(inactive_pages)
    try:
        model.initialize_global_boot(
            inactive_pages,
            config=model.GlobalBootConfig(
                arena_zero=state.arena_zero,
                arena_table=state.arena_table,
                arena_count=state.arena_count,
                arena_capacity=state.arena_capacity,
                cache_enabled=state.cache_enabled,
            ),
        )
    except model.RefillUnsupported:
        pass
    else:
        raise AssertionError("inactive_global_tls")
    assert digest_pages(inactive_pages) == before_pages
    negative.append({"case": "inactive_global_tls", "rejected": True, "unchanged": True})

    for label, kwargs in (
        ("bad_prot", {"length": 0x40000, "prot": 1}),
        ("bad_flags", {"length": 0x40000, "flags": 0x12}),
        ("bad_length", {"length": 0x30001}),
        ("overlap", {"length": 0x1000, "address": 0x1360_0000}),
    ):
        before_pages = digest_pages(pages)
        before_mappings = tuple(guest_os.mappings)
        try:
            guest_os.map_anonymous(**kwargs)
        except model.RefillUnsupported:
            pass
        else:
            raise AssertionError(label)
        assert digest_pages(pages) == before_pages
        assert tuple(guest_os.mappings) == before_mappings
        negative.append({"case": label, "rejected": True, "unchanged": True})

    rollback_pages = {key: bytearray(value) for key, value in baseline.items()}
    rollback_arena = model.create_arena(rollback_pages, arena_index=1)
    rollback_cache = model.create_tcache(rollback_pages, arena_address=rollback_arena)
    rollback_thread = 0x12F0_0000
    for offset in range(0, 0x80, 8):
        model.write_u64(rollback_pages, rollback_thread + offset, 0)
    model.write_u32(rollback_pages, rollback_thread + 8, 1)
    model.write_u64(rollback_pages, rollback_thread + 0x10, rollback_cache)
    model.write_u64(rollback_pages, rollback_thread + 0x30, rollback_arena)
    model.write_u32(rollback_pages, rollback_thread + 0x48, 1)
    rollback_os = model.GuestOS(rollback_pages, next_address=0x1360_0000)
    before_pages = digest_pages(rollback_pages)
    try:
        model.allocate_small_object(
            rollback_pages,
            thread_state_address=rollback_thread,
            request_size=0x40000,
            guest_os=rollback_os,
        )
    except model.RefillUnsupported:
        pass
    else:
        raise AssertionError("allocation_failure_rollback")
    assert digest_pages(rollback_pages) == before_pages
    assert not rollback_os.mappings
    negative.append({"case": "allocation_failure_rollback", "rejected": True, "unchanged": True})

    result = {
        "evidence_id": "vm9_os_region_register_20261003",
        "status": "guest_os_owner_and_region_registration_verified",
        "checkpoint_pages": len(baseline),
        "checkpoint_sha256": digest_pages(baseline),
        "global_boot": {
            "ready_before": state.ready,
            "ready_after": boot.ready,
            "arena_count": boot.arena_count,
            "arena_capacity": boot.arena_capacity,
            "tls_generation_odd": bool(boot.tls_generation & 1),
            "component_inventory": [
                {"symbol": item.symbol, "status": item.status} for item in inventory
            ],
        },
        "mapping": {
            "base": hex(registration.region_base),
            "length": hex(registration.region_length),
            "prot": registration.mapping.prot,
            "flags": hex(registration.mapping.flags),
            "zero_initialized_pages": registration.region_length // 0x1000,
            "first_free_page": registration.first_free_page,
            "free_page_count": registration.free_page_count,
            "free_node": hex(registration.free_node),
            "first_allocation": hex(pointer),
            "integrated_first_malloc": hex(full_result.free_list.object_address),
            "metadata_after_first_allocation": [
                hex(value) for value in (0x31, 0x1031, 0x2031, 0x3BFF0, 0x3BFF0)
            ],
        },
        "negative_cases": negative,
        "unsupported": [
            "arbitrary syscalls",
            "mapping outside 0x13600000..0x14000000",
            "whole-region unmap/release",
            "lookup-cache generation and callback-table boot",
        ],
        "fresh_input_signer": False,
    }
    options.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
