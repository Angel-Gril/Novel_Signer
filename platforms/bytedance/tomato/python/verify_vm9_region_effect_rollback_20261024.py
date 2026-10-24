"""Verify rollback of allocator region registration and GuestOS ownership."""
from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from pathlib import Path

import vm9_allocator as model
from vm9_effects import EffectJournal


def digest_pages(pages) -> str:
    digest = hashlib.sha256()
    for page in sorted(pages):
        digest.update(page.to_bytes(8, "little"))
        digest.update(bytes(pages[page]))
    return digest.hexdigest()


def verify(checkpoint):
    baseline = pickle.load(checkpoint.open("rb"))
    baseline = {key: bytearray(value) for key, value in baseline.items()}
    state = model.read_global_boot_state(baseline)
    pages = {key: bytearray(value) for key, value in baseline.items()}
    arena = model.create_arena(pages, arena_index=1)
    guest_os = model.GuestOS(pages, next_address=0x1360_0000)
    before = digest_pages(pages)
    before_mappings = tuple(guest_os.mappings)
    before_cursor = guest_os.next_address
    journal = EffectJournal()
    try:
        with journal.transaction():
            model.register_os_region(pages, arena_address=arena,
                guest_os=guest_os, base=0x1360_0000,
                anonymous_name=b"vm9-region", effect_journal=journal)
            if not guest_os.mappings:
                raise AssertionError("region registration did not publish mapping")
            raise model.RefillUnsupported("controlled region owner rejection")
    except model.RefillUnsupported:
        pass
    assert digest_pages(pages) == before
    assert tuple(guest_os.mappings) == before_mappings
    assert guest_os.next_address == before_cursor
    assert len(journal) == 0
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
    allocation_before = digest_pages(rollback_pages)
    journal = EffectJournal()
    try:
        with journal.transaction():
            model.allocate_small_object(rollback_pages,
                thread_state_address=rollback_thread, request_size=0x2C,
                guest_os=rollback_os, effect_journal=journal)
            assert rollback_os.mappings
            raise model.RefillUnsupported("controlled malloc owner rejection")
    except model.RefillUnsupported:
        pass
    assert digest_pages(rollback_pages) == allocation_before
    assert not rollback_os.mappings and len(journal) == 0

    result = dict(schema="vm9-region-effect-rollback-v1",
        evidence_label="Sample verified", checkpoint_sha256=digest_pages(baseline),
        arena_address=hex(arena), python_controls=2, rollback_controls=2,
        region_pages_and_allocator_metadata_rolled_back=True,
        lifecycle_malloc_owner_rolled_back=True,
        guest_os_mapping_owner_rolled_back=True, native_input_snapshot_used=False,
        real_kernel_mapping_verified=False, complete_allocator_rollback_verified=False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.checkpoint)
    args.output.write_text(json.dumps(result, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
