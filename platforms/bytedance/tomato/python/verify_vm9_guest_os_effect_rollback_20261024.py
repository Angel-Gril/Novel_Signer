"""Verify opt-in rollback of the explicit GuestOS mapping owner."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import vm9_allocator as allocator
from vm9_effects import EffectJournal


def _digest(os):
    return ({key: bytes(value) for key, value in os.pages.items()},
            tuple(os.mappings), os.next_address)


def verify():
    rows = []

    pages = {}
    guest_os = allocator.GuestOS(pages)
    journal = EffectJournal()
    before = _digest(guest_os)
    try:
        with journal.transaction():
            mapping = guest_os.map_anonymous(0x3000, anonymous_name=b"journal",
                effect_journal=journal)
            guest_os.name_exact(mapping.base, mapping.length, b"renamed",
                effect_journal=journal)
            guest_os.protect_exact(mapping.base, mapping.length, 1,
                effect_journal=journal)
            raise allocator.RefillUnsupported("controlled mapping rejection")
    except allocator.RefillUnsupported:
        pass
    assert _digest(guest_os) == before and len(journal) == 0
    rows.append(dict(case="map_name_protect_outer_failure",
        pages_mappings_cursor_rolled_back=True))

    pages = {}
    guest_os = allocator.GuestOS(pages)
    journal = EffectJournal()
    mapping = guest_os.map_anonymous(0x2000, effect_journal=journal)
    before_mapping = _digest(guest_os)
    mark = journal.checkpoint()
    guest_os.unmap_range(mapping.base, 0x1000, effect_journal=journal)
    assert len(guest_os.mappings) == 1
    journal.rollback(mark)
    assert _digest(guest_os) == before_mapping
    rows.append(dict(case="unmap_range_explicit_rollback",
        split_mapping_and_pages_restored=True))

    pages = {}
    guest_os = allocator.GuestOS(pages)
    journal = EffectJournal()
    before = _digest(guest_os)
    mapping = guest_os.map_anonymous(0x1000, effect_journal=journal)
    assert mapping.base == 0x13600000 and len(journal) == 1
    journal.rollback(0)
    assert _digest(guest_os) == before
    rows.append(dict(case="map_explicit_rollback",
        mapping_cursor_and_zero_pages_restored=True))

    pages = {}
    guest_os = allocator.GuestOS(pages)
    before = _digest(guest_os)
    try:
        guest_os.map_anonymous(0x1000, effect_journal=object())
    except TypeError:
        pass
    else:
        raise AssertionError("invalid GuestOS effect journal accepted")
    assert _digest(guest_os) == before
    rows.append(dict(case="invalid_journal", rejected_without_mutation=True))

    return dict(schema="vm9-guest-os-effect-rollback-v1",
        evidence_label="Sample verified", controls=rows,
        python_controls=len(rows), rollback_controls=3,
        native_input_snapshot_used=False, mapping_topology_claim="owner-only",
        real_os_mapping_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify()
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n",
            encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in result.items() if k != "controls"}))


if __name__ == "__main__":
    main()
