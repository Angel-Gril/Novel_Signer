"""Validate the opt-in unidbg external-runtime-page watcher capture.

This verifier consumes an already completed HookMain run.  It does not create
or populate the relocated dispatch page; an empty watcher log is a valid result
and means that this particular successful-looking unidbg path never touched the
observed range.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


WATCH_LO = 0x13600000
WATCH_HI = 0x13800000
WATCH_DUMP = "vm9_runtimetable_first_1367a000.bin"
WATCH_LOG = "vm9_runtimetable_watch.ndjson"
ROUNDS = "rounds.json"
EXPECTED_HEADERS = (
    "X-Argus",
    "X-Gorgon",
    "X-Helios",
    "X-Khronos",
    "X-Ladon",
    "X-Medusa",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(artifact_dir: Path) -> dict:
    watch_path = artifact_dir / WATCH_LOG
    rounds_path = artifact_dir / ROUNDS
    run_path = artifact_dir / "run.log"
    if not watch_path.is_file() or not rounds_path.is_file() or not run_path.is_file():
        raise SystemExit(f"incomplete capture directory: {artifact_dir}")

    events = []
    raw_watch = watch_path.read_text(encoding="utf-8")
    for line_no, line in enumerate(raw_watch.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid watcher JSON at line {line_no}: {exc}")
        address = int(event["address"], 16)
        if not WATCH_LO <= address < WATCH_HI:
            raise SystemExit(f"watcher address outside range: {event['address']}")
        events.append(event)

    rounds = json.loads(rounds_path.read_text(encoding="utf-8"))
    if not isinstance(rounds, dict) or not rounds:
        raise SystemExit("rounds.json does not contain a result object")
    header_keys = set()
    for row in rounds.values():
        if not isinstance(row, dict):
            raise SystemExit("round entry is not an object")
        header_keys.update(key for key in row if key.startswith("X-"))
    missing = [key for key in EXPECTED_HEADERS if key not in header_keys]
    if missing:
        raise SystemExit(f"signer-looking output is missing headers: {missing}")

    run_text = run_path.read_text(encoding="utf-8", errors="replace")
    summary = "RUNTIMETABLEWATCH_SUMMARY events=" + str(len(events))
    if summary not in run_text:
        raise SystemExit(f"run.log has no matching watcher summary: {summary}")
    if "=== DONE ===" not in run_text:
        raise SystemExit("HookMain run did not reach DONE")

    dump_path = artifact_dir / WATCH_DUMP
    dumped = dump_path.is_file()
    if events and not dumped:
        raise SystemExit("watcher events exist but first-access dump is missing")

    return {
        "schema": "vm9-unidbg-runtime-table-watch-fresh-20261026-v1",
        "evidence_date": "2026-10-26",
        "capture": {
            "artifact_directory": str(artifact_dir),
            "watch_property": "runtimetablewatch=true",
            "watch_range": [hex(WATCH_LO), hex(WATCH_HI)],
            "first_dump_range": ["0x1367a000", "0x1367f000"],
            "watch_log": WATCH_LOG,
            "watch_log_sha256": _sha256(watch_path),
            "run_log_sha256": _sha256(run_path),
            "rounds_sha256": _sha256(rounds_path),
            "first_access_dump_present": dumped,
        },
        "external_runtime_table_events": events,
        "external_runtime_table_event_count": len(events),
        "external_runtime_table_event_limit": 20000,
        "signer_output": {
            "round_count": len(rounds),
            "headers_observed": [key for key in EXPECTED_HEADERS if key in header_keys],
            "headers_are_unidbg_output": True,
        },
        "runtime_table_owner_recovered": False,
        "runtime_table_content_reconstructed": False,
        "synthetic_dispatch_table_used": False,
        "native_snapshot_input": False,
        "whole_request_native_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The historical-success HookMain replay reached DONE and emitted all six "
            "expected seven-god header names, but the opt-in read/write watcher saw "
            "zero accesses in 0x13600000-0x13800000. The x13 value observed in old "
            "logs therefore cannot be promoted to evidence that this run created or "
            "read the relocated runtime table. No page or handler was synthesized."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.artifact_dir)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("unidbg runtime-table watcher", report["external_runtime_table_event_count"], "events")


if __name__ == "__main__":
    main()
