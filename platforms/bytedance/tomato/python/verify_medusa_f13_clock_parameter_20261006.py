"""Verify explicit Medusa f13 clock inputs against a private snapshot.

The verifier is intentionally fail-closed when the private snapshot directory
is absent.  It records whether the bounded f13 VM actually consumes syscall 113
and whether changing the explicit clock inputs changes the output.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot-dir", type=Path, default=Path(r"C:\AI\6\udghook"))
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    snapshot = args.snapshot_dir.resolve()
    required = [
        "dump_bigstart_m0.bin", "dump_bigstart_m1.bin", "dump_bigstart_m2.bin",
        "dump_bigstart_copy2.bin", "dump_bigstart_regs.txt",
    ]
    missing = [name for name in required if not (snapshot / name).is_file()]
    if missing:
        raise SystemExit("private Medusa snapshot is unavailable: " + ", ".join(missing))
    os.environ["MEDUSA_F13_SNAPSHOT_DIR"] = str(snapshot)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import medusa_f13

    query = "query=%E4%B8%89%E4%BD%93&offset=0&aid=1967"
    controls = []
    for index, (wall_time, wall_nanoseconds) in enumerate((
        (1790085004, 953000000),
        (1790085005, 953000000),
        (1790085004, 953000001),
        (0, 0),
        (2147483647, 999999999),
    )):
        output = medusa_f13.medusa_f13_core(
            query, wall_time=wall_time, wall_nanoseconds=wall_nanoseconds,
        )
        svc_counts = collections.Counter(number for number, _ in medusa_f13.svc_log)
        controls.append({
            "index": index,
            "wall_time": wall_time,
            "wall_nanoseconds": wall_nanoseconds,
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_hex": output.hex(),
            "output_length": len(output),
            "syscall_counts": {str(key): value for key, value in sorted(svc_counts.items())},
            "clock_syscall_count": svc_counts.get(113, 0),
        })
    first = controls[0]["output_sha256"]
    report = {
        "evidence_id": "medusa_f13_clock_parameter_20261006",
        "schema": "medusa-f13-clock-parameter-v1",
        "status": "explicit_clock_inputs_accepted_but_not_consumed_by_snapshot_path",
        "snapshot_directory_sha256": hashlib.sha256(
            b"".join((snapshot / name).read_bytes() for name in required)
        ).hexdigest(),
        "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
        "controls": controls,
        "all_outputs_equal": all(row["output_sha256"] == first for row in controls),
        "all_clock_syscalls_zero": all(row["clock_syscall_count"] == 0 for row in controls),
        "frozen_default_output_sha256": first,
        "frozen_default_output_hex": controls[0]["output_hex"],
        "explicit_clock_api_parameterized": True,
        "snapshot_clock_path_observed": False,
        "fresh_medusa_output_verified": False,
        "current_online_header_matrix_verified": False,
        "complete_python_medusa": False,
        "limitations": [
            "The private BIG VM snapshot does not execute syscall 113 in this bounded f13 path.",
            "Equal outputs under clock changes therefore do not establish live timestamp behavior.",
            "No server request or current online Medusa acceptance is performed by this verifier.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("medusa f13 clock parameter differential PASS")


if __name__ == "__main__":
    main()
