"""Check that the current runtime evidence keeps unresolved claims closed.

This is a small cross-record guard.  It does not infer a result from a
missing field: every selected record must expose at least one of the
unresolved flags, and any exposed unresolved flag must remain ``false``.
The guard is intentionally read-only and never turns an OkHttp or synthetic
observation into Cronet evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "vm9-claim-matrix-20261106-v1"
UNRESOLVED = (
    "cronet_entry_runtime_observed",
    "cronet_runtime_branch_observed",
    "runtime_adapter_identity_resolved",
    "r4_callback_cronet_identity_joined",
    "ordinary_cronet_six_head_chain_verified",
    "callback_url_or_map_object_identity_joined",
    "provider_method_or_field_identity_joined",
    "android_captured_jni_buffer_consumption_byte_joined",
    "complete_native_outer_state_equal",
    "complete_standalone_signer_verified",
    "fresh_standalone_signer_verified",
    "whole_request_native_python_differential_verified",
    "online_header_acceptance_verified",
    "current_online_header_matrix_verified",
)

RECORDS = (
    "vm9_cronet_callback_type_boundary_20261105.json",
    "vm9_cronet_callback_injection_scan_20261105.json",
    "vm9_cronet_callback_dex_implementation_scan_20261105.json",
    "vm9_cronet_static_adapter_r4_chain_20261105.json",
    "vm9_cronet_ordinary_initializer_static_20261105.json",
    "vm9_cronet_boe_guard_runtime_20261105.json",
    "vm9_cronet_provider_runtime_state_20261105.json",
    "vm9_cronet_synthetic_manager_r4_dispatch_20261105.json",
    "vm9_cronet_runtime_selector_state_20261105.json",
    "vm9_okhttp_r4_stack_20261105.json",
    "vm9_networkparams_runtime_window_20261105.json",
    "vm9_okhttp_r4_multirequest_20261106.json",
    "vm9_outer_graph_fresh_20261106.json",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def claims_for(report: dict[str, Any]) -> dict[str, Any]:
    claims = report.get("claims")
    require(claims is None or isinstance(claims, dict), "claims must be an object")
    result = dict(claims or {})
    for key in UNRESOLVED:
        if key in report:
            result[key] = report[key]
    return result


def verify(root: Path) -> dict[str, Any]:
    evidence_root = root / "evidence"
    rows: list[dict[str, Any]] = []
    for name in RECORDS:
        path = evidence_root / name
        require(path.is_file(), f"missing evidence: {name}")
        report = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(report, dict), f"invalid evidence object: {name}")
        claims = claims_for(report)
        exposed = {key: claims[key] for key in UNRESOLVED if key in claims}
        require(exposed, f"no unresolved flags exposed: {name}")
        bad = {key: value for key, value in exposed.items() if value is not False}
        require(not bad, f"unresolved claim opened in {name}: {bad}")
        rows.append({
            "evidence_file": f"evidence/{name}",
            "schema": report.get("schema"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "unresolved_flags_checked": sorted(exposed),
        })
    return {
        "schema": SCHEMA,
        "record_count": len(rows),
        "all_exposed_unresolved_flags_false": True,
        "records": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    default_root = Path(__file__).resolve().parents[1]
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.root)
    if args.output:
        require(not args.output.exists(), "output already exists")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "records"},
                     ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
