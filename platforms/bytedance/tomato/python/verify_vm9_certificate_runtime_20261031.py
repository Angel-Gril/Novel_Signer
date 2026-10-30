"""Verify the bounded redacted runtime certificate evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "evidence/vm9_certificate_runtime_20261031.json"
GADGET_APK = "305166cd1b1b94b43a5f0e342ac683e67677605e56d9fec6caafe60bae8dc0e0"
BRIDGE = "64d858590ffcb961e6b66ff687cba9cdeb8ddf9111ed31d7b31af7ce1106dedf"
HEADERS = {"X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_digest(row: dict) -> None:
    assert set(row) == {"length", "sha256"}
    assert isinstance(row["length"], int) and row["length"] >= 0
    assert re.fullmatch(r"[0-9a-f]{64}", row["sha256"])


def check_name(row: dict | None) -> None:
    if row is None: return
    assert row.get("is_null") is False
    assert set(row) == {"is_null", "length", "sha256"}
    assert isinstance(row["length"], int) and row["length"] >= 0
    assert re.fullmatch(r"[0-9a-f]{64}", row["sha256"])


def verify(record: dict) -> dict:
    assert record["schema"] == "vm9-certificate-runtime-evidence-20261031-v1"
    assert record["artifact"] == {"package": "com.dragon.read", "version_code": 72532,
        "gadget_apk_sha256": GADGET_APK, "bridge_sha256": BRIDGE}
    assert record["capture_count"] == 2 and len(record["captures"]) == 2
    all_cert, all_factor = [], []
    for capture in record["captures"]:
        assert re.fullmatch(r"[0-9a-f]{64}", capture["capture_sha256"])
        assert capture["capture_bytes"] > 0 and re.fullmatch(r"[0-9a-f]{64}", capture["source_sha256"])
        assert capture["raw_capture_retained_in_evidence"] is False
        assert "ms.bd.c.s2.k" in capture["hooked_targets"]
        assert "ms.bd.c.s2.j.certificate" in capture["hooked_targets"]
        for row in capture["certificate_reads"]["enter"]:
            assert row["target"] in {"ms.bd.c.s2.k", "ms.bd.c.s2.j.certificate"}
            check_name(row["input"])
            assert row["context"]["thread_id"] > 0 and row["context"]["stack"]
        for row in capture["certificate_reads"]["return"]:
            assert row["target"] in {"ms.bd.c.s2.k", "ms.bd.c.s2.j.certificate"}
            check_name(row["input"])
            result = row["result"]
            assert result["is_null"] is False
            assert result["length"] in {716, 1057}
            assert re.fullmatch(r"[0-9a-f]{64}", result["sha256"])
            assert row["context"]["thread_id"] > 0 and row["context"]["stack"]
            all_cert.append(result)
        for factor in capture["six_header_calls"]:
            assert factor["result"]["count"] == 6
            assert {row["key"] for row in factor["result"]["rows"]} == HEADERS
            for row in factor["result"]["rows"]: check_digest(row["value"])
            check_digest(factor["url"])
            for key in ("length", "sha256", "path"): assert key in factor["route"]
            all_factor.append(factor)
    assert record["certificate_callback_observed"] is True
    assert record["six_header_callback_observed"] is True
    assert all_cert and all_factor
    assert record["certificate_and_six_headers_same_call_correlated"] is False
    for key in ("certificate_value_is_unique_cause_verified", "whole_request_native_python_differential_verified",
                "cronet_runtime_branch_observed", "online_header_acceptance_verified",
                "raw_urls_or_header_values_retained", "target_app_modified"):
        assert record[key] is False
    assert not re.search(r"https?://|ibssh_|frp-hat", json.dumps(record))
    return {"status": "verified_boundary", "certificate_return_events": len(all_cert),
            "six_header_calls": len(all_factor), "certificate_values_observed": sorted({r["length"] for r in all_cert})}


def main() -> int:
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    result = verify(record)
    for case in ("false_correlation", "missing_header", "online_acceptance", "raw_url"):
        invalid = copy.deepcopy(record)
        if case == "false_correlation": invalid["certificate_and_six_headers_same_call_correlated"] = True
        elif case == "missing_header": invalid["captures"][0]["six_header_calls"][0]["result"]["rows"].pop()
        elif case == "online_acceptance": invalid["online_header_acceptance_verified"] = True
        else: invalid["interpretation"] += " https://secret.invalid"
        try: verify(invalid)
        except AssertionError: continue
        raise AssertionError(f"invalid evidence accepted: {case}")
    result["negative_controls"] = 4
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
