"""Verify the UI follow-up path-separation evidence."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "evidence/vm9_networkparams_followup_20261031.json"
GADGET_APK = "305166cd1b1b94b43a5f0e342ac683e67677605e56d9fec6caafe60bae8dc0e0"
BRIDGE = "64d858590ffcb961e6b66ff687cba9cdeb8ddf9111ed31d7b31af7ce1106dedf"
HEADERS = {"X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"}
EXPECTED_CAPTURES = {
    "k": {
        "capture_sha256": "3429b649810eb6904dc9d3d161c574da81e1626fe0e477b5903a47e2a2e044dd",
        "capture_bytes": 37044,
        "source_sha256": "6c0f6d0f57971d7f70e9ba20226a0830fd694a92bff376baab13542a219f51a8",
        "security_factor_count": 1,
        "certificate_return_count": 2,
    },
    "l": {
        "capture_sha256": "ee942045b0ee6a21e00b2554e13cdaa73949ce79ab2fb6fa851128dceadcbae2",
        "capture_bytes": 5788,
        "source_sha256": "86de590c7fcaadb0246896e84a984e66bd3eb241d2459f42ed5210865a46e167",
        "security_factor_count": 2,
        "certificate_return_count": 0,
    },
}


def check_digest(value: dict) -> None:
    assert set(value) == {"length", "sha256"}
    assert isinstance(value["length"], int) and value["length"] >= 0
    assert re.fullmatch(r"[0-9a-f]{64}", value["sha256"])


def verify(record: dict) -> dict:
    assert record["schema"] == "vm9-networkparams-followup-20261031-v1"
    assert record["artifact"] == {
        "package": "com.dragon.read",
        "version_code": 72532,
        "gadget_apk_sha256": GADGET_APK,
        "bridge_sha256": BRIDGE,
    }
    assert record["capture_count"] == 2 and len(record["captures"]) == 2
    factor_count = 0
    cert_count = 0
    for capture in record["captures"]:
        assert capture["label"] in {"k", "l"}
        expected = EXPECTED_CAPTURES[capture["label"]]
        assert {key: capture[key] for key in ("capture_sha256", "capture_bytes", "source_sha256")} == {
            key: expected[key] for key in ("capture_sha256", "capture_bytes", "source_sha256")
        }
        assert re.fullmatch(r"[0-9a-f]{64}", capture["capture_sha256"])
        assert capture["capture_bytes"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", capture["source_sha256"])
        assert capture["raw_capture_retained_in_evidence"] is False
        assert "ms.bd.c.r4.onCallToAddSecurityFactor" in capture["hooked_targets"]
        assert "CronetUrlRequest.addSecurityFactor" in capture["hooked_targets"]
        assert "CronetUrlRequestContext.addSecurityFactor" in capture["hooked_targets"]
        assert "CronetUrlRequestContext.o0" in capture["hooked_targets"]
        assert capture["cronet_event_count"] == 0
        assert len(capture["security_factor_calls"]) == expected["security_factor_count"]
        for factor in capture["security_factor_calls"]:
            factor_count += 1
            assert factor["result"]["count"] == 6
            assert {row["key"] for row in factor["result"]["rows"]} == HEADERS
            check_digest(factor["url"])
            check_digest({"length": factor["route"]["length"],
                          "sha256": factor["route"]["sha256"]})
            check_digest(factor["route"]["path"])
            for row in factor["input"]["rows"]:
                check_digest(row["value"])
            for row in factor["result"]["rows"]:
                check_digest(row["value"])
        for row in capture["certificate_returns"]:
            cert_count += 1
            assert row["result"]["is_null"] is False
            assert row["result"]["length"] in {716, 1057}
            check_digest({"length": row["result"]["length"], "sha256": row["result"]["sha256"]})
        assert len(capture["certificate_returns"]) == expected["certificate_return_count"]
    assert factor_count == 3
    assert cert_count == 2
    assert record["security_factor_callback_observed"] is True
    assert record["six_header_call_count"] == 3
    assert record["cronet_runtime_branch_observed"] is False
    for key in (
        "same_request_certificate_correlation_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
        "raw_urls_or_header_values_retained",
        "target_app_modified",
    ):
        assert record[key] is False
    assert not re.search(r"https?://|ibssh_|frp-hat", json.dumps(record))
    return {"status": "verified_path_separation", "six_header_calls": factor_count,
            "certificate_returns": cert_count, "cronet_events": 0}


def main() -> int:
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    result = verify(record)
    invalid = copy.deepcopy(record)
    invalid["cronet_runtime_branch_observed"] = True
    try:
        verify(invalid)
    except AssertionError:
        pass
    else:
        raise AssertionError("negative control accepted")
    result["negative_controls"] = 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
