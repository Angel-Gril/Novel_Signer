"""Verify the observed absence of certificate callbacks in four native runs."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import verify_vm9_package_identity_control_20261031 as identity


EVIDENCE = identity.ROOT / "evidence/vm9_certificate_native_replay_20261031.json"
HEADERS = {"X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa"}


def verify(record: dict) -> dict:
    assert record["schema"] == "vm9-certificate-native-replay-20261031-v1"
    observed_identity = json.loads(identity.EVIDENCE.read_text(encoding="utf-8"))
    identity.verify(observed_identity)
    assert record["capture_source_sha256"] == identity.digest(
        identity.ROOT / "python/capture_vm9_certificate_replay_20261031.py")
    assert record["native_inputs_sha256"] == {
        "SO_MAIN": "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c",
        "SO_CPP": "6760e8b9953361968ee8f34ae40ef68bd3b47aa7ba37ef1dcf8902c07d0dc036",
        "APK": identity.OFFICIAL_APK,
    }
    for key in ("harness_source_sha256", "isolated_source_sha256", "isolated_hook_class_sha256",
                "classpath_file_sha256", "identity_evidence_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", record[key])
    assert record["configured_certificates"] == {
        "official_legacy": observed_identity["package_manager_observations"]["official"]["legacy_signatures"][0],
        "resigned": observed_identity["package_manager_observations"]["resigned"]["legacy_signatures"][0],
    }
    assert record["frozen_timestamp_ms"] == 1790261111000
    assert record["emulated_pid"] == 11340 and record["ab_switch"] == 2
    assert record["fake_random"] and record["fresh_rootfs_per_run"]
    runs = record["runs"]
    assert [row["label"] for row in runs] == ["null_a", "null_b", "official_legacy", "resigned"]
    for row in runs:
        assert row["exit_code"] == 0 and row["native_run_completed"]
        assert row["native_signing_tag_observed"]
        assert row["certificate_callback_count"] == row["null_certificate_callback_count"] == 0
        assert row["certificate_callback_markers"] == []
        headers = row["header_observations"]
        assert set(headers) == HEADERS
        for value in headers.values():
            assert set(value) == {"length", "sha256"} and value["length"] > 0
            assert re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
        assert headers["X-Khronos"] == {"length": 10,
            "sha256": hashlib.sha256(b"1790261111").hexdigest()}
        assert headers == runs[0]["header_observations"]
    assert record["null_control_repeat_equal"] is True
    assert record["output_differences_vs_null"] == {"official_legacy": [], "resigned": []}
    assert record["installed_harness_source_unchanged"] and record["temporary_artifacts_cleaned"]
    for key in ("certificate_input_delivery_verified", "certificate_input_sensitivity_evaluated",
                "target_app_modified", "live_app_callback_observed",
                "whole_request_native_python_differential_verified", "fresh_standalone_signer_verified",
                "online_header_acceptance_verified", "raw_urls_or_header_values_retained"):
        assert record[key] is False, key
    assert not re.search(r"https?://|ibssh_|frp-hat", json.dumps(record))
    return {"status": "verified_boundary", "native_runs": len(runs),
            "certificate_callback_count": 0, "certificate_input_sensitivity_evaluated": False}


def main() -> int:
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    result = verify(record)
    for case in ("false_delivery", "substituted_certificate", "changed_repeat", "false_online_acceptance"):
        invalid = copy.deepcopy(record)
        if case == "false_delivery":
            invalid["certificate_input_delivery_verified"] = True
        elif case == "substituted_certificate":
            invalid["configured_certificates"]["official_legacy"]["sha256"] = identity.CURRENT_CERT
        elif case == "changed_repeat":
            invalid["runs"][1]["header_observations"]["X-Medusa"]["sha256"] = "0" * 64
        else:
            invalid["online_header_acceptance_verified"] = True
        try:
            verify(invalid)
        except AssertionError:
            continue
        raise AssertionError(f"invalid evidence accepted: {case}")
    result["negative_controls"] = 4
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
