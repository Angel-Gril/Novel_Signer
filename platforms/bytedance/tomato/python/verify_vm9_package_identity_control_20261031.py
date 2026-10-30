"""Check package-identity and re-sign control evidence; optionally recheck APKs."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import struct
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).parents[1]
EVIDENCE = ROOT / "evidence/vm9_package_identity_control_20261031.json"
OFFICIAL_APK = "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd"
CONTROL_APK = "125f9633912e3e150afb8513bbba5c0161361b643378ef6e45fbc9aa383d3d20"
LEGACY_CERT = "c6bbd352ee9ccfbdec729ba9260d5fd8a48ca163379ff2c0d741dd2ec2bfd0d9"
CURRENT_CERT = "1a5a89132e82ed5b9b2aa05cbf138b6a00096326cf90a1c17480aa0af1f0a163"
CONTROL_CERT = "56407d729c43d59cbcffce1c4b89c3d6b74ad23cc5e3868f6e4afab5e1cf18d3"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(record: dict) -> dict:
    assert record["schema"] == "vm9-package-identity-control-20261031-v1"
    for name, apk, legacy, current, length in (
        ("official", OFFICIAL_APK, LEGACY_CERT, CURRENT_CERT, 921),
        ("resigned", CONTROL_APK, CONTROL_CERT, CONTROL_CERT, 716),
        ("restored", OFFICIAL_APK, LEGACY_CERT, CURRENT_CERT, 921),
    ):
        row = record["package_manager_observations"][name]
        assert row["event"] == "package_identity"
        assert row["package"] == "com.dragon.read" and row["version_code"] == 72532
        assert row["version_name"] == "7.2.5.32" and row["sdk"] == 33
        assert row["apk_sha256"] == apk
        assert row["legacy_signatures"] == [{"length": length, "sha256": legacy}]
        assert row["current_signers"] == [{"length": length, "sha256": current}]
        expected_history = [row["legacy_signatures"][0]]
        if legacy != current:
            expected_history += row["current_signers"]
        assert row["signing_history"] == expected_history
        assert row["debuggable"] is False and row["target_process_instrumented"] is False
        assert row["probe_source_sha256"] == digest(ROOT / "python/android/Vm9PackageIdentity.java")
    system = record["system_package_observations"]["android"]
    assert system == {
        "event": "package_identity",
        "package": "android",
        "sdk": 33,
        "version_code": 33,
        "version_name": "13",
        "debuggable": False,
        "apk_sha256": "9eaf067a1b163d662bd2bacc68a2816374d983931f7ef7dde0b1f3cc14f0ec93",
        "legacy_signatures": [{"length": 1057, "sha256": "c3916f312e2cffe031498137ea9e9f6693902af5dde9ecf720f43adbe34a6c4d"}],
        "current_signers": [{"length": 1057, "sha256": "c3916f312e2cffe031498137ea9e9f6693902af5dde9ecf720f43adbe34a6c4d"}],
        "signing_history": [{"length": 1057, "sha256": "c3916f312e2cffe031498137ea9e9f6693902af5dde9ecf720f43adbe34a6c4d"}],
        "target_process_instrumented": False,
        "probe_source_sha256": digest(ROOT / "python/android/Vm9PackageIdentity.java"),
    }
    comparison = record["archive_comparison"]
    assert comparison["original_entry_count"] == comparison["resigned_entry_count"] == 21771
    assert comparison["added_entries"] == ["META-INF/GADGET.RSA", "META-INF/GADGET.SF"]
    assert comparison["removed_entries"] == ["META-INF/BYTESIGN.RSA", "META-INF/BYTESIGN.SF"]
    assert comparison["changed_common_entries"] == []
    assert comparison["gadget_library_present"] is False
    assert record["static_callback"]["tag"] == "0x1000002"
    assert record["static_callback"]["package_info_flags"] == 64
    assert record["static_callback"]["whole_j_method_decode_verified"] is False
    assert record["static_callback"]["actual_app_callback_value_observed"] is False
    behavior = record["behavior_control"]
    assert behavior["same_device"] and behavior["both_fresh_installs"]
    assert behavior["same_book_and_chapter"] and behavior["chapter_number"] == 1
    assert behavior["official_bookstore_loaded"] and behavior["resigned_bookstore_loaded"]
    assert behavior["resigned_reader_warning"] == "当前版本不安全，请到正规应用市场下载"
    assert behavior["restored_official_chapter_body_visually_observed"] is True
    assert behavior["resigned_response_code_observed"] is None
    for name in (
        "certificate_bytes_are_unique_cause_verified", "cronet_runtime_branch_observed",
        "whole_request_native_python_differential_verified", "fresh_standalone_signer_verified",
        "online_six_header_acceptance_verified", "raw_requests_or_header_values_retained",
    ):
        assert record[name] is False, name
    checks = record["cli_checks"]
    assert [(row["case"], row["exit_code"]) for row in checks["negative_cases"]] == [
        ("missing_package", 1), ("overwrite_refused", 2), ("invalid_package", 2)]
    assert checks["existing_output_unchanged"] and checks["missing_package_output_absent"]
    assert checks["device_temporary_dex_cleaned"]
    assert checks["before_temp_count"] == checks["after_temp_count"] == 0
    assert checks["driver_source_sha256"] == digest(
        ROOT / "python/capture_vm9_package_identity_android_20261031.py")
    for row in record["local_visual_observations"].values():
        assert row["visually_reviewed"] is True
        assert re.fullmatch(r"[0-9a-f]{64}", row["screen_sha256"])
        assert re.fullmatch(r"[0-9a-f]{64}", row["ui_xml_sha256"])
    return {"status": "verified_boundary", "same_chapter_control": True,
            "legacy_certificate_rotation_verified": True, "signer_complete": False}


def verify_apks(original: Path, resigned: Path, record: dict) -> None:
    assert digest(original) == OFFICIAL_APK and digest(resigned) == CONTROL_APK
    with ZipFile(original) as a, ZipFile(resigned) as b:
        left, right = set(a.namelist()), set(b.namelist())
        assert len(left) == len(a.namelist()) == 21771
        assert len(right) == len(b.namelist()) == 21771
        comparison = record["archive_comparison"]
        assert sorted(right - left) == comparison["added_entries"]
        assert sorted(left - right) == comparison["removed_entries"]
        assert sorted(n for n in left & right if a.read(n) != b.read(n)) == []
        assert not any(n.startswith("lib/") and "gadget" in n.lower() for n in right)
        data = a.read("classes16.dex")
        assert hashlib.sha256(data).hexdigest() == record["static_callback"]["dex_sha256"]
        # This bounded switch was located by the DEX method indexer, not a byte search.
        # Only this dispatch slice is checked; s2.j's full decode is incomplete.
        switch = 0x67FD9E
        assert data[switch] == 0x2B  # packed-switch
        payload = switch + 2 * struct.unpack_from("<i", data, switch + 2)[0]
        ident, count, first_key = struct.unpack_from("<HHi", data, payload)
        assert (payload, ident, count, first_key) == (0x6814BC, 0x100, 3, 0x1000001)
        target = switch + 2 * struct.unpack_from("<i", data, payload + 12)[0]
        assert target == 0x67FDE8
        assert data[target:target + 6].hex() == "7701f4da2700"  # invoke-static/range s2.k
        assert data[0x6818A8:0x6818AC].hex() == "13004000"  # const/16 v0, 64


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-apk", type=Path)
    parser.add_argument("--resigned-apk", type=Path)
    args = parser.parse_args()
    if (args.original_apk is None) != (args.resigned_apk is None):
        parser.error("provide both APK paths together")
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    result = verify(record)
    for case in ("wrong_legacy_certificate", "changed_code", "false_acceptance"):
        invalid = copy.deepcopy(record)
        if case == "wrong_legacy_certificate":
            invalid["package_manager_observations"]["official"]["legacy_signatures"] = invalid[
                "package_manager_observations"]["official"]["current_signers"]
        elif case == "changed_code":
            invalid["archive_comparison"]["changed_common_entries"] = ["classes16.dex"]
        else:
            invalid["online_six_header_acceptance_verified"] = True
        try:
            verify(invalid)
        except AssertionError:
            continue
        raise AssertionError(f"invalid evidence accepted: {case}")
    if args.original_apk is not None:
        verify_apks(args.original_apk, args.resigned_apk, record)
    result["apk_archives_rechecked"] = args.original_apk is not None
    result["negative_controls"] = 3
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
