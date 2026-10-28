"""Verify the redacted live Android-JVM frameSign capture.

The capture is produced by attaching to the already-running Tomato process and
calling the app's real x1 -> MSManagerUtils -> MSManager.frameSign path.  Raw
URLs and signature values are never accepted in the evidence output; only their
lengths and SHA-256 digests are retained.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PROFILES = ("homepage", "detail", "search")
EXPECTED_KEYS = ("frametype", "lid", "signinfo", "signvalue", "signversion")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def digest(value: str) -> dict[str, object]:
    return {"length": len(value), "sha256": sha256_bytes(value.encode("utf-8"))}


def load_capture(path: Path) -> tuple[dict, dict[str, dict]]:
    provider = None
    rows: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        event = item.get("event")
        if event == "provider_ready":
            provider = item
        elif event == "frame_sign":
            profile = item.get("profile")
            if profile in PROFILES:
                rows[profile] = item
        elif event == "frame_sign_raw":
            raise AssertionError("capture contains raw frameSign output")
    if provider is None:
        raise AssertionError("missing provider_ready event")
    if set(rows) != set(PROFILES):
        raise AssertionError(("profiles", sorted(rows)))
    return provider, rows


def verify(*, capture: Path, x1_source: Path, manager_source: Path,
           core_source: Path, output: Path) -> dict:
    provider, rows = load_capture(capture)
    if provider.get("package_name") != "com.dragon.read":
        raise AssertionError(("package", provider.get("package_name")))
    if provider.get("init_trigger") != "triggered":
        raise AssertionError(("init_trigger", provider.get("init_trigger")))
    if provider.get("manager_present") is not True:
        raise AssertionError("MSManager provider was not returned")
    if provider.get("manager_class") != "com.bytedance.mobsec.metasec.ml.MSManager":
        raise AssertionError(("manager_class", provider.get("manager_class")))
    modules = {item.get("name") for item in provider.get("modules", [])}
    if "libmetasec_ml.so" in modules:
        raise AssertionError("capture unexpectedly reports a direct libmetasec_ml.so module")

    observations = {}
    for profile in PROFILES:
        row = rows[profile]
        if row.get("frame_type") != 0:
            raise AssertionError(("frame_type", profile, row.get("frame_type")))
        url = row.get("url")
        if not isinstance(url, dict) or set(url) != {"length", "sha256"}:
            raise AssertionError(("redacted_url", profile))
        raw_rows = row.get("rows")
        if not isinstance(raw_rows, list):
            raise AssertionError(("rows", profile))
        by_key = {item.get("key"): item for item in raw_rows}
        if tuple(sorted(by_key)) != tuple(sorted(EXPECTED_KEYS)):
            raise AssertionError(("keys", profile, sorted(by_key)))
        clean = {}
        for key in EXPECTED_KEYS:
            value = by_key[key]
            if set(value) != {"key", "length", "sha256"}:
                raise AssertionError(("raw_value_or_shape", profile, key))
            if not isinstance(value["length"], int) or value["length"] <= 0:
                raise AssertionError(("value_length", profile, key))
            if not isinstance(value["sha256"], str) or len(value["sha256"]) != 64:
                raise AssertionError(("value_digest", profile, key))
            clean[key] = {"length": value["length"], "sha256": value["sha256"]}
        if clean["frametype"]["length"] != 1 or clean["signversion"]["length"] != 3:
            raise AssertionError(("constant_fields", profile, clean))
        if clean["signvalue"]["length"] != 64:
            raise AssertionError(("signvalue_length", profile, clean["signvalue"]))
        observations[profile] = {"url": url, "fields": clean}

    url_hashes = {row["url"]["sha256"] for row in observations.values()}
    signinfo_hashes = {row["fields"]["signinfo"]["sha256"] for row in observations.values()}
    signvalue_hashes = {row["fields"]["signvalue"]["sha256"] for row in observations.values()}
    if len(url_hashes) != 3:
        raise AssertionError("controlled URL profiles are not distinct")
    if len(signinfo_hashes) != 3 or len(signvalue_hashes) != 3:
        raise AssertionError("actual JVM frameSign did not vary with the URL profiles")

    source_hashes = {
        "capture": sha256(capture),
        "x1_source": sha256(x1_source),
        "manager_source": sha256(manager_source),
        "core_source": sha256(core_source),
    }
    report = {
        "schema": "vm9-actual-android-jvm-frame-sign-20261028-v1",
        "evidence_date": "2026-10-28",
        "process_package": provider["package_name"],
        "manager_class": provider["manager_class"],
        "init_path": "x1.k(Application) -> x1.l(Context) -> MSManagerUtils.init -> MSManagerUtils.get(1967)",
        "frame_sign_method": "MSManager.frameSign(String,int) via the real Android JVM object",
        "frame_type": 0,
        "profiles": list(PROFILES),
        "result_keys": list(EXPECTED_KEYS),
        "result_cardinality": 5,
        "distinct_url_profiles_verified": True,
        "signinfo_sensitive_to_url": True,
        "signvalue_sensitive_to_url": True,
        "observations": observations,
        "provider_modules_matching_filter": sorted(modules),
        "direct_metasec_module_observed": False,
        "actual_jni_provider_verified": True,
        "live_android_jvm_verified": True,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "source_hashes": source_hashes,
        "interpretation": (
            "An attach-safe probe in the running com.dragon.read process invoked the app's "
            "real x1 initialization path. MSManagerUtils.init returned a live manager for "
            "app id 1967, and reflection invoked MSManager.frameSign(String,int) on that "
            "object for three distinct URL profiles. All calls returned the five-key result "
            "shape; both signinfo and signvalue changed with the URL. This closes the live "
            "Android-JVM/JNI frameSign boundary only. It is not a whole-request native/Python "
            "differential, standalone signer, or online acceptance result."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--x1-source", type=Path, required=True)
    parser.add_argument("--manager-source", type=Path, required=True)
    parser.add_argument("--core-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(
        capture=args.capture,
        x1_source=args.x1_source,
        manager_source=args.manager_source,
        core_source=args.core_source,
        output=args.output,
    )
    print(json.dumps({
        "actual_jni_provider_verified": report["actual_jni_provider_verified"],
        "live_android_jvm_verified": report["live_android_jvm_verified"],
        "signinfo_sensitive_to_url": report["signinfo_sensitive_to_url"],
        "signvalue_sensitive_to_url": report["signvalue_sensitive_to_url"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
