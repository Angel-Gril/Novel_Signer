"""Verify that the pinned signer ELF is embedded in the installed-version APK."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


APK_SHA256 = "95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd"
DSO_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"
DSO_ENTRY = "lib/arm64-v8a/libmetasec_ml.so"
RUNTIME_SCHEMA = "vm9-runtime-app-version-20261028-v1"
SCHEMA = "vm9-signer-apk-provenance-20261102-v1"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_record(apk: Path, sample: Path, runtime_record: Path) -> dict:
    runtime = json.loads(runtime_record.read_text(encoding="utf-8"))
    if runtime.get("schema") != RUNTIME_SCHEMA:
        raise AssertionError("unexpected runtime identity record")
    if runtime.get("installed_apk_sha256") != APK_SHA256:
        raise AssertionError("installed APK identity record changed")
    if runtime.get("pinned_apk_sha256") != APK_SHA256:
        raise AssertionError("pinned APK identity record changed")
    if runtime.get("package") != "com.dragon.read":
        raise AssertionError("unexpected installed package")
    if runtime.get("installed_version_name") != "7.2.5.32":
        raise AssertionError("unexpected installed package version name")
    if runtime.get("installed_version_code") != 72532:
        raise AssertionError("unexpected installed package version")
    if runtime.get("pinned_apk_version_code") != 72532:
        raise AssertionError("pinned APK version does not match installed version")

    apk_digest = sha256_file(apk)
    if apk_digest != APK_SHA256:
        raise AssertionError("APK digest does not match installed package")

    with zipfile.ZipFile(apk) as archive:
        entries = [name for name in archive.namelist()
                   if name.endswith("/libmetasec_ml.so")]
        if entries != [DSO_ENTRY]:
            raise AssertionError(("unexpected native library entries", entries))
        embedded = archive.read(DSO_ENTRY)

    embedded_digest = sha256(embedded)
    sample_digest = sha256_file(sample)
    if embedded_digest != DSO_SHA256 or sample_digest != DSO_SHA256:
        raise AssertionError(("native sample identity", embedded_digest, sample_digest))
    if len(embedded) != 3971808 or sample.stat().st_size != len(embedded):
        raise AssertionError("native library size mismatch")

    return {
        "schema": SCHEMA,
        "evidence_date": "2026-11-02",
        "artifact": {
            "package": runtime["package"],
            "version_name": runtime["installed_version_name"],
            "version_code": runtime["installed_version_code"],
            "apk_sha256": apk_digest,
        },
        "embedded_native_library": {
            "entry": DSO_ENTRY,
            "bytes": len(embedded),
            "sha256": embedded_digest,
        },
        "pinned_signer_sample": {
            "bytes": sample.stat().st_size,
            "sha256": sample_digest,
            "byte_identical_to_embedded_library": True,
        },
        "previous_research_version_label": {
            "version_name": runtime["pinned_research_version_name"],
            "version_code": runtime["pinned_research_version_code"],
            "apk_identity_claim_superseded": True,
        },
        "installed_apk_matches_pinned_artifact": True,
        "runtime_device_abi": runtime["device_abi"],
        "runtime_mapped_library_identity_verified": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False,
        "online_header_acceptance_verified": False,
        "interpretation": (
            "The exact APK digest recorded for the installed 7.2.5.32 package was "
            "recomputed from fq_7xz.apk. Its sole libmetasec_ml.so entry is byte-identical "
            "to the pinned ELF used by the native signer replay. The old 7.1.3.32 label "
            "therefore describes a historical research-version label, not the APK identity "
            "of this signer sample. This proves artifact provenance, not which translated "
            "library mapping the running x86_64 process selected."
        ),
    }


def verify(record: dict, apk: Path, sample: Path, runtime_record: Path) -> dict:
    if record != build_record(apk, sample, runtime_record):
        raise AssertionError("record differs from the pinned APK/member hashes")
    return {
        "status": "verified_apk_native_sample_provenance",
        "apk_version_code": record["artifact"]["version_code"],
        "native_library_bytes": record["embedded_native_library"]["bytes"],
        "native_sample_byte_identical": record["pinned_signer_sample"]["byte_identical_to_embedded_library"],
        "runtime_mapped_library_identity_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--runtime-record", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--record", type=Path)
    args = parser.parse_args()

    if args.output is not None:
        if args.output.exists():
            parser.error("--output already exists")
        record = build_record(args.apk, args.sample, args.runtime_record)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        record = json.loads(args.record.read_text(encoding="utf-8"))
    print(json.dumps(
        verify(record, args.apk, args.sample, args.runtime_record),
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
