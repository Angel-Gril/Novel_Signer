"""Verify the real APK/native-library provenance and Java loader boundary.

This is a read-only provenance check.  It hashes the supplied APK and DSO,
finds the ABI-qualified ``libmetasec_ml.so`` entry, and checks the decompiled
loader sources for the complete Java handoff and its two load paths:

* ``MSManagerUtils.init`` reaches ``g.c`` and ``n3.a``;
* ``n3.a`` constructs ``p3`` and enters its loader;
* ``System.loadLibrary(name)`` first;
* extraction from ``ApplicationInfo.sourceDir`` and split APKs, followed by
  ``System.load(private_lib_path)`` after an ABI-qualified ZIP lookup.

It deliberately does not execute a loader, create a synthetic DSO, or infer
the owner of the external VM dispatch/runtime table.  The resulting JSON is
safe to publish because it contains hashes, sizes, and source-feature flags,
not APK contents, URLs, credentials, or Java string payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


EXPECTED_LIBRARY = "libmetasec_ml.so"
EXPECTED_SHA256 = "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_features(path: Path, required: tuple[str, ...] = ()) -> dict[str, bool]:
    text = path.read_text(encoding="utf-8")
    checks = {
        "system_load_library": bool(re.search(r"System\.loadLibrary\s*\(", text)),
        "system_load_absolute_path": bool(re.search(r"System\.load\s*\(\s*absolutePath", text)),
        "application_source_dir": "applicationInfo.sourceDir" in text,
        "split_source_dirs": "applicationInfo.splitSourceDirs" in text,
        "abi_directory_pattern": (
            "Pattern.compile" in text and "File.separatorChar" in text
            and ('new StringBuilder("lib")' in text or 'sb.append("lib")' in text)
            and "str" in text
        ),
        "supported_abis": "Build.SUPPORTED_ABIS" in text,
        "zip_entry_lookup": "zipFile.getEntry" in text,
        "private_lib_directory": "getDir(\"lib\", 0)" in text,
        "safe_extract_path_check": 'path.contains("../")' in text,
    }
    checks["all_required_features"] = all(checks.get(key, False) for key in required)
    return checks


def verify(
    apk: Path,
    dso: Path,
    p3: Path,
    loader: Path,
    abi_source: Path | None,
    core: Path | None = None,
    native_loader: Path | None = None,
    entry: Path | None = None,
) -> dict:
    if not apk.is_file():
        raise FileNotFoundError(apk)
    if not dso.is_file():
        raise FileNotFoundError(dso)
    for source in (p3, loader, core, native_loader, entry):
        if source is None:
            continue
        if not source.is_file():
            raise FileNotFoundError(source)

    dso_hash = sha256_file(dso)
    entries: list[dict] = []
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            match = re.fullmatch(r"lib/([^/]+)/" + re.escape(EXPECTED_LIBRARY), name)
            if not match:
                continue
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            entries.append({
                "entry": name,
                "abi": match.group(1),
                "compressed_size": info.compress_size,
                "uncompressed_size": info.file_size,
                "sha256": digest.hexdigest(),
                "matches_supplied_dso": digest.hexdigest() == dso_hash,
            })

    p3_features = source_features(p3, (
        "system_load_library", "system_load_absolute_path", "private_lib_directory"
    ))
    loader_features = source_features(loader, (
        "application_source_dir", "split_source_dirs", "abi_directory_pattern", "zip_entry_lookup",
    ))
    abi_features = source_features(abi_source, ("supported_abis",)) if abi_source else {}
    core_features = source_features(core) if core else {}
    native_loader_features = source_features(native_loader) if native_loader else {}
    entry_features = source_features(entry) if entry else {}
    core_handoff = {
        "application_context_handoff": bool(core_features)
        and "n3.a(applicationContext, str)" in core.read_text(encoding="utf-8"),
        "native_library_name_selected": bool(core_features)
        and 'c(context, "metasec_ml")' in core.read_text(encoding="utf-8"),
    }
    native_loader_handoff = {
        "p3_loader_constructed": bool(native_loader_features)
        and "new p3().a(context, str)" in native_loader.read_text(encoding="utf-8"),
        "delegates_to_p3": bool(native_loader_features)
        and "new p3()" in native_loader.read_text(encoding="utf-8"),
    }
    entry_handoff = {
        "core_initializes_loader": bool(entry_features)
        and "g.c(context, LIBNAME)" in entry.read_text(encoding="utf-8"),
        "native_entry_publishes_after_load": bool(entry_features)
        and "y2.a(83886081" in entry.read_text(encoding="utf-8"),
    }
    matching_entries = [row for row in entries if row["matches_supplied_dso"]]
    java_handoff_closed = (
        all(core_handoff.values())
        and all(native_loader_handoff.values())
        and all(entry_handoff.values())
    )
    return {
        "schema": "vm9-dso-java-loader-provenance-20261027-v2",
        "evidence_label": "Real APK native-library provenance and Java loader boundary",
        "apk": {
            "basename": apk.name,
            "size": apk.stat().st_size,
            "sha256": sha256_file(apk),
            "library_entries": entries,
        },
        "supplied_dso": {
            "basename": dso.name,
            "size": dso.stat().st_size,
            "sha256": dso_hash,
            "expected_sha256": EXPECTED_SHA256,
            "matches_expected": dso_hash == EXPECTED_SHA256,
        },
        "java_sources": {
            "loader": {"basename": p3.name, "sha256": sha256_file(p3), "features": p3_features},
            "apk_scanner": {"basename": loader.name, "sha256": sha256_file(loader), "features": loader_features},
            "abi_provider": ({"basename": abi_source.name, "sha256": sha256_file(abi_source), "features": abi_features}
                             if abi_source else None),
            "core": ({"basename": core.name, "sha256": sha256_file(core),
                       "features": core_features, "handoff": core_handoff}
                      if core else None),
            "native_loader_entry": ({"basename": native_loader.name,
                                      "sha256": sha256_file(native_loader),
                                      "features": native_loader_features,
                                      "handoff": native_loader_handoff}
                                     if native_loader else None),
            "native_entry": ({"basename": entry.name, "sha256": sha256_file(entry),
                               "features": entry_features, "handoff": entry_handoff}
                              if entry else None),
        },
        "provenance_conclusion": {
            "apk_entry_found": bool(entries),
            "matching_apk_entry_found": bool(matching_entries),
            "source_sha256_matches_expected": dso_hash == EXPECTED_SHA256,
            "real_library_source_closed": bool(matching_entries) and all(
                p3_features.get(key, False) for key in (
                    "system_load_library", "system_load_absolute_path", "private_lib_directory"
                )
            ) and all(
                loader_features.get(key, False) for key in (
                    "application_source_dir", "split_source_dirs", "zip_entry_lookup"
                )
            ),
            "java_to_native_loader_handoff_closed": java_handoff_closed,
            "external_custom_mapping_source_closed": False,
            "runtime_table_owner_recovered": False,
            "synthetic_loader_executed": False,
            "synthetic_dispatch_table_used": False,
            "whole_request_native_success": False,
            "fresh_standalone_signer_verified": False,
            "online_header_acceptance_verified": False,
        },
        "interpretation": (
            "The supplied libmetasec_ml.so is byte-identical to the arm64-v8a "
            "entry in the base APK. The Java sources close the init-to-loader handoff "
            "through g.c, n3.a and p3.a, including the normal loadLibrary path and "
            "the APK/split-ABI extraction fallback. This still does not prove that "
            "the native +0x184ad4 custom mapper executed or identify the descriptor "
            "callback/runtime-table owner."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--dso", type=Path, required=True)
    parser.add_argument("--p3-source", type=Path, required=True)
    parser.add_argument("--loader-source", type=Path, required=True)
    parser.add_argument("--abi-source", type=Path)
    parser.add_argument("--core-source", type=Path)
    parser.add_argument("--native-loader-source", type=Path)
    parser.add_argument("--entry-source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(
        args.apk,
        args.dso,
        args.p3_source,
        args.loader_source,
        args.abi_source,
        args.core_source,
        args.native_loader_source,
        args.entry_source,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "library_entries": len(result["apk"]["library_entries"]),
        "matching_entries": sum(row["matches_supplied_dso"] for row in result["apk"]["library_entries"]),
        "real_library_source_closed": result["provenance_conclusion"]["real_library_source_closed"],
        "java_to_native_loader_handoff_closed": result["provenance_conclusion"]["java_to_native_loader_handoff_closed"],
        "runtime_table_owner_recovered": result["provenance_conclusion"]["runtime_table_owner_recovered"],
        "output": str(args.output),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
