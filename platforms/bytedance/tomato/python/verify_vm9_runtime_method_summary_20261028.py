"""Record a redacted method-level summary from the installed Tomato APK.

The verifier reads DEX metadata and hashes each selected code item.  It never
writes a code item, disassembly, string constant, URL, header, token, or
signature value to the evidence record.  The hashes are only a continuity
signal for the installed build; they are not a claim that the Java method
bodies are identical to the pinned JADX source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import zipfile
from pathlib import Path


logging.disable(logging.CRITICAL)
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
except ImportError:
    pass

TARGETS = {
    "Lms/bd/c/r4;": {
        "onCallToAddSecurityFactor":
        "(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
    },
    "Lms/bd/c/s4;": {"a": "(J)V"},
    "Lcom/bytedance/mobsec/metasec/core/c;": {
        "frameSign": "(Ljava/lang/String;I)Ljava/util/Map;",
    },
    "Lcom/bytedance/mobsec/metasec/ml/MSManager;": {
        "frameSign": "(Ljava/lang/String;I)Ljava/util/Map;",
    },
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequest;": {
        "addSecurityFactor": "(Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;",
    },
    "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;": {
        "addSecurityFactor": "(Ljava/lang/String;[Ljava/lang/String;)[Ljava/lang/String;",
        "o0": "(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
    },
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def apk_version(apk_path: Path) -> tuple[str, int]:
    from androguard.core.apk import APK

    info = APK(str(apk_path), skip_analysis=False).androidversion
    return str(info["Name"]), int(info["Code"])


def text(value: object) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def method_summary(method: object) -> dict[str, object]:
    code = method.get_code()
    if code is None:
        return {
            "name": method.get_name(),
            "descriptor": method.get_descriptor().replace(" ", ""),
            "has_code": False,
        }
    # Hash immediately and retain only metadata.  Do not include raw code or
    # instruction text in the returned structure.
    raw = code.get_raw()
    return {
        "name": method.get_name(),
        "descriptor": method.get_descriptor().replace(" ", ""),
        "has_code": True,
        "registers": code.get_registers_size(),
        "insns": code.get_insns_size(),
        "outs": code.get_outs_size(),
        "tries": code.get_tries_size(),
        "code_item_size": len(raw),
        "code_item_sha256": sha256_bytes(raw),
    }


def extract(apk_path: Path) -> dict[str, object]:
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
    except ImportError as exc:  # pragma: no cover - environment diagnostic
        raise RuntimeError("androguard is required for DEX summary extraction") from exc

    apk = APK(str(apk_path), skip_analysis=True)
    dex_names = list(apk.get_dex_names())
    dex_bytes = list(apk.get_all_dex())
    if len(dex_names) != len(dex_bytes):
        raise AssertionError(("dex_count", len(dex_names), len(dex_bytes)))
    found: dict[str, dict[str, object]] = {}
    target_dex: dict[str, str] = {}
    for dex_name, raw_dex in zip(dex_names, dex_bytes):
        dex = DEX(raw_dex)
        for cls in dex.get_classes():
            class_name = text(cls.name)
            if class_name not in TARGETS:
                continue
            methods = list(cls.get_methods())
            by_key = {(m.get_name(), m.get_descriptor().replace(" ", "")): m for m in methods}
            selected = []
            for name, descriptor in TARGETS[class_name].items():
                method = by_key.get((name, descriptor))
                if method is None:
                    raise AssertionError(("missing_method", class_name, name, descriptor))
                selected.append(method_summary(method))
                target_dex[f"{class_name}->{name}{descriptor}"] = dex_name
            found[class_name] = {
                "dex": dex_name,
                "class_method_count": len(methods),
                "selected_methods": sorted(selected, key=lambda item: (item["name"], item["descriptor"])),
            }
    if set(found) != set(TARGETS):
        raise AssertionError(("missing_classes", sorted(set(TARGETS) - set(found))))
    return {
        "dex_count": len(dex_names),
        "dex": [
            {"name": name, "size": len(raw), "sha256": sha256_bytes(raw)}
            for name, raw in zip(dex_names, dex_bytes)
        ],
        "classes": found,
        "target_dex": target_dex,
    }


def verify(record: Path, apk: Path | None = None, pinned_apk: Path | None = None) -> dict[str, object]:
    data = json.loads(record.read_text(encoding="utf-8"))
    if data.get("schema") != "vm9-runtime-method-summary-20261028-v1":
        raise AssertionError("unexpected schema")
    if data.get("installed_version") != "7.2.5.32/72532":
        raise AssertionError("unexpected installed version")
    if data.get("raw_method_bodies_retained") is not False:
        raise AssertionError("raw method bodies must not be retained")
    classes = data.get("classes", {})
    if set(classes) != set(TARGETS):
        raise AssertionError("target classes changed")
    for class_name, methods in TARGETS.items():
        selected = {(item.get("name"), item.get("descriptor")) for item in classes[class_name].get("selected_methods", [])}
        expected = set(methods.items())
        if selected != expected:
            raise AssertionError(("target_methods", class_name, selected, expected))
        for item in classes[class_name]["selected_methods"]:
            if item.get("has_code") is not True:
                raise AssertionError(("missing_code", class_name, item))
            if set(item) != {
                "name", "descriptor", "has_code", "registers", "insns", "outs",
                "tries", "code_item_size", "code_item_sha256",
            }:
                raise AssertionError(("unexpected_method_fields", class_name, item.keys()))
            if len(item["code_item_sha256"]) != 64:
                raise AssertionError(("bad_method_digest", class_name, item))
    if apk is not None:
        if sha256(apk) != data.get("apk_sha256"):
            raise AssertionError("APK digest mismatch")
        with zipfile.ZipFile(apk) as archive:
            for dex_item in data["dex"]:
                raw = archive.read(dex_item["name"])
                if len(raw) != dex_item["size"] or sha256_bytes(raw) != dex_item["sha256"]:
                    raise AssertionError(("DEX digest mismatch", dex_item["name"]))
    if pinned_apk is not None:
        if sha256(pinned_apk) != data.get("pinned_apk_sha256"):
            raise AssertionError("pinned APK digest mismatch")
        if data.get("pinned_apk_byte_identical") is not True:
            raise AssertionError("pinned APK is not marked byte-identical")
        if data.get("method_body_identity_to_pinned_apk") is not True:
            raise AssertionError("method identity to pinned APK is not marked")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--pinned-apk", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    extracted = extract(args.apk)
    pinned_sha = None
    pinned_match = None
    method_match = None
    pinned_apk_version_name = None
    pinned_apk_version_code = None
    if args.pinned_apk is not None:
        pinned_sha = sha256(args.pinned_apk)
        pinned_match = pinned_sha == sha256(args.apk)
        if not pinned_match:
            raise AssertionError("installed APK and pinned APK artifacts differ")
        # A byte-identical APK has byte-identical DEX and code items. Avoid a
        # second full Androguard parse; if the artifacts ever differ, fail
        # closed until an explicit two-artifact comparison is implemented.
        method_match = True
        pinned_apk_version_name, pinned_apk_version_code = apk_version(args.pinned_apk)
        if (pinned_apk_version_name, pinned_apk_version_code) != ("7.2.5.32", 72532):
            raise AssertionError("unexpected pinned APK manifest version")
    interpretation = (
        "The installed 7.2.5.32 APK contains the selected callback, Cronet, frameSign, "
        "and startup methods with the recorded descriptors. Each code item is represented "
        "only by metadata and a SHA-256 digest. This proves installed-build method "
        "continuity and does not claim a complete six-header signer or an observed business "
        "request."
    )
    if pinned_match:
        interpretation = (
            "The installed APK is byte-identical to the pinned fq_7xz.apk artifact, whose "
            "manifest is 7.2.5.32/72532, and the selected method summaries match that "
            "artifact. The separate 7.1.3.32/71332 label belongs to the pinned ELF/JADX "
            "native research baseline, not this APK manifest. This closes artifact and "
            "selected-method continuity; it does not prove a complete six-header signer, "
            "an observed business request, or online acceptance."
        )
    report = {
        "schema": "vm9-runtime-method-summary-20261028-v1",
        "evidence_date": "2026-10-28",
        "package": "com.dragon.read",
        "installed_version": "7.2.5.32/72532",
        "apk_sha256": sha256(args.apk),
        "apk_size": args.apk.stat().st_size,
        "pinned_research_version": "7.1.3.32/71332",
        "pinned_apk_basename": args.pinned_apk.name if args.pinned_apk else None,
        "pinned_apk_sha256": pinned_sha,
        "pinned_apk_byte_identical": pinned_match,
        "pinned_apk_version_name": pinned_apk_version_name,
        "pinned_apk_version_code": pinned_apk_version_code,
        "classes": extracted["classes"],
        "target_dex": extracted["target_dex"],
        "dex_count": extracted["dex_count"],
        "dex": extracted["dex"],
        "raw_method_bodies_retained": False,
        "method_body_identity_to_pinned_apk": method_match,
        "business_request_runtime_call_observed": False,
        "interpretation": interpretation,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.verify:
        verify(args.output, args.apk, args.pinned_apk)
    print(json.dumps({
        "schema": report["schema"],
        "installed_version": report["installed_version"],
        "dex_count": report["dex_count"],
        "target_classes": len(report["classes"]),
        "raw_method_bodies_retained": report["raw_method_bodies_retained"],
        "pinned_apk_byte_identical": report["pinned_apk_byte_identical"],
        "method_body_identity_to_pinned_apk": report["method_body_identity_to_pinned_apk"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
