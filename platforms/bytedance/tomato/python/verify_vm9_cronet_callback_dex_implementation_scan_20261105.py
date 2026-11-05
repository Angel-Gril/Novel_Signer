"""Validate the bounded all-Dex Cronet callback implementation scan."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_callback_dex_implementation_scan_20261105"
APK_DEFAULT = Path(r"C:\AI\6\fq_7xz.apk")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
DEX_NAME = re.compile(r"classes(?:\d+)?\.dex$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_hash(value: Any, label: str) -> None:
    require(isinstance(value, str) and HEX_256.fullmatch(value) is not None,
            f"{label} sha256")


def verify_record(evidence: Path, apk: Path) -> dict[str, Any]:
    report = json.loads(evidence.read_text(encoding="utf-8"))
    require(report.get("schema") ==
            "vm9-cronet-callback-dex-implementation-scan-20261105-v2", "schema")
    require(report.get("evidence_date") == "2026-11-05", "date")
    scope = report["source_scope"]
    require(scope == {
        "artifact": "fq_7xz.apk all DEX direct scan with target-bearing DEX parsed",
        "package_name": "com.dragon.read",
        "version_name": "7.2.5.32",
        "version_code": 72532,
        "raw_method_bodies_retained": False,
        "scan_unit": "all 27 classes*.dex; classes16.dex and classes17.dex parsed",
        "scan_library": "androguard.core.dex.DEX",
    }, "source scope")
    artifacts = report["source_artifacts"]
    for key in ("apk_sha256", "classes16_dex_sha256", "classes17_dex_sha256"):
        check_hash(artifacts[key], key)
    require(artifacts["classes16_dex_size"] == 8008060 and
            artifacts["classes17_dex_size"] == 8226640 and
            artifacts["apk_dex_count"] == 27, "artifact ledger")
    require(apk.is_file(), "missing APK")
    require(digest(apk) == artifacts["apk_sha256"], "APK hash")
    with zipfile.ZipFile(apk) as archive:
        dex_names = [name for name in archive.namelist() if DEX_NAME.fullmatch(name)]
        require(len(dex_names) == artifacts["apk_dex_count"], "APK DEX count")
        dex16 = archive.read("classes16.dex")
        dex17 = archive.read("classes17.dex")
    require(len(dex16) == artifacts["classes16_dex_size"] and
            hashlib.sha256(dex16).hexdigest() == artifacts["classes16_dex_sha256"],
            "classes16.dex artifact")
    require(len(dex17) == artifacts["classes17_dex_size"] and
            hashlib.sha256(dex17).hexdigest() == artifacts["classes17_dex_sha256"],
            "classes17.dex artifact")

    scan = report["dex_scan"]
    require(scan == {
        "target_callback_type": "Lcom/ttnet/org/chromium/net/w;",
        "target_descriptor_byte_occurrence_dex_count": 2,
        "target_descriptor_byte_occurrence_dexes": [
            {"dex": "classes16.dex", "size": 8008060, "occurrences": 1},
            {"dex": "classes17.dex", "size": 8226640, "occurrences": 1},
        ],
        "parsed_target_dexes": ["classes16.dex", "classes17.dex"],
        "parsed_target_dex_class_counts": {"classes16.dex": 8524, "classes17.dex": 9612},
        "target_callback_type_declaration_count": 1,
        "concrete_target_subclass_count": 1,
        "concrete_target_subclasses": [{
            "dex": "classes17.dex",
            "class": "Lorg/chromium/c;",
            "superclass": "Lcom/ttnet/org/chromium/net/w;",
            "interfaces": [],
        }],
        "concrete_target_override": {
            "class": "Lorg/chromium/c;",
            "method": "a",
            "descriptor": "(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
            "has_code": True,
        },
        "target_method_a_signature": "(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "target_method_a_declaration_count": 1,
        "target_method_a_has_code": False,
        "target_method_a_direct_dispatch_ref_count": 1,
        "target_method_a_direct_dispatch_refs": [{
            "dex": "classes16.dex",
            "caller_class": "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;",
            "caller_method": "o0",
            "caller_descriptor": "(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
            "invoke_kind": "invoke-virtual",
            "target_method": "Lcom/ttnet/org/chromium/net/w;->a(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        }],
        "builder_callback_method_signature": "Lcom/ttnet/org/chromium/net/h;->t(Lcom/ttnet/org/chromium/net/w;)Lcom/ttnet/org/chromium/net/h;",
        "builder_callback_direct_dispatch_ref_count": 1,
        "builder_callback_direct_dispatch_refs": [{
            "dex": "classes16.dex",
            "caller_class": "Lcom/ttnet/org/chromium/net/c$a;",
            "caller_method": "u",
            "caller_descriptor": "(Lcom/ttnet/org/chromium/net/w;)Lcom/ttnet/org/chromium/net/c$a;",
            "invoke_kind": "invoke-virtual",
            "target_method": "Lcom/ttnet/org/chromium/net/h;->t(Lcom/ttnet/org/chromium/net/w;)Lcom/ttnet/org/chromium/net/h;",
        }],
        "application_side_builder_callback_callsite_count": 1,
        "application_side_builder_callback_callsites": [{
            "dex": "classes17.dex",
            "caller_class": "Lorg/chromium/CronetClient;",
            "caller_method": "tryCreateCronetEngine",
            "caller_descriptor": "(Landroid/content/Context;ZZZZLjava/lang/String;ZLcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
            "invoke_kind": "invoke-virtual",
            "target_method": "Lcom/ttnet/org/chromium/net/f$a;->f0(Lcom/ttnet/org/chromium/net/w;)Lcom/ttnet/org/chromium/net/f$a;",
        }],
        "application_side_target_method_refs_outside_cronet_namespace": 0,
    }, "DEX scan ledger")

    claims = report["claims"]
    require(claims["dex_concrete_w_subclass_resolved"] is True and
            claims["cronet_callback_implementation_class_resolved"] is True and
            claims["cronet_w_a_dispatch_owner_resolved_to_context_o0"] is True and
            claims["cronet_builder_callback_dispatch_owner_resolved_to_api_wrapper"] is True and
            claims["application_side_builder_callback_callsite_resolved"] is True and
            claims["runtime_adapter_identity_resolved"] is False and
            claims["cronet_entry_runtime_observed"] is False and
            claims["r4_callback_cronet_identity_joined"] is False,
            "adapter boundary")
    for key in (
        "ordinary_cronet_six_head_chain_verified",
        "callback_url_or_map_object_identity_joined",
        "provider_method_or_field_identity_joined",
        "android_captured_jni_buffer_consumption_byte_joined",
        "complete_standalone_signer_verified",
        "whole_request_native_python_differential_verified",
        "online_header_acceptance_verified",
    ):
        require(claims[key] is False, f"{key} overclaim")
    return {
        "schema": report["schema"],
        "dex_concrete_w_subclass_resolved": claims["dex_concrete_w_subclass_resolved"],
        "cronet_callback_implementation_class_resolved": claims["cronet_callback_implementation_class_resolved"],
        "cronet_w_a_dispatch_owner_resolved_to_context_o0": claims["cronet_w_a_dispatch_owner_resolved_to_context_o0"],
        "application_side_builder_callback_callsite_resolved": claims["application_side_builder_callback_callsite_resolved"],
        "runtime_adapter_identity_resolved": claims["runtime_adapter_identity_resolved"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path,
                        default=root / "evidence" / f"{NAME}.json")
    parser.add_argument("--apk", type=Path, default=APK_DEFAULT)
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence, args.apk), sort_keys=True))


if __name__ == "__main__":
    main()
