"""Validate the static Cronet -> app adapter -> NetworkParams -> r4 chain."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_static_adapter_r4_chain_20261105"
APK_DEFAULT = Path(r"C:\AI\6\fq_7xz.apk")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_record(evidence: Path, apk: Path) -> dict[str, Any]:
    report = json.loads(evidence.read_text(encoding="utf-8"))
    require(report.get("schema") == "vm9-cronet-static-adapter-r4-chain-20261105-v1", "schema")
    require(report.get("evidence_date") == "2026-11-05", "date")
    scope = report["source_scope"]
    require(scope == {
        "artifact": "fq_7xz.apk DEX static Cronet adapter and NetworkParams chain",
        "package_name": "com.dragon.read",
        "version_name": "7.2.5.32",
        "version_code": 72532,
        "raw_method_bodies_retained": False,
        "parsed_dexes": ["classes3.dex", "classes16.dex", "classes17.dex", "classes23.dex", "classes26.dex"],
        "scan_library": "androguard.core.dex.DEX",
    }, "source scope")
    artifacts = report["source_artifacts"]
    require(isinstance(artifacts["apk_sha256"], str) and
            HEX_256.fullmatch(artifacts["apk_sha256"]) is not None, "APK hash format")
    require(apk.is_file(), "missing APK")
    require(hashlib.sha256(apk.read_bytes()).hexdigest() == artifacts["apk_sha256"], "APK hash")
    with zipfile.ZipFile(apk) as archive:
        for name in scope["parsed_dexes"]:
            item = artifacts[name]
            require(HEX_256.fullmatch(item["sha256"]) is not None, f"{name} hash format")
            data = archive.read(name)
            require(len(data) == item["size"], f"{name} size")
            require(hashlib.sha256(data).hexdigest() == item["sha256"], f"{name} hash")

    chain = report["static_chain"]
    require(chain["cronet_context_dispatch"] == {
        "caller": "Lcom/ttnet/org/chromium/net/impl/CronetUrlRequestContext;->o0(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "target": "Lcom/ttnet/org/chromium/net/w;->a(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "dex": "classes16.dex",
    }, "Cronet dispatch")
    require(chain["cronet_callback_implementation"] == {
        "class": "Lorg/chromium/c;",
        "superclass": "Lcom/ttnet/org/chromium/net/w;",
        "method": "a(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "delegates_to": "Lorg/chromium/CronetAppProviderManager;->onCallToAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "dex": "classes17.dex",
    }, "implementation")
    require(chain["manager_provider_boundary"] == {
        "manager_method": "Lorg/chromium/CronetAppProviderManager;->onCallToAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "provider_field_type": "Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;",
        "interface_method": "onCallToAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "dex": "classes17.dex",
    }, "manager boundary")
    require(chain["application_adapter"] == {
        "class": "Lcom/dragon/read/base/http/b;",
        "superclass": "Lcom/bytedance/ttnet/cronet/AbsCronetDependAdapter;",
        "inherited_interface": "Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;",
        "provider_static_field": "Lcom/dragon/read/base/http/b;->c:Lcom/dragon/read/base/http/b;",
        "dex": "classes3.dex",
    }, "application adapter")
    require(chain["adapter_registration"] == {
        "callsite": "Lcom/dragon/read/app/launch/task/n0;->m()V",
        "argument": "Lcom/dragon/read/base/http/b;->c",
        "target": "Lvi2/a;->a(Lcom/bytedance/ttnet/cronet/AbsCronetDependAdapter;)V",
        "dex": "classes3.dex",
        "guard": "Lcom/dragon/read/util/DebugManager;->isBOEMode()Z",
        "guard_behavior": "registration is skipped when isBOEMode() returns false",
    }, "adapter registration")
    require(chain["adapter_registration_caller"] == {
        "caller": "Lcom/dragon/read/app/launch/task/n0;->n(Landroid/app/Application;)V",
        "target": "Lcom/dragon/read/app/launch/task/n0;->m()V",
        "dex": "classes3.dex",
        "guard_owner": "n0.m",
    }, "adapter registration caller")
    require(chain["adapter_manager_set"] == {
        "caller": "Lvi2/a;->a(Lcom/bytedance/ttnet/cronet/AbsCronetDependAdapter;)V",
        "target": "Lorg/chromium/CronetAppProviderManager;->setAdapter(Ljava/lang/Object;)V",
        "cast_type": "Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;",
        "dex": "classes3.dex",
    }, "manager set")
    require(chain["base_adapter_security_factor"] == {
        "method": "Lcom/bytedance/ttnet/cronet/AbsCronetDependAdapter;->onCallToAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "input_conversion": "Map<String,String> values are wrapped as one-element ArrayList values",
        "target": "Lcom/bytedance/frameworks/baselib/network/http/NetworkParams;->tryAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "dex": "classes26.dex",
    }, "base adapter")
    require(chain["network_params_dispatch"] == {
        "method": "Lcom/bytedance/frameworks/baselib/network/http/NetworkParams;->tryAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "callback_field": "sAddSecurityFactorProcessCallback",
        "callback_interface": "Lcom/bytedance/frameworks/baselib/network/http/NetworkParams$b;->onCallToAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "dex": "classes23.dex",
    }, "NetworkParams")
    require(chain["r4_registration"] == {
        "callsite": "Lms/bd/c/s4;->a(J)V",
        "constructs": "Lms/bd/c/r4;-><init>(Lms/bd/c/s4;)V",
        "target": "Lcom/bytedance/frameworks/baselib/network/http/NetworkParams;->setAddSecurityFactorProcessCallback(Lcom/bytedance/frameworks/baselib/network/http/NetworkParams$b;)V",
        "dex": "classes16.dex",
    }, "r4 registration")
    require(chain["r4_native_security_factor"] == {
        "class": "Lms/bd/c/r4;",
        "interface": "Lcom/bytedance/frameworks/baselib/network/http/NetworkParams$b;",
        "method": "onCallToAddSecurityFactor(Ljava/lang/String;Ljava/util/Map;)Ljava/util/Map;",
        "native_tag": "0x3000001",
        "result_shape": "native string pairs are converted into a returned HashMap",
        "dex": "classes16.dex",
    }, "r4 native path")

    claims = report["claims"]
    for key in (
        "cronet_static_w_to_r4_owner_chain_verified",
        "cronet_static_adapter_class_b_verified",
        "cronet_app_adapter_registration_boe_guard_verified",
        "networkparams_static_callback_registration_to_r4_verified",
        "r4_native_security_factor_tag_static_verified",
        "r4_callback_observed_in_prior_runtime_capture",
    ):
        require(claims[key] is True, f"{key}")
    for key in (
        "cronet_entry_runtime_observed",
        "runtime_adapter_identity_resolved",
        "r4_callback_cronet_identity_joined",
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
        "cronet_static_w_to_r4_owner_chain_verified": claims["cronet_static_w_to_r4_owner_chain_verified"],
        "cronet_static_adapter_class_b_verified": claims["cronet_static_adapter_class_b_verified"],
        "networkparams_static_callback_registration_to_r4_verified": claims["networkparams_static_callback_registration_to_r4_verified"],
        "r4_native_security_factor_tag_static_verified": claims["r4_native_security_factor_tag_static_verified"],
        "ordinary_cronet_six_head_chain_verified": claims["ordinary_cronet_six_head_chain_verified"],
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
