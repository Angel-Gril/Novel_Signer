"""Validate the ordinary Cronet initializer's static provider path."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any


NAME = "vm9_cronet_ordinary_initializer_static_20261105"
APK_DEFAULT = Path(r"C:\AI\6\fq_7xz.apk")
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_record(evidence: Path, apk: Path) -> dict[str, Any]:
    report = json.loads(evidence.read_text(encoding="utf-8"))
    require(report.get("schema") == "vm9-cronet-ordinary-initializer-static-20261105-v1", "schema")
    require(report.get("evidence_date") == "2026-11-05", "date")
    scope = report["source_scope"]
    require(scope == {
        "artifact": "fq_7xz.apk DEX static ordinary Cronet initializer path",
        "package_name": "com.dragon.read",
        "version_name": "7.2.5.32",
        "version_code": 72532,
        "raw_method_bodies_retained": False,
        "parsed_dexes": ["classes3.dex", "classes17.dex", "classes23.dex", "classes26.dex"],
        "scan_library": "androguard.core.dex.DEX",
    }, "source scope")
    artifacts = report["source_artifacts"]
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
    require(chain["ordinary_startup_entry"] == {
        "caller": "Lcom/dragon/read/app/launch/task/n0;->n(Landroid/app/Application;)V",
        "target": "Lcom/dragon/read/base/http/e;->h(Lcom/dragon/read/base/http/e$b;)V",
        "argument": "Lcom/dragon/read/app/launch/task/n0$a;",
        "dex": "classes3.dex",
    }, "startup entry")
    require(chain["initializer_wrapper"] == {
        "caller": "Lcom/dragon/read/base/http/e;->h(Lcom/dragon/read/base/http/e$b;)V",
        "target": "Lcom/dragon/read/base/http/e;->d(Lcom/dragon/read/base/http/e$b;)V",
        "postcondition": "sets Lcom/dragon/read/base/http/e;->b true after d returns",
        "dex": "classes3.dex",
    }, "initializer wrapper")
    require(chain["ordinary_provider_registration"] == {
        "caller": "Lcom/dragon/read/base/http/e;->d(Lcom/dragon/read/base/http/e$b;)V",
        "provider": "Lcom/dragon/read/base/http/b;->c:Lcom/dragon/read/base/http/b;",
        "target": "Lcom/bytedance/ttnet/TTNetInit;->setCronetDepend(Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
        "boe_guard_present": False,
        "dex": "classes3.dex",
    }, "provider registration")
    require(chain["ordinary_ttnet_setup"] == {
        "provider_context_setup": "Lcom/dragon/read/base/http/e;->n(Landroid/content/Context;)V -> TTNetInit.setTTNetDepend(Lcom/bytedance/ttnet/ITTNetDepend;)",
        "ttnet_init": "Lcom/dragon/read/base/http/e;->m(Landroid/content/Context;Landroid/app/Application;)V -> TTNetInit.tryInitTTNet(...)",
        "cronet_force_init": "Lcom/dragon/read/base/http/e;->d(...)V -> TTNetInit.forceInitCronetKernel()",
        "dex": "classes3.dex",
    }, "TTNet setup")
    require(chain["ttnet_provider_storage"] == {
        "method": "Lcom/bytedance/ttnet/TTNetInit;->setCronetDepend(Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
        "stores": "Lcom/bytedance/ttnet/TTNetInit;->sCronetProvider",
        "forwards_to": "Lcom/bytedance/frameworks/baselib/network/http/cronet/impl/SsCronetHttpClient;->setCronetAppInfoProvider(Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
        "dex": "classes26.dex",
    }, "provider storage")
    require(chain["force_init_provider_to_engine"] == {
        "method": "Lcom/bytedance/ttnet/TTNetInit;->forceInitCronetKernel()V",
        "provider_source": "Lcom/bytedance/ttnet/TTNetInit;->sCronetProvider",
        "target": "Lcom/bytedance/frameworks/baselib/network/http/cronet/impl/SsCronetHttpClient;->tryCreateCronetEngine(ZZZZZLcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
        "dex": "classes26.dex",
    }, "force init")
    require(chain["engine_to_callback_builder"] == {
        "method": "Lcom/bytedance/frameworks/baselib/network/http/cronet/impl/SsCronetHttpClient;->tryCreateCronetEngine(ZZZZZLcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
        "interface_target": "Lcom/bytedance/frameworks/baselib/network/http/cronet/ICronetClient;->tryCreateCronetEngine(Landroid/content/Context;ZZZZZLjava/lang/String;ZLcom/bytedance/frameworks/baselib/network/http/cronet/ICronetAppProvider;)V",
        "application_builder_callsite": "Lorg/chromium/CronetClient;->tryCreateCronetEngine(...)V -> Lcom/ttnet/org/chromium/net/f$a;->f0(Lcom/ttnet/org/chromium/net/w;)Lcom/ttnet/org/chromium/net/f$a;",
        "dex": "classes23.dex/classes17.dex",
    }, "engine builder")

    claims = report["claims"]
    for key in (
        "ordinary_startup_initializer_static_path_verified",
        "ordinary_provider_registration_boe_independent_static_verified",
        "ttnet_provider_storage_to_sscronet_static_verified",
        "force_init_provider_to_engine_static_verified",
        "engine_builder_callback_provider_static_verified",
    ):
        require(claims[key] is True, key)
    for key in (
        "runtime_initializer_calls_observed",
        "runtime_provider_identity_resolved",
        "cronet_entry_runtime_observed",
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
    return {"schema": report["schema"], **{key: claims[key] for key in (
        "ordinary_startup_initializer_static_path_verified",
        "ordinary_provider_registration_boe_independent_static_verified",
        "ttnet_provider_storage_to_sscronet_static_verified",
        "force_init_provider_to_engine_static_verified",
        "engine_builder_callback_provider_static_verified",
        "runtime_initializer_calls_observed",
        "runtime_provider_identity_resolved",
        "ordinary_cronet_six_head_chain_verified",
    )}}


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--evidence", type=Path, default=root / "evidence" / f"{NAME}.json")
    parser.add_argument("--apk", type=Path, default=APK_DEFAULT)
    args = parser.parse_args()
    print(json.dumps(verify_record(args.evidence, args.apk), sort_keys=True))


if __name__ == "__main__":
    main()
