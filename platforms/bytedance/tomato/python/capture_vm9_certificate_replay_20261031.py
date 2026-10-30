"""Measure native signer sensitivity to measured package certificates, offline.

Compile an isolated copy of the existing HookMain harness. No target APK, live
application, installed harness source or server response is modified. Raw signer
outputs stay in a temporary directory; the evidence retains only digests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile

from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from verify_vm9_package_identity_control_20261031 import EVIDENCE, digest, verify_apks


HEADERS = ("X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa")
# Use the harness's established first signing profile, without network I/O.
INPUT_URL = "https://novel.snssdk.com/api/novel/channel/homepage?aid=1967"
TIMESTAMP_MS = 1790261111000
ANCHOR = "            case 16777218:\n"
INJECTION = '''                if (System.getProperty("vm9certpath") != null) {
                    try {
                        byte[] cert = Files.readAllBytes(Paths.get(System.getProperty("vm9certpath")));
                        StringBuilder hex = new StringBuilder();
                        for (byte value : MessageDigest.getInstance("SHA-256").digest(cert)) {
                            hex.append(String.format("%02x", value & 255));
                        }
                        System.out.println("VM9_CERT_INPUT length=" + cert.length + " sha256=" + hex);
                        return new ByteArray(vm, cert);
                    } catch (Exception error) {
                        throw new IllegalStateException("certificate input failed", error);
                    }
                }
'''
ROOTFS_PATTERN = r'(static final File ROOTFS\s*=\s*)new File\("[^"]+"\);'


def summary(value: str | bytes) -> dict:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def extract_certificate(apk: Path, entry: str, expected: dict) -> bytes:
    with ZipFile(apk) as archive:
        certificates = pkcs7.load_der_pkcs7_certificates(archive.read(entry))
    matches = [cert.public_bytes(Encoding.DER) for cert in certificates
               if summary(cert.public_bytes(Encoding.DER)) == expected]
    if len(matches) != 1:
        raise ValueError("APK does not contain the measured legacy certificate")
    return matches[0]


def capture(args: argparse.Namespace) -> dict:
    identity = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    verify_apks(args.original_apk, args.resigned_apk, identity)
    source_path = args.harness_dir / "src/main/java/HookMain.java"
    source = source_path.read_text(encoding="utf-8")
    if source.count(ANCHOR) != 1:
        raise ValueError("HookMain certificate callback anchor is not unique")
    patched = source.replace(ANCHOR, ANCHOR + INJECTION)
    patched = patched.replace(ANCHOR, ANCHOR + '                System.out.println("VM9_CERT_CALLBACK");\n')
    patched, rootfs_replacements = re.subn(ROOTFS_PATTERN,
        r'\1new File(System.getProperty("vm9rootfs"));', patched)
    if rootfs_replacements != 1:
        raise ValueError("HookMain rootfs anchor is not unique")
    native_paths = {}
    for field in ("SO_MAIN", "SO_CPP", "APK"):
        paths = re.findall(r'static final File ' + field + r'\s*=\s*new File\("([^"]+)"\);', source)
        if len(paths) != 1:
            raise ValueError(f"HookMain {field} path is not unique")
        native_paths[field] = Path(paths[0])
    native_inputs = {name: digest(path) for name, path in native_paths.items()}
    if native_inputs["SO_MAIN"] != "712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c":
        raise ValueError("HookMain is not loading the pinned ELF")
    if native_inputs["APK"] != digest(args.original_apk):
        raise ValueError("HookMain is not loading the official APK")
    classpath_file = args.harness_dir / "_cp.txt"
    classpath = os.pathsep.join(str((args.harness_dir / entry).resolve())
        for entry in classpath_file.read_text(encoding="utf-8").strip().split(os.pathsep))
    source_hash = digest(source_path)
    certificates = {
        "official_legacy": extract_certificate(args.original_apk, "META-INF/BYTESIGN.RSA",
            identity["package_manager_observations"]["official"]["legacy_signatures"][0]),
        "resigned": extract_certificate(args.resigned_apk, "META-INF/GADGET.RSA",
            identity["package_manager_observations"]["resigned"]["legacy_signatures"][0]),
    }
    reports = []
    with tempfile.TemporaryDirectory(prefix="vm9-cert-replay-") as temporary:
        work = Path(temporary)
        classes = work / "classes"
        classes.mkdir()
        patched_path = work / "HookMain.java"
        patched_path.write_text(patched, encoding="utf-8", newline="\n")
        compiled = subprocess.run([args.javac, "-J-Xmx256m", "-cp", classpath, "-d", str(classes),
                                   str(patched_path)], cwd=args.harness_dir, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=90)
        if compiled.returncode:
            raise RuntimeError(f"isolated harness compile failed: {compiled.stderr[-3000:]}")
        for label, certificate_key in (("null_a", None), ("null_b", None),
                                       ("official_legacy", "official_legacy"), ("resigned", "resigned")):
            run_dir = work / label
            run_dir.mkdir()
            rounds = run_dir / "rounds.json"
            props = ["-Dfrzclock=true", f"-Dfrozents={TIMESTAMP_MS}", "-Dfakerand=true",
                     "-Demupid=11340", "-Ddiagscan=false", "-Dabswitch=2", "-Dovcert=false",
                     f"-Dsignurl0={INPUT_URL}", f"-Dartifactdir={run_dir}", f"-Droundsout={rounds}",
                     f"-Dvmtraceout={run_dir / 'vmtrace.json'}", f"-Dvm9rootfs={run_dir / 'rootfs'}"]
            if certificate_key is not None:
                cert_path = run_dir / "certificate.der"
                cert_path.write_bytes(certificates[certificate_key])
                props.append(f"-Dvm9certpath={cert_path}")
            completed = subprocess.run([args.java, "-Xmx384m", "-cp", str(classes) + os.pathsep + classpath,
                                        *props, "HookMain"], cwd=run_dir, capture_output=True,
                                       text=True, encoding="utf-8", errors="replace", timeout=args.timeout)
            if completed.returncode or not rounds.exists() or "=== DONE ===" not in completed.stdout:
                raise RuntimeError(f"native control {label} did not complete; exit={completed.returncode}")
            row = json.loads(rounds.read_text(encoding="utf-8"))["0"]
            if row.get("url") != INPUT_URL or any(not row.get(name) for name in HEADERS):
                raise ValueError(f"native control {label} returned an incomplete header map; "
                                 f"keys={sorted(row)}, input_matches={row.get('url') == INPUT_URL}")
            if row["X-Khronos"] != str(TIMESTAMP_MS // 1000):
                raise ValueError("frozen clock was not honored")
            markers = [{"length": int(length), "sha256": sha} for length, sha in re.findall(
                r"^VM9_CERT_INPUT length=(\d+) sha256=([0-9a-f]{64})$", completed.stdout, re.MULTILINE)]
            null_count = completed.stdout.count("[cert] returning null")
            callback_count = completed.stdout.splitlines().count("VM9_CERT_CALLBACK")
            if certificate_key is None:
                if markers or null_count != callback_count:
                    raise ValueError("null certificate callback markers are inconsistent")
            elif (len(markers) != callback_count or null_count
                  or any(marker != summary(certificates[certificate_key]) for marker in markers)):
                raise ValueError("measured certificate callback markers are inconsistent")
            if "MS.a tag=0x3000001" not in completed.stdout:
                raise ValueError("native signing tag was not observed")
            report = {"label": label, "exit_code": completed.returncode,
                      "certificate_callback_markers": markers, "null_certificate_callback_count": null_count,
                      "certificate_callback_count": callback_count,
                      "header_observations": {name: summary(row[name]) for name in HEADERS},
                      "native_signing_tag_observed": True, "native_run_completed": True}
            reports.append(report)
            print(json.dumps({"event": "certificate_control_completed", "label": label}), flush=True)
        class_hash = digest(classes / "HookMain.class")
        patched_hash = digest(patched_path)
    if source_hash != digest(source_path):
        raise RuntimeError("installed harness source changed during the experiment")
    if native_inputs != {name: digest(path) for name, path in native_paths.items()}:
        raise RuntimeError("native input artifact changed during the experiment")
    baseline = reports[0]["header_observations"]
    repeat_equal = reports[1]["header_observations"] == baseline
    if not repeat_equal:
        raise ValueError("null controls are not repeatable; cannot attribute certificate sensitivity")
    input_delivery = all(report["certificate_callback_markers"] for report in reports[2:])
    return {
        "schema": "vm9-certificate-native-replay-20261031-v1",
        "harness_source_sha256": source_hash, "isolated_source_sha256": patched_hash,
        "isolated_hook_class_sha256": class_hash, "classpath_file_sha256": digest(classpath_file),
        "identity_evidence_sha256": digest(EVIDENCE), "capture_source_sha256": digest(Path(__file__)),
        "native_inputs_sha256": native_inputs,
        "configured_certificates": {name: summary(cert) for name, cert in certificates.items()},
        "input": summary(INPUT_URL), "frozen_timestamp_ms": TIMESTAMP_MS,
        "emulated_pid": 11340, "ab_switch": 2, "fake_random": True,
        "null_control_repeat_equal": repeat_equal, "runs": reports,
        "output_differences_vs_null": {report["label"]: [name for name in HEADERS
            if report["header_observations"][name] != baseline[name]] for report in reports[2:]},
        "certificate_input_delivery_verified": bool(input_delivery),
        "certificate_input_sensitivity_evaluated": bool(input_delivery),
        "fresh_rootfs_per_run": True,
        "installed_harness_source_unchanged": True, "temporary_artifacts_cleaned": True,
        "target_app_modified": False, "live_app_callback_observed": False,
        "whole_request_native_python_differential_verified": False,
        "fresh_standalone_signer_verified": False, "online_header_acceptance_verified": False,
        "raw_urls_or_header_values_retained": False,
        "boundary": "Offline native replay with explicit unidbg Java/OS callbacks and a fresh rootfs per run. Configured certificate bytes are delivered only if the native code requests callback 0x1000002. Zero callback events leave input sensitivity unevaluated, even when output digests are identical. No live application or server-acceptance conclusion follows.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness-dir", type=Path, required=True)
    parser.add_argument("--original-apk", type=Path, required=True)
    parser.add_argument("--resigned-apk", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--javac", default="javac")
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    result = capture(args)
    with args.output.open("x", encoding="utf-8") as target:
        target.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "observed_native_replay_boundary",
                      "certificate_input_delivery_verified": result["certificate_input_delivery_verified"],
                      "output_differences_vs_null": result["output_differences_vs_null"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
