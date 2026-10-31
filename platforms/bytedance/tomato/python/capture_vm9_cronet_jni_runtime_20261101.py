"""Capture the native Cronet JNI boundary without a JavaScript Java bridge.

The probe attaches to ART's ``JNI_GetCreatedJavaVMs`` and obtains one live
``JNIEnv`` table.  It hooks the standard ``GetMethodID`` and
``CallObjectMethodV`` entries (0x108 and 0x118) and records only the private
``addSecurityFactor`` method name/signature, thread ids, and event counts.
URLs, headers, certificates, request bodies, and native bytes are never
retained.  A zero call count is a bounded observation, not proof that Cronet
is unreachable.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


PROBE_JS = r"""
'use strict';
var vm9State = {table: null, methods: Object.create(null)};
function emit(row) { try { send(row); } catch (_) {} }
function readCString(p) {
  try { return p && !p.isNull() ? p.readUtf8String() : null; } catch (_) { return null; }
}
function installTable(env) {
  try {
    if (!env || env.isNull()) return;
    var table = env.readPointer();
    var tableKey = String(table);
    if (vm9State.table === tableKey) return;
    var getMethodID = table.add(0x108).readPointer();
    var callObjectMethodV = table.add(0x118).readPointer();
    vm9State.table = tableKey;
    emit({event: 'jni_table', table: tableKey,
      table_offsets: {GetMethodID: 0x108, CallObjectMethodV: 0x118},
      get_method_id: String(getMethodID), call_object_method_v: String(callObjectMethodV)});
    Interceptor.attach(getMethodID, {
      onEnter: function (args) {
        this.name = readCString(args[2]);
        this.sig = readCString(args[3]);
      },
      onLeave: function (retval) {
        if (!this.name || this.name.indexOf('addSecurityFactor') < 0 || retval.isNull()) return;
        var methodId = String(retval);
        vm9State.methods[methodId] = {name: this.name, sig: this.sig};
        emit({event: 'jni_get_method_id', method_id: methodId, name: this.name,
          sig: this.sig, thread_id: Process.getCurrentThreadId()});
      }
    });
    Interceptor.attach(callObjectMethodV, {
      onEnter: function (args) {
        var methodId = String(args[2]);
        var method = vm9State.methods[methodId];
        if (!method) return;
        emit({event: 'jni_call_object_method_v', method_id: methodId,
          name: method.name, sig: method.sig, thread_id: Process.getCurrentThreadId()});
      }
    });
    emit({event: 'jni_hooks_installed'});
  } catch (e) {
    emit({event: 'jni_table_error', error: String(e)});
  }
}
var art = Process.findModuleByName('libart.so');
if (!art) {
  emit({event: 'art_missing'});
} else {
  var getEnvHandler = art.enumerateExports().filter(function (e) {
    return e.name.indexOf('JNIEnvExt13GetEnvHandler') >= 0;
  })[0];
  if (getEnvHandler) {
    emit({event: 'get_env_handler', address: String(getEnvHandler.address)});
    Interceptor.attach(getEnvHandler.address, {
      onEnter: function (args) { this.out = args[2]; },
      onLeave: function (retval) {
        if (retval.toInt32() === 0 && this.out && !this.out.isNull()) {
          try { installTable(this.out.readPointer()); } catch (_) {}
        }
      }
    });
  } else {
    emit({event: 'get_env_handler_missing'});
  }
  try {
    var created = art.enumerateExports().filter(function (e) {
      return e.name === 'JNI_GetCreatedJavaVMs';
    })[0];
    if (created) {
      var vmOut = Memory.alloc(Process.pointerSize);
      var countOut = Memory.alloc(4);
      var getVms = new NativeFunction(created.address, 'int', ['pointer', 'int', 'pointer']);
      if (getVms(vmOut, 1, countOut) === 0 && countOut.readU32() > 0) {
        var vm = vmOut.readPointer();
        var vmTable = vm.readPointer();
        var attach = new NativeFunction(vmTable.add(0x20).readPointer(),
          'int', ['pointer', 'pointer', 'pointer']);
        var envOut = Memory.alloc(Process.pointerSize);
        attach(vm, envOut, ptr(0));
        installTable(envOut.readPointer());
        emit({event: 'jni_vm_attached'});
      }
    } else {
      emit({event: 'jni_created_vms_missing'});
    }
  } catch (e) {
    emit({event: 'jni_vm_error', error: String(e)});
  }
}
emit({event: 'probe_ready', pid: Process.id});
"""


def adb(args: list[str], serial: str) -> str:
    result = subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()


def launch_and_find_pid(serial: str, package: str, activity: str, timeout: float) -> int:
    adb(["shell", "am", "force-stop", package], serial)
    adb(["shell", "am", "start", "-n", f"{package}/{activity}"], serial)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = adb(["shell", "pidof", package], serial)
        if raw:
            return int(raw.split()[0])
        time.sleep(0.05)
    raise RuntimeError(f"target process did not appear within {timeout:g}s")


def choose_process(device: Any, package: str, pid: int | None, name: str | None) -> int:
    if pid is not None:
        return pid
    names = {name} if name else {package}
    for process in device.enumerate_processes():
        if process.name in names:
            return int(process.pid)
    raise RuntimeError(f"process not found: {name or package}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default="com.dragon.read")
    parser.add_argument("--activity", default=".pages.splash.SplashActivity")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--process-name")
    parser.add_argument("--device", choices=("usb", "remote"), default="usb")
    parser.add_argument("--remote", default="127.0.0.1:27042")
    parser.add_argument("--adb-serial", help="ADB serial used with --launch")
    parser.add_argument("--launch", action="store_true", help="cold-launch before attaching")
    parser.add_argument("--launch-timeout", type=float, default=30.0)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration <= 0 or args.launch_timeout <= 0:
        parser.error("duration and launch-timeout must be positive")
    if args.launch and not args.adb_serial:
        parser.error("--adb-serial is required with --launch")
    if args.launch and (args.pid is not None or args.process_name):
        parser.error("--launch cannot be combined with --pid or --process-name")
    try:
        import frida
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SystemExit("frida is required for the runtime probe") from exc

    device = (
        frida.get_usb_device(timeout=10)
        if args.device == "usb"
        else frida.get_device_manager().add_remote_device(args.remote)
    )
    pid = (
        launch_and_find_pid(args.adb_serial, args.package, args.activity, args.launch_timeout)
        if args.launch
        else choose_process(device, args.package, args.pid, args.process_name)
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output_file = output.open("x", encoding="utf-8", newline="\n")
    lock = threading.Lock()

    def record(payload: Any) -> None:
        line = json.dumps(payload, ensure_ascii=False)
        with lock:
            print(line, flush=True)
            output_file.write(line + "\n")
            output_file.flush()

    session = None
    script = None
    try:
        session = device.attach(pid)
        session.on("detached", lambda reason, crash=None: record({"event": "session_detached", "reason": str(reason)}))

        def on_message(message: dict, _data: bytes | None) -> None:
            if message.get("type") == "send":
                record(message.get("payload"))
            else:
                record({"event": "frida_message", "message": message})

        script = session.create_script(PROBE_JS)
        script.on("message", on_message)
        script.load()
        record({"event": "script_loaded", "pid": pid})
        time.sleep(args.duration)
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        output_file.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
