"""Attach to a running Tomato process and record redacted signing boundaries.

The probe deliberately does not trigger a request. It hooks the ordinary
Cronet/NetworkParams callback and the separate MSManager.frameSign API, then
emits only lengths and SHA-256 digests for URLs, headers and returned values.
"""
from __future__ import annotations

import argparse
import json
import time
from typing import Any


JS = r"""
'use strict';
function emit(x) { try { send(x); } catch (_) {} }
function digest(value) {
  try {
    var s = String(value);
    var md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
    var bytes = Java.use('java.lang.String').$new(s).getBytes('UTF-8');
    var out = md.digest(bytes), h = '';
    for (var i = 0; i < out.length; i++) { var b = out[i]; if (b < 0) b += 256; h += ('0' + b.toString(16)).slice(-2); }
    return {length: s.length, sha256: h};
  } catch (e) { return {error: String(e)}; }
}
function mapSummary(m) {
  var rows = [];
  try {
    var it = m.entrySet().iterator();
    while (it.hasNext()) { var e = it.next(); rows.push({key: String(e.getKey()), value: digest(e.getValue())}); }
  } catch (e) { return {error: String(e)}; }
  rows.sort(function(a, b) { return a.key < b.key ? -1 : (a.key > b.key ? 1 : 0); });
  return {count: rows.length, rows: rows};
}
function arraySummary(a) {
  var rows = [];
  try { for (var i = 0; i < a.length; i += 2) rows.push({key: String(a[i]), value: digest(a[i + 1])}); }
  catch (e) { return {error: String(e)}; }
  return {count: rows.length, rows: rows};
}
function hookOnce(holder, name, install) {
  try { if (!holder[name]) { install(); holder[name] = true; } }
  catch (e) { emit({event: 'hook_error', target: name, error: String(e)}); }
}
function install() {
  Java.perform(function() {
    try {
      var M = Java.use('com.bytedance.mobsec.metasec.ml.MSManager');
      hookOnce(M, '__vm9_frameSign_hook', function() {
        var f = M.frameSign.overload('java.lang.String', 'int');
        f.implementation = function(url, frameType) {
          var result = f.call(this, url, frameType);
          emit({event: 'frameSign', url: digest(url), frame_type: frameType, result: result ? mapSummary(result) : {count: 0}});
          return result;
        };
        emit({event: 'hooked', target: 'MSManager.frameSign'});
      });
    } catch (e) { emit({event: 'hook_error', target: 'MSManager.frameSign', error: String(e)}); }
    try {
      var R = Java.use('ms.bd.c.r4');
      hookOnce(R, '__vm9_security_factor_hook', function() {
        var f = R.onCallToAddSecurityFactor.overload('java.lang.String', 'java.util.Map');
        f.implementation = function(url, input) {
          var result = f.call(this, url, input);
          emit({event: 'securityFactor', url: digest(url), input: input ? mapSummary(input) : {count: 0}, result: result ? mapSummary(result) : {count: 0}});
          return result;
        };
        emit({event: 'hooked', target: 'ms.bd.c.r4.onCallToAddSecurityFactor'});
      });
    } catch (e) { emit({event: 'hook_error', target: 'ms.bd.c.r4.onCallToAddSecurityFactor', error: String(e)}); }
    try {
      var C = Java.use('com.ttnet.org.chromium.net.impl.CronetUrlRequest');
      hookOnce(C, '__vm9_cronet_security_factor_hook', function() {
        var f = C.addSecurityFactor.overload('java.lang.String', '[Ljava.lang.String;');
        f.implementation = function(url, input) {
          var result = f.call(this, url, input);
          emit({event: 'cronetSecurityFactor', url: digest(url), input: arraySummary(input), result: result ? arraySummary(result) : {count: 0}});
          return result;
        };
        emit({event: 'hooked', target: 'CronetUrlRequest.addSecurityFactor'});
      });
    } catch (e) { emit({event: 'hook_error', target: 'CronetUrlRequest.addSecurityFactor', error: String(e)}); }
    try {
      var Ctx = Java.use('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext');
      hookOnce(Ctx, '__vm9_cronet_context_security_factor_hook', function() {
        var f = Ctx.addSecurityFactor.overload('java.lang.String', '[Ljava.lang.String;');
        f.implementation = function(url, input) {
          var result = f.call(this, url, input);
          emit({event: 'cronetContextSecurityFactor', url: digest(url), input: arraySummary(input), result: result ? arraySummary(result) : {count: 0}});
          return result;
        };
        emit({event: 'hooked', target: 'CronetUrlRequestContext.addSecurityFactor'});
      });
    } catch (e) { emit({event: 'hook_error', target: 'CronetUrlRequestContext.addSecurityFactor', error: String(e)}); }
  });
}
setInterval(install, 2000);
install();
emit({event: 'probe_ready', pid: Process.id});
"""


def choose_process(device: Any, package: str, pid: int | None) -> Any:
    if pid is not None:
        return device.attach(pid)
    for process in device.enumerate_processes():
        if process.name in (package, "番茄免费小说"):
            return device.attach(process.pid)
    raise RuntimeError(f"process not found: {package}")


def attach_or_spawn(device: Any, package: str, pid: int | None, spawn: bool) -> tuple[Any, int | None]:
    """Attach to an existing process or install hooks before a spawned launch."""
    if not spawn:
        return choose_process(device, package, pid), None
    if pid is not None:
        raise ValueError("--pid and --spawn cannot be combined")
    spawned_pid = int(device.spawn([package]))
    return device.attach(spawned_pid), spawned_pid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--package", default="com.dragon.read")
    parser.add_argument("--device", choices=("usb", "remote"), default="usb")
    parser.add_argument("--remote", default="127.0.0.1:27042")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument(
        "--spawn",
        action="store_true",
        help="spawn the package suspended, install hooks, then resume it",
    )
    args = parser.parse_args()
    try:
        import frida
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SystemExit("frida is required for the runtime probe") from exc
    if args.device == "usb":
        device = frida.get_usb_device(timeout=10)
    else:
        device = frida.get_device_manager().add_remote_device(args.remote)
    session, spawned_pid = attach_or_spawn(device, args.package, args.pid, args.spawn)

    def on_message(message: dict, _data: bytes | None) -> None:
        if message.get("type") == "send":
            print(json.dumps(message.get("payload"), ensure_ascii=False), flush=True)
        else:
            print(json.dumps({"event": "frida_message", "message": message}, ensure_ascii=False), flush=True)

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    if spawned_pid is not None:
        device.resume(spawned_pid)
        print(json.dumps({"event": "spawn_resumed", "pid": spawned_pid}, ensure_ascii=False), flush=True)
    try:
        time.sleep(max(0.0, args.duration))
    finally:
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
