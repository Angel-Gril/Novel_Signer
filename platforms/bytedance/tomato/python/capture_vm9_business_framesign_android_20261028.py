"""Attach to a running Tomato process and record redacted signing boundaries.

The probe deliberately does not trigger a request. It hooks the ordinary
Cronet/NetworkParams callback and the separate MSManager.frameSign API, then
emits only lengths and SHA-256 digests for URLs, headers and returned values.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
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
    try {
      var CtxO0 = Java.use('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext');
      hookOnce(CtxO0, '__vm9_cronet_context_o0_hook', function() {
        var f = CtxO0.o0.overload('java.lang.String', 'java.util.Map');
        f.implementation = function(url, input) {
          var result = f.call(this, url, input);
          emit({event: 'cronetContextO0', url: digest(url), input: input ? mapSummary(input) : {count: 0}, result: result ? mapSummary(result) : {count: 0}});
          return result;
        };
        emit({event: 'hooked', target: 'CronetUrlRequestContext.o0'});
      });
    } catch (e) { emit({event: 'hook_error', target: 'CronetUrlRequestContext.o0', error: String(e)}); }
  });
}
setInterval(function () {
  if (typeof Java !== 'undefined') {
    try { install(); } catch (e) { emit({event: 'hook_error', target: 'install', error: String(e)}); }
  }
}, 2000);
if (typeof Java !== 'undefined') {
  install();
} else {
  emit({event: 'awaiting_java_bridge'});
}
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


def _load_source(bridge_js: Path | None, chunk_size: int) -> tuple[str, list[str]]:
    """Build the probe source and split it for embedded Gadget transports.

    Frida Gadget's embedded script transport is less tolerant of very large
    source strings than frida-server.  The caller uses a tiny receiver script
    and posts these chunks one at a time when ``--bridge-js`` is supplied.
    """
    source = JS
    if bridge_js is not None:
        source = bridge_js.read_text(encoding="utf-8") + "\n" + JS
    return source, [source[i : i + chunk_size] for i in range(0, len(source), chunk_size)]


def _load_script(session: Any, source: str, chunks: list[str], on_message: Any) -> Any:
    if not chunks:
        raise ValueError("probe source is empty")
    if len(chunks) == 1:
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        return script

    receiver = """
var __vm9_chunks = [];
function __vm9_arm() {
  recv('vm9_chunk', function (message) {
    __vm9_chunks.push(message.payload);
    send({event: 'chunk_ack', index: __vm9_chunks.length});
    __vm9_arm();
  });
  recv('vm9_done', function () {
    try { eval(__vm9_chunks.join('')); send({event: 'bridge_eval_done'}); }
    catch (e) { send({event: 'bridge_eval_error', error: String(e), stack: e.stack}); }
  });
}
__vm9_arm();
"""
    script = session.create_script(receiver)
    script.on("message", on_message)
    script.load()

    def post_next(message: dict, _data: bytes | None = None) -> None:
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("event") != "chunk_ack":
            return
        index = int(payload["index"])
        if index < len(chunks):
            script.post({"type": "vm9_chunk", "payload": chunks[index]})
        else:
            script.post({"type": "vm9_done", "payload": ""})

    script.on("message", post_next)
    script.post({"type": "vm9_chunk", "payload": chunks[0]})
    return script


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--package", default="com.dragon.read")
    parser.add_argument("--device", choices=("usb", "remote"), default="usb")
    parser.add_argument("--remote", default="127.0.0.1:27042")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument(
        "--bridge-js",
        type=Path,
        help=(
            "compiled frida-java-bridge bundle; required for Frida Gadget "
            "sessions where the built-in Java global is unavailable"
        ),
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=50000,
        help="source chunk size for --bridge-js (default: 50000)",
    )
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

    if args.chunk_size < 4096:
        raise SystemExit("--chunk-size must be at least 4096")
    source, chunks = _load_source(args.bridge_js, args.chunk_size)

    def forward_chunk_ack(message: dict, data: bytes | None) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("event") == "chunk_ack":
                return
        on_message(message, data)

    script = _load_script(session, source, chunks, forward_chunk_ack)
    print(
        json.dumps(
            {"event": "script_loaded", "source_length": len(source), "chunks": len(chunks)},
            ensure_ascii=False,
        ),
        flush=True,
    )
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
