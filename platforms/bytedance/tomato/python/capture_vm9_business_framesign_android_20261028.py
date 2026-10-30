"""Attach to a running Tomato process and record redacted signing boundaries.

The probe deliberately does not trigger a request. It hooks the ordinary
Cronet/NetworkParams callback and the separate MSManager.frameSign API, then
emits only lengths and SHA-256 digests for URLs, headers and returned values.
"""
from __future__ import annotations

import argparse
import json
import threading
from pathlib import Path
from typing import Any


CERTIFICATE_JS = r"""
'use strict';
var certificateState = Object.create(null);
var certificateScheduled = false;
var certificateTimer = null;
function certificateEmit(row) { try { send(row); } catch (_) {} }
function certificateBytes(value) {
  if (value === null) return {is_null: true};
  var bytes = Java.cast(value, Java.use('[B'));
  var length = Number(Java.use('java.lang.reflect.Array').getLength(bytes));
  var md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
  var hash = md.digest.overload('[B').call(md, bytes), hex = '';
  for (var i = 0; i < hash.length; i++) {
    var b = hash[i]; if (b < 0) b += 256;
    hex += ('0' + b.toString(16)).slice(-2);
  }
  return {is_null: false, length: length, sha256: hex};
}
function certificateName(value) {
  if (value === null || value === undefined) return {is_null: true};
  var s = String(value);
  var md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
  var bytes = Java.use('java.lang.String').$new(s).getBytes('UTF-8');
  var hash = md.digest(bytes), hex = '';
  for (var i = 0; i < hash.length; i++) {
    var b = hash[i]; if (b < 0) b += 256;
    hex += ('0' + b.toString(16)).slice(-2);
  }
  return {is_null: false, length: s.length, sha256: hex};
}
function certificateContext() {
  try {
    return {thread_id: Process.getCurrentThreadId(),
      stack: Java.backtrace({limit: 24}).frames.slice(0, 24).map(function(frame) {
        return {class: frame.className, method: frame.methodName};
      })};
  } catch (_) { return {unavailable: true}; }
}
function certificateHook(name, install) {
  if (certificateState[name] === 'installed') return;
  try {
    install(); certificateState[name] = 'installed';
    certificateEmit({event: 'hooked', target: name});
  } catch (e) {
    var error = String(e);
    if (certificateState[name] !== error) {
      certificateEmit({event: 'certificate_hook_error', target: name, error: error});
    }
    certificateState[name] = error;
  }
}
function observeCertificate(target, original, receiver, args, name) {
  var context = certificateContext();
  certificateEmit({event: 'certificate_read_enter', target: target, input: certificateName(name), context: context});
  // Keep application exceptions and returned objects exactly as produced by the original.
  var result;
  try { result = original.apply(receiver, args); }
  catch (error) {
      certificateEmit({event: 'certificate_read_threw', target: target, input: certificateName(name), context: context});
    throw error;
  }
  try {
    certificateEmit({event: 'certificate_read_return', target: target,
      input: certificateName(name), context: context, result: certificateBytes(result)});
  } catch (_) {
    certificateEmit({event: 'certificate_summary_error', target: target,
      input: certificateName(name), context: context});
  }
  return result;
}
function installCertificateHooks() {
  if (typeof Java === 'undefined' || certificateScheduled) return;
  certificateScheduled = true;
  try {
    Java.perform(function() {
      try {
        certificateHook('ms.bd.c.s2.k', function() {
          var S = Java.use('ms.bd.c.s2');
          var k = S.k.overload('java.lang.String');
          k.implementation = function(name) {
            return observeCertificate('ms.bd.c.s2.k', function() {
              return k.call(this, name);
            }, this, [], name);
          };
        });
        certificateHook('ms.bd.c.s2.j.certificate', function() {
          var S = Java.use('ms.bd.c.s2');
          var j = S.j.overload('int', 'int', 'long', 'java.lang.String', 'java.lang.Object');
          j.implementation = function(tag, kind, handle, name, input) {
            if (tag !== 16777218) return j.call(this, tag, kind, handle, name, input);
            return observeCertificate('ms.bd.c.s2.j.certificate', function() {
              return j.call(this, tag, kind, handle, name, input);
            }, this, [], name);
          };
        });
      } finally {
        certificateScheduled = false;
        if (certificateState['ms.bd.c.s2.k'] === 'installed' &&
            certificateState['ms.bd.c.s2.j.certificate'] === 'installed' && certificateTimer !== null) {
          clearInterval(certificateTimer); certificateTimer = null;
        }
      }
    });
  } catch (e) {
    certificateScheduled = false;
    certificateEmit({event: 'certificate_install_error', error: String(e)});
  }
}
certificateTimer = setInterval(installCertificateHooks, 500);
installCertificateHooks();
"""


JS = r"""
'use strict';
function emit(x) { try { send(x); } catch (_) {} }
function signingContext() {
  if (typeof vm9TraceSigning === 'undefined' || !vm9TraceSigning) return undefined;
  try {
    return {
      thread_id: Process.getCurrentThreadId(),
      stack: Java.backtrace({limit: 24}).frames.slice(0, 24).map(function(frame) {
        return {class: frame.className, method: frame.methodName};
      })
    };
  } catch (e) { return {error: String(e)}; }
}
function routeDigest(url) {
  try {
    var uri = Java.use('android.net.Uri').parse(String(url));
    var summary = digest(String(uri.getScheme()) + '://' + String(uri.getHost()) + String(uri.getPath()));
    summary.path = digest(String(uri.getPath()));
    return summary;
  } catch (e) { return {error: String(e)}; }
}
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
    var Entry = Java.use('java.util.Map$Entry');
    while (it.hasNext()) { var e = Java.cast(it.next(), Entry); rows.push({key: String(e.getKey()), value: digest(e.getValue())}); }
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
var hookState = Object.create(null);
var installScheduled = false;
var installTimer = null;
var hookNames = [
  'MSManager.frameSign',
  'ms.bd.c.r4.onCallToAddSecurityFactor',
  'CronetUrlRequest.addSecurityFactor',
  'CronetUrlRequestContext.addSecurityFactor',
  'CronetUrlRequestContext.o0'
];
function hookOnce(name, install) {
  if (hookState[name] === 'installed') return;
  try {
    install();
    hookState[name] = 'installed';
    emit({event: 'hooked', target: name});
  } catch (e) {
    var error = String(e);
    if (hookState[name] !== error) emit({event: 'hook_error', target: name, error: error});
    hookState[name] = error;
  }
}
function allHooksInstalled() {
  for (var i = 0; i < hookNames.length; i++) {
    if (hookState[hookNames[i]] !== 'installed') return false;
  }
  return true;
}
function install() {
  if (typeof Java === 'undefined' || installScheduled) return;
  installScheduled = true;
  try {
    Java.perform(function() {
      try {
        hookOnce('MSManager.frameSign', function() {
          var M = Java.use('com.bytedance.mobsec.metasec.ml.MSManager');
          var f = M.frameSign.overload('java.lang.String', 'int');
          f.implementation = function(url, frameType) {
            var result = f.call(this, url, frameType);
            emit({event: 'frameSign', url: digest(url), frame_type: frameType, result: result ? mapSummary(result) : {count: 0}});
            return result;
          };
        });
        hookOnce('ms.bd.c.r4.onCallToAddSecurityFactor', function() {
          var R = Java.use('ms.bd.c.r4');
          var f = R.onCallToAddSecurityFactor.overload('java.lang.String', 'java.util.Map');
          f.implementation = function(url, input) {
            var result = f.call(this, url, input);
            emit({event: 'securityFactor', url: digest(url), route: routeDigest(url), input: input ? mapSummary(input) : {count: 0}, result: result ? mapSummary(result) : {count: 0}, context: signingContext()});
            return result;
          };
        });
        hookOnce('CronetUrlRequest.addSecurityFactor', function() {
          var C = Java.use('com.ttnet.org.chromium.net.impl.CronetUrlRequest');
          var f = C.addSecurityFactor.overload('java.lang.String', '[Ljava.lang.String;');
          f.implementation = function(url, input) {
            var result = f.call(this, url, input);
            emit({event: 'cronetSecurityFactor', url: digest(url), input: arraySummary(input), result: result ? arraySummary(result) : {count: 0}});
            return result;
          };
        });
        hookOnce('CronetUrlRequestContext.addSecurityFactor', function() {
          var Ctx = Java.use('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext');
          var f = Ctx.addSecurityFactor.overload('java.lang.String', '[Ljava.lang.String;');
          f.implementation = function(url, input) {
            var result = f.call(this, url, input);
            emit({event: 'cronetContextSecurityFactor', url: digest(url), input: arraySummary(input), result: result ? arraySummary(result) : {count: 0}});
            return result;
          };
        });
        hookOnce('CronetUrlRequestContext.o0', function() {
          var CtxO0 = Java.use('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext');
          var f = CtxO0.o0.overload('java.lang.String', 'java.util.Map');
          f.implementation = function(url, input) {
            var result = f.call(this, url, input);
            emit({event: 'cronetContextO0', url: digest(url), input: input ? mapSummary(input) : {count: 0}, result: result ? mapSummary(result) : {count: 0}});
            return result;
          };
        });
      } catch (e) {
        emit({event: 'install_error', error: String(e)});
      } finally {
        installScheduled = false;
        if (allHooksInstalled() && installTimer !== null) {
          clearInterval(installTimer);
          installTimer = null;
        }
      }
    });
  } catch (e) {
    installScheduled = false;
    emit({event: 'install_error', error: String(e)});
  }
}
installTimer = setInterval(install, 2000);
if (typeof Java === 'undefined') emit({event: 'awaiting_java_bridge'});
install();
emit({event: 'probe_ready', pid: Process.id});
"""

DIAGNOSTIC_JS = r"""
'use strict';
function diagnosticEmit(event) { try { send(event); } catch (_) {} }
var diagnosticState = Object.create(null);
var diagnosticScheduled = false;
var diagnosticTimer = null;
var diagnosticNames = ['resource_warning', 'error_code_exception', 'reader_exception', 'response_deserialized'];
function diagnosticHook(name, install) {
  if (diagnosticState[name] === 'installed') return;
  try {
    install();
    diagnosticState[name] = 'installed';
    diagnosticEmit({event: 'hooked', target: name});
  } catch (e) {
    var error = String(e);
    if (diagnosticState[name] !== error) {
      diagnosticEmit({event: 'hook_error', target: name, error: error});
    }
    diagnosticState[name] = error;
  }
}
function stackRows(throwable) {
  var rows = [];
  try {
    var frames = throwable.getStackTrace();
    for (var i = 0; i < frames.length && i < 32; i++) {
      var frame = frames[i];
      rows.push({class: String(frame.getClassName()), method: String(frame.getMethodName())});
    }
  } catch (e) { return [{error: String(e)}]; }
  return rows;
}
function installDiagnostics() {
  if (typeof Java === 'undefined' || diagnosticScheduled) return;
  diagnosticScheduled = true;
  try {
    Java.perform(function() {
      try {
        diagnosticHook('resource_warning', function() {
          var Resources = Java.use('android.content.res.Resources');
          var getString = Resources.getString.overload('int');
          getString.implementation = function(id) {
            var result = getString.call(this, id);
            if (id === 2131104020) {
              diagnosticEmit({event: 'version_warning_resource', resource_id: id});
            }
            return result;
          };
        });
        diagnosticHook('response_deserialized', function() {
          var NetReqUtil = Java.use('com.dragon.read.util.NetReqUtil');
          var after = NetReqUtil.doAfterDeserialization.overload(
            'java.lang.String', 'java.lang.Throwable', 'int', 'java.lang.Object', 'java.util.List');
          after.implementation = function(url, error, status, response, headers) {
            try {
              diagnosticEmit({
                event: 'response_deserialized',
                url: digest(url),
                route: routeDigest(url),
                thread_id: Process.getCurrentThreadId(),
                http_status: Number(status),
                business_code: Number(NetReqUtil.parseResponseCode(response)),
                response_class: response ? String(response.getClass().getName()) : null,
                transport_error_class: error ? String(error.getClass().getName()) : null
              });
            } catch (_) {}
            return after.call(this, url, error, status, response, headers);
          };
        });
        diagnosticHook('error_code_exception', function() {
          var ErrorCodeException = Java.use('com.dragon.read.base.http.exception.ErrorCodeException');
          ErrorCodeException.$init.overloads.forEach(function(init, index) {
            init.implementation = function() {
              var result = init.apply(this, arguments);
              try {
                var code = Number(this.getCode());
                var error = String(this.getError());
                if (code === 110 || error.indexOf('ILLEGAL_ACCESS') >= 0) {
                  diagnosticEmit({
                    event: 'error_code_exception_created',
                    code: code,
                    error_kind: error.indexOf('ILLEGAL_ACCESS') >= 0 ? 'ILLEGAL_ACCESS' : 'redacted',
                    constructor_overload: index,
                    stack: stackRows(this)
                  });
                }
              } catch (_) {}
              return result;
            };
          });
        });
        diagnosticHook('reader_exception', function() {
          var Controller = Java.use('com.dragon.reader.lib.support.DefaultFrameController');
          Controller.O4.overloads.forEach(function(method, index) {
            method.implementation = function() {
              var rows = [];
              for (var i = 0; i < arguments.length; i++) {
                try {
                  var value = arguments[i];
                  if (!value || typeof value.getClass !== 'function') continue;
                  var type = String(value.getClass().getName());
                  if (type.indexOf('ReaderException') < 0) continue;
                  var row = {class: type};
                  value = Java.cast(value, Java.use(type));
                  try {
                    var code = value.getCode();
                    row.code_name = String(code);
                    row.code_value = Number(code.getCode());
                  } catch (_) {}
                  try {
                    var cause = value.getThrowable();
                    row.cause_class = String(cause.getClass().getName());
                    row.cause_stack = stackRows(cause);
                  } catch (_) {}
                  rows.push(row);
                } catch (_) {}
              }
              if (rows.length) {
                diagnosticEmit({event: 'reader_exception_boundary', overload: index, errors: rows});
              }
              return method.apply(this, arguments);
            };
          });
        });
      } catch (e) {
        diagnosticEmit({event: 'diagnostic_install_error', error: String(e)});
      } finally {
        diagnosticScheduled = false;
        var installed = diagnosticNames.every(function(name) {
          return diagnosticState[name] === 'installed';
        });
        if (installed && diagnosticTimer !== null) {
          clearInterval(diagnosticTimer);
          diagnosticTimer = null;
        }
      }
    });
  } catch (e) {
    diagnosticScheduled = false;
    diagnosticEmit({event: 'diagnostic_install_error', error: String(e)});
  }
}
diagnosticTimer = setInterval(installDiagnostics, 2000);
installDiagnostics();
"""


def choose_process(
    device: Any, package: str, pid: int | None, process_name: str | None = None
) -> Any:
    if pid is not None:
        return device.attach(pid)
    names = (process_name,) if process_name else (package, "番茄免费小说")
    for process in device.enumerate_processes():
        if process.name in names:
            return device.attach(process.pid)
    raise RuntimeError(f"process not found: {process_name or package}")


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
    parser.add_argument(
        "--process-name",
        help="exact process name to attach; useful for an embedded Frida Gadget",
    )
    parser.add_argument("--device", choices=("usb", "remote"), default="usb")
    parser.add_argument("--remote", default="127.0.0.1:27042")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument(
        "--output",
        type=Path,
        help="write the redacted JSONL capture to a new file",
    )
    parser.add_argument(
        "--observe-certificate-inputs",
        action="store_true",
        help="observe certificate callback 0x1000002 without changing its return value",
    )
    parser.add_argument(
        "--diagnose-reader-errors",
        action="store_true",
        help="record redacted reader error constructors and wrapper stacks",
    )
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
    if args.chunk_size < 4096:
        raise SystemExit("--chunk-size must be at least 4096")
    if args.spawn and args.process_name:
        parser.error("--process-name cannot be combined with --spawn")
    if args.pid is not None and (args.spawn or args.process_name):
        parser.error("--pid cannot be combined with --spawn or --process-name")
    source, chunks = _load_source(args.bridge_js, args.chunk_size)
    if args.observe_certificate_inputs:
        source = source + "\n" + CERTIFICATE_JS
        chunks = [source[i : i + args.chunk_size] for i in range(0, len(source), args.chunk_size)]
    if args.diagnose_reader_errors:
        source = "var vm9TraceSigning = true;\n" + source + "\n" + DIAGNOSTIC_JS
        chunks = [
            source[i : i + args.chunk_size]
            for i in range(0, len(source), args.chunk_size)
        ]
    try:
        import frida
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SystemExit("frida is required for the runtime probe") from exc
    if args.device == "usb":
        device = frida.get_usb_device(timeout=10)
    else:
        device = frida.get_device_manager().add_remote_device(args.remote)
    if args.output is not None:
        output_path = args.output.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_file = output_path.open("x", encoding="utf-8", newline="\n")
    else:
        output_file = None
    session = None
    script = None
    output_lock = threading.Lock()
    stopped = threading.Event()

    def record(payload: Any) -> None:
        line = json.dumps(payload, ensure_ascii=False)
        with output_lock:
            print(line, flush=True)
            if output_file is not None:
                output_file.write(line + "\n")
                output_file.flush()

    try:
        if args.spawn:
            session, spawned_pid = attach_or_spawn(
                device, args.package, args.pid, args.spawn
            )
        else:
            session, spawned_pid = choose_process(
                device, args.package, args.pid, args.process_name
            ), None

        def on_detached(reason: str, _crash: Any = None) -> None:
            record({"event": "session_detached", "reason": str(reason)})
            stopped.set()

        session.on("detached", on_detached)

        def on_message(message: dict, _data: bytes | None) -> None:
            if message.get("type") == "send":
                record(message.get("payload"))
            else:
                record({"event": "frida_message", "message": message})

        def forward_chunk_ack(message: dict, data: bytes | None) -> None:
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, dict) and payload.get("event") == "chunk_ack":
                    return
            on_message(message, data)

        script = _load_script(session, source, chunks, forward_chunk_ack)
        record({"event": "script_loaded", "source_length": len(source), "chunks": len(chunks)})
        if spawned_pid is not None:
            device.resume(spawned_pid)
            record({"event": "spawn_resumed", "pid": spawned_pid})
        stopped.wait(max(0.0, args.duration))
    finally:
        try:
            if script is not None:
                try:
                    script.unload()
                except (frida.InvalidOperationError, frida.TransportError):
                    pass  # An exited target has already destroyed the script.
                finally:
                    try:
                        session.detach()
                    except (frida.InvalidOperationError, frida.TransportError):
                        pass
            elif session is not None:
                try:
                    session.detach()
                except (frida.InvalidOperationError, frida.TransportError):
                    pass
        finally:
            with output_lock:
                if output_file is not None:
                    output_file.close()
                    output_file = None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
