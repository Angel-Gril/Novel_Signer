"""Bounded, redacted observation of the selector -> Cronet -> r4 route.

Attach to an already running application. No request is generated. The optional
selector override lasts only for this instrumentation session. Stage nesting is
an observation, not proof of Java object identity or online header acceptance.
The older capture source is reused without changing its pinned artifact.
Optional reader observation records incoming FullResponse codes and the local
rejection cache, without recording book/chapter identifiers or response content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import threading
import time
from typing import Any, Callable

import capture_vm9_business_framesign_android_20261028 as shared


ROUTE_JS = r"""
'use strict';
(function () {
  var sequence = 0, nextCall = 0, emitted = 0, capped = false;
  var stacks = Object.create(null), counts = Object.create(null);
  var installed = [], missing = [], timer = null, scheduled = false, done = false;
  var readerCacheField = null;
  var headerNames = ['X-Argus', 'X-Gorgon', 'X-Helios', 'X-Khronos', 'X-Ladon', 'X-Medusa'];
  function emit(row) {
    if (emitted >= vm9RouteConfig.event_limit) {
      if (!capped) { capped = true; try { send({event: 'route_event_limit'}); } catch (_) {} }
      return;
    }
    row.sequence = ++sequence;
    emitted++;
    try { send(row); } catch (_) {}
  }
  function attempt(fn) { try { return fn(); } catch (_) { return null; } }
  function className(value) {
    if (value === null || value === undefined) return null;
    return attempt(function () { return String(value.getClass().getName()); });
  }
  function resultKeys(value) {
    return attempt(function () {
      if (!value) return [];
      var keys = [], it = value.keySet().iterator();
      while (it.hasNext()) {
        var key = String(it.next());
        if (headerNames.indexOf(key) !== -1) keys.push(key);
      }
      return keys.sort();
    });
  }
  function readerObservation(stage, receiver, args, call, tid, phase) {
    if (stage !== 'reader_response' && stage !== 'reader_cache' && stage !== 'reader_cache_update') return;
    function blocked(helper, key) {
      if (readerCacheField === null) {
        readerCacheField = Java.use('com.dragon.read.reader.utils.ChapterOriginalContentHelper')
          .class.getDeclaredField('a');
        readerCacheField.setAccessible(true);
      }
      return !!Java.cast(readerCacheField.get(helper), Java.use('java.util.HashSet')).contains(key);
    }
    try {
      if (stage === 'reader_response' && phase === 'before') {
        var response = Java.cast(args[args.length - 1],
          Java.use('readersaas.com.dragon.read.saas.rpc.model.FullResponse'));
        emit({event: 'route_reader_response', call_id: call, thread_id: tid,
              code: Number(response.code.value.getValue())});
      } else if (stage === 'reader_cache' && phase === 'before') {
        emit({event: 'route_reader_cache', call_id: call, thread_id: tid,
              blocked: blocked(receiver, args[2])});
      } else if (stage === 'reader_cache_update') {
        emit({event: 'route_reader_cache_update', call_id: call, thread_id: tid,
              phase: phase, blocked: blocked(args[0], args[1])});
      }
    } catch (_) {
      emit({event: 'route_reader_observation_unavailable', stage: stage,
            call_id: call, thread_id: tid, phase: phase});
    }
  }
  function install(owner, method, stage, required) {
    var target = owner + '.' + method;
    try {
      var type = Java.use(owner), overloads = type[method].overloads;
      if (!overloads || overloads.length === 0) throw Error('missing overload');
      overloads.forEach(function (original) {
        original.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          var tid = Process.getCurrentThreadId(), stack = stacks[tid] || (stacks[tid] = []);
          var call = ++nextCall, parent = stack.length ? stack[stack.length - 1] : null;
          counts[stage] = (counts[stage] || 0) + 1;
          stack.push(call);
          emit({event: 'route_enter', stage: stage, target: target,
                call_id: call, parent_call_id: parent, thread_id: tid});
          try {
            readerObservation(stage, this, args, call, tid, 'before');
            var result = original.call.apply(original, [this].concat(args));
            readerObservation(stage, this, args, call, tid, 'after');
            var returned = result;
            if (stage === 'selector' && vm9RouteConfig.force_selector) returned = true;
            attempt(function () {
              var row = {event: 'route_leave', stage: stage, target: target,
                         call_id: call, thread_id: tid, result_class: className(result)};
              if (stage === 'selector') { row.original = !!result; row.returned = !!returned; }
              if (stage === 'cronet_map' || stage === 'manager' || stage === 'r4')
                row.security_keys = resultKeys(result);
              emit(row);
            });
            return returned;
          } catch (error) {
            emit({event: 'route_throw', stage: stage, target: target,
                  call_id: call, thread_id: tid});
            throw error;
          } finally {
            stack.pop();
            if (stack.length === 0) delete stacks[tid];
          }
        };
      });
      installed.push(target);
      emit({event: 'route_hooked', target: target, stage: stage, overloads: overloads.length});
    } catch (_) {
      missing.push({target: target, required: required});
      emit({event: 'route_hook_unavailable', target: target, required: required});
    }
  }
  function setup() {
    if (done || scheduled || typeof Java === 'undefined') return;
    scheduled = true;
    try {
      Java.perform(function () {
        try {
          install('com.bytedance.ttnet.HttpClient', 'isCronetClientEnable', 'selector', true);
          install('com.bytedance.ttnet.HttpClient', 'getHttpClient', 'client_selection', false);
          install('com.bytedance.ttnet.HttpClient', 'getDefaultClient', 'client_selection', false);
          install('com.bytedance.frameworks.baselib.network.http.cronet.impl.SsCronetHttpClient', 'execute', 'cronet_http', false);
          install('org.chromium.CronetClient', 'openConnection', 'cronet_connection', false);
          install('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext', 'X', 'cronet_create', false);
          install('com.ttnet.org.chromium.net.impl.CronetUrlRequest', 'o', 'cronet_start', false);
          install('com.ttnet.org.chromium.net.impl.CronetUrlRequest', 'addSecurityFactor', 'cronet_request', true);
          install('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext', 'addSecurityFactor', 'cronet_context', true);
          install('com.ttnet.org.chromium.net.impl.CronetUrlRequestContext', 'o0', 'cronet_map', true);
          install('org.chromium.CronetAppProviderManager', 'onCallToAddSecurityFactor', 'manager', true);
          install('ms.bd.c.r4', 'onCallToAddSecurityFactor', 'r4', true);
          if (vm9RouteConfig.observe_reader_response) {
            install('com.dragon.read.reader.utils.ChapterOriginalContentHelper', 'F0', 'reader_response', true);
            install('com.dragon.read.reader.utils.ChapterOriginalContentHelper', 'i0', 'reader_cache', true);
            install('com.dragon.read.reader.utils.ChapterOriginalContentHelper', 'y0', 'reader_cache_update', true);
          }
          done = true;
          emit({event: 'route_ready', required_hooks_ready: !missing.some(function (row) { return row.required; }),
                installed: installed, unavailable: missing, force_selector: vm9RouteConfig.force_selector});
        } finally {
          scheduled = false;
          if (timer !== null) { clearInterval(timer); timer = null; }
        }
      });
    } catch (_) {
      scheduled = false;
      emit({event: 'route_setup_error'});
    }
  }
  rpc.exports = {routeSummary: function () {
    return {counts: counts, event_limit_reached: capped,
            required_hooks_ready: done && !missing.some(function (row) { return row.required; }),
            force_selector: vm9RouteConfig.force_selector};
  }};
  timer = setInterval(setup, 250);
  setup();
})();
"""


def bounded_call(frida: Any, seconds: float, operation: Callable[[], Any]) -> Any:
    """Cancel the actual Frida operation, including enumeration and attach."""
    cancellable = frida.Cancellable()
    timer = threading.Timer(seconds, cancellable.cancel)
    timer.daemon = True
    timer.start()
    try:
        with cancellable:
            return operation()
    finally:
        timer.cancel()
        timer.join()


def build_source(bridge: Path | None, force_selector: bool, event_limit: int,
                 observe_reader_response: bool = False) -> str:
    original, _ = shared._load_source(bridge, 50000)
    if not original.endswith(shared.JS):
        raise ValueError('shared bridge loader contract changed')
    config = json.dumps({'force_selector': force_selector, 'event_limit': event_limit,
                         'observe_reader_response': observe_reader_response})
    return original[:-len(shared.JS)] + '\nvar vm9RouteConfig = ' + config + ';\n' + ROUTE_JS


def positive_seconds(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= 300:
        raise argparse.ArgumentTypeError('seconds must be finite and in (0, 300]')
    return result


def capture(args: argparse.Namespace, source: str, frida: Any, output: Any) -> int:
    lock = threading.Lock()
    ready = threading.Event()
    failed = threading.Event()
    detached = threading.Event()
    closed = False
    session = script = None
    stage = 'connect'
    status = 'error'
    cleanup_ok = True

    def record(row: dict[str, Any]) -> None:
        with lock:
            if closed:
                return
            line = json.dumps(row, ensure_ascii=False)
            output.write(line + '\n')
            output.flush()
            print(line, flush=True)

    def on_detached(_reason: str, _crash: Any = None) -> None:
        record({'event': 'route_session_detached'})
        detached.set()

    def on_message(message: dict, _data: Any) -> None:
        row = message.get('payload')
        if message.get('type') != 'send' or not isinstance(row, dict):
            record({'event': 'route_script_error'})
            failed.set()
            return
        event = row.get('event', '')
        if isinstance(event, str) and event.startswith('route_'):
            record(row)
            if event == 'route_ready':
                if row.get('required_hooks_ready') is True:
                    ready.set()
                else:
                    failed.set()
            elif event == 'route_setup_error':
                failed.set()
        elif event == 'bridge_eval_error':
            record({'event': 'route_script_error'})
            failed.set()

    record({'event': 'route_capture_start', 'force_selector': args.force_selector,
            'duration_seconds': args.duration, 'operation_timeout_seconds': args.operation_timeout,
            'source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
            'ordinary_cronet_six_head_chain_verified': False,
            'complete_standalone_signer_verified': False,
            'online_header_acceptance_verified': False})
    try:
        if args.device == 'remote':
            device = bounded_call(frida, args.operation_timeout,
                                  lambda: frida.get_device_manager().add_remote_device(args.remote))
        else:
            device = bounded_call(frida, args.operation_timeout,
                                  lambda: frida.get_device(args.adb_serial, timeout=args.operation_timeout))
        if args.pid is None:
            stage = 'enumerate'
            processes = bounded_call(frida, args.operation_timeout, device.enumerate_processes)
            matches = [row.pid for row in processes if row.name == args.package]
            if len(matches) != 1:
                raise ValueError('expected exactly one target process; pass --pid')
            pid = matches[0]
        else:
            pid = args.pid
        stage = 'attach'
        session = bounded_call(frida, args.operation_timeout, lambda: device.attach(pid))
        session.on('detached', on_detached)
        stage = 'load'
        chunks = [source[index:index + 50000] for index in range(0, len(source), 50000)]
        script = bounded_call(frida, args.operation_timeout,
                              lambda: shared._load_script(session, source, chunks, on_message))
        stage = 'ready'
        deadline = time.monotonic() + args.operation_timeout
        while not ready.is_set():
            if failed.is_set() or detached.is_set():
                raise RuntimeError('hook installation failed')
            if time.monotonic() >= deadline:
                raise TimeoutError('hook readiness deadline')
            ready.wait(0.05)
        stage = 'observe'
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            if failed.is_set() or detached.wait(min(0.1, max(0, deadline - time.monotonic()))):
                raise RuntimeError('capture interrupted')
        stage = 'summary'
        summary = bounded_call(frida, args.operation_timeout, script.exports_sync.route_summary)
        record({'event': 'route_summary', **summary})
        if summary.get('event_limit_reached') or summary.get('required_hooks_ready') is not True:
            raise RuntimeError('capture coverage incomplete')
        status = 'observed_window'
    except Exception as error:
        record({'event': 'route_capture_error', 'stage': stage, 'error_type': type(error).__name__})
    finally:
        for cleanup_stage, operation in (
            ('unload', script.unload if script is not None else None),
            ('detach', session.detach if session is not None else None),
        ):
            if operation is None or detached.is_set():
                continue
            try:
                bounded_call(frida, args.operation_timeout, operation)
            except Exception as error:
                cleanup_ok = False
                record({'event': 'route_cleanup_error', 'stage': cleanup_stage,
                        'error_type': type(error).__name__})
        record({'event': 'route_capture_finished', 'status': status,
                'hooks_ready': ready.is_set(), 'cleanup_complete': cleanup_ok,
                'ordinary_cronet_six_head_chain_verified': False,
                'complete_standalone_signer_verified': False,
                'online_header_acceptance_verified': False})
        with lock:
            closed = True
    return 0 if status == 'observed_window' and cleanup_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', choices=('remote', 'usb'), default='remote')
    parser.add_argument('--remote', default='127.0.0.1:27042')
    parser.add_argument('--adb-serial')
    parser.add_argument('--pid', type=int)
    parser.add_argument('--package', default='com.dragon.read')
    parser.add_argument('--bridge-js', type=Path)
    parser.add_argument('--duration', type=positive_seconds, default=60.0)
    parser.add_argument('--operation-timeout', type=positive_seconds, default=15.0)
    parser.add_argument('--event-limit', type=int, default=10000)
    parser.add_argument('--force-selector', action='store_true',
                        help='temporarily return true from isCronetClientEnable; default is observation only')
    parser.add_argument('--observe-reader-response', action='store_true',
                        help='observe incoming reader error codes and rejection-cache state without content or identifiers')
    paths = parser.add_mutually_exclusive_group(required=True)
    paths.add_argument('--output', type=Path, help='new JSONL file; existing files are refused')
    paths.add_argument('--emit-script', type=Path, help='write JavaScript for offline syntax checking')
    args = parser.parse_args(argv)
    if args.pid is not None and args.pid <= 0:
        parser.error('--pid must be positive')
    if not 100 <= args.event_limit <= 100000:
        parser.error('--event-limit must be in [100, 100000]')
    if args.device == 'usb' and not args.adb_serial:
        parser.error('--device usb requires --adb-serial')
    if args.device != 'usb' and args.adb_serial:
        parser.error('--adb-serial requires --device usb')
    source = build_source(args.bridge_js, args.force_selector, args.event_limit,
                          args.observe_reader_response)
    if args.emit_script is not None:
        with args.emit_script.open('x', encoding='utf-8', newline='\n') as output:
            output.write(source)
        return 0
    import frida
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        return capture(args, source, frida, output)


if __name__ == '__main__':
    raise SystemExit(main())
