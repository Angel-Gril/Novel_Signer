"""Host lifecycle/privacy checks; these do not establish an Android request."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import threading
import time
from types import SimpleNamespace

import capture_vm9_cronet_route_android_20261117 as probe


JS_CHECK = r"""
const assert = require('node:assert/strict'), vm = require('node:vm');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8')).source;
function check(force) {
  const events = [], methods = new Map(), calls = new Map(), timers = new Set();
  let thrown = null, tid = 7;
  const H = 'com.bytedance.ttnet.HttpClient';
  const C = 'com.ttnet.org.chromium.net.impl.CronetUrlRequestContext';
  const M = 'org.chromium.CronetAppProviderManager';
  const R = 'ms.bd.c.r4';
  const targets = [
    [H, 'isCronetClientEnable'], [H, 'getHttpClient'], [H, 'getDefaultClient'],
    ['com.bytedance.frameworks.baselib.network.http.cronet.impl.SsCronetHttpClient', 'execute'],
    ['org.chromium.CronetClient', 'openConnection'], [C, 'X'],
    ['com.ttnet.org.chromium.net.impl.CronetUrlRequest', 'o'],
    ['com.ttnet.org.chromium.net.impl.CronetUrlRequest', 'addSecurityFactor'],
    [C, 'addSecurityFactor'], [C, 'o0'], [M, 'onCallToAddSecurityFactor'], [R, 'onCallToAddSecurityFactor']
  ];
  const classes = {};
  const secret = 'PRIVATE_REQUEST_VALUE';
  const result = {getClass() { throw Error(secret); }, keySet() { return {iterator() {
    const keys = ['authorization', 'X-Argus', 'X-Gorgon', 'X-Helios', 'X-Khronos', 'X-Ladon', 'X-Medusa'];
    let index = 0; return {hasNext() { return index < keys.length; }, next() { return keys[index++]; }};
  }}; }};
  for (const [owner, name] of targets) {
    const target = owner + '.' + name;
    const method = {call(_receiver, ...args) {
      calls.set(target, (calls.get(target) || 0) + 1);
      if (target === H + '.isCronetClientEnable') return false;
      if (target === C + '.o0') return methods.get(M + '.onCallToAddSecurityFactor').implementation(...args);
      if (target === M + '.onCallToAddSecurityFactor') return methods.get(R + '.onCallToAddSecurityFactor').implementation(...args);
      if (target === R + '.onCallToAddSecurityFactor' && thrown) throw thrown;
      return result;
    }};
    methods.set(target, method);
    (classes[owner] || (classes[owner] = {}))[name] = {overloads: [method]};
  }
  const context = vm.createContext({
    Process: {getCurrentThreadId() { return tid; }}, rpc: {exports: {}},
    Java: {perform(fn) { fn(); }, use(name) { return classes[name]; }},
    send(row) { events.push(row); },
    setInterval(fn) { timers.add(fn); return fn; }, clearInterval(fn) { timers.delete(fn); }
  });
  vm.runInContext(source.replace('"force_selector": false', '"force_selector": ' + force), context);
  assert.equal(events.find(e => e.event === 'route_ready').required_hooks_ready, true);
  for (const [owner, method, stage] of [
    [C, 'X', 'cronet_create'],
    ['com.ttnet.org.chromium.net.impl.CronetUrlRequest', 'o', 'cronet_start']
  ]) {
    const target = owner + '.' + method;
    assert.ok(events.some(e => e.event === 'route_hooked' && e.target === target && e.stage === stage),
              'hook the creation/start names verified in the pinned Android DEX');
    assert.equal(methods.get(target).implementation(secret), result);
    assert.equal(calls.get(target), 1, 'preserve the original creation/start call');
  }
  assert.equal(timers.size, 0, 'installation timer must stop');
  assert.equal(methods.get(H + '.isCronetClientEnable').implementation(), force);
  assert.equal(calls.get(H + '.isCronetClientEnable'), 1, 'invoke original exactly once');
  assert.equal(methods.get(C + '.o0').implementation(secret, {}), result, 'preserve exact result');
  const enters = events.filter(e => e.event === 'route_enter' && ['cronet_map', 'manager', 'r4'].includes(e.stage));
  assert.deepEqual(enters.map(e => e.stage), ['cronet_map', 'manager', 'r4']);
  assert.equal(enters[0].parent_call_id, null);
  assert.equal(enters[1].parent_call_id, enters[0].call_id);
  assert.equal(enters[2].parent_call_id, enters[1].call_id);
  const returned = events.filter(e => e.event === 'route_leave' && e.security_keys);
  for (const row of returned) assert.equal(row.security_keys.length, 6);
  thrown = Error(secret);
  assert.throws(() => methods.get(C + '.o0').implementation(secret, {}), actual => actual === thrown);
  assert.equal(events.filter(e => e.event === 'route_throw').length, 3);
  thrown = null; tid = 8;
  assert.equal(methods.get(R + '.onCallToAddSecurityFactor').implementation(secret, {}), result);
  assert.equal(events.filter(e => e.event === 'route_enter').at(-1).parent_call_id, null);
  for (let index = 0; index < 200; index++) methods.get(R + '.onCallToAddSecurityFactor').implementation(secret, {});
  assert.equal(context.rpc.exports.routeSummary().event_limit_reached, true);
  assert.equal(events.filter(e => e.event === 'route_event_limit').length, 1);
  assert.ok(!JSON.stringify(events).includes(secret), 'never serialize arguments or exception messages');
  assert.ok(!JSON.stringify(events).includes('authorization'), 'retain only security key names');
}
check(false); check(true);
console.log(JSON.stringify({passive_selector_preserved: true, explicit_override: true,
  original_result_and_exception_preserved: true, nesting_and_thread_cleanup: true,
  telemetry_failure_isolated: true, event_limit_enforced: true, raw_values_omitted: true}));
"""


class Script:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.unloaded = False
        self.exports_sync = SimpleNamespace(route_summary=lambda: {
            'counts': {}, 'required_hooks_ready': True, 'event_limit_reached': False,
            'force_selector': False,
        })

    def on(self, _name, callback) -> None:
        self.callback = callback

    def load(self) -> None:
        if self.mode == 'load_error':
            raise RuntimeError('PRIVATE_REQUEST_VALUE')
        if self.mode != 'never_ready':
            self.callback({'type': 'send', 'payload': {
                'event': 'route_ready', 'required_hooks_ready': self.mode != 'missing_hook',
            }}, None)

    def unload(self) -> None:
        self.unloaded = True
        if self.mode == 'unload_error':
            raise RuntimeError('PRIVATE_REQUEST_VALUE')


class Session:
    def __init__(self, mode: str) -> None:
        self.script = Script(mode)
        self.detached = False

    def on(self, _name, callback) -> None:
        self.callback = callback

    def create_script(self, _source):
        return self.script

    def detach(self) -> None:
        self.detached = True
        self.callback('application-requested')


def host_lifecycle_checks(frida) -> None:
    for mode in ('normal', 'load_error', 'missing_hook', 'never_ready', 'unload_error', 'enumerate_error'):
        session = Session(mode)

        def enumerate_processes():
            if mode == 'enumerate_error':
                raise RuntimeError('PRIVATE_REQUEST_VALUE')
            return [SimpleNamespace(name='com.dragon.read', pid=11)]

        device = SimpleNamespace(enumerate_processes=enumerate_processes, attach=lambda _pid: session)
        backend = SimpleNamespace(Cancellable=frida.Cancellable,
                                  get_device_manager=lambda: SimpleNamespace(add_remote_device=lambda _remote: device))
        args = SimpleNamespace(device='remote', remote='local.invalid', package='com.dragon.read', pid=None,
                               operation_timeout=0.08, duration=0.001, force_selector=False)
        output = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()):
            code = probe.capture(args, probe.build_source(None, False, 100), backend, output)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        assert code == (0 if mode == 'normal' else 1), mode
        assert rows[-1]['event'] == 'route_capture_finished'
        assert rows[-1]['ordinary_cronet_six_head_chain_verified'] is False
        assert rows[-1]['online_header_acceptance_verified'] is False
        assert 'PRIVATE_REQUEST_VALUE' not in output.getvalue()
        if mode != 'enumerate_error':
            assert session.detached, mode
        if mode not in ('enumerate_error', 'load_error'):
            assert session.script.unloaded, mode
        if mode == 'unload_error':
            assert rows[-1]['cleanup_complete'] is False

    cancelled = threading.Event()

    def wait_for_cancel():
        current = frida.Cancellable.get_current()
        handler = current.connect(cancelled.set)
        try:
            assert cancelled.wait(1), 'cancellation timer did not fire'
            current.raise_if_cancelled()
        finally:
            current.disconnect(handler)

    start = time.monotonic()
    try:
        probe.bounded_call(frida, 0.03, wait_for_cancel)
    except frida.OperationCancelledError:
        pass
    else:
        raise AssertionError('native cancellation was swallowed')
    assert time.monotonic() - start < 1


def main() -> None:
    import frida
    node = shutil.which('node')
    if not node:
        raise SystemExit('node is required for JavaScript behavior checks')
    source = probe.build_source(None, False, 100)
    result = subprocess.run([node, '-e', JS_CHECK], input=json.dumps({'source': source}),
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    javascript = json.loads(result.stdout)
    host_lifecycle_checks(frida)
    for value in ('nan', 'inf', '-1', '0', '301'):
        try:
            probe.positive_seconds(value)
        except Exception:
            pass
        else:
            raise AssertionError('invalid deadline accepted')
    print(json.dumps({'javascript': javascript, 'host_lifecycle_cases': 6,
                      'native_cancellation_verified': True,
                      'android_request_verified': False}, sort_keys=True))


if __name__ == '__main__':
    main()
