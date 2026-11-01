"""Host regression checks for capture hooks; does not prove an Android request."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SOURCE = Path(__file__).with_name("capture_vm9_business_framesign_android_20261028.py")

JS_CHECK = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const events = [], timers = new Map(), pending = [];
const assigned = new Map(), implementations = new Map();
let nextTimer = 1, ready = false, originalCalls = 0;
function method(name) {
  const overload = {call() { originalCalls++; return null; }};
  Object.defineProperty(overload, 'implementation', {set(f) {
    assigned.set(name, (assigned.get(name) || 0) + 1);
    implementations.set(name, f);
  }});
  return {overload() { return overload; }};
}
const classes = {
  'com.bytedance.mobsec.metasec.ml.MSManager': {frameSign: method('frameSign')},
  'ms.bd.c.r4': {onCallToAddSecurityFactor: method('securityFactor')},
  'com.ttnet.org.chromium.net.impl.CronetUrlRequest': {addSecurityFactor: method('cronet')},
  'com.ttnet.org.chromium.net.impl.CronetUrlRequestContext': {
    addSecurityFactor: method('context'), o0: method('o0')
  }
};
const context = vm.createContext({
  Process: {id: 1}, send(e) { events.push(e); },
  setInterval(f) { const id = nextTimer++; timers.set(id, f); return id; },
  clearInterval(id) { timers.delete(id); }
});
vm.runInContext(input.source, context);
assert.equal(events[0].event, 'awaiting_java_bridge');
context.Java = {
  perform(f) { pending.push(f); },
  use(name) {
    if (name === 'ms.bd.c.r4' && !ready) throw Error('class not loaded');
    return new Proxy(classes[name] || {}, {
      get(target, key) {
        if (!(key in target)) throw Error('no such Java member: ' + key);
        return target[key];
      },
      set() { throw Error('Java wrapper properties are not hook state'); }
    });
  }
};
const tick = [...timers.values()][0];
tick(); tick(); tick();
assert.equal(pending.length, 1, 'only one Java.perform may wait for a loader');
pending.shift()();
assert.equal(implementations.size, 4);
ready = true;
tick(); pending.shift()();
assert.equal(implementations.size, 5);
assert.equal(timers.size, 0);
tick(); pending.shift()();
assert.deepEqual([...assigned.values()], [1, 1, 1, 1, 1]);
assert.equal(events.filter(e => e.event === 'hooked').length, 5);
assert.equal(implementations.get('frameSign')('https://redacted.invalid', 0), null);
assert.equal(originalCalls, 1);
console.log(JSON.stringify({hook_count: 5, retry_without_replacement: true,
  pending_install_deduplicated: true, original_called_once: true}));
"""


CERTIFICATE_CHECK = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8')).source;
const events = [], timers = new Map(), pending = [], assigned = new Map();
let nextTimer = 1, result = [0, -128, -1, 10], thrown = null, kCalls = 0, jCalls = 0;
const k = {call() { kCalls++; if (thrown) throw thrown; return result; }};
const j = {call(_receiver, tag) { jCalls++; return tag === 16777218 ? k.implementation('') : 123; }};
for (const [name, method] of [['k', k], ['j', j]]) {
  Object.defineProperty(method, 'implementation', {set(value) {
    assigned.set(name, (assigned.get(name) || 0) + 1); this.impl = value;
  }, get() { return this.impl; }});
}
const S = {k: {overload() { return k; }}, j: {overload() { return j; }}};
const context = vm.createContext({send(row) { events.push(row); },
  Process: {getCurrentThreadId() { return 7; }},
  setInterval(f) { const id = nextTimer++; timers.set(id, f); return id; },
  clearInterval(id) { timers.delete(id); }});
vm.runInContext(source, context);
context.Java = {perform(f) { pending.push(f); }, cast(value) {
  if (!Array.isArray(value)) throw Error('not bytes'); return value;
}, backtrace() { return {frames: [{className: 'test.Owner', methodName: 'read'}]}; },
use(name) {
  if (name === 'ms.bd.c.s2') return S;
  if (name === '[B') return {};
  if (name === 'java.lang.reflect.Array') return {getLength(value) { return value.length; }};
  if (name === 'java.lang.String') return {$new(value) { return {
    getBytes() { return [...Buffer.from(String(value), 'utf8')]; }
  }; }};
  if (name === 'java.security.MessageDigest') return {getInstance() { const digest = bytes =>
    [...crypto.createHash('sha256').update(Buffer.from(bytes)).digest()];
    const method = bytes => digest(bytes); method.overload = () => ({call(_receiver, bytes) { return digest(bytes); }});
    return {digest: method};
  }};
  throw Error('unexpected class: ' + name);
}};
const tick = [...timers.values()][0];
tick(); tick(); assert.equal(pending.length, 1); pending.shift()();
assert.equal(timers.size, 0);
tick(); pending.shift()();
assert.deepEqual([...assigned.values()], [1, 1]);
const before = events.length;
assert.equal(j.implementation(16777217, 0, 0, '', null), 123);
assert.equal(events.length, before, 'non-certificate dispatch must remain unobserved');
const actual = j.implementation(16777218, 0, 0, '', null);
assert.equal(actual, result, 'return the exact original object');
assert.equal(kCalls, 1); assert.equal(jCalls, 2);
const rows = events.filter(row => row.event === 'certificate_read_return');
assert.equal(rows.length, 2);
for (const row of rows) {
  assert.equal(row.result.length, 4);
  assert.equal(row.result.sha256, crypto.createHash('sha256').update(Buffer.from(result)).digest('hex'));
  assert.equal(row.context.thread_id, 7);
  assert.deepEqual(Object.keys(row.result).sort(), ['is_null', 'length', 'sha256']);
}
result = null;
assert.equal(k.implementation(''), null);
assert.equal(events.at(-1).result.is_null, true);
const error = Error('original exception'); thrown = error;
assert.throws(() => k.implementation(''), actual => actual === error);
assert.equal(events.at(-1).event, 'certificate_read_threw');
thrown = null; result = {};
assert.equal(k.implementation(''), result, 'observation errors must not alter the original result');
assert.equal(events.at(-1).event, 'certificate_summary_error');
console.log(JSON.stringify({binary_digest: true, exact_return_preserved: true,
  original_exception_preserved: true, unrelated_tag_untouched: true, hook_deduplicated: true}));
"""


class Script:
    def __init__(self, fail_load: bool = False) -> None:
        self.fail_load = fail_load
        self.callbacks: list = []
        self.unloaded = False

    def on(self, _name, callback) -> None:
        self.callbacks.append(callback)

    def load(self) -> None:
        if self.fail_load:
            raise RuntimeError("load failed")
        for callback in self.callbacks:
            callback({"type": "send", "payload": {"event": "probe_ready"}}, None)

    def unload(self) -> None:
        self.unloaded = True


class Session:
    def __init__(self, fail_load: bool = False) -> None:
        self.script = Script(fail_load)
        self.detached = False

    def on(self, _name, callback) -> None:
        self.detached_callback = callback

    def create_script(self, _source):
        self.script.source = _source
        return self.script

    def detach(self) -> None:
        self.detached = True


class Device:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.attached: list[int] = []

    def enumerate_processes(self):
        return [SimpleNamespace(name="com.dragon.read", pid=11),
                SimpleNamespace(name="Gadget", pid=22)]

    def attach(self, target):
        self.attached.append(target)
        return self.session


DIAGNOSTIC_CHECK = r"""
const assert = require('node:assert/strict'), vm = require('node:vm');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8')).source;
const context = vm.createContext({setInterval: () => 1, send: () => {}});
vm.runInContext(source, context);
function throwable(name, next) {
  return {getClass: () => ({getName: () => name}), getCause: () => next,
    getStackTrace: () => [{getClassName: () => 'Reader', getMethodName: () => 'decode'}]};
}
function make(name, next) {
  const value = throwable(name, next); value.equals = other => other === value;
  value.getMessage = () => { throw Error('messages may contain private content'); };
  value.toString = value.getMessage; return value;
}
const root = make('DecodeException', null), wrapper = make('RuntimeException', root);
const result = context.causeChain(wrapper);
assert.deepEqual(Array.from(result.rows, row => row.class), ['RuntimeException', 'DecodeException']);
assert.equal(result.terminal, 'complete');
const cycle = make('Cycle', null); cycle.getCause = () => cycle;
assert.equal(context.causeChain(cycle).terminal, 'cycle');
let chain = null; for (let i = 0; i < 9; i++) chain = make('Wrapper', chain);
assert.equal(context.causeChain(chain).rows.length, 6);
assert.equal(context.causeChain(chain).terminal, 'limit');
const broken = make('Broken', null); broken.getCause = () => { throw Error('unavailable'); };
assert.equal(context.causeChain(broken).terminal, 'unavailable');
assert.equal(context.causeChain(null).rows.length, 0);
assert.ok(!JSON.stringify(result).includes('message'));
process.stdout.write(JSON.stringify({nested_cause_types: true, cycle_and_depth_bounded: true,
  exception_messages_omitted: true}));
"""


CRONET_CACHED_CHECK = r"""
const assert = require('node:assert/strict'), vm = require('node:vm');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8')).source;
function run(failLookup) {
  const events = [], hooks = new Map(), deleted = [], allocated = [];
  let exception = false, clears = 0;
  class Pointer {
    constructor(value) { this.value = value; }
    add(offset) { return new Pointer(this.value + offset); }
    readPointer() { return this.target || this; }
    writePointer(value) { this.target = value; }
    readUtf8String() { return this.value; }
    isNull() { return this.value === 0; }
    toString() { return String(this.value); }
  }
  const pointer = value => new Pointer(value);
  const env = pointer(10000); env.target = pointer(0);
  const functions = {
    6: (_env, name) => pointer(name.value),
    17: () => { exception = false; clears++; },
    23: (_env, ref) => deleted.push(ref),
    33: (_env, owner, name, sig) => {
      if (failLookup && name.value === 'addSecurityFactor') {
        exception = true; return pointer(0);
      }
      const result = pointer(name.value === 'addSecurityFactor'
        ? owner.value.endsWith('Context') ? '0x22' : '0x11' : name.value);
      const state = {};
      hooks.get(264).onEnter.call(state, [env, owner, name, sig]);
      hooks.get(264).onLeave.call(state, result);
      return result;
    },
    36: (_env, _owner, method, args) => {
      if (method.value === 'getClassLoader') return pointer('loader');
      assert.equal(method.value, 'loadClass');
      return pointer(args.target.value);
    },
    113: (_env, _owner, name) => pointer(name.value),
    116: () => pointer('application'),
    167: (_env, name) => { allocated.push(name); return name; },
    228: () => exception ? 1 : 0
  };
  const context = vm.createContext({
    send: event => events.push(event), ptr: pointer,
    Process: {pointerSize: 8, getCurrentThreadId: () => 7, findModuleByName: () => null, id: 1},
    Memory: {allocUtf8String: pointer, alloc: pointer},
    NativeFunction: function (address) { return functions[address.value / 8]; },
    Interceptor: {attach: (address, handlers) => hooks.set(address.value, handlers)},
    setInterval: () => 1, clearInterval: () => {}, rpc: {exports: {}}
  });
  vm.runInContext(source, context);
  context.installTable(env);
  context.resolveCachedMethods(env);
  assert.equal(events.filter(e => e.event === 'jni_get_method_id').length, 0,
    'active lookups must not masquerade as passive lookups');
  assert.equal(events.filter(e => e.event === 'jni_call_object_method_v').length, 0);
  assert.equal(context.vm9State.lookupThread, null);
  if (failLookup) {
    assert.equal(events.filter(e => e.event === 'jni_seed_error').length, 1);
    assert.equal(events.filter(e => e.event === 'jni_seed_complete').length, 0);
    assert.equal(clears, 1); assert.equal(exception, false);
    assert.equal(deleted.length, 7);
  } else {
    assert.equal(events.filter(e => e.event === 'jni_method_seed').length, 2);
    assert.equal(events.filter(e => e.event === 'jni_seed_complete').length, 1);
    assert.equal(deleted.length, 9);
    hooks.get(280).onEnter([env, pointer('receiver'), pointer('0x11')]);
    assert.equal(events.filter(e => e.event === 'jni_call_object_method_v').length, 1);
    hooks.get(280).onEnter([env, pointer('receiver'), pointer('0x99')]);
    assert.equal(events.filter(e => e.event === 'jni_call_object_method_v').length, 1);
  }
}
run(false); run(true);
process.stdout.write(JSON.stringify({cached_calls: true, lookup_separation: true,
  local_refs_released: true, java_exception_cleared: true}));
"""


def check_cronet_lifecycle() -> dict:
    source = SOURCE.with_name("capture_vm9_cronet_jni_runtime_20261101.py")
    spec = importlib.util.spec_from_file_location("vm9_cronet_capture", source)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    cached_check = subprocess.run(
        ["node", "-e", CRONET_CACHED_CHECK], input=json.dumps({"source": capture.PROBE_JS}),
        text=True, capture_output=True, check=True, timeout=20)
    session = Session()
    device = Device(session)
    selected = []
    spawned = []
    resumed = []
    device.spawn = lambda _args: spawned.append(33) or 33
    device.resume = resumed.append
    fake_frida = SimpleNamespace(
        get_device=lambda serial, timeout: selected.append(serial) or device,
        get_usb_device=lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("explicit serial must not select an arbitrary USB device")),
        get_device_manager=lambda: SimpleNamespace(add_remote_device=lambda _address: device),
    )
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "serial.jsonl"
        argv = [str(source), "--adb-serial", "emulator-5554", "--pid", "11",
                "--duration", "0.001", "--output", str(output)]
        with patch.dict(sys.modules, {"frida": fake_frida}), \
                patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            assert capture.main() == 0
        assert selected == ["emulator-5554"] and device.attached == [11]
        assert session.detached and session.script.unloaded

        cached_output = Path(temp) / "cached-option.jsonl"
        with patch.dict(sys.modules, {"frida": fake_frida}), \
                patch.object(sys, "argv", argv[:-1] + [str(cached_output), "--resolve-cached-methods"]), \
                contextlib.redirect_stdout(io.StringIO()):
            assert capture.main() == 0
        assert session.script.source.startswith("var VM9_RESOLVE_CACHED_METHODS = true;")

        output.write_text("existing evidence\n", encoding="utf-8")
        argv = [str(source), "--device", "remote", "--spawn",
                "--duration", "0.001", "--output", str(output)]
        with patch.dict(sys.modules, {"frida": fake_frida}), \
                patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            try:
                capture.main()
            except FileExistsError:
                pass
            else:
                raise AssertionError("existing evidence was overwritten")
        assert not spawned, "output collision must be detected before spawning"
        assert output.read_text(encoding="utf-8") == "existing evidence\n"

        verifier_spec = importlib.util.spec_from_file_location(
            "vm9_cronet_verifier", source.with_name("verify_vm9_cronet_jni_runtime_20261101.py"))
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        base = [
            {"event": "probe_ready"}, {"event": "script_loaded"},
            {"event": "jni_hooks_installed"},
            {"event": "jni_table", "table_offsets": {"GetMethodID": 264, "CallObjectMethodV": 280},
             "table": "0x1", "get_method_id": "0x2", "call_object_method_v": "0x3"},
        ]
        seeds = [{"event": "jni_method_seed", "method_id": f"0x{index}",
                  "name": "addSecurityFactor", "sig": verifier.EXPECTED_SIGNATURE,
                  "class_name": name, "thread_id": 7}
                 for index, name in enumerate((
                     "com.ttnet.org.chromium.net.impl.CronetUrlRequest",
                     "com.ttnet.org.chromium.net.impl.CronetUrlRequestContext"), 4)]
        complete = {"event": "jni_seed_complete", "method_count": 2}
        cached_path = Path(temp) / "cached.jsonl"
        def write_rows(rows):
            cached_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        write_rows(base + seeds + [complete])
        summary = verifier.verify(cached_path)
        assert summary["cached_method_ids_resolved"] and not summary["cronet_runtime_branch_observed"]
        call = {"event": "jni_call_object_method_v", "method_id": "0x4",
                "name": "addSecurityFactor", "sig": verifier.EXPECTED_SIGNATURE, "thread_id": 9}
        write_rows(base + seeds + [complete, call])
        assert verifier.verify(cached_path)["cronet_runtime_branch_observed"]
        for invalid in (base + seeds[:1], base + seeds + [complete, {**call, "method_id": "0x99"}],
                        base + [call] + seeds + [complete],
                        base + [complete] + seeds,
                        base + [{"event": "jni_seed_error"}]):
            write_rows(invalid)
            try:
                verifier.verify(cached_path)
            except AssertionError:
                pass
            else:
                raise AssertionError("invalid cached-method evidence was accepted")
        for event, fail_stage in (("device_error", "device"), ("spawn_error", "spawn"),
                                  ("attach_error", "attach"), ("script_error", "script"),
                                  ("resume_error", "resume")):
            session = Session(fail_load=fail_stage == "script")
            device.session = session
            def fail(*_args, **_kwargs):
                raise RuntimeError("controlled failure")
            device.spawn = fail if fail_stage == "spawn" else lambda _args: 33
            device.resume = fail if fail_stage == "resume" else resumed.append
            target = Path(temp) / f"{event}.jsonl"
            argv[-1] = str(target)
            resume_count = len(resumed)
            with patch.dict(sys.modules, {"frida": fake_frida}), \
                    patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(fake_frida, "get_device_manager",
                                 fail if fail_stage == "device" else fake_frida.get_device_manager), \
                    patch.object(device, "attach", fail if fail_stage == "attach" else device.attach):
                assert capture.main() == 2, event
            rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
            assert sum(row.get("event") == event for row in rows) == 1, rows
            try:
                verifier.verify(target)
            except AssertionError as error:
                assert "probe reported errors" in str(error), str(error)
            else:
                raise AssertionError("setup failure was accepted as runtime evidence")
            if fail_stage in ("script", "resume"):
                assert session.detached and session.script.unloaded
            if fail_stage in ("attach", "script"):
                assert len(resumed) == resume_count + 1, "failed setup must release a suspended spawn"
        with patch.object(capture, "adb", side_effect=["", "Error type 3\nError: Activity class does not exist."]):
            try:
                capture.launch_and_find_pid("serial", "example.app", ".Missing", 1)
            except RuntimeError as error:
                assert str(error) == "ADB activity launch failed"
            else:
                raise AssertionError("activity error returned as a successful launch")
    return {"exact_device_serial": True, "collision_before_spawn": True,
            "structured_setup_errors": True, "failed_spawn_cleanup": True,
            "cached_methods": json.loads(cached_check.stdout)}


def main() -> int:
    spec = importlib.util.spec_from_file_location("vm9_capture", SOURCE)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    with tempfile.TemporaryDirectory() as bridge_temp:
        bridge_path = Path(bridge_temp) / "metadata_bridge.js"
        bridge_path.write_text("📦\n/path/to/bundle/index.js\n✄\nvar bridgeReady = true;\n",
                               encoding="utf-8")
        normalized, _chunks = capture._load_source(bridge_path, 4096)
        assert normalized.startswith("var bridgeReady = true;\n"), \
            "known bridge packaging preamble must be removed"
        assert "📦" not in normalized and "✄" not in normalized
    for source in (capture.JS, capture.DIAGNOSTIC_JS, capture.CERTIFICATE_JS):
        subprocess.run(["node", "--check"], input=source, text=True, check=True)
    diagnostic_result = subprocess.run(
        ["node", "-e", DIAGNOSTIC_CHECK], input=json.dumps({"source": capture.DIAGNOSTIC_JS}),
        text=True, check=True, capture_output=True, timeout=20)
    result = subprocess.run(
        ["node", "-e", JS_CHECK], input=json.dumps({"source": capture.JS}),
        text=True, check=True, capture_output=True,
    )
    certificate_result = subprocess.run(
        ["node", "-e", CERTIFICATE_CHECK], input=json.dumps({"source": capture.CERTIFICATE_JS}),
        text=True, check=True, capture_output=True,
    )
    session = Session()
    device = Device(session)
    assert capture.choose_process(device, "com.dragon.read", None, "Gadget") is session
    assert device.attached == [22]
    try:
        capture.choose_process(device, "com.dragon.read", None, "MissingGadget")
    except RuntimeError:
        pass
    else:
        raise AssertionError("explicit process selection fell back to another app")
    fake_frida = SimpleNamespace(
        get_device_manager=lambda: SimpleNamespace(add_remote_device=lambda _address: device),
        InvalidOperationError=LookupError, TransportError=ConnectionError,
    )
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "capture.jsonl"
        argv = [str(SOURCE), "--device", "remote", "--process-name", "Gadget",
                "--duration", "0", "--output", str(output)]
        with patch.dict(sys.modules, {"frida": fake_frida}), \
                patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            assert capture.main() == 0
            assert session.detached and session.script.unloaded
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            assert [row["event"] for row in rows] == ["probe_ready", "script_loaded"]
            try:
                capture.main()
            except FileExistsError:
                pass
            else:
                raise AssertionError("capture overwrote existing output")
            session = Session(fail_load=True)
            device.session = session
            argv[-1] = str(Path(temp) / "failed.jsonl")
            try:
                capture.main()
            except RuntimeError as error:
                assert str(error) == "load failed"
            else:
                raise AssertionError("load failure was hidden")
            assert session.detached
            session = Session()
            device.session = session
            argv[-1] = str(Path(temp) / "exited.jsonl")
            argv[argv.index("--duration") + 1] = "600"
            with patch.object(session.script, "load", lambda: session.detached_callback(
                    "process-terminated", None)), \
                    patch.object(session.script, "unload", side_effect=LookupError("script is destroyed")), \
                    patch.object(session, "detach", side_effect=LookupError("session is detached")):
                assert capture.main() == 0
            exited_rows = [json.loads(line) for line in Path(argv[-1]).read_text(
                encoding="utf-8").splitlines()]
            assert exited_rows[0] == {"event": "session_detached", "reason": "process-terminated"}
    print(json.dumps({
        "status": "pass", "javascript": json.loads(result.stdout),
        "certificate_observer": json.loads(certificate_result.stdout),
        "exact_process_selection": True, "jsonl_metadata": True,
        "overwrite_refused": True, "detach_after_load_failure": True,
        "target_exit_ends_capture": True, "destroyed_script_cleanup": True,
        "evidence_boundary": "host regression only; Android business callback unverified",
        "cronet_lifecycle": check_cronet_lifecycle(),
        "reader_diagnostics": json.loads(diagnostic_result.stdout),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
