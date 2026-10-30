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


def main() -> int:
    spec = importlib.util.spec_from_file_location("vm9_capture", SOURCE)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    for source in (capture.JS, capture.DIAGNOSTIC_JS):
        subprocess.run(["node", "--check"], input=source, text=True, check=True)
    result = subprocess.run(
        ["node", "-e", JS_CHECK], input=json.dumps({"source": capture.JS}),
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
        "exact_process_selection": True, "jsonl_metadata": True,
        "overwrite_refused": True, "detach_after_load_failure": True,
        "target_exit_ends_capture": True, "destroyed_script_cleanup": True,
        "evidence_boundary": "host regression only; Android business callback unverified",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
