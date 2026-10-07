# Novel Signer research archive

This repository separates reverse engineering notes by platform. The current release records what was reproduced against live interfaces, what is only an offline snapshot, and what remains unverified.

## Platform directories

- [ByteDance / Tomato](platforms/bytedance/tomato/README.md) — current `v7.1.3.32` request chain, header matrix, chapter decryption, search analysis, and the Rust integration boundary.
- [Tomato complete analysis and usage guide](platforms/bytedance/tomato/COMPLETE_ANALYSIS_AND_USAGE.md) — consolidated completion status, interface chain, evidence rules, research APIs, and final product boundary.
- [ByteDance / Douyin](platforms/bytedance/douyin/REPORT.md) — static/community algorithm inventory. The current online six-god interface was not tested in this workspace.
- [Qidian](platforms/qidian/REPORT.md) — an explicit evidence gap. No Qidian APK, signed sample, API matrix, or chapter decryption vector was available here.

The public evidence files contain endpoint names, parameter names, status/length/hash summaries, and local trial labels. They intentionally omit device identifiers, tokens, complete request headers, raw responses, APKs, native libraries, and reusable tickets.

## Current practical status

The Tomato Java/Unidbg bridge can produce a current-version sample accepted by the live directory and reader endpoints. The old pure-Python Medusa interpreter is parameterized only for an older 225-byte snapshot. Current VM9 diagnostics now carry one paired detail capture through all three segments with 303 malloc/free calls replaced by Python, actual native host continuation, and a matching 779-byte body. This path no longer needs a trained handoff or callback-page injection. It still requires captured initial state, native ARM64 callbacks, trace entry registers and frame handling. Therefore the default Rust crate reports current Medusa as unavailable until those dependencies are independently reproduced. See the [current VM9 checkpoint](platforms/bytedance/tomato/VM9_PROGRESS.md).

Fresh ELF constructor research now verifies configuration-tree lookup and
insertion, complete 136/320-byte constructor bodies and their lazy getters,
including cold TLS/key creation, destructor registration and scoped writers.
Same-run checks compare memory and ordered allocator/clock/registration/wake
effects. Serialized guard and virtual OS boundaries remain explicit, and full
Python startup is unfinished; see the
[constructor report](platforms/bytedance/tomato/SIGNER_CONSTRUCTION.md).

JNI continuation now compares the actual dispatcher, its integer variadic frame,
and exception order (54 controls/10 negatives), plus Long conversion with an
explicit cache mutex (34 controls/11 negatives). Two original JNI_OnLoad probes
execute the dispatcher in the same run and stop before Long conversion. The
cache mutex constructor adds 8 controls/6 negatives. Its integration with the
same fresh cold startup, once completion and fresh signer remain open;
see the [JNI report](platforms/bytedance/tomato/REQUEST_JNI_DISPATCH.md).

Cold JNI caller composition subsequently passes 14 native/Python controls and
four negatives. Four constructor-to-original-JNI_OnLoad prefix probes naturally
complete cold once and stop before startup VM entries, using an explicit driver
and controlled services. Python full bootstrap and fresh signing remain open;
see the [cold once report](platforms/bytedance/tomato/REQUEST_JNI_COLD_ONCE.md).

## Build and checks

```text
python scripts/check_python.py
cargo check --manifest-path platforms/bytedance/tomato/rust/Cargo.toml
```

GitHub Actions runs the same checks, a public-data secret scan, and publishes `docs/` with GitHub Pages.

The `build-rust` workflow also produces Linux and Windows artifacts on manual dispatch or version tags. Those artifacts are the current Rust integration scaffold; they do not contain a current online Medusa implementation until the independent VM work is completed.


The latest bounded root factory/caller runs from fresh ELF/TLS/reference
inputs without native entry snapshots. Eight controls match all32 terminal
slots and ordered effects (206 allocations/93 frees for the full factory).
Real allocator boot, outer signer/handle and fresh request signing remain
open. See the [root initialization report](platforms/bytedance/tomato/ROOT_INITIALIZATION.md)
for reproducible checks and the exact boundary.

Outer startup now independently reproduces the default main-thread caller and three deferred worker descriptors; worker TLS/support prefixes and executor context initialization are also verified. Condition/queue/executor scheduling now adds 256 native controls, including same-fresh-startup idle worker wait/stop/argument cleanup. All six default initialization callers now pass 24 fresh cold/hot controls. Their serial task composition passes four further controls, including 48 nested returns per cold execution and six distinct mapped regions. The earlier partial-arena once-completion claim is corrected. The same fresh startup now runs its nonempty default queue through all six task bodies, wait/stop, normal return and argument cleanup in four native controls; eight new rollback checks and eight idle-worker regressions pass. A further same-startup control runs the explicit bionic key cleanup phase and releases empty support/wrapper after argument cleanup; 20 key-dispatch and eight support-destructor controls pass. Emulated-TLS array cleanup, fallback chains, nonempty support loops and the actual registry tree destructor now add 62 native controls and 13 rollback checks, including fresh registration/key and actual registry init/exit compositions. Real executor shared/weak release and the matching-libc guest pthread_exit state machine add 70 native controls and 11 rollback checks. A same-fresh-startup nonempty worker now also completes the full guest joinable exit branch after its six default tasks. Detached list removal and owned guest mapping release are verified separately. Explicit allocator/TLS/OS services, unknown callbacks and support-associated state types, real thread creation/termination, real allocator boot and fresh request signing remain unfinished. See the [startup report](platforms/bytedance/tomato/STARTUP_INITIALIZATION.md).

番茄 JNI 后续检查点新增 **34 组 once/getter/mask 对照、9 项负控制**，另有 4 条
原始启动前缀及 4 条 memcpy ABS64 单变量导入观察；A 已定位到 pthread_create 边界，
B 的 descriptor publication 待恢复。完整 Python bootstrap 对照仍为 0，详见
[once/mask 与启动报告](platforms/bytedance/tomato/REQUEST_JNI_COLD_MASK.md)。
