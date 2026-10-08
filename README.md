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

番茄 JNI 后续检查点已验证原始 A JNI_OnLoad 返回、同次六个默认 caller / 48 嵌套
返回、wait-stop 和 argument free。新增 **2 个同次 TLS cleanup、2 个 guest joinable
exit 观察**，实际 support slot 清零并依次释放 argument/payload/wrapper；到达显式 OS
exit 服务。B 在两个基址运行原始 constructor/factory，自然返回并各发布 **121 个
非空 descriptor**；另 242 个 Python lookup 控制消费 native 生成 root，不能作为独立
Python factory 证明。独立 XOR prefix 另有 82 个对照（含两个实际 ELF blob）及 8 个回滚
通过，仍停在 reader 前；另两次 actual reader 在 Python XOR 输入下返回 0，Python
AST 对照仍 0。独立 u32 原语新增 258 个对照/7 个回滚；有符号 i32 原语另通过
1336 个对照/10 个回滚，失败时保留输出。section envelope/排序与
通用 custom/function/export/start/data count 新增 202 个对照/12 个回滚（含 8 项
实际 ELF section 输入）。后续 vector 扩容与 type section 又通过 102 / 372 个对照、
34 个回滚，包含 4 个实际 ELF 输入控制。回调参数/状态/type cells 已核对，返回仍是
受控服务。section 2 的 function/global import 又通过 254 个对照、14 个回滚，
含 6 项实际 ELF 输入；完整 1/2/3/7/12 组合每基址 300 次回调一致。后续 u64 读取通过
1438 个对照/10 个回滚，table/memory import 通过 234 个对照/15 个回滚；其中 6 项
为实际 function/global 输入加合成 table/memory，核对 19 字节 limits，转换临时指针。
section 4/5 定义又通过 **266 个对照、18 个回滚**，复用 limits 解析并独立启用；
数量/条目回调、import 索引偏移和 uint32 回绕一致。样本没有真实 section 4/5，
6 项组合使用实际 function/global 输入加合成定义，完整选取组合每基址 306 次回调。
有符号 i64 又通过 **1480 个对照、10 个回滚**；section 6 与初始化表达式通过
**390 个对照、26 个回滚**，其中 10 项含真实 ELF global 输入。独立 global 开关
与 16 字节显式工作区保留 end-only 的局部高字语义；GOT 操作码表重定位已对照。
真实 section 6 有 22 项，完整 1/2/3/6/7/12 组合每基址 455 次回调一致。
section 10 又通过 **228 个对照、15 个回滚**，包含 6 项真实 code 输入：121 个
函数体、54533 个原始指令字，完整选取组合每基址 55351 次回调。独立启用开关
和回调预算已验证；这里只读取指令字，尚未执行指令或构造实际 AST。
section 9 空元素列表、section 11 data 与独立 expression helper 又通过 **450 个对照、
33 个回滚、16 个 abort 边界检查**，其中 6 项含真实 ELF data；完整选取组合每基址
55369 次回调。两类 section 独立启用；非空元素列表的原生 abort 分支仍拒绝。
section 0 的五类特殊 custom 又通过 **860 个对照、32 个回滚**，含 10 项真实 ELF
custom 输入；全部实际 section 组合每基址匹配 55369 次回调。特殊 custom 默认关闭，
要求独立八字节工作区和每段记录预算。实际 AST 和完整 reader 未恢复。
真实 OS 线程/allocator、独立 Medusa 与 fresh 签名仍未完成，
完整 Python bootstrap 对照仍为 **0**。详见
[原始 JNI 与同次 worker 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md)。
