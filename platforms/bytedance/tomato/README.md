# Tomato / Fanqie (ByteDance)

Current boundary (2026-10-08, host Asia/Shanghai): constructor finalization and explicit JNI
publication services have passed fresh native comparisons. The current request
caller and bounded request VM prefix also pass; fresh request signatures and
online acceptance remain open. See [VM9_PROGRESS.md](VM9_PROGRESS.md) for the
verification scope and next callback; older stops below are historical evidence.

Actual JNI dispatcher/exception handling now passes 54 native/Python controls
and 10 negatives; Long conversion adds 34 controls and 11 negatives with an
explicit cache mutex. Two original JNI_OnLoad observations execute the actual
dispatcher and stop before Long conversion; once remains 1 and the cache mutex
global is zero in those probes. The later +0x271940 cache mutex constructor
passes 8 controls/6 negatives; combining it with the same fresh cold startup
and producing a fresh signer output remain open.
See [REQUEST_JNI_DISPATCH.md](REQUEST_JNI_DISPATCH.md).


The later cold getter composition adds 14 native/Python controls and four
negatives. Four constructor-to-original-JNI_OnLoad prefix probes, with one
explicit driver continuation, naturally complete cold once and stop before
the two startup VM entries. VM bodies, all ELF constructors and Python full
bootstrap remain open. See [REQUEST_JNI_COLD_ONCE.md](REQUEST_JNI_COLD_ONCE.md).

This directory is limited to the `com.dragon.read` / Tomato material. Douyin and Qidian are documented in their own directories.

Read in this order:

1. [REPORT.md](REPORT.md) — algorithm and confidence summary;
2. [API_CALLS.md](API_CALLS.md) — the request chain and response evidence;
3. [SIGNATURE.md](SIGNATURE.md) — header dependencies, six/seven-god terminology, and the 16-selector result;
4. [SEARCH.md](SEARCH.md) — static search model and the still-empty live responses;
5. [COMPLETE_ANALYSIS_AND_USAGE.md](COMPLETE_ANALYSIS_AND_USAGE.md) — consolidated status, interface/analysis/usage guide, evidence rules, and product boundary;
6. [VM9_PROGRESS.md](VM9_PROGRESS.md) — the current independent-execution checkpoint and blocker;
7. [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md) — callback-8 allocator/refill evidence;
8. [ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md) — empty bins, real mapped-slab initialization, cleanup and same-capture validation;
9. [RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md) — generated TLS/TSD/arena/cache and input-driven constructor evidence;
10. [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md) — default A/B constructor graph, callback pair binding, JNI cleanup, and fresh-memory evidence;
11. [rust/README.md](rust/README.md) — what the no-JVM Rust crate can and cannot do today.

The Python folder contains the verified primitives and the old Medusa snapshot interpreter. It is labelled carefully because a successful old snapshot replay is not proof of current online compatibility.

Latest constructor work restores configuration-tree lookup/insertion,
the complete 136/320-byte constructor bodies and both lazy getters.
Fresh differences and same-run checks include cold TLS/key/destructor
registration, scoped writer cleanup and observable stack padding. Guard/OS
boundaries remain explicit; the complete Python prelude and 88-byte
initialization are still open. See
[SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md).

The configuration cipher work now restores the mode-0 decrypt callback and
advances parser to step 725, with fresh component and same-run cold-state
differences. Read [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) for the memory ABI,
reproduction commands and evidence limits. Complete Python startup, Rust
current-interface signing and a usable search/download webpage remain open.

The separate stream/reference path is also restored and verified. Read
[STREAM_REFERENCE.md](STREAM_REFERENCE.md) for RC4 state, X5 call convention,
reference ownership and the next fill/resize boundary.


The bounded root factory/caller now runs from fresh ELF/TLS/reference inputs
without a native entry prelude. Eight controls compare all32 terminal slots,
heap, main image, TLS/generation and ordered effects; full factory counts are
206/93. Read [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md) for the exact
input and allocator/OS boundary. Complete current Medusa and the final
search/download product remain open.

The outer startup caller now passes four fresh-input controls (86 steps, 16 allocations, three deferred worker creations). Worker TLS/support prefixes pass 16 cold/warm controls; executor context initialization adds eight controls with the actual emulated-TLS model. New condition/queue/executor scheduler controls pass 92/94/62 native differences; eight same-fresh-startup controls now run idle workers through wait, stop and argument cleanup. The older native-only probe remains boundary evidence. The shared OP45 register decode is corrected with 308 native differences and fresh root/parser regressions. Read [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md) for the exact thread and allocator boundary. Default initialization task bodies, OS thread-exit cleanup, real allocator boot and independent Medusa signing remain open.

### Python once/mask 与原始启动导入边界

新增 34 组原生/Python 差分、9 项负控制，恢复正常 cold once、缓存 getter 和完整
64 位 mask。另 4 条原始启动前缀及 4 条 memcpy ABS64 导入观察定位 A 的 pthread_create
与 B 的 descriptor publication 缺口。完整 Python bootstrap 对照仍 0，fresh Medusa
和下载产品尚未完成。详见 [本轮报告](REQUEST_JNI_COLD_MASK.md)。
