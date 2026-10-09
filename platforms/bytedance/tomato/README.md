# Tomato / Fanqie (ByteDance)

Current boundary (2026-10-09 Asia/Shanghai; earlier host trial label `20261008`): original A
JNI_OnLoad returns `0x10006`; its same-run queue worker executes six default
callers / 48 nested returns, cleanup, matching-libc wait, explicit stop and
argument free. Two new TLS cleanup and two guest joinable exit observations
clear the actual support slot and free argument/payload/wrapper in order.
Guest state 0→1 reaches explicit syscall 93 exit. Thread creation/termination,
allocator/OS/JNI/warm TLS and the empty cxa thread list remain explicit inputs.

Two original B constructor/factory observations now return naturally and each
publish 121 nonzero descriptors. 242 Python lookup comparisons consume native
generated roots, distinct from the earlier 50 synthetic-root controls and six
negatives. Independent Python factory, original JNI B composition, B VM and
full Python bootstrap (0 controls) remain open. The independent XOR prefix
adds 82 native/Python controls (including two real ELF blobs) and eight
rollback cases; it stops before the +31b360 reader. Two subsequent native
reader observations accept that Python XOR input and return 0 after 1658
controlled allocations each. The independent u32 helper adds 258 comparisons/seven rollback
checks. The signed i32 helper adds 1336 comparisons/10 rollback checks; failed
reads preserve output. Reader envelope/order and generic-custom/function/export/start/data-count
handlers add 202 comparisons/12 rollback checks, including eight actual ELF
section controls from fresh Python XOR. Callback arguments and state match;
callbacks remain explicit status services. Word-vector grow and section 1 types
add 102 / 372 comparisons and 34 rollback checks, including four fresh ELF
input controls; type cells at each callback and pointer publication match.
Function/global imports in section 2 add 254 comparisons and 14 rollback checks,
including six fresh ELF inputs; the 1/2/3/7/12 composition matches 300 callbacks
per base. Parsing requires explicit `enable_function_global_imports=True`.
The u64 reader adds 1438 comparisons/10 rollback checks; table/memory imports
add 234 comparisons/15 rollback checks. Six compositions combine fresh ELF
function/global inputs with synthetic table/memory imports; actual ELF table/memory
import inputs remain absent. Their 19-byte descriptors match after normalizing
the transient native stack pointer to model scratch. Parsing requires
`enable_table_memory_imports=True` and a mapped 32-byte `import_scratch_address`.
Sections 4/5 add 266 comparisons/18 rollback checks with the independent
`enable_table_memory_sections=True`, reusing that scratch and descriptor parser.
Count/entry callbacks and indices offset by imports match; definitions do not
increment import counts. The sample has no real sections 4/5. Six compositions
add synthetic definitions to fresh ELF function/global input; the full selected
composition matches 306 callbacks per base. See [section 4/5 evidence](evidence/vm9_alternative_reader_table_memory_sections_fresh_20261008.json).
Signed i64 adds 1480 comparisons/10 rollback checks; section 6 and initializers
add 390 comparisons/26 rollback checks, including ten fresh ELF global inputs.
Globals require the independent `enable_global_section=True` and a mapped,
aligned, disjoint 16-byte `global_scratch_address` with an explicit caller-local
seed. End-only retains its high word; i32 results zero-extend; opcode kinds
follow the actual GOT table pointer, with relocation/overrides checked. The
actual section has 22 definitions, and 1/2/3/6/7/12 matches 455 callbacks per base.
See the [global/initializer report](REQUEST_JNI_STARTUP_WORKERS.md#68-有符号-i64-与-section-6-初始化表达式2026-10-08-utc).
Section 10 adds 228 comparisons/15 rollback checks, including six actual ELF code
inputs. Its 121 bodies contain 54533 raw words; the full selected composition
matches 55351 callbacks per base. Use the independent `enable_code_section=True`;
`max_code_words` bounds all word callbacks, including native retries without cursor
progress. This reads words; instruction execution and actual AST remain open. See
the [code report](REQUEST_JNI_STARTUP_WORKERS.md#69-section-10-元数据局部类型与指令字读取2026-10-08-utc).
Sections 9/11 and their distinct +0x3215f0 expression helper add 450 comparisons,
33 rollback checks and 16 native abort boundary checks. Six controls contain
actual ELF data (three segments); full 1/2/3/6/7/12/10/11 matches 55369 callbacks
per base. Each section requires its own opt-in and an eight-byte expression
scratch region. Section 9 supports empty element vectors; nonempty vectors reach
native abort and remain unsupported. See the
[segment report](REQUEST_JNI_STARTUP_WORKERS.md#610-section-911-与独立-expression-helper2026-10-08-utc).
Section 0 special custom handlers add 860 comparisons and 32 rollback checks,
including ten actual ELF custom controls. All actual sections, including three
custom payloads, match 55369 callbacks per base. Enable these metadata parsers
with `enable_special_custom_sections=True`, an independent eight-byte
`custom_scratch_address` and `max_custom_records=4096` per custom section.
Subsection limits and the custom flag are restored on parse failure. See the
[custom report](REQUEST_JNI_STARTUP_WORKERS.md#611-section-0-特殊-custom-元数据2026-10-08-utc).
Actual type/start/local group count/raw-word callbacks and temporary callback cleanup
add 308 native/Python comparisons and 54 rollback checks, including 32 actual
ELF type inputs. Actual vtables run naturally; node bytes, pointer publication,
allocation/destruction/free ordering and owner state at every effect match.
The five callback slots are +18/+20/+a0/+b0/+168; cleanup covers five reverse
node lists, two bounded trees and a byte buffer. These separate APIs require a
detached callback and empty unrecovered output containers. Parser composition,
other AST callbacks and wrapper cleanup remain open. See the
[AST/cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#612-实际-ast-callback-与临时清理2026-10-09-asiashanghai).
Slot +160 subsequently adds 176 comparisons and 30 rollback checks for
176-byte data record reserve/move and the +2cc1ec non-deleting destructor.
All fixtures are synthetic and run at two bases. Nested vectors transfer,
destination padding remains intact, and publication/destruction/free match.
Data storage at output+f0 is now validated in the shared ownership graph;
record creation and attached parser composition remain open. See the
[data reserve/destructor report](REQUEST_JNI_STARTUP_WORKERS.md#613-data-record-容量预留搬移与析构2026-10-09-asiashanghai).
Allocation/free remain explicit services;
complete AST construction and complete Python reader remain open. Independent Medusa, fresh
signatures and online acceptance remain unfinished. See [the startup/worker
report](REQUEST_JNI_STARTUP_WORKERS.md) and [VM9_PROGRESS.md](VM9_PROGRESS.md).
Older observations below are historical.

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

### 原始 JNI 与同次默认 worker 的后续检查点

原有 A 原始启动/六个 caller/wait-stop 控制回归通过；新增 2 个同次 TLS cleanup、
2 个 guest joinable exit 观察，实际 support 清零及三次 free/poison 通过。B 新增两个
原始 constructor/factory 自然返回与 121 个 descriptor 发布观察，另 242 个 Python
lookup 控制使用 native 生成 root。另 82 个独立 XOR prefix 控制和 8 个回滚通过，
仍停在 reader 前。Python factory / 完整 bootstrap 对照仍 0，真实 OS
线程与独立签名链仍待完成。详见 [后续报告](REQUEST_JNI_STARTUP_WORKERS.md)。
