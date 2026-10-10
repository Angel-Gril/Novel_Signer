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
通过，仍停在 reader 前；另两次 actual reader 在 Python XOR 输入下返回 0；
当时完整 Python reader AST 对照为 0。独立 u32 原语新增 258 个对照/7 个回滚；有符号 i32 原语另通过
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
要求独立八字节工作区和每段记录预算。全量 AST 和完整 reader 仍未恢复。
实际 type/start/local group 数量/raw-word 五个 callback 与临时 callback 清理又通过
**308 个原生/Python 对照、54 个回滚**，含 32 项真实 ELF 类型输入。原生实际
vtable 执行，核对节点内容、分配/析构/free 顺序与每个副作用时的容器状态。
随后恢复 slot `+160` 的 176 字节 data record 容量预留、反向搬移和 `+2cc1ec`
非 deleting 析构：新增 **176 个对照、30 个回滚**，合成输入在两个基址均通过。
嵌套 vector 转移、目标 padding、发布和倒序释放一致。
随后 slot `+140` 的 data record 创建与追加通过 **148 个对照、105 个回滚**；
内嵌结果 sentinel、u32 截断、扩容发布和临时释放与原生一致，全部输入合成。
随后 slot `+158` 的 payload 写入与 parser length 参数修复通过 **104 个 AST 对照、
34 个参数对照、30 个回滚**，含 6 项实际 ELF payload 与 2 项实际 section 输入。
零长度保留原 payload；非零写入最后记录，扩容发布和释放顺序与原生一致。
随后 slot `+148/+150` 的 data expression frame、u32 修补和树节点删除通过
**148 个对照、36 个回滚**，全部输入合成。保存原始字节长度、左右旋转、释放顺序
及连续删除与原生一致；树 payload 的检查宽度修正为 4 字节。
随后 slots `+f0/+100/+108/+110/+118` 的零字、element 容量预留/创建/表达式
通过 **282 个对照、159 个回滚**；184 字节记录、144 字节嵌套记录的搬移和
倒序清理与原生一致，全部输入合成。复用同一 frame/raw/tree owner。
随后 slots `+120/+128/+130/+138` 的 element 结果类型、嵌套容量预留和
表达式创建/结束通过 **230 个对照、133 个回滚**；完整 u64 类型值、144 字节
记录的转移/释放和连续创建扩容与原生一致。六组旧回归 JSON 逐字节一致。
随后 slots `+c0/+c8/+d0/+d8/+e0/+e8` 的 instruction predicate、结束和
四种带类型常量通过 **398 个对照、122 个回滚**。返回 0/1、保留最外层 frame、
tag/数值分步扩容与原始浮点位一致；七组旧回归 JSON 逐字节一致。
随后 slots `+b8/+f8` 在已有 144 字节布局上追加 local group、结束并保存长度，
通过 **252 个对照、37 个回滚**。完整 u64 类型、u32 累计回绕、扩容与释放一致；
八组旧回归 JSON 逐字节一致。
随后 `+50` 恢复 function 创建、独立类型缓存与 144 字节记录清理，通过
**188 个对照、136 个回滚**。输出与缓存分别深拷贝类型，扩容、padding 和
析构顺序与原生一致；九组旧回归 JSON 逐字节一致。
随后 `+a8` 恢复 code-begin、双修补树处理和 56 字节 child 追加，通过
**284 个对照、100 个回滚**。logical function 选择、metadata、raw 起点、frame、
padding 与扩容释放一致；十组旧回归 JSON 逐字节一致。
随后 table `+58/+60` 恢复容量预留、48 字节记录与独立缓存，通过
**184 个对照、77 个回滚**。实际入口栈提供被复制的 padding；guest 字节没有
屏蔽，十一组旧回归 JSON 逐字节一致。
随后 memory `+68/+70` 恢复 40 字节记录、完整 descriptor 与独立缓存，通过
**272 个对照、65 个回滚**。两种默认 maximum、目标 padding 和搬移/析构
与原生一致；十二组旧回归 JSON 逐字节一致。
随后 global `+78/+80` 恢复 176 字节记录、24 字节独立缓存与记录析构，通过
**328 个对照、120 个回滚**。完整 type、mutable 低位、vector 转移与清理
顺序一致；十三组旧回归 JSON 逐字节一致。
随后 global expression `+88/+90` 恢复 frame、raw fixup 与完整 64 位 end，
并支持 global 内联 AST 的 local/结束回调，通过 **212 个对照、54 个回滚**；
十四组旧回归 JSON 逐字节一致。
AST 字符串复制基础另通过 **68 个对照、12 个回滚**，供后续 import/export 回调复用。
见 [字符串复制报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#627-ast-字符串复制基础2026-10-10-asiashanghai)。
Export AST 回调、五类节点克隆/删除与仅含 export 的输出清理另通过
**362 个对照、247 个回滚**，16 组旧回归 JSON 逐字节一致。
见 [export 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#628-export-ast-回调与专属输出清理2026-10-10-asiashanghai)。
五类 Import AST 回调与仅含 import 的输出清理另通过 **858 个对照、410 个回滚**；
17 组旧回归 JSON 逐字节一致。
见 [import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#629-import-ast-回调与专属输出清理2026-10-10-asiashanghai)。
完整 output wrapper 清理另通过 **330 个对照、214 个回滚**；旧 import/export 两组回归逐字节一致。
见 [output 清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#630-完整-output-wrapper-清理2026-10-10-asiashanghai)。
已贯通 generic/type/function/start/data-count 与空 export 的 attached parser/AST，
通过 **214 项对照、83 项回滚**；旧 section、AST/cleanup 两组 JSON 逐字节一致。
见 [module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#631-attached-parser-与有界-ast-module2026-10-10-asiashanghai)。
函数 import 的 heap 名称组合另通过 **180 项对照、43 项回滚**；默认关闭，
两名称均需至少 23 字节。旧 module/import 两组（1072/493）JSON 逐字节一致。
见 [函数 import module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#632-heap-名称函数-import-的-attached-ast-组合2026-10-10-asiashanghai)。
短名称/空名称和长短混用另通过 **448 项对照、64 项回滚**，需开启额外 inline
opt-in；恢复真实 caller helper 写入。旧 module/heap 两组（394/126）JSON
逐字节一致。见 [inline import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#633-inline-名称函数-import-与真实-caller-栈写入2026-10-10-asiashanghai)。
Table/memory/global 的长名称 attached import 另通过 **406 项对照、72 项回滚**，
恢复真实 descriptor、ABI 参数、AST 与 cache 清理；新开关默认关闭。旧三组
（842/190）JSON 逐字节一致；短名称的后续恢复见下方。
见 [其他 import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#634-tablememoryglobal-import-的-attached-ast-组合2026-10-10-asiashanghai)。
Table/memory/global 的短名称和空名称组合另通过 **612 项对照、41 项回滚**，
需开启额外 inline other-import 开关；恢复 caller padding，默认关闭。旧四组
（1,248/262）JSON 逐字节一致，完整 signer 仍未完成。
见 [短名称其他 import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#635-短名称其他-import-与-caller-栈传递2026-10-11-asiashanghai)。
Table/memory definitions 的实际 AST 组合另通过 **470 项对照、32 项回滚**，
新开关默认关闭，含 12 项 SP 移位、12 项高位 guest 和完整 record 检查。
八组旧回归（2,582/463）JSON 逐字节一致。
见 [definitions 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#636-tablememory-definitions-的-attached-ast-组合2026-10-11-asiashanghai)。
Global definitions 与初始化表达式的实际 AST 组合另通过 **398 项对照、37 项回滚**，
含 12 项 SP 移位、12 项高位 guest 与 780 个完整 global record 检查。
五组旧回归（1,614/315）JSON 逐字节一致。
见 [global module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#637-global-definitions-与初始化表达式的-attached-ast-组合2026-10-11-asiashanghai)。
Code definitions 的实际 AST 组合另通过 **256 项对照、42 项回滚**，
含 8 项完整实际 ELF body 对照、12 项 SP 移位、12 项高位 guest；
另有 8 项主动截停的原生观察确认短输入不前进，原始指令字只保存不执行。
四组旧回归（1,124/235）JSON 逐字节一致。
见 [code module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#638-code-definitions-的-attached-ast-组合2026-10-11-asiashanghai)。
完整实际 ELF 的 reader AST 已在两个基址通过：229328 字节输入、121 个
code bodies、54533 个 raw words、55369 次回调，input/guest/1 MiB heap/
effects/cleanup/globals 全量一致。本阶段共 **406 项对照、36 项回滚**；
前一版本的三组旧回归 **1502/99** JSON 逐字节一致，最终修复对其
实际执行范围的 AST 等价检查通过。见
[完整模块 reader AST 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#641-完整实际-module-的-reader-ast2026-10-11-asiashanghai)。
零条目 type 的 incoming X22、parse/root、factory/bootstrap 和 signer 仍未完成。见
[AST/清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#612-实际-ast-callback-与临时清理2026-10-09-asiashanghai)。
[Data reserve/析构报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#613-data-record-容量预留搬移与析构2026-10-09-asiashanghai)。
[Data 创建报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#614-data-record-创建与追加2026-10-09-asiashanghai)。
[Data payload 与 length 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#615-data-payload-写入与-parser-length-参数修复2026-10-09-asiashanghai)。
[Data expression 与树删除报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#616-data-expression-frameu32-修补与树节点删除2026-10-09-asiashanghai)。
[Element 回调与清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#617-element-回调与嵌套记录清理2026-10-09-asiashanghai)。
[Element 嵌套表达式报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#618-element-结果类型与嵌套表达式2026-10-09-asiashanghai)。
[Instruction 与常量报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#619-instruction-predicate-与带类型常量2026-10-09-asiashanghai)。
[Local group 与结束报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#620-local-group-与函数结束回调2026-10-09-asiashanghai)。
[Function 创建与清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#621-function-创建类型缓存与清理2026-10-09-asiashanghai)。
[Code-begin 与修补树报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#622-code-begin双修补树与-child-追加2026-10-09-asiashanghai)。
[Table 与栈 padding 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#623-table-预留创建与显式栈-padding2026-10-09-asiashanghai)。
[Memory 与独立缓存报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#624-memory-预留创建与独立缓存2026-10-09-asiashanghai)。
[Global 与记录清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#625-global-预留创建与记录清理2026-10-09-asiashanghai)。
[Global expression 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#626-global-expression-与内联-ast-回调2026-10-10-asiashanghai)。
真实 OS 线程/allocator、独立 Medusa 与 fresh 签名仍未完成，
完整 Python bootstrap 对照仍为 **0**。详见
[原始 JNI 与同次 worker 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md)。
