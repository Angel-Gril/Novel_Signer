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
零条目 type 的 incoming X22 现已恢复，新增 **198 项对照、9 项回滚**；
同一最终版另通过 **36/77** 关联回归，包含两个完整实际 module。见
[零条目 type 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#642-零条目-type-与-incoming-x222026-10-11-asiashanghai)。
parse 指令格式转换已恢复，**434 项对照、10 项拒绝检查**通过。见
[parse codec 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#643-parse-指令格式转换2026-10-11-asiashanghai)。
parse 模块转换通过 **170 项对照、25 项回滚检查**，其中 4 项完整实际 ELF
每次匹配 139 个函数、54533 个 decoded words。见
[parse conversion 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#644-parse-模块转换与-builtin-catalog2026-10-11-asiashanghai)。
converted module 清理通过 **146 项对照、21 项回滚检查**。见
[converted cleanup 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#645-converted-module-清理2026-10-11-asiashanghai)。
instruction builder catalog 初始化通过 **40 项对照、22 项回滚检查**。见
[builder catalog 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#646-instruction-builder-catalog2026-10-11-asiashanghai)。
decoded instruction 构造通过 **116422 次原生对照、24 项回滚检查**，
含两份完整实际模块的全部指令。见
[runtime builder 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#647-decoded-instruction-运行时构造2026-10-11-asiashanghai)。
runtime 二次转换/root linking 通过 **3918 个 descriptor 对照、27 项回滚检查**，
覆盖全部 600 种副表规则。见 [runtime linking 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#648-runtime-descriptor-二次转换与-root-linking2026-10-11-asiashanghai)。
defined descriptor 构造与失败清理通过 **288 个原生对照、35 项回滚检查**，
含两份实际模块全部 109066 条指令。见 [defined descriptor 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#649-defined-descriptor-构造与失败清理2026-10-11-asiashanghai)。
builtin function catalog 通过 **32 个原生对照、198 个哈希对照、34 项检查**，
恢复 73 项名称/函数绑定。见 [builtin catalog 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#650-builtin-function-catalog-与名称哈希2026-10-11-asiashanghai)。
imported descriptor 通过 **106 个原生对照、36 项回滚检查**，
含两份 fresh 模块的全部 36 项函数导入。见 [imported descriptor 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#651-imported-descriptor-解析与构造2026-10-11-asiashanghai)。
root 构造通过 **62 个原生对照、34 项回滚检查**，
含两份实际模块的 278 个描述符、109066 条指令。见 [root 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#652-root-构造全局数据搬移与运行时链接2026-10-11-asiashanghai)。
factory 独立组合通过 **26 个原生对照、38 项回滚检查**。见 [factory 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#653-factory-独立组合与两层清理2026-10-11-asiashanghai)。
构造器通过 **2 份完整原生对照、22 项回滚检查**，242 个描述符发布槽一致。见 [构造器报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#654-构造器输入生成与描述符发布2026-10-11-asiashanghai)。
B 有界运行时通过 **48 项执行、6 项初始化、27 项回滚检查**。见 [运行时报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#655-b-运行状态与有界描述符执行2026-10-11-asiashanghai)。
共享 B callable 通过 **84 项原生对照、12 项回滚检查**，含52项A/queue回归。见 [callable 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#656-b-callable-的共享移动与清理2026-10-11-asiashanghai)。
B 主线程 startup 与两类真实导入回调通过 **28 项原生对照、41 项回滚检查**；每次19次分发、3个延后执行的线程请求、22项有序效果匹配。见 [startup 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#657-b-主线程-startup-与真实导入回调2026-10-11-asiashanghai)。
B worker 调用程序的指令扩展通过 **112 项 runtime 对照、4 项 startup 回归、40 项回滚检查**；实际 worker descriptor 使用显式导入 provider。见 [worker runtime 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#658-b-worker-的分支与组合指令2026-10-11-asiashanghai)。
B worker 完整算术与 CAS/memset 通过 **310 项 runtime 对照、30 项 builtin 对照、4 项 startup 回归、69 项回滚检查**；24项实际嵌套程序执行真实 memset 回调。见 [worker arithmetic 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#659-b-worker-完整算术与内存内置函数2026-10-11-asiashanghai)。
共享 once 已接入 B 六个控制字，**60 项原生对照、22 项回滚检查**通过；含24项A回归。见 [共享 once 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#660-b-复用共享-once-状态机2026-10-11-asiashanghai)。
B完整callable已恢复六个外层及48个嵌套程序，**18 项原生对照、36 项回滚检查**通过；每次cold任务120847次分发、6分配、6唤醒。见 [完整 callable 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#661-b-完整-worker-callable-与嵌套初始化2026-10-11-asiashanghai)。
B同次startup队列worker、TLS key清理及完整guest pthread_exit通过 **12 项原生对照、24 项回滚检查**。见 [队列与清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#662-b-同次-startup-的队列-worker-与清理2026-10-11-asiashanghai)。
另外四个ELF module constructor通过 **8 项原生对照、2 项原B回归、77 项回滚检查**，复用同一factory。见 [constructor报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#663-另外四个-elf-module-constructors2026-10-11-asiashanghai)。
六个ELF support constructor通过 **48 项原生对照、51 项回滚检查**，累计覆盖11/13个init_array入口。见 [ELF支持报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#664-六个-elf-support-constructors2026-10-11-asiashanghai)。
ELF guarded string constructor通过 **18 项原生对照、25 项回滚、12 项既有入口回归**，累计覆盖12/13个init_array成员。见 [guard报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#665-elf-guarded-string-constructor2026-10-11-asiashanghai)。
ELF configuration constructor通过 **16 项原生对照、72 项回滚**，既有 registry **38/14** 结果逐字节一致；13/13个init_array成员已有独立实现，完整顺序加载待验。见 [配置报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#666-elf-configuration-constructor2026-10-11-asiashanghai)。
完整13项init_array顺序组合通过 **4项原生对照、40项回滚**；共享堆/TLS/全局状态和全部存活页面匹配。完整二进制加载/链接待验。见 [顺序组合报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#667-elf-init_array-完整顺序组合2026-10-11-asiashanghai)。
完整样本ELF映射/符号链接通过 **10项映射对照、2项完整构造序列、42项拒绝**；990页与18481项重定位一致。见 [ELF加载报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#668-elf-映射与完整符号链接2026-10-11-asiashanghai)。
完整ELF构造→JNI→条件主线程startup通过 **4项原生对照、38项回滚**；finalizer callable另有32/9项检查。见 [完整JNI报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#669-完整-jni-与两条主线程-startup-组合2026-10-11-asiashanghai)。
同次executor/初始化queue与guest退出通过 **4项对照、28项回滚**。见 [完整worker报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#670-完整-jni-后的两条-worker-与-guest-退出清理2026-10-11-asiashanghai)。
Finalizer延时提交通过 **8项对照、24项callable、25项回滚**。见 [延时报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#671-jni-finalizer-的首条延时任务提交2026-10-11-asiashanghai)。
三条worker及完整guest退出通过 **4项完整对照、4项copied probe、47项回滚**。见 [finalizer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#672-jni-finalizer-完整-worker-与-guest-退出2026-10-11-asiashanghai)。
实际延时callback与两段image VM通过 **4项完整对照、22项页面回滚**。见 [延时回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#673-实际延时-jni-callable-与两段-image-vm2026-10-11-asiashanghai)。
实际timed poll、转交与queue清理通过 **4项完整对照、20项页面回滚**。见 [timed转交报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#674-实际-timed-poll转交与-queue-清理2026-10-11-asiashanghai)。
三条worker协作等待、到期转交与完整退出通过 **4项完整对照、23项页面回滚**。见 [协作worker报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#675-三条-worker-协作等待转交与完整退出2026-10-11-asiashanghai)。
Java byte array转引用通过 **52项原生/Python对照、19项回滚**，见 [byte array报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#676-java-byte-array-转引用与实际诊断锁2026-10-11-asiashanghai)。
JNI引用字段、无参数方法和清理通过 **74项对照、18项回滚**，见 [JNI引用报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#677-jni-引用字段无参数方法与引用清理2026-10-11-asiashanghai)。
实际reference作用域与MD5生命周期通过 **80项对照、16项回滚**，见 [作用域报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#678-实际-reference-作用域与-md5-生命周期2026-10-11-asiashanghai)。
已初始化对象的live lookup通过 **48项对照、11项回滚**，见 [live lookup报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#679-已初始化对象的实际-live-java-lookup2026-10-11-asiashanghai)。
cold encoded SDK及其live lookup组合通过 **62项对照、13项回滚**，见 [cold SDK报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#680-cold-encoded-sdk-getter-与实际-live-lookup2026-10-11-asiashanghai)。
带整型/引用参数的JNI方法和静态字段通过 **140项对照、11项回滚**，见 [JNI member报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#681-带整型引用参数的-jni-方法与静态字段2026-10-11-asiashanghai)。
实际UTF构造及Java service查找通过 **42项对照、9项回滚**，见 [Java service报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#682-实际-utf-构造与-java-service-查找2026-10-12-asiashanghai)。
实际live initializer及cold lookup通过 **92项对照、6项回滚**，见 [initializer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#683-实际-live-initializer-与-cold-lookup2026-10-12-asiashanghai)。
VM/callable/worker live服务接线通过 **6项原生对照、2项worker入口检查、16项回滚**，见 [provider报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#684-delayed-vmcallableworker-的-live-provider-接线2026-10-12-asiashanghai)。
实际request stack evaluator通过 **78项对照、1项请求VM入口检查、20项回滚**，见 [evaluator报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#685-实际-request-stack-evaluator-与请求-vm-接线2026-10-12-asiashanghai)。
实际boolean scope清理通过 **46项对照、1项请求VM入口检查、28项回滚**，见 [scope报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#686-实际-boolean-scope-清理与-elapsed-event2026-10-12-asiashanghai)。
实际JNI发布器与byte gate通过 **44项对照、1项请求入口检查、20项回滚**；请求到1019步，见 [发布器报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#687-实际-jni-发布器与请求-byte-gate2026-10-12-asiashanghai)。
实际请求对象构造通过 **60项对照、1项请求入口检查、34项回滚**；请求到1419步，见 [请求对象报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#688-实际请求对象构造与临时引用生命周期2026-10-12-asiashanghai)。
实际registry计数通过 **40项对照、1项请求入口检查、36项回滚**；请求到1444步，见 [计数报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#689-实际-registry-计数回调与拥有者-tls-接线2026-10-12-asiashanghai)。
实际树与iterator ABI通过 **24项对照、1项请求入口检查、13项回滚**；请求到1539步，见 [iterator报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#690-实际请求树构造与-iterator-abi2026-10-12-asiashanghai)。
进程析构导入与注册通过 **16项对照、1项请求入口检查、17项回滚**；请求到1558步，见 [注册报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#691-实际进程析构导入与注册2026-10-12-asiashanghai)。
填充字符串与wrapper通过 **40项对照、1项请求入口检查、20项回滚**；请求到1567步，见 [填充报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#692-实际填充字符串构造与-wrapper-字节参数2026-10-12-asiashanghai)。
树查询与C-string wrapper通过 **28项对照、1项请求入口检查、20项回滚**；请求到1812步，见 [collection报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#693-实际树查询与-c-字符串长度-wrapper2026-10-12-asiashanghai)。
guest table比较通过 **48项对照、1项请求入口检查、26项回滚**；请求到1995步，见 [比较报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#694-实际-guest-table-折叠比较与-singleton-接线2026-10-12-asiashanghai)。
树计数、value清理与iterator遍历通过 **128项对照、1项请求入口检查、40项回滚**；请求到2321步，见 [树遍历报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#695-请求树计数与-value-清理和-iterator-遍历2026-10-12-asiashanghai)。
局部树析构通过 **32项对照、1项请求入口检查、27项回滚**；请求到2329步，见 [局部树析构报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#696-请求局部树析构2026-10-12-asiashanghai)。
请求后续清理通过 **78项对照、1项入口检查、36项回滚**；空header/NULL JNI输入的VM在2475步返回，见 [请求清理与VM返回报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#697-请求对象与树删除清理和-vm-返回2026-10-12-asiashanghai)。
请求scoped tree构造通过 **24项对照、1项入口、31项回滚**，见 [scoped tree报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#698-请求-scoped-tree-reference-构造2026-10-12-asiashanghai)。
VM load/compare-store修复通过 **114项对照、1项入口、21项拒绝/回滚**，见 [VM load/store报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#699-vm-load-与串行-comparestore2026-10-12-asiashanghai)。
caller物理返回恢复通过 **16项原生对照、1项入口、26项拒绝**；25项全部页面不变，canary入口的新增分配映射保留。见 [caller返回报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6100-request-caller-物理返回2026-10-12-asiashanghai)。
NULL raw cleanup修复通过 **16项新增对照、6项回滚**；构造请求的105次有效packed输入、10次服务与物理返回一致。见 [整链有效字段报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6101-null-raw-cleanup-与整链有效字段2026-10-12-asiashanghai)。
ASCII case与request byte flag通过 **92项新增对照、8项回滚**；构造非空请求推进到2174步，尚未完成JNI输入转换。见 [ASCII/byte flag报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6102-ascii-case-与-request-byte-flag2026-10-12-asiashanghai)。
Byte search通过 **80项新增对照、12项回滚、8项扫描上限检查**；构造非空请求推进到2224步。见 [byte search报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6103-request-byte-search2026-10-12-asiashanghai)。
定长字符串请求分发通过 **18项新增对照、10项回滚**；构造非空入口推进到2243步，拒绝时保留64个新增allocator OS页。见 [sized dispatch报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6104-request-sized-string-dispatch2026-10-12-asiashanghai)。
二进制相等判断通过 **48项新增对照、8项回滚**，含16项actual libc memcmp；构造非空入口推进到2395步。见 [binary equality报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6105-request-binary-equality2026-10-12-asiashanghai)。
构造非空请求2395步的 **98次回调路径与有效packed输入** 与原native全部一致；substring body与完整非空等价仍未完成。见 [非空ABI报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6106-constructed-nonempty-request-effective-abi2026-10-12-asiashanghai)。
Field clone/substring通过 **74项新增对照、20项回滚**；构造非空入口推进到2510步。见 [substring报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6107-field-clone-与-substring2026-10-12-asiashanghai)。
CString/StringObject拼接与清理通过 **84项新增对照、28项回滚**；构造非空入口推进到2520步。见 [组合报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6108-cstringstringobject-拼接2026-10-12-asiashanghai)。
StringObject/CString构造通过 **68项新增对照、24项回滚**；非空入口在2520步遇到未恢复的matching-libc realloc。见 [对象/CString报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6109-stringobjectcstring-构造2026-10-12-asiashanghai)。
Matching-libc同类别realloc通过 **18项新增对照、28项回滚**；非空入口推进到2538步，下一StringObject搜索回调待恢复。见 [同类别realloc报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6110-matching-libc-同类别-realloc2026-10-12-asiashanghai)。
StringObject ASCII casefold搜索通过 **72项新增对照、20项回滚**；非空入口推进到2590步。见 [casefold搜索报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6111-stringobject-ascii-casefold-搜索2026-10-12-asiashanghai)。
StringObject ASCII CString pattern搜索通过 **76项新增对照、24项回滚**；非空入口推进到2761步。见 [CString搜索报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6112-cstring-pattern-搜索2026-10-12-asiashanghai)。
VM signed64乘法与低半部读取通过 **238项新增对照**；非空入口推进到2850步。见 [signed product报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6113-vm-signed-product-与-low-copy2026-10-12-asiashanghai)。
状态numeric member读取通过 **60项新增对照、18项回滚**；request state callback仍待接入。见 [state numeric报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6114-state-numeric-member-读取2026-10-12-asiashanghai)。
Lazy state service通过 **8项新增对照、7项回滚**，前置singleton136已初始化。见 [state service报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6115-lazy-state-service2026-10-12-asiashanghai)。
实际request state构造通过 **16项新增对照、7项回滚**；非空入口推进2911步。见 [request state报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6116-request-state-构造与清理2026-10-12-asiashanghai)。
实际request elapsed getter通过 **36项新增对照、12项回滚**；非空入口推进3167步。见 [request elapsed报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6117-request-elapsed-seconds2026-10-12-asiashanghai)。
实际request reference copy/hash64通过 **84项新增对照、6项回滚**；非空入口推进3257步。见 [request reference/hash报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6119-request-stringobject-table-hash642026-10-12-asiashanghai)。
实际request TLS读写通过 **34项新增对照**；非空入口推进3307步。见 [request TLS报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6120-request-tls-uint32-读写2026-10-12-asiashanghai)。
实际request binary transform组件通过 **24项新增对照、10项回滚**，外层caller仍待恢复。见 [transform报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6121-request-binary-transform2026-10-12-asiashanghai)。
实际request hex reference通过 **20项新增对照、8项回滚**；外层caller继续恢复。见 [hex报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6122-request-hexadecimal-reference2026-10-12-asiashanghai)。
原始MD5与scoped reference assignment通过 **54项新增对照、12项回滚**；外层getter和格式化继续恢复。见 [raw MD5报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6123-request-raw-md5-and-reference-assignment2026-10-12-asiashanghai)。
版本word getter通过 **40项新增对照、10项回滚**；外层两遍格式化继续恢复。见 [version报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6124-request-version-word2026-10-13-asiashanghai)。
两遍allocated printf通过 **36项新增对照、9项回滚**；外层组合与cleanup继续恢复。见 [allocated printf报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6125-request-allocated-printf2026-10-13-asiashanghai)。
外层suffix及raw free通过 **32项新增对照、11项回滚**；非空入口推进至3405步，继续恢复287168。见 [suffix报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6126-request-outer-suffix-and-raw-free2026-10-13-asiashanghai)。
metadata与unsigned printf通过 **46项新增对照、12项回滚**；非空入口推进至3520步。见 [metadata报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6127-request-metadata-formatting2026-10-13-asiashanghai)。
Base64 encode通过 **68项新增对照、10项回滚**；非空入口推进至3538步。见 [Base64报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6128-request-base64-encoder2026-10-13-asiashanghai)。
单byte StringObject通过 **30项新增对照、7项回滚**；入口推进至3550步。见 [character报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6129-request-character-string2026-10-13-asiashanghai)。
右端character-set trim通过 **64项新增对照、9项回滚**；入口推进至3559步。见 [right-set报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6130-request-right-character-set-trim2026-10-13-asiashanghai)。
左端character-set trim通过 **94项新增对照、11项回滚**；入口推进至3767步。见 [left-set报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6131-request-left-character-set-trim2026-10-13-asiashanghai)。
嵌套token VM caller与两次decode通过 **20项新增对照、8项回滚**，内层179步，下一random getter。见 [token VM报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6132-request-token-vm-caller-and-prefix2026-10-13-asiashanghai)。
random state、getter和actual consumer通过 **98项新增对照、15项回滚**。见 [random报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6133-request-random-state-and-getter2026-10-13-asiashanghai)。
嵌套random与actual外层consumer接线通过 **12项新增对照、5项回滚**，下一shared reader。见 [nested random报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6134-request-nested-random-continuation2026-10-13-asiashanghai)。
嵌套shared-reader consumer通过 **28项新增对照、7项回滚**，下一diagnostic scope。见 [nested readers报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6135-request-nested-shared-readers2026-10-13-asiashanghai)。
嵌套diagnostic consumers通过 **16项新增对照、5项回滚**，内层推进至231步。见 [nested scopes报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6136-request-nested-diagnostic-scopes2026-10-13-asiashanghai)。
嵌套string生命周期通过 **36项新增对照、8项回滚**，内层推进至287步。见 [nested lifecycle报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6137-request-nested-string-lifecycle2026-10-13-asiashanghai)。
嵌套string transforms通过 **46项新增对照、10项回滚**，内层推进至321步。见 [nested strings报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6138-request-nested-string-transforms2026-10-13-asiashanghai)。
嵌套scoped MD5通过 **32项新增对照、8项回滚**，内层推进至422步。见 [nested MD5报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6139-request-nested-scoped-md52026-10-13-asiashanghai)。
request轮密钥/分组helper通过 **32项新增对照、8项回滚**；caller待恢复。见 [round/block报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6140-request-round-schedule-and-block-helpers2026-10-13-asiashanghai)。
request cipher caller通过 **48项新增对照、10项回滚**；owning cross-bin realloc待恢复。见 [cipher caller报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6141-request-allocated-and-string-cipher-callers2026-10-13-asiashanghai)。
cross-bin realloc通过 **18项新增对照、9项回滚**，owning内层推进至430步。见 [cross-bin报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6142-matching-libc-cross-bin-small-realloc2026-10-13-asiashanghai)。
append/Base64 reference通过 **34项新增对照、8项回滚**，内层推进至505步。见 [append/Base64报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6143-request-nested-append-and-base64-reference2026-10-13-asiashanghai)。
nested printf通过 **36项新增对照、10项回滚**，内层推进至574步的return。见 [nested printf报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6144-request-nested-allocated-printf2026-10-13-asiashanghai)。
nested caller return通过 **32项新增对照、10项回滚**，owning外层推进至3879步。见 [nested return报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6145-request-nested-caller-return2026-10-13-asiashanghai)。
URL条件通过 **40项新增对照、7项回滚**，外层推进至3900步。见 [URL条件报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6146-request-url-condition2026-10-13-asiashanghai)。
第二VM caller/prefix通过 **20项新增对照、8项回滚**，owning内层推进至617步。见 [第二VM报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6147-request-second-vm-caller-and-prefix2026-10-13-asiashanghai)。
第二VM consumers通过 **153项新增原生对照、12项回滚**，owning第二VM推进至8184步。见 [second consumer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6148-request-second-vm-consumers2026-10-13-asiashanghai)。
child VM caller/prefix通过 **26项新增原生对照、10项回滚**，owning child推进至290步。见 [child VM报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6149-request-child-vm-caller-and-prefix2026-10-13-asiashanghai)。
child VM四个实际consumer通过 **83项新增原生对照、13项回滚**，owning child推进至19295步并完成有界原生差分。见 [child consumer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6150-request-child-vm-consumers2026-10-13-asiashanghai)。
environment helper caller/prefix通过 **33项新增原生对照、11项回滚**，owning helper推进至134步并完成有界原生差分。见 [environment helper报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6151-request-environment-helper-vm-callers-and-prefixes2026-10-14-asiashanghai)。
实际environment acquisition callback通过 **17项新增原生对照、6项回滚**，owning helper推进至214步。见 [environment acquisition报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6152-request-environment-acquisition-callback2026-10-14-asiashanghai)。
实际environment StringObject callbacks通过 **39项新增原生对照、9项回滚**，owning helper推进至226步。见 [StringObject报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6153-request-environment-stringobject-callbacks2026-10-14-asiashanghai)。
实际environment logger通过 **13项新增原生对照、9项回滚**，owning helper完成日志与清理并到262步VM退出边界。见 [logger报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6154-request-environment-logger-and-cleanup2026-10-14-asiashanghai)。
environment helper return通过 **53项新增原生对照、8项回滚**，child推进至19302步、下一204B80 JNI。见 [helper return报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6155-request-environment-helper-return2026-10-15-asiashanghai)。
204B80共享JNI语义通过 **32项新增原生对照、10项回滚**，保留finalizer既有行为。见 [availability报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6156-jni-static-method-availability2026-10-15-asiashanghai)。
实际availability wrapper通过 **26项新增原生对照、9项回滚**，返回值/声明保存帧/packed一致。见 [wrapper报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6157-jni-availability-wrapper2026-10-15-asiashanghai)。
child availability接线通过 **1项新增原生对照、6项入口拒绝**，child推进至19470步、下一2814E4环境获取。见 [child callback报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6158-child-jni-availability-callback2026-10-15-asiashanghai)。
child environment新增 **17项原生对照**，推进至19533步、下一28155C字符串构造。见 [child environment报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6159-child-environment-acquisition2026-10-15-asiashanghai)。
完整signer仍未完成。见
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
