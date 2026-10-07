新增直接 handoff 证据：`evidence/vm9_descriptor_branch_handoff_fresh_20261006.json`。
它在 fresh descriptor/reader 对象上实测 `+0x2584b8` 的 `ldp/mov/br`，并对
`+0x32a444/+0x32a4fc` 完成 16 组 native/Python 差分。这只证明当前有界 root
VM 使用的直接 branch ABI；`+0x2584ac` pre-dispatch、packed callback object、
完整当前 Medusa 和线上矩阵仍未完成。

新增一条可复核证据：`evidence/vm9_descriptor_target_roles_fresh_20261006.json`
直接在 fresh guest 页上调用 active writer 生成的 `+0x32a444/+0x32a4fc`，16
组控制全部通过；它证明的是 shared-reader 函数本身及其 mutex/count 语义，
不是完整 descriptor trampoline、callback object、当前 Medusa 或线上签名。
旧偏移 `+0x31e444/+0x31e4fc` 已明确标记为 superseded。

# 番茄（ByteDance Tomato）完整分析与使用报告

> 截止：2026-10-07
> 结论：**本项目整体尚未完成，不能作为当前线上小说搜索下载器发布。**

这份报告把已经获得的接口、签名、解密、运行时和证据边界集中到一处。它是研究归档和后续开发的使用说明，不把桥接实验、旧快照复现或捕获状态回放描述成独立的线上实现。

2026-10-07 最新JNI检查点：actual dispatcher/异常/TLS组合54个对照、10个负控制，
Long转换34个对照、11个负控制通过。另两条同次原始JNI_OnLoad自然执行dispatcher，
四次GetEnv后停在+270854前；once仍1，正确cache mutex/class/method地址仍全0。
Long组件使用显式已构造cache mutex，不能拼接成原始入口已完成Long/once的证据。
下一处是mutex构造/发布来源，再接回同次fresh启动。完整bootstrap、fresh签名、
线上矩阵、Rust和下载产品仍未完成。见 [REQUEST_JNI_DISPATCH.md](REQUEST_JNI_DISPATCH.md)。

2026-10-07 此前cold switch前缀观察：另两条原始JNI_OnLoad在同次执行中经过
实际TLS获取，到达+26e70c前；三次GetEnv、六个显式allocator请求，once仍1。
线程TLS slot从空开始，subsystem globals/OS keys、JNI服务和136/320reference
仍为显式输入；没有完整Python bootstrap对照，没有执行dispatcher旧stub。
下一处为实际JNI dispatcher及+270854转换，完整signer/线上/下载产品仍未通过。
见 [JNI初始化报告第6节](REQUEST_JNI_INITIALIZATION.md#6-后续原始-cold-switch-initializer-已经经过-tls-获取)。

2026-10-07 此前 JNI dispatch 初始化检查点：56个原生/Python对照、9个负控制，
恢复 `+0x26e19c/+0x26f154` 的ELF解码、注册尝试、方法ID和类引用发布；四个
publication→初始化同次组合通过。另有六个原始JNI_OnLoad探针：四个使用
warm switch once状态停在两个startup入口，两个保留cold switch并经matching
libc mutex到达TLS获取调用前 `+0x26edc4`。cold once仍为1，未完成初始化。
完整Python bootstrap/真实Android JVM、fresh签名和产品均未通过。下一处为
cold switch的TLS/JNI getter，再继续实际startup。详见
[REQUEST_JNI_INITIALIZATION.md](REQUEST_JNI_INITIALIZATION.md)。

2026-10-07 此前JavaVM发布检查点：54个原生/Python对照、11个负控制，恢复
`+0x271998 → +0x27be88` 的VM发布、caller编码/恢复和实际live X6 spill；六个
同次原生调用的publication→TLS获取组合通过。另有四个原始JNI_OnLoad探针：
warm依赖fixture下GetEnv失败返回-1，成功后真实publisher执行并停在+27bca0。
这些探针未验证Python完整bootstrap；GetEnv/pthread/clock等服务仍为显式输入。
下一处为+26e19c及其后的实际startup/JNI服务。当前owning session保持957返回/
965缺少JavaVM拒绝，fresh签名和产品仍未完成。详见
[REQUEST_JNI_PUBLICATION.md](REQUEST_JNI_PUBLICATION.md)。

2026-10-07 此前TLS/JavaVM环境获取检查点：新增40个原生对照/14个负控制，
关闭legacy acquisition stub，执行原始TLS、析构注册、GetEnv和attach/detach路径；
六个evaluator控制到达FindClass `+0x28b71c`调用前，环境和类名参数与原生一致。
JavaVM/pthread/分配仍为显式组件服务，真实Android JVM与完整JNI尚未验证。
同次owning session低基址保持957步返回；高基址保持965步，在恢复的acquisition
内部因 `+0x3deed8` 的JavaVM指针为0而停于attach `+0x26ef7c`，父事务未提交。
fresh Medusa、线上矩阵和下载产品仍未完成。详见
[REQUEST_JNI_ENVIRONMENT.md](REQUEST_JNI_ENVIRONMENT.md)。

2026-10-07 此前warm event发布检查点：新增40个原生控制/14个负控制，恢复
string所有权移动、非空record迁移、vector增长/200条丢弃和caller清理。
低基址同次owning session的合成请求模型在957/+ffb78返回，event record
增至2条，33次分配/18次free与输出引用通过；页状态已提交。高基址仍
965/+f8fd0的真实JNI获取。返回条件另由原生dispatcher/handler/ret控制验证，
不把解释器VMExit当作无条件成功。synthetic输出是tree reference，未生成
Medusa签名，whole-native request/真实URL/headers/JNI及线上矩阵仍未通过。
详见 [REQUEST_EVENT_EMISSION.md](REQUEST_EVENT_EMISSION.md)。

2026-10-07 此前event formatter检查点：新增22个原生控制/19个负控制，
恢复144字节五参数对象、live uint64/int32索引渲染、heap C++输出和临时清理。
同次owning allocator低基址生成mode/event/辅助strings，内部推进至事件发布
`+0x28ff44`，请求free计数17；高基址仍`+0x26edc4`。外层945/965与完整父事务
未提交的边界保持。双全局页比较还补齐了mode共用的六组hex selector。
完整callback/fresh签名/线上矩阵仍未通过。详见
[REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。

2026-10-07 此前mode组件检查点：新增38个原生控制/14个负控制，恢复token/
参数向量、signed32渲染、inline转换及清理。同次owning allocator可独立生成
`{"x0":0}`，低基址内部推进到五参数formatter `+0x28e86c`，高基址仍真实JNI
`+0x26edc4`。外层仍945/965，完整event父事务未提交。builder比较明确排除
未指定token padding，完整mode控制比较完整最终payload。详见
[REQUEST_MODE_FORMAT.md](REQUEST_MODE_FORMAT.md)。

2026-10-07 此前leaf前导检查点：新增30个原生对照/6个负控制，恢复采样和
九组Java线程栈lazy初始化。同次组合仍945/965步，内部推进至mode builder
`+0x28f0f4`和真实JNI acquisition `+0x26edc4`。10个未采样诊断路径返回，
其余路径暂存后拒绝，完整callback/fresh signer未通过。本批原生在JNI调用
前停止，没有使用既有env stub。详见 [REQUEST_LEAF_PREFIXES.md](REQUEST_LEAF_PREFIXES.md)。

2026-10-07 此前内部callback检查点：新增76个组件对照/10个负控制，恢复事件
包装、boolean gate的有界编排和24-byte C++ string。event formatter/evaluator/
scope cleanup的原生body仍未恢复；组合生成暂存前导后明确拒绝，外层仍945/965步，
下一缺口分别`+0x28ddd0`和`+0x28b05c`。此外修正realloc hook与旧控制误称：
原truncation路径realloc=0，新强制控制在两基址各1次；formatter证据现在16条。
matching-libc realloc、完整request/真实URL/headers/JNI/fresh签名仍未通过。
详见 [REQUEST_EVENT_GATE.md](REQUEST_EVENT_GATE.md)。

2026-10-07 此前时钟检查点：monotonic clock、140 字节 raw state 和无 waiter
serial guard release 及 shared pointer getter 新增 **82 个原生控制、18 个负控制**及 **4 个 outer
constructor 回归**。同次 owning clock/allocator 组合低基址推进到 **945 /
+0xffb48** 的 `+0x28dc38`，高基址到 **965 / +0xf8fd0** 的 `+0x28bb5c`。
clock id 1、nanoseconds 到 microseconds 的 signed divide、raw/outer constructor
区别已有组件对照；仍无 whole-native request、真实 URL/headers/JNI 或 fresh
签名。固定虚拟 clock 所得 elapsed=0 不是线上时间戳冻结证明。完整接口与复现
见 [REQUEST_CLOCK_STATE.md](REQUEST_CLOCK_STATE.md)。下方是各较早阶段的边界。

2026-10-07 此前字符串阶段检查点：C-string equality、signed `%d|%s`、serial guard
及 ELF memset 输入依赖新增 **56 个原生对照、11 个负控制**。同次 Python 请求低
基址到 **919 / +0xffae0**，高基址到 **793 / +0xf87bc**；下一处分别为
`+0x285f60 → +0x2914d0` 与 `+0x2859e0 → +0x32a330`。本次增长沿 owning
allocator 的 malloc/copy/free，不等于已恢复真实 realloc；后者仍明确拒绝。
高基址的中途 NULL 来自尚未绑定的 memset ABS64 relocation，已按原 ELF 解析
PLT service 解决。详细调用、比较窗口、native/helper 返回差别及关键证据用途见
[REQUEST_STRING_CALLBACKS.md](REQUEST_STRING_CALLBACKS.md)。完整 request/真实
URL/headers/JNI、fresh Medusa、线上矩阵和下载产品仍未完成；下方旧条目保留当时
的范围，不能作为本次新边界的成功证明。


2026-10-07 当前请求检查点：`+0x16e32c` ORi 和 `+0x256ed4` 字符串 getter 的
acquire/clone/release 与 VM 退出已有 **28 个新增原生对照、7 个负控制**；6 个
外层 prefix 回归验证了 30 个物理 callback frame，36 个此前 nested 前缀对照也
通过。原生 caller/wrapper 返回已观察，Python 完整 native ABI 仍未建模。
低基址同次 Python constructor/request 使用实际 receiver 与 owning allocator，
推进到 **816 / +0xf85b4**，下一 callback 为 `+0x285990 → +0x248908`，格式
`%d|%s`、首参 -5。高基址外层更早停在 **641 / +0xf812c** 的字符串比较 callback
`+0x2858ec → +0x24880c`，whole-native 分支一致性未验证。两者不能合并为完整
request 成功。详细字段、调用、复现与关键证据引用见
[REQUEST_NESTED_VM.md](REQUEST_NESTED_VM.md)；此前条目按各自日期和输入边界理解。
这些结果不构成 fresh Medusa、当前线上验签、无 JVM Rust 或最终下载产品完成。


最新纠正：初始化回调 `0x1000000e` 返回 `MSC.GetABSwitch()`，旧桥接器误传冻结时间。恢复 APK 默认值 `2` 后，三个旧失败时间输入成功，未取整时间的详情请求也被线上接受。Python 已独立恢复这一全局和 bit-5 分支，18 个字节码对照通过；默认 A/B=2 的 publisher 是 `+0x28c268`，两个 child/handler、root 已观测字段装配、callback pair 绑定、引用计数和 JNI 清理已有 92 个新建内存对照。2026-10-04 又恢复了 0x2d0-byte service 配置图、完整无竞争 guard 状态和真实 getter → handler 构造，72 个 native 对照、15 个拒绝/回滚例通过；root 前段的 264-byte 配置及全局启动仍未完成。此前“时间取整稳定”的结论只适用于旧误配桥接器，不能作为 native 时间约束。详见 [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md) 与 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md)。修正后当前搜索在 b/c 两个主机仍为空。

2026-10-04 的后续恢复包括 guest-table cipher（256 组 native 差分 / 11 个回滚例）及完整 mode-0 配置解密 callback（200 / 12）。后续又恢复了流状态和 reference 生命周期（174 / 9）。四次 fresh 控制中的 parser 已在 3318 步 / `+0x9c95c` 退出，165 字节消息成功解包，119 次分配、47 次 free、TLS/generation/有序副作用及 32 个虚拟槽均一致。新增字符串重填为 190 / 5，消息解包/清理为 208 / 6；60 条完整子树对照包括四次 `+0x262608` caller 验证：所需 parser 前导由 Python 生成，7 个拒绝/回滚案例通过；caller 之前的 root/堆/TLS 状态仍由同次 native 输入提供，完整 Python 冷启动和88-byte其它初始化分支仍未完成。接口、用法与证据用途见 [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) 、[STREAM_REFERENCE.md](STREAM_REFERENCE.md) 与 [PARSER_UNPACK.md](PARSER_UNPACK.md)。

较早的恢复完成已观察的 `+0x26194c → +0x261c54 → +0x261cb0` 默认配置构造路径（helper **166 / 5**、流组件回归 **174 / 9**），并将 root 推进到第605步；修正了 -0x340 工作栈、iterator length 与 saved-frame getter 的归属，详见 [CONFIGURATION_INITIALIZATION.md](CONFIGURATION_INITIALIZATION.md)。

最新检查点恢复了 `+0x25ee84 → +0x26cd0c → +0x26cdc4` 冷启动共享引用、日志／SDK／环境 getter、格式化和目录依赖（**106 组 native 差分 / 15 个拒绝回滚案例**）。Python 生成的 state caller 和完整48-byte owner 已接回 root：state VM **363步 / +0xa54bc退出，28次分配 / 21次free**；root **716步 / +0x99f04退出，171 / 93**，二者全部32个终止虚拟槽与guest/image/TLS/generation/有序副作用一致。组合为 **4个controls / 16段VM / 68条子树**，另有7个state caller前置拒绝案例。详见 [STATE_OWNER_INITIALIZATION.md](STATE_OWNER_INITIALIZATION.md)。

本次又独立生成了 `+0x257578 → +0x257084 → +0x257308 → VM +0x991c0` 默认 root factory。**8个 fresh ELF/TLS 控制不使用任何 native 函数／VM 入口快照**，32个终止虚拟槽、全部主 image、guest/TLS/generation 和有序副作用一致；完整factory分配／释放为206/93，另有9个caller拒绝和2个factory失败回滚案例。旧component对照增至4个controls/16段VM/76条子树，仍单独标注native函数入口输入。详见 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md)。

当前控制仍使用明确的nonreusing malloc/free与虚拟OS；真实allocator全局boot、TLS/arena/OS region贯通、外层signer/handle、fresh请求签名输出和线上新矩阵仍未完成。无JVM Rust、当前非空搜索与分页、其它平台及最终Pages/Actions产品的完成状态没有变化。

2026-10-06 新增并纠正 logger 边界证据：native fresh trace 已贯通 `+0x26cdc4 → +0x26cf08 → +0x26e9e0 → +0x271ec8 → +0x271ddc → +0x271f18`；四组控制匹配真实 24-byte owned string object 前缀、`METASEC` 标签、fallback 文本、level=6、sink 全局前后状态和返回值。此前的 0x80-byte 记录只是周围 native stack window，已标记为历史范围，不能当作 128 字节完整对象。该结果只关闭 literal logger/sink 状态边界，sink callback 实体、descriptor trampoline、fresh Medusa、线上全头矩阵和最终下载产品仍未完成。详见 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md)、`evidence/vm9_logger_sink_match_20261006.json` 和 `EVIDENCE_INDEX.json`。
新增 descriptor trampoline 组件证据：`+0x2584ac` 的预调度、descriptor 重载和显式分支回调已作为事务性 Python 边界验证；这只说明指令级 continuation contract，不能替代 packed x8 对象构造、真实 callback body、fresh Medusa 或线上验证。详见 `evidence/vm9_descriptor_trampoline_semantics_20261006.json`。
静态 target-role 审计已纠正：active writer 的两个值实际是 image-relative `+0x32a444/+0x32a4fc`，对应 shared-reader acquire/release 的函数入口；此前 `+0x31e444/+0x31e4fc` 是偏移选错的一页下方位置，已在 evidence 中标记为 superseded。最终 `br x1` handoff、callback object 和完整 VM continuation 仍未闭合。详见 `evidence/vm9_descriptor_target_roles_20261006.json`。

外层启动的最新恢复：`+0x28040c → VM +0xa7050` 的 4 个 fresh 控制完成 86 步／16 次分配／3 次 deferred worker 创建；worker TLS support 前段为16个冷／热控制，executor context 的实际 emulated-TLS 初始化另有8个冷／热对照；native-only guest 调度探针已到达 timedwait，完整 Python worker仍未通过。OP45 的第二寄存器 bit 21 和 equality 语义由 308 个 native 控制确认，共用 VM 的 root／state／parser 回归通过。worker dispatch、真实 allocator boot、fresh 请求签名和新线上矩阵仍未验证。详见 [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md)。


#
#
#
#
The public callback model keeps these boundaries explicit through `vm9_callbacks.dispatch_packed_callback_consumer` and `dispatch_callback_result_writer`. A caller must provide the packed word and callback body; missing or invalid inputs fail closed. This is how the native evidence can be reused without turning a captured value into a false parameterization claim.


### Medusa f13 clock input status

`python/verify_medusa_f13_clock_parameter_20261006.py` can reproduce the f13 core with private snapshots supplied through `MEDUSA_F13_SNAPSHOT_DIR`. Its evidence records identical output for multiple explicit timestamps and no syscall 113. Use this as a negative control when reviewing timestamp work: the Python API accepts time, but the current snapshot path does not consume it, so live timestamp freezing and online Medusa acceptance remain open.

### 2026-10-07：fresh request nested VM 前缀恢复

新增 [REQUEST_NESTED_VM.md](REQUEST_NESTED_VM.md) 集中说明本轮字段解码、
调用方式和证据边界。`+0x16d7d0` 的 dispatcher 已接到 10 次 STORE64、op17
sub-dispatch、OR64 和 signed MOVhi；6 组 fresh caller 对照到达 `+0x16e32c`。
这些输入由显式对象/x8、fresh 页和 ELF 重定位生成，没有使用 native 前导快照。
新增组件/组合共 48 组 native/Python 对照与 8 组拒绝/回滚控制通过；每组组合
比较从 store loop 开始的 61 次写入顺序和规定内存范围。

该结果可作为 VM word 解码、内存顺序、寄存器恢复和 dispatch table 定位的原生
差分证据；它仍不证明真实 URL/header/JNI 转换、整个 request callback 返回、
完整 Medusa 输出、当前线上验签或无 JVM Rust 下载器。下一处是 `+0x16e32c`。


## Callback result writeback

`python/verify_vm9_callback_result_writer_native_fresh_20261006.py` executes the exact `+0x28863c` result writer on fresh objects. Reviewers can use its evidence to verify that the callback receives the object pointer and that only the low 32 bits of `w0` are written back at `+0x08`, with the saved caller registers restored. It remains a consumer/result boundary; it does not provide the upstream packed x8 composition or a current Medusa signer.

## Packed callback consumer ABI

`python/verify_vm9_packed_callback_consumer_native_fresh_20261006.py` executes the exact native consumer at `+0x2887f0` with fresh callback objects. Its evidence is useful for reviewing object layout and register order: the packed x8 word is passed unchanged as the callback's `x8`, while `+0x10/+0x18` become `x0/x1`. The verifier does not parameterize how the packed value was produced, so `compose_packed_callback_x8` remains fail-closed.

## Separate callback return trampoline

The verifier `python/verify_vm9_callback_return_trampoline_native_fresh_20261006.py` executes the exact native bytes at `+0x25863c` and `+0x25865c` on fresh synthetic registers, stack and object memory. The resulting evidence is useful when distinguishing callback-family paths: it proves the stack restoration, object zeroing and selector-dependent `br x8` boundary independently of the direct descriptor wrapper. It does not prove the final target body, packed callback x8 construction, current VM9 object graph or online signer.

## Native descriptor trampoline evidence

`python/verify_vm9_descriptor_trampoline_native_fresh_20261006.py` executes the private ELF bytes at `+0x2584ac` in a controlled ARM64 emulator. Its JSON evidence records 12 fresh descriptor controls, including the saved caller `x30`, callback return PC, descriptor rewrite, final `x0/x1`, and the final branch boundary. This is useful as a key instruction-level proof when reviewing the signer: it validates the wrapper ABI independently of the Python model. It must be cited together with the limitation fields because the callback mutation is synthetic and the current VM9 object graph, packed callback x8, Medusa output, and server acceptance are still unresolved.

## 1. 完成度结论

| 范围 | 当前状态 | 可以据此声称什么 |
| --- | --- | --- |
| `device_register` | 私有桥接试验记录中跑通；公开索引未单独列证据 | 能取得后续请求所需的设备/会话资料；公开报告不包含真实设备标识和票据 |
| `registerkey` | 已跑通并解出会话章节密钥 | 可进入章节解密流程；报告只公开 key version 和摘要 |
| 目录接口 | **桥接线上验证通过** | 当前样本返回 611 个章节条目 |
| `reader/full` | **桥接线上验证通过** | `crypt_status=0`，AES-CBC 解密得到 6,496 字节 HTML；摘要见 `EVIDENCE_INDEX.json` |
| AES-CBC/压缩解码 | 已实现并有向量 | 可验证章节明文长度和 SHA-256 |
| Helios | Python/向量和线上矩阵支持 | 在已测阅读请求中是必需头之一 |
| 旧版 Medusa（225 字节快照） | 纯 Python 可复现 | 只能研究旧快照字段和 VM 语义，不能代表当前线上 VM9 |
| 当前 Medusa VM9 | Java/Unidbg 桥接通过；捕获状态回放通过 | 当前样本可以被桥接器签出并被阅读接口接受；仍未完成独立 fresh-input 参数化 |
| Perseus | 当前时间窗内可加可不加 | 只能说明本次矩阵未发现硬依赖，不等于永久可省略 |
| Gorgon/Ladon/Argus | 有算法/向量或矩阵证据 | 在已测阅读矩阵中可移除；不要把该结论外推到其他产品或接口 |
| 搜索 | 当前 `7.1.3.32` 首阶段仍为空；旧 `6.8.1.32` 配置的外部 Java 服务已返回两页 | 旧服务分别返回 9/10 本书、同一 searchId；不代表当前版本搜索或独立 signer 完成 |
| Python allocator/runtime | TLS、arena、tcache、OS region、空 bin、清理、受控 fresh root factory，以及 logger object/formatter 输入边界已独立建模 | 是 VM9 研究组件，不是完整 Medusa signer |
| Rust | scaffold 可编译；明确返回 current Medusa unavailable | 可承载已验证纯 Rust 边界和参数模型，不能独立访问当前阅读接口 |
| 抖音 | 仅静态/社区材料 | 没有当前版本线上签名和正文闭环 |
| 起点 | 证据缺口 | 没有 APK、签名样本、接口矩阵或章节解密向量 |
| GitHub Pages 下载网页 | 尚未开始产品实现 | 当前 `docs/` 是路线说明和研究归档，不是可用下载器 |
| GitHub Actions | 已有检查/构建骨架 | 只能构建研究归档和 Rust scaffold，不能发布完整下载能力 |

### 对“六神/七神/16/24 神”的准确结论

历史里的“神”是请求头名称，不是 VM 层。六个传统名称是 Gorgon、Ladon、Argus、Khronos、Helios、Medusa；Neptune 常被作为第七个软字段描述；Perseus 是另一个独立 VM 头。

当前材料直接证明了 Medusa 中存在等价于 `state & 0x0f` 的选择器，因此只能确认 **16 个 selector 值的 dispatch 空间**。现有样本没有逐一重建 16 个分支，也没有可靠的 24 分支结果。`jadx_out16`、`jadx_out24` 是分析目录名，不能当成 16/24 套算法已完成的证据。

## 2. 已恢复的番茄调用链

以下链路使用当前 Java/Unidbg signer 和同一会话上下文。公开报告隐去设备标识、token、完整请求头和可复用票据。

```text
device_register
  -> registerkey
  -> directory/detail
  -> reader/full/v1
  -> AES-CBC 解密与压缩解码
```

### 2.1 设备注册

```http
POST /service/2/device_register/
```

这是 ByteDance 日志/注册服务。请求体包含应用 profile 和生成的设备指纹；响应提供后续请求使用的会话标识。私有桥接试验记录包含该步骤，但当前公开 `EVIDENCE_INDEX.json` 没有独立的 `device_register` 摘要，因此这里不把它作为可由公开仓库单步复核的线上证据。该请求在已记录流程中不依赖阅读接口的 Medusa 头。

### 2.2 章节密钥注册

```http
POST /reading/crypt/registerkey
```

请求体包含 JSON `content` 和 key-version。`content` 是 AES-CBC 信封：前 16 字节是 IV 文本，后续字节加密小端设备/用户字段。响应 `data.key` 仍是 AES-CBC 信封，解出本次会话的章节密钥。已观察的 key version 是 `598113575`；原始密钥不进入公开仓库。

### 2.3 目录

```http
GET /reading/directory/detail
```

当前桥接请求使用 `X-Helios`、`X-Medusa`、`X-Khronos`。成功样本返回 611 个章节条目。必须同时保存请求时间、响应长度、JSON 结构和会话上下文，单独一个 HTTP 200 不足以证明目录成功。

### 2.4 正文

```http
GET /reading/reader/full/v1/
```

响应是带 base64 章节载荷的 JSON envelope。成功样本的 `crypt_status=0`；用 `registerkey` 返回的会话密钥解密后得到 6,496 字节 HTML。公开证据用明文 SHA-256 证明解密结果：

```text
13e2415e7bef414a197a62aca08ccb11bf9cf436bc3f955b676fa03fac2fa2f7
```

### 2.5 阅读请求头矩阵

| 变量 | 结果 | 证据边界 |
| --- | --- | --- |
| Helios + Medusa + Khronos | HTTP 200，非空响应 | 当前阅读矩阵的基线 |
| 再加 Gorgon/Ladon/Argus | HTTP 200，非空响应 | 这些头在该矩阵可选 |
| 再加 Perseus | HTTP 200，非空响应 | 兼容组合可用 |
| 移除 Perseus | HTTP 200，非空响应 | 当前时间窗内未发现硬依赖 |
| 移除 Medusa | HTTP 200，空响应 | 传输层 200，但业务失败；Medusa 是当前阅读接口硬依赖 |

矩阵必须在时间戳窗口内成对运行。过期时间会把“签名错误”和“时间窗失效”混在一起。

## 3. 签名与解密模块

| 模块 | 当前实现/证据 | 使用限制 |
| --- | --- | --- |
| `X-Khronos` | 秒级时间戳 | 必须与请求 `_rticket`/签名时间一致 |
| `X-Neptune` | 软时间字段；桥接公开路径可移除 | 不作为当前阅读硬依赖 |
| `X-Gorgon` | 当前 0404 形式和 KSA/PRGA 路径 | 只对已分析版本和输入向量负责 |
| `X-Ladon` | 34 轮 Speck-like 变换 | 不将 Tomato 结果外推到抖音 |
| `X-Argus` | Tomato 变体的 SHA-256/AES 细节 | 与常见 Douyin Argus 不混用 |
| `X-Helios` | 34 轮 VM 的 Python 翻译和向量 | 当前阅读矩阵必需 |
| `X-Medusa` | 旧快照纯 Python；当前版本桥接 | 当前 VM9 仍不能独立 fresh-input 生成 |
| `X-Perseus` | 独立 VM 快照/实验辅助 | 当前时间窗可选，未来风控可能重新要求 |
| 章节 AES-CBC | 已实现 | 必须使用同一 registerkey 会话密钥和 IV 规则 |

详细证据分别在 [SIGNATURE.md](SIGNATURE.md)、[API_CALLS.md](API_CALLS.md) 和 [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json)。

## 4. 搜索接口现状

### 4.1 静态恢复的请求模型

搜索 feed 构造 `GetSearchPageRequest`，调用 `u15.c.i0(request)`。已恢复字段包括：

```text
query, searchId, passback, correctedQuery, useCorrect, offset,
bookshelfSearchPlan, searchSource, tabType, tabName, targetMainId,
userIsLogin, bookstoreTab, clickedContent, searchSourceId, sourceBookId,
clientAbInfo, isFirstEnterSearch, fromHalfScreen, reportInfo, clientExtra
```

feed 路径固定写入 `bookshelfSearchPlan=4`；`PlaceUtils.addPlaceColumnParams` 还可能补充字段，补充规则尚未完全验证。

### 4.2 当前路径和实测结果

```text
GET /reading/bookapi/search/tab/v
GET /reading/bookapi/search/page/v/
GET /reading/bookapi/search/page/v1/
```

2026-09-29 的同步时间戳探针对四种路径均得到 HTTP 200、0 字节 body，body SHA-256 是空流摘要 `e3b0...2b855`。APK hook 观察到的 `sinfonlineb`、`query=三体&offset=0&aid=1967` 形状也返回空 body。

这证明了签名和传输可以到达路径，不证明搜索被业务接受，更不证明有书籍列表。Rust 的 `search_params` 只是参数模型；调用者必须把搜索状态显示为“未验证”。

2026-10-03 补充了两个分开的结论：旧 `6.8.1.32` 请求配置的外部 Java 服务返回第一页 9 本、第二页 10 本，第二页沿用同一 `searchId`，两页无重复书籍；服务包含缓存、重试和设备池，尚未捕获原始上游请求。当前 `7.1.3.32` 使用成功详情请求的设备配置、同一 session 对和数字首进入标志，在 b/c 两个域名上仍返回 HTTP 200、空 body，没有取得可进入第二阶段的 `searchId`。详见 [SEARCH.md](SEARCH.md)，不能混用版本或 session 来宣称当前搜索完成。

初始化也获得了新证据：相同 URL 下，某些时间输入未发布 signer handle，原桥接器错误回退到 app manager，随后发生虚表读取错误。私有桥接器已修正为明确失败、保留日志、清空旧签名；新鲜详情请求仍被服务器接受。11 个时间输入只证明这一边界，尚未恢复任意时间下的 native 初始化。详见 [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md)。

## 5. Python 研究 API

代码位于 `python/`。这些 API 用来验证 VM9 初始化和 allocator 边界，不应直接当作线上 signer。

### 5.1 GuestOS 映射和 fresh region

```python
from vm9_allocator import GuestOS, register_os_region

pages = {}
guest_os = GuestOS(pages, next_address=0x13600000)
registration = register_os_region(
    pages,
    guest_os=guest_os,
    arena_address=arena,
    length=0x40000,
)
```

`GuestOS` 只接受当前明确建模的匿名私有映射：页对齐、`PROT=3`、`MAP_PRIVATE|MAP_ANONYMOUS`、非重叠、地址范围受限。失败在提交前回滚，不覆盖原页。

### 5.2 TLS、arena、tcache 和 small allocation

下面是边界 API 的示意调用。`pages`、`arena_zero`、`arena_table`、`arena` 和
`thread_pointer` 必须由调用者从同一次受信采样或自己的 guest 初始化中提供；
它不是一个可以独立启动当前线上 Medusa 的完整脚本。

```python
from vm9_allocator import (
    AllocatorConstants, GlobalBootConfig, initialize_global_boot,
    prepare_thread_allocator, allocate_small_object,
)

def run_allocator_step(
    pages, *, arena_zero, arena_table, thread_pointer, guest_os
):
    # These inputs must come from the same trusted guest initialization.
    constants = AllocatorConstants()
    boot_config = GlobalBootConfig(
        arena_zero=arena_zero,
        arena_table=arena_table,
    )
    initialize_global_boot(pages, config=boot_config)
    thread = prepare_thread_allocator(
        pages, thread_pointer=thread_pointer, constants=constants
    )
    return allocate_small_object(
        pages,
        thread_state_address=thread,
        request_size=24,
        guest_os=guest_os,
        constants=constants,
    )
```

已验证组件包括 pthread TLS generation 检查、stale TLS 清理、base allocation、arena/tcache/thread state 创建、arena 选择、空 bin refill、slab bitmap、free list/tree、清理和 purge。`GLOBAL_BOOT_COMPONENTS` 会明确哪些 boot 仍是 `captured-input` 或 `partial`，不能被误读为完整 `je_*_boot` 重建。

### 5.3 构造器和 callback 边界

```python
from vm9_objects import construct_string_object
from vm9_callbacks import clock_callback, publish_callback_descriptor

payload = construct_string_object(
    pages,
    object_address=obj,
    source_address=source,
    allocate=lambda staged, size: allocate_payload(staged, size),
)
clock = clock_callback(
    pages,
    wrapper_address=wrapper,
    clock_id=1,
    seconds=123456789,
    nanoseconds=0,
)
descriptor = publish_callback_descriptor(
    pages,
    descriptor_address=descriptor_addr,
    branch_target=target,
    object_address=obj,
)
```

`compose_packed_callback_x8` 会显式抛出 `RefillUnsupported`，因为 packed callback x8 的组合写入者尚未被独立参数化。这个拒绝是设计的一部分，不能用一个捕获常量替代。

服务引用型 handler 依赖两个 guarded singleton。`construct_service_reference(kind="flag")` 生成 2-byte zero payload；`kind="service"` 默认用 Python 构造完整已测 0x2d0-byte 图，读取 fresh ELF/GOT 输入。冷 getter 要求显式 `thread_id`，会生成 guard 的 acquire/release 状态与线程 ID；已发布 getter 不重复分配。handler 可以用 `initialize_services=True` 连续构造并复制这两个引用。`verify_vm9_service_singletons.py` 用 72 个真实 native 对照和 15 个拒绝/回滚例验证这些局部组件；完整 root、诊断全局副作用和独立 signer 仍未完成。

### 5.4 配置树和 136/320 字节构造器

`vm9_registry.py` 的 `compare_string_fields`、`lookup_configuration_value` 和 `insert_configuration_pair` 分别用于验证配置 key 比较、查询和所有权转移式插入。比较器遇到双方相同 NUL 会提前判等；重复插入会删除传入 key 和原 value，不能使用普通字典排序或覆盖语义替代 native 行为。

`set_configuration_u32` 包括 scoped writer、缺失 key 克隆、u32 覆盖和清理，返回旧值或 `0x000a985f`。`construct_registry320`、`construct_singleton136` 已恢复完整构造主体；`get_registry320_reference`、`get_singleton136_reference` 完整构造后才发布 lazy reference。调用者需要提供 caller stack、allocator/free、clock、TLS 初始化/解析和广播边界；cold getter 还需要 `thread_id`。复用栈槽位会改变后续 TLS padding，不能清零或注入 native 的结果页。

配置树通过 96 组 native 差分 / 11 个回滚例，完整主体和 getter 通过 38 / 14。四次 fresh native 控制新增 20 条同次入口子树对照，串接实际 Python 冷 TLS/key/析构注册，并比较内存和有序 allocation/free/clock/registration/wake。详细布局、证据和限制见 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md)。这些结果保留串行 guard/OS 边界和 native 输入前导快照依赖；mode-0 `+0x259dbc` 已贯通，parser 已在第 3318 步 / `+0x9c95c` 退出，其所需 caller/VM 前导已由 Python 生成，但 caller 之前的 root 初始化仍未独立恢复；尚不能直接调用这些组件生成当前线上 Medusa。

### 5.5 验证命令

在仓库根目录运行：

```powershell
python scripts/check_python.py
python platforms/bytedance/tomato/python/verify_vm9_initialization.py `
  --capture-dir <trusted-private-capture-dir> `
  --output <sanitized-output.json>
python platforms/bytedance/tomato/python/verify_vm9_allocator_lifecycle.py `
  --checkpoint <trusted-private-checkpoint.pkl> `
  --output <sanitized-output.json>
python platforms/bytedance/tomato/python/verify_vm9_os_region.py `
  --checkpoint <trusted-private-checkpoint.pkl> `
  --output <sanitized-output.json>
python platforms/bytedance/tomato/python/verify_vm9_callbacks.py `
  --output <sanitized-output.json>
cargo check --manifest-path platforms/bytedance/tomato/rust/Cargo.toml
```

其中前三个脚本需要同次采样的受信任私有 ARM64 capture/checkpoint；这些输入不在 Git 仓库，不能用公开 evidence 文件冒充。输出只应是脱敏 JSON。最近一次记录的研究验证为：初始化差分 85 cases（11 个拒绝）、allocator lifecycle 83 cases（8 个拒绝）、fresh region 对比 4,256 pages、callback 边界 3 个拒绝；这些是组件验收，不是线上 Medusa 验收。

## 6. Rust 当前使用范围

入口在 `rust/`：

```text
rust/src/api.rs       # 路径常量与搜索参数模型
rust/src/signature.rs # 已验证的纯 Rust 辅助头边界
rust/src/status.rs    # capability/unavailable 明确错误
```

默认 crate 可以在 Windows/Linux 上编译，不依赖 JVM、Android artifact 或 dynarmic。`status::current_medusa()` 会返回明确的 `CapabilityError`，理由是当前 VM9 独立参数化尚未完成。这个错误必须保留，不能为了让下载器“看起来可用”而生成猜测头。

当前 Rust 能做的是保存已恢复的接口/参数模型、构建检查和能力边界；它还不能独立完成当前线上 `registerkey -> directory -> reader/full` 下载闭环。

## 7. 逆向分析过程和关键证据

1. 从 APK/JADX 恢复 Java/Kotlin 请求构造、路径、参数和 header 进入点。
2. 从 ELF/native 符号、ARM64 指令和 hook 记录定位 Helios/Medusa/Perseus、构造器、allocator 和 callback 边界。
3. 用 Java/Unidbg 桥接器生成当前版本签名，采用同一时间戳和会话贯穿注册、目录、正文。
4. 对章节做 AES-CBC/压缩解码，用 `crypt_status`、明文长度和明文 hash 证明得到的是解密正文。
5. 对 VM9 做 trace、寄存器、内存页和 native write watch 对比；把 callback 8、clock、string constructor、OS region 和 allocator 生命周期逐个拆成可拒绝的 Python 组件。
6. 对每个结论区分四种证据：静态恢复、离线向量、桥接线上接受、fresh-input 独立实现。只有最后两项同时闭合，才可称为当前线上独立 signer。
7. 对公开证据做脱敏：不提交设备标识、token、完整 headers、原始响应、APK、so 和可复用票据。

### 证据如何在逆向报告中使用

- 证明“头是必需的”：使用同一会话、同一时间窗的单变量 paired matrix；`drop_medusa` 空 body 对比 `drop_perseus` 非空 body，才能支持硬依赖判断。
- 证明“章节确实解密”：同时给出 `registerkey` key version、`crypt_status=0`、解密长度和 SHA-256；只给 HTTP 200 不足够。
- 证明“当前 VM 输入相关”：同一 URL/时间戳/PID 重复得到同一 digest，改变其中一个得到 digest 或分支长度变化；这仍是桥接证据，不替代独立实现。
- 证明“allocator 组件是真实结构”：报告页数、指针、metadata、free node、回滚拒绝和同次采样重放；不要只贴一段捕获内存。
- 证明“callback 写入来源”：使用 instruction-level write watch 和 caller/callee liveness；不能把 callback page 常量当成通用输入。
- 证明“fresh-input 已完成”：必须用未读过的输入从初始化开始生成 Medusa，重新跑目录/正文矩阵，并与已捕获输入分开记录。当前尚未达到此门槛。

主要证据索引：

- [API_CALLS.md](API_CALLS.md)
- [SIGNATURE.md](SIGNATURE.md)
- [SEARCH.md](SEARCH.md)
- [VM9_PROGRESS.md](VM9_PROGRESS.md)
- [RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md)
- [ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md)
- [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json)

## 8. 平台隔离和最终产品路线

平台目录必须保持独立：

```text
platforms/bytedance/tomato/  # 番茄：当前目录
platforms/bytedance/douyin/  # 抖音：单独版本、签名和线上证据
platforms/qidian/            # 起点：独立 APK、接口和解密证据
```

抖音目录当前只有静态/社区算法清单，不能引用番茄线上矩阵。起点目录是证据缺口报告，不能从通用小说项目或其他平台推导接口。

最终产品可以按以下顺序落地：

1. 完成当前 Medusa fresh-input 参数化，或取得可复现、可公开验证的匹配样本。
2. 用同一版本、同一设备策略完成 `device_register -> registerkey -> directory -> reader/full` 的无 JVM Rust 闭环。
3. 让搜索返回非空 JSON，确认字段、分页和书籍 ID；再做下载器的选择书籍/章节流程。
4. 分别完成抖音和起点的独立线上验证，不共享未经证明的 header 或参数。
5. 以平台能力矩阵为输入开发 GitHub Pages 搜索/章节/下载网页；未完成的平台显示“未验证”，不伪装成可用。
6. GitHub Actions 在检查通过后构建 Rust 的 Linux/Windows 构件，并部署 Pages。当前 Actions 仅适合研究归档、检查和 scaffold 构建。

## 9. 当前验收矩阵和下一步

### 已通过

- 当前桥接可生成被阅读接口接受的 Helios + Medusa 请求。
- 注册、目录、正文和章节解密链路有公开脱敏证据。
- 旧 225 字节 Medusa 快照、Helios 和若干辅助头有 Python/向量级复现。
- VM9 的 TLS/arena/tcache/OS region/allocator/callback 子边界有输入驱动验证。
- 配置树、136/320 字节完整构造主体与 getter 在明确边界下通过 native 差分和同次子树验证。
- Rust crate、Python 文件和 JSON evidence 可检查。
- `+0x171268` 的 VM `STORE64` 字段解码，以及 `+0x991c0` 四组 fresh root writer 输入已通过；这只闭合 descriptor 字段写入边界，不等于 callback continuation 或 Medusa 完成。

### 仅桥接或捕获状态通过

- 当前 VM9 Medusa 的 228 字节和 802–804 字节分支。
- 三段 trace continuation、native callback、clock 和 constructor 交接。
- bridge 性能优化后的同 digest 结果。

### 仍需完成

- 当前版本 Medusa 的独立 fresh-input Python 参数化。
- packed callback x8、lookup cache、callback tables、mutex/ctl boot 和剩余 native object graph。
- 无 JVM Rust signer/download 完整链路及线上复测。
- 当前 `7.1.3.32` 非空搜索响应和分页行为；旧配置外部服务已有两页证据。
- 全头服务器矩阵的更多时间窗/版本复测，特别是 Perseus 的风控变化。
- 抖音当前版本、起点平台完整接口/签名/正文实测。
- GitHub Pages 小说搜索下载网页和最终 Actions 发布流程。

**最终判定：当前项目是有实证的逆向研究归档和实现 scaffold，状态为“可继续开发”，不是“完整下载器”或“可直接发布的最终产品”。** 本报告是分析证据和使用说明，不是授权绕过未完成边界或发布不可验证能力。
