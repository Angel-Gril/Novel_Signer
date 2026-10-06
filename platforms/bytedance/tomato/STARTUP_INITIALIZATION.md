# 外层启动 caller 与 worker 调度／清理

## 2026-10-06: outer constructor logger/trampoline 边界

外层构造器边界控制已从 fresh ELF/TLS 和同次 actual allocator 状态跑过 4 组：两种 image base、属性缺失和 SDK=30。主启动、registry getter、root factory 之后稳定进入 `+0x26e9e0` logger，再到 active `+0x2584ac` descriptor trampoline；证据记录 callback 参数、descriptor field0/field8 和拒绝位置。

这里仍然是显式边界：native outer 的入口序列已固定为 `+0x257084 → +0x257308 → +0x168324 → +0x26cf08 → +0x26e9e0 → +0x271ec8 → +0x271ddc`，而 Python 当前走到 `+0x2584ac`，说明 VM prelude/分支尚未对齐。logger 的 global/BSS 状态写入、native `+0x26cf08` handoff、descriptor writer 的输入驱动来源没有完成，不能把这组到达证据写成完整 outer constructor 或 fresh Medusa。真实 OS 线程、线上全头矩阵、f13 冻结、Rust 和最终 Pages/Actions 产品仍未完成。logger provider 的 SDK=30 控制还明确暴露了 singleton136 cold/warm 依赖，不能把属性转换通过写成 logger 已完成。

## 启动到 registry/root 的同次状态桥接（2026-10-06）

主启动的 actual allocator 结果现在可以直接交给新的 [外层前段组合器](python/vm9_outer_allocator.py)：fresh `+0x28040c` 返回后不重新构造 allocator，而是在同一个 guest OS/TLS 状态中运行 registry string caller，再调用 root factory。4 组组合结果见 [组合证据](evidence/vm9_outer_prefix_actual_allocator_20261006.json)。同一 checkpoint 还完成两个 child、两类 handler、callback pair 绑定和 JNI publication；这是 Python 状态连续性证据，native whole-prefix 对照和 fresh signer 仍保持未完成。


当前独立 Python 已恢复 `+0x28040c → VM +0xa7050` 的默认主线程路径、worker TLS support、executor context，以及 queue／executor 的有界串行调度。空闲和默认非空 queue worker 均已从同次 fresh 启动贯通等待、停止、正常返回和 argument 清理。非空 worker 执行全部六项默认初始化及 48 次嵌套 VM；worker 返回时 support 仍由 pthread TLS 持有。显式 key 清理阶段已进一步恢复 emulated-TLS 数组、fallback 链、实际 TLS registry 树析构和有界非空 support 向量。已恢复真实 executor shared owner 的零引用／weak 引用释放，以及 matching libc 的 guest `pthread_exit`：线程析构、cleanup handlers、线程状态、detached 注销和 owned mapping 回收。一个同次 fresh 非空 worker 已贯通完整 guest 可 join 退出分支。**默认 matching libc 冷启动、实际 allocator 与同次非空 worker 的 guest 可 join pthread_exit 分支已分别验证；完整 allocator 分支、实际 detached worker 注销／回收组合及 root 接入、真实 OS 线程创建／终止、未识别 callback、非空 support 的关联状态具体析构、独立 fresh 请求 Medusa 和新的线上全头矩阵仍未通过。**

实现见 [vm9_startup.py](python/vm9_startup.py) 和 [vm9_thread_exit.py](python/vm9_thread_exit.py)。此前的独立 root factory 见 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md)，本次启动结果不能替代请求签名验收。

## 当前 Python registry 字符串 caller（2026-10-06）

`+0x256e50 → VM +0x98d50` 的有界 Python caller 已恢复 lazy decode、scoped writer、C-string/object append 和 release，12 native／6 rollback 通过；底层新增 `+0x2486b0` C-string append 为28/8，受影响旧字符串/registry回归204/22。cold/warm普通调用分别147/119步，stop `+0x99018`，每次返回全部32槽、guest/image/TLS、释放前字节和副作用顺序均匹配。

该验收使用既有 registry 布局生成的组件输入、显式 warm scoped TLS 和合成 allocator effects；**已通过同次实际 allocator/TLS 下的 main startup／registry/reference／string prefix／actual root 前段组合；仍需 native whole-prefix 对照和 outer publication**。累计内容的 `+0x256ff0 → +0x248908` 格式化分支保留明确拒绝；matching-libc realloc尚未恢复。证据和复现见 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md#当前-registry-字符串-caller-与-c-字符串追加2026-10-06)。

## 此前 native 外层接入控制（2026-10-06）

[外层 native-only 控制](python/verify_vm9_outer_signer_native.py) 已从同次 fresh `+0x1658e4 → +0x27c930` 自然返回，10组通过。它实际执行默认主 startup、root factory、两 child／handler 和 callback publication；每组 310 malloc／115 free／1 GC／3 flush，warm getter 复用 wrapper 且没有额外副作用。root 的 caller 输入由 native constructor 准备，入口 SP 为 getter SP−`0x210`。此前 307/115 的 recursive-mutex oracle 拒绝边界已恢复，专用对照为48 native／15拒绝，受影响回归106/34。

该控制使用三条未执行的虚拟 pthread descriptor 和显式 JNI 服务，**不是同次独立 Python startup／worker／root 组合验收**。既有 Python 主 startup、worker 和 actual root 仍是分别通过的组件。该 caller 的有界 Python 组件已进一步通过，但完整 prefix 与 outer 的同次组合仍需验收。native 控制的证据、复现和边界见 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md#此前递归-mutex-与-native-外层冷启动2026-10-06)。

## 此前 small GC 与独立 actual root（2026-10-06）

matching libc `+0x9833c` 的 small-cursor GC 已恢复，共 **28 native／8 rollback** 终态通过。正 low watermark 复用 shared small flush，负 low watermark 调整 fill，按原生 W-register shift 更新 fill，并更新 low／cursor／event。覆盖负／零／正 watermark、fill 边界、cursor=35／exact wrap，以及 malloc／free／large allocation 对 small GC 的触发。large cursor 仍拒绝；旧公开 allocator 入口默认仍保留 event=228 的拒绝边界。见 [GC owner](python/vm9_libc_exit.py)、[验证器](python/verify_vm9_libc_gc.py) 和 [脱敏证据](evidence/vm9_libc_gc_native_20261006.json)。

新的 [实际 allocator root bridge](python/vm9_root_allocator.py) 已完成 **10 native／8 rollback**：从独立 fresh 输入贯通自然 libc cold boot、actual allocator 和完整 `+0x257578` root factory。每组 206 malloc／93 free、3 flush／1 GC，716 步 root VM；32 槽、guest／主 image／观察的 TLS 与 libc globals／全部 retained mappings、有序回调和 OS metadata 全部匹配。两基址、四种 SDK profile，以及改变 stack／mapping／canary 的两组都通过。GC 后与第 206 次分配后失败仍完整回滚 guest owned state。见 [root 说明](ROOT_INITIALIZATION.md) 和 [root 证据](evidence/vm9_root_actual_allocator_native_20261006.json)。

本组从 root factory 输入开始，**尚未将同次 main startup／非空 worker 接到 root**。以前 170/54、event=228 的 root 拒绝是历史边界，不能继续当作当前 frontier；也不能据此跳到 fresh 签名已完成。下一步从同次启动状态组合 root，再推进 signer／handle、fresh Medusa 输出和新的线上全头矩阵。

受影响回归 **90 native／55 rollback** 全部终态通过（旧 fresh root、small flush、cached free、默认 tcache 边界），见 [回归证据](evidence/vm9_root_actual_allocator_regression_20261006.json)。

## 上一阶段 small 满缓存 flush 与 root GC 定位（2026-10-06）

已把 matching libc `free +0x91d18 → +0x97f40` 的满 small-cache 分支恢复到生产实现。缓存满时归还前半槽位、保留后半槽位，再追加本次 free；按槽位的实际 arena 分组，在各自 bin mutex 下更新共享 bitmap／slab tree，归并 preferred arena 的统计，搬移保留向量，并更新 count／low watermark。`+0x97f40` 由 [vm9_libc_exit.py](python/vm9_libc_exit.py) 单一实现持有，TLS 析构复用 remaining=0，C free 使用 remaining=count/2；没有复制第二套 flush 逻辑。

新增 `release_small_with_flush(guest_os, *, pointer, libc_base, thread_pointer, scratch_address, os_call)`，从 ready actual allocator 状态执行有界 C free，在同一个 GuestOS 事务成功后发布页面／mappings／cursor。旧 `release_cached_small` 默认入口仍保留满缓存拒绝边界。重复 free 在 flush 之前检查整个缓存，防止已归还前半槽位后遗漏 duplicate；profiling、large／huge free、GC 等未恢复分支仍拒绝。

[新差分 CLI](python/verify_vm9_libc_small_flush.py) 的 **14 组原生对照／7 项拒绝与回滚**全部终态通过：两个基址各覆盖 32／128／256 字节 class、flush 后复用、连续三次 flush、foreign-only 与 mixed arena 缓存。所有 malloc 返回值以及每次 malloc／void free 返回后的完整观察 globals、TLS 和 retained mapping bytes 匹配；最终 guest 区、OS 顺序、mappings／保护／cursor 也一致。输入是双方独立的 fresh ELF／TLS／显式虚拟 OS，未用 native 快照或返回值初始化 Python。

busy bin mutex、count 越界、错误 cached class、满缓存 duplicate、后段重复 cached slot、后段 GC event 和第 3 次 slot 归还后 provider failure 均明确拒绝，全部 guest 页及 mapping／cursor 保持调用前状态。后段 duplicate／provider failure 各完成 3 次实际 slot 归还，GC failure 完成 4 次。重构后的 actual joinable guest exit、旧 key-phase、cached-free 回归 **20 组原生对照／24 项回滚**全部终态通过。

证据：[fresh small flush](evidence/vm9_libc_small_flush_native_20261006.json)、[共享回归](evidence/vm9_libc_small_flush_regression_20261006.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_small_flush.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output small-flush-result.json
```

上一阶段接回独立 root Python 前段后，越过了 **165 次分配／42 次释放、class 2 满缓存**，曾推进到 **170 次分配／54 次释放**，在下一次 free 的 **tcache event=228** 明确拒绝。当前 GC cursor=0、signed low watermark=-1、fill divisor log2=1；静态原生分支为 **`+0x91cbc → +0x9833c`**，随后更新 cursor／watermark／event，并可能进入共享 small flush。当时下一步是恢复 GC owner 和做完整 root 对照；这两项已由顶部的新证据推进。[历史 GC 前段证据](evidence/vm9_root_actual_allocator_gc_frontier_20261006.json) 明确标记 root、native root 比较和 fresh 签名均未通过；没有清零计数或跳过 GC 来继续。

## 当前实际 allocator 与完整 guest 可 join 退出组合（2026-10-06）

同次 fresh ELF／显式 TLS／虚拟 OS → 主线程 startup → 自己生成的非空 queue worker → 六项默认任务 → argument free → matching libc `pthread_exit +0x68138` 的可 join 分支，现在已完成独立 Python 组合。**2 组原生对照／6 项拒绝与回滚检查均已终态通过**，覆盖两个 relocated image bases。每次仍有 22 次实际 malloc、六项 caller 返回，以及独立计数的 48 次 native／48 次 Python nested return；退出继续完成 **3 次 allocator、1 次 support、1 次 libc emulated-TLS array callback**。五次回调返回后，完整观察 image、双方 TLS、libc globals、全部保留 mapping 页逐项一致；最终状态、OS／clock／wait／wake 顺序、映射记录／保护／cursor 也一致。

| 本轮恢复项 | 实现与已验证行为 |
| --- | --- |
| libc emulated-TLS | [vm9_libc_emutls.py](python/vm9_libc_emutls.py)：`+0x9be24/+0x9bd10/+0x9bd90` getter／once／payload，以及 `+0x9bd3c` 数组析构；使用自然 ready allocator，首字为容量，后面为 indexed pointers |
| libc ELF 输入 | `cpu_fresh` 按 ELF 的 defined `pthread_create` symbol／R_AARCH64_GLOB_DAT 补齐 `+0xd8da8` relocation；这是 loader 输入，未设置 runtime ready flag，也未创建 OS 线程 |
| 空 small slab／purge | [vm9_libc_release.py](python/vm9_libc_release.py)：`+0x78220/+0x77cf0/+0x7f0b0` 的 extent tree、dirty queue、邻接合并、page tags、统计及 bin／arena mutex 切换；复用共享 bitmap owner |
| guest 退出组合 | [vm9_libc_exit.py](python/vm9_libc_exit.py)：`run_worker_pthread_exit` 与 [vm9_thread_exit.py](python/vm9_thread_exit.py) 共用退出 body，在同一个 GuestOS 事务中执行 getter、实际 allocator free、key callback 和 guest terminal service |

每个组合实际发出两次 `madvise(address, length, 4)`，长度依次为 **4096／20480**；provider 明确返回 0。guest pthread return value 为 9，state 为 1，allocator／support／libc-emutls key value 清零，析构 head／cleanup 链为空，最后到达 guest `exit(0)`。这里只核对显式 advisory 服务的顺序、元数据和保留页内容；虚拟服务不模拟真实内核丢弃物理页的效果。

libc emulated-TLS 组件另有 **20 组原生对照／9 项回滚**通过，覆盖 cold、repeat、aligned64、template、two descriptors、two threads、preassigned index 和三类实际 free 析构。每次返回比较 descriptor／template、TLS、globals 和 retained mappings，最终 guest 区也一致。该 libc 的数组 ABI 不带主库 emutls 的延迟析构 header，不能复用其布局。

busy emutls mutex、未知 cleanup handler、第一／第二次 purge 失败、后段未知 key callback和 terminal exit provider 失败均明确拒绝。失败时全部 guest 页、owned mappings／cursor 保持调用前状态；已经调用的外部 OS／wake provider 效果不回滚。两项晚期检查在完成两次 madvise 后拒绝，terminal 检查在实际调用 exit provider 后拒绝。所有 CLI 均收取终态；共享 pthread_exit、旧 key-phase、cached free、worker allocator、tcache 回归合计 **154 组原生对照／61 项回滚**通过。

证据：[完整 guest 可 join 组合](evidence/vm9_same_startup_worker_actual_allocator_pthread_exit_native.json)、[libc emulated-TLS](evidence/vm9_libc_emutls_native_20261006.json)、[共享回归](evidence/vm9_same_startup_worker_actual_allocator_pthread_exit_regression.json)。公开 JSON 仅含 hash、合成 case／offset／count／boolean，没有 native 内存、设备或请求数据。

复现（先设置本地样本环境变量；样本 hash 必须匹配报告）：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_emutls.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output libc-emutls-result.json
python -B platforms/bytedance/tomato/python/verify_vm9_startup_worker_pthread_exit_allocator.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output worker-pthread-exit-result.json
```

**验收边界仍是实际 allocator 的 guest 可 join 分支。** 本轮未组合 actual detached worker 的线程列表注销／thread region unmap，未执行 host thread 创建／终止；realloc／emutls growth、whole-region release、replacement spare region、large cache／huge free、profiling、非默认 purge hook 及未知 callback 仍明确拒绝。独立 fresh Medusa 签名、线上全头矩阵和 f13 时间戳实验尚未通过。

此阶段首次 actual root 探针在 165 次分配／42 次释放的 class 2 满缓存处拒绝，[旧前段观察](evidence/vm9_root_actual_allocator_frontier_20261006.json) 仍只记录那次未完成运行。该分支已由顶部 14/7 small-flush 对照恢复，当时 root 边界前移到 170/54 的 GC event；顶部新 actual-root 证据已越过这处边界。两项旧前段本身不构成 root 返回或请求签名通过的证据。

## 先前实际 allocator 的 worker TLS key 退出（2026-10-06）

同次 fresh 主线程 startup → 实际分配的非空 queue worker → 六项默认任务 → argument free，现已继续贯通自然注册的 allocator／support key 析构。**两个基址的 2 个 native 对照／5 项拒绝与回滚检查均终态通过**。每个组合仍有 22 次实际 malloc、六项 caller 完整返回，以及独立计数的 **48 次 native／48 次 Python nested return**；随后在三轮 key 清理中实际完成 **3 次 matching libc `+0x99584` 和 1 次 support callback**。四次析构返回后的完整观察 image、双方 TLS、libc globals 和全部保留 mapping 页均逐项匹配，最终 allocator／support 的 TLS value 清零。OS／clock／wait／wake 顺序、映射记录／保护／cursor 也一致。

生产实现 [vm9_libc_exit.py](python/vm9_libc_exit.py) 恢复 `+0x99584 → +0x9975c` 的清 flag、tcache 卸载／计数归并、缓存刷新、直接／internal small release、arena 引用与指针表清理、fallback TSD 的实际分配及后续轮重发布。缓存中确有属于另一 arena 的槽位，按实际 owner 分组刷新后才关闭差异。fallback 分配使用所属 OS 事务的 page staging chain，保留 key 清理已完成的写入；Python 初始化不读取 native 输出。

入口 `cleanup_worker_thread_keys(guest_os, *, image_base, thread_pointer, libc_base, scratch_address, os_call)` 从已经提交的同次 worker 输出继续。`guest_os` 必须持有该 worker 的实际 allocator mappings，`scratch_address` 为调用者提供的映射临时区；`os_call` 沿用 matching-libc 的显式虚拟 OS 服务。返回 `(iteration, key_index, destructor, value)` 记录。所有 key 回调成功后才提交 guest 页／mapping／cursor；外部服务效果不能回滚。该入口完成 key 清理阶段，不会终止宿主线程。

busy cache mutex、count 越界、非空 large cache、后段未知 key callback 和后段损坏 support 向量均明确拒绝，全部 guest 页及 owned mappings／cursor 保持调用前状态。后两项在至少三次实际 internal free 后拒绝，覆盖晚期回滚。原有 tcache、独立 worker allocator、通用 key 清理回归 **94 个 native 对照／35 项回滚**全部通过。证据：[同次实际 allocator TLS 退出](evidence/vm9_same_startup_worker_actual_allocator_tls_exit_native.json)、[共享回归](evidence/vm9_same_startup_worker_actual_allocator_tls_exit_regression.json)。

后续原生探针从同次 worker 返回进入 matching libc `+0x68138 → +0x6b2a4 → +0x9be24`，额外创建 libc emulated-TLS 状态；key 阶段出现自然注册的 `+0x9bd3c` 析构。单基址探针在显式虚拟 `madvise` 成功返回下，观察到 4096／20480 字节两次 advice=4 请求及 guest `exit(0)`。这项先前探针只是原生路径定位。其 getter／数组析构、实际空 slab／extent release 和 purge 服务已由本文件顶部的新 Python 组合证据推进，原探针本身不能作为组合通过的证据。

**本节旧入口仅验收 key 阶段。** 它仍拒绝 matching empty-slab extent release／purge、非空 large cache、profiling 等分支；完整 guest 可 join 路径及 empty-slab／purge 由顶部新增组合验收。实际 detached 注销／回收组合、root 接入、fresh Medusa 签名及新的线上全头矩阵仍需继续。Rust、非空搜索与分页、抖音／起点及最终 Pages／Actions 产品仍待验收。

复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_startup_worker_exit_allocator.py --library <matching-main.so> --libc <matching-libc.so> --output <private-worker-tls-exit-report.json>
```

## 前一阶段：同次 startup→worker／实际 allocator 正常返回（2026-10-06）

同次 fresh ELF／TLS 运行已贯通 `+0x28040c` 主线程 startup → 实际分配的非空 queue descriptor → 独立 worker TLS／栈 → 六项默认任务 → 正常返回及 argument 清理。**两个基址的 2 个 native 对照／4 项回滚检查已终态通过**。每个 native 组合实际执行 22 次 malloc PLT、1 次 argument free，没有替代 allocator 返回值；六个顶层 caller 完整返回，native 和 Python 分别记录 **48 次嵌套 VM 返回**。每项全部 32 槽、虚拟栈、image、TLS、libc globals、全部保留 mapping 页，以及最终 guest／image／双方 TLS／映射、OS／clock／wait／wake 顺序均一致。

主线程／worker 的显式线程 ID 分别为 137／271，使用独立 64 KiB 栈。早期组合只有 `+0x3e2f3c` guard owner 不一致，原因是 native oracle 仍固定返回主线程 gettid；改为随当前 TPIDR 的显式 provider 后关闭差异，没有复制 native TLS 或放宽断言。正式验证也修正了临时 negative fixture 的 once 地址，最终全部 CLI exit 0。

生产入口为 [run_default_queue_worker](python/vm9_startup_allocator.py)。unmapped 栈、第三项 busy once、第三次 broadcast 失败，以及六项任务完成后重新引入 argument 所有权，均证明整个 worker 的 guest／mapping／protection／cursor 回滚；主线程已提交状态保留，外部 provider 效果不回滚。small free、主线程 startup、独立 worker 分配共享回归 **32／24**全部通过。证据：[同次实际 allocator worker](evidence/vm9_same_startup_worker_actual_allocator_native.json)、[共享回归](evidence/vm9_same_startup_worker_actual_allocator_regression.json)。

该前一阶段的正常返回只完成 argument 清理；support 和 allocator TSD 仍由 TLS 持有。上方最新 key 退出检查点已恢复自然注册的 **matching libc `+0x99584`** 及其有界 cleanup／internal-free 分支。**实际 allocator 与完整 pthread_exit 的组合、完整 root、fresh Medusa、线上矩阵、真实 OS 线程创建／终止仍未通过。** Rust、非空搜索与分页、其他平台和最终 Pages／Actions 产品仍待后续验收。

复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_startup_worker_allocator.py --library <matching-main.so> --libc <matching-libc.so> --output <private-composed-report.json>
```

## 当前主线程 startup／独立 worker allocator 检查点（2026-10-06）

`+0x28040c` 主线程启动现已接回实际 matching libc malloc：两个基址的 **2 个 native 对照／3 项回滚检查**通过。每次有 16 次实际 malloc、3 个显式 guest thread-create 请求和 2 次析构注册；全部 32 槽、主 image、主线程 TLS、libc globals、owned mappings 的字节，以及 OS、线程描述符、注册与映射顺序一致。第三次 thread-create 失败时，guest 页／mapping／protection／cursor 回滚，外部 provider 已发生的效果保留。生产入口为 [initialize_main_startup](python/vm9_startup_allocator.py)。

独立 worker 首次分配已恢复 `+0x99610 → +0x99600/+0x8e0ec → +0x996d4` 的 TSD fallback：临时环链、实际 128 字节分配、保留 padding 的字段初始化、key 发布和节点移除。显式 foreign live-node 控制也验证了非空环链保留。默认 1／2 个 arena 的选择、arena 1 构造、实际 OS region 注册贯通；`+0x7de3c/+0x8ed90` 还会为 worker 实际分配 arena 指针表，省略它会造成保留 mapping 的真实字节差异。

worker 分配矩阵 **14 个 native 对照／8 项拒绝与回滚检查**通过，覆盖两基址、small／large／mixed、两 worker、单 CPU 与 40 次 65536 字节跨 region。每次返回都比较 globals、TLS 和全部保留 mapping 页；相关 tcache、region、cold、large、serial 默认任务回归 **148／70**全部终态通过。证据：[主线程](evidence/vm9_main_startup_actual_allocator_native.json)、[独立 worker 分配](evidence/vm9_worker_actual_allocator_native.json)、[共享回归](evidence/vm9_worker_actual_allocator_regression.json)。

这些结果仍采用显式虚拟 OS 服务、线程输入和串行调度。这一较早阶段尚未完成同次 worker；上方最新组合现已通过正常 argument 清理。此较早检查点尚未执行实际 allocator 的 TLS 退出；上方最新检查点现已验证有界 key 清理。**完整 pthread_exit／root／fresh Medusa 签名和线上矩阵仍未通过**；arena table 扩展、inflight TSD 重入、full-bin／GC、large cache／free／huge 和其余 callback 仍有明确拒绝边界。真实 OS 线程创建和完整物理 libc 栈不在本轮证据范围。

复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_worker_allocator.py --library <matching-main.so> --libc <matching-libc.so> --output <private-worker-report.json>
python -B platforms/bytedance/tomato/python/verify_vm9_startup_allocator.py --library <matching-main.so> --libc <matching-libc.so> --output <private-startup-report.json>
```

## 当前默认任务与实际 allocator 组合（2026-10-06）

新增 [vm9_startup_allocator.py](python/vm9_startup_allocator.py) 的 `initialize_default_task()`，现已将 `+0x280554` 的六项默认 VM 正文接回从 fresh ELF/TLS 自然启动的 matching libc allocator。两基址各一组实际原生代码对照通过，均完整返回六个默认 caller，并分别计数 native/Python 的 **48 次嵌套返回**。首次 0x4000 请求实际执行 cold boot、CPU FILE 生命周期、atfork/table/TSD，再完成六次实际 public large 分配；这些 owned mapping 中的初始化结果均逐 caller 匹配，没有显式分配器提供返回指针或 native 初始化快照输入。

新组合通过 **2 个 native 对照／4 项拒绝与回滚检查**，旧默认任务、public large 和自然 cold 回归 **42／21** 均通过。证据：[实际 allocator→默认任务](evidence/vm9_default_task_actual_allocator_native.json)、[回归](evidence/vm9_default_task_actual_allocator_regression.json)。这一阶段仍使用显式虚拟 OS／broadcast、合成独立线程栈与 TLS；同次 startup worker 的真实 allocator 组合、root 和 fresh Medusa 尚未完成。

## 当前 allocator 检查点（2026-10-06）

Python 已从 fresh ELF／受控 TLS 输入贯通默认 empty-config libc 冷启动，实际读入 CPU 文件、释放 FILE 缓冲、注册 atfork、发布 arena table、迁移 static TSD，并自然返回 `flag=0`。没有在 `+0x8e41c` 提前返回，没有人工设置 ready flag，也没有用 native 初始化快照提供 Python 输入。该冷启动阶段覆盖默认虚拟 OS 服务下的 0 至 14336 字节 public small 请求；后续新增章节另验证 14337 至 65536 字节的空 large-cache 分配。两者均不代表 all-branch allocator 或完整独立 Medusa 已完成。

本轮新增 **96 个 native 对照／27 项拒绝与回滚检查**；旧 free、runtime boot、stdio 和 readonly FILE 回归 **152／64** 全通过。详细边界、复现命令和下一处 large 分配见下方“实际 FILE 读入、CPU 查询与默认冷启动自然返回”。

## 验证结果与输入边界

| 验证范围 | Native 对照 | 拒绝／回滚检查 | 已比较内容 |
| --- | ---: | ---: | --- |
| OP45 寄存器相等分支 | 308 | — | 两种基址、全部寄存器索引、正负位移边界、taken／not-taken、32 槽无写入 |
| 主线程 caller／默认 enqueue | 4 | 13 | 86 步、32 个终止槽、guest、全部主 image、TLS、generation、分配及有序副作用 |
| executor／queue worker support 前段 | 16 | 6 | 冷／热 key、两种基址和线程 ID、唯一引用清空、TLS 发布、generation、dispatch 参数 |
| executor context／emulated TLS | 8 | 4 | 冷／热 emulated TLS、实际 ELF descriptor、分配、字段／padding、guest／image／TLS／generation／有序副作用 |
| matching libc condition／owned wrapper | 92 | 5 | timed／untimed、shared／private、errno、generation、过期／负 deadline／上限截断、clock／futex 顺序、mutex 转移 |
| queue callable 生命周期／循环 | 94 | 5 | inline／heap／empty、自移动赋值、擦除和 padding、等待后投递／停止、invoke 与释放顺序 |
| executor deque／poll／signal wait／循环 | 62 | 6 | segment 边界、非重复任务析构／释放、W32 delay、timeout／signal／spurious wake、clock 顺序 |
| 同次 fresh 启动→独立 TLS→空闲 worker→清理 | 8 | 6 | 启动生成 argument、完整主 image、双方 TLS、generation、分配／副作用、argument free、support TLS 所有权 |
| 同次 fresh 启动→非空默认 worker→六项正文→清理 | 4 | 8 新增、6 调度回归 | 两基址／两线程 ID，独立 worker 栈；每项全部 32 槽、虚拟栈、guest 和六区域，最终 image／双方 TLS／generation、分配及副作用顺序 |
| matching libc key 清理／空 support 析构 | 20 + 8 | 3 | 四轮上限、按 key 排序、失效 generation 保留、callback 前清 value、重新发布／删除后续 key、容量释放及顺序 |
| 同次默认 worker→显式 support key 退出清理 | 1 | 14 调度回归 | 全六项／48 次返回后，TLS value 清零，argument→support→wrapper 三次 free，完整 guest／image／双 TLS／generation 和副作用顺序 |
| emulated-TLS 数组／fallback 链／非空 support | 14 + 12 + 16 | 13 项共享拒绝／回滚 | 延迟重发布与错误状态、容量重新加载、回调前弹出与新增节点、mutex／broadcast／exit bit／引用计数及向量释放 |
| fresh 注册→三类 key 析构组合 | 6 | 同上 | 两种基址，1／3 个注册回调；含合成 support 的混合 key，LIFO、array defer→free、显式 heap 无遗留块 |
| 实际 TLS registry 树析构／fresh 注册退出组合 | 10 + 4 | 同上 | 空／单／三节点树、左链、右子树动态替换、真实 +0x268cf0 callback、emulated key 先于 fallback 的顺序 |

主线程每次使用 16 次分配、3 次成功的 guest thread-create 请求、2 次析构注册、1 次 condition wake，没有 free。线程 entry 分别是 `+0x326a2c`、`+0x3260a4`、`+0x3260a4`。Python 生成了线程参数、共享 executor、两个 queue 和第一个 queue 的 48 字节任务向量。它在 `+0xa71c8` 退出。

两边分别创建 fresh ELF 与显式 fixture 输入。Native 退出内存和寄存器仅作为 expected outputs；Python 没有读取 native 函数或 VM 入口快照，也不执行 native 指令。worker 对照独立构造逻辑 argument／support 输入，没有用主线程 native 输出灌入 Python。worker 冷 key 控制显式占用 generation 的前两个槽；这些合成表值在 native 入口写入，避免覆盖 libc 的已解析重定位页。

主线程单独对照的 thread-create 环境只发布 guest handle 并记录 entry／argument，**不运行 worker、不创建 host thread**。新增组合对照随后显式调度第一个 executor worker 或第三个空闲 queue worker。有序比较排除了 pthread 输出的临时物理 scratch 地址，仍比较真实发布的 handle、entry、argument、顺序和其他副作用；报告字段 `physical_thread_output_scratch_compared=false` 明确记录该范围。未比较完整物理栈。

## OP45 修正的关键证据

启动 VM 在 `+0xa7158` 的分支之前，native／Python 的全部 32 槽一致。旧解码将第二寄存器高位取自 bit 25，错误比较 R2／R1；native 的 `+0x16ecec` handler 用 bit 21，实际比较 R2／R17。两者相等时跳到 `+0xa7180`，选择 `+0x281408 → +0x28054c` 的 RET 清理回调。

该 handler 恢复的是 64 位寄存器 equality。此前按 `sub=0/33/53` 分别解释为 nonpositive／zero／inequality 的猜测已移除：这些位属于寄存器和位移。新 verifier 使用合成指令直接对照 handler，同时完整启动 caller 证明 dispatch 也经过该 handler。生产实现没有针对 bytecode PC 的特例、trace hook 或 branch hook。

`vm_full.py` 是共用解释器，因此本次重新运行已有回归：[vm9_startup_regression_20261005.json](evidence/vm9_startup_regression_20261005.json)。fresh root 的 8 组、旧 component 的 4 组／16 段 VM／76 条子树、state owner 的 52 组／6 个拒绝、parser digest 的 142 组／5 个拒绝均通过。旧 component 仍保留自己的 native 入口输入边界，没有被重新标成独立启动。

## Arena boot body and once gate (2026-10-05)

The first `+0x280890` arena initializer is now reproduced from fresh ELF pages and an explicit allocator boundary. Two image bases (`0x122c0000` and `0x775c205000`) match the native body: one `0x4000` allocation, complete zero fill, eight published pointers at `base+0x3e09a8`, and the serial `+0x32a0a0` state transition. The native image table is observed explicitly because the differential oracle does not copy mutated image pages back into its input dictionary. A null allocator is rejected before any guest-page mutation.

This closes only the first arena publication body. The nested `+0x280970` and seven `+0x2809f8` initialization VMs, OS region registration, thread-exit destruction, complete allocator boot, and independent current Medusa remain open. Evidence: [vm9_arena_boot_native_20261005.json](evidence/vm9_arena_boot_native_20261005.json).

## Worker 调度、等待与所有权

`attach_worker_support` 对应 `+0x326a2c/+0x3260a4 → +0x32cc40 → +0x326120`。冷路径创建 support key，析构入口为 `+0x32ce6c`，完成串行 guard 发布；热路径复用 key。native 随后先清空 argument 的唯一 wrapper 引用，再将 wrapper 发布到当前线程的 TLS。

`initialize_executor_context` 独立恢复 `+0x326b18`：调用既有 Python emulated-TLS 模型处理实际 ELF descriptor `+0x3d1340`，冷路径分配 128／23 字节，发布 context 指针、初始化 enable、vtable、自引用和零字段，保留未写 padding。原有 8 个冷／热控制及 4 个拒绝检查保持通过。

`wait_condition` 和 `wait_owned_condition` 已恢复 matching libc 的 wait／timedwait 与 `+0x329574/+0x3295c4`。timed wait 先按 condition bit 1 选择 realtime／monotonic，将 absolute deadline 换为 relative timespec。过期 deadline 返回 110 并保持锁，不调用 futex；发生 futex 时先 unlock，返回后 relock。matching libc 使用 futex operation 0／128；真实 bionic errno 在 TP+0x10。原始负 syscall 错误保留 errno，只 -110 成为返回 110，-4 等在该 wait 内返回 0。owned wrapper 还恢复了 signed deadline clamp 和向零截断的秒／纳秒换算。报告区分“过期保持锁”和“futex 返回后重新加锁”，不会将未执行的解锁标为通过。

queue 的 `+0x326578` 已恢复取首任务、48 字节向量擦除、unlock、invoke、析构与等待循环。`move_callable`／`assign_callable`／`destroy_callable` 支持已验证的两种 inline vtable；heap ownership 移动会清 source，inline copy 保留 source，self assignment 变空。普通析构与 reset 的 pointer 清空行为不同。94 组原生对照验证 heap／inline／empty、擦除首／中／尾、多任务消费、等待期间投递和空队列停止，并比较完整 guest 与保留的 padding。**这些 queue 调度控制把任务正文设为双方相同的显式环境回调，未执行默认初始化 VM。**

executor 的 `+0x326dfc` poll、`+0x326ec8` 取到期任务、`+0x326f48` next-delay、`+0x32722c/+0x32725c` deque pop 和 `+0x328958` 循环已有 Python 模型。每个 segment 容纳 512 个 pointer；弹出后清 slot、更新 head/count，按 native spare-block 规则释放旧 segment。非重复任务执行后析构 callable 并 free 64 字节 task；next-delay 使用 signed W32 差值，空队列返回 -1。repeat 的插入／排序尚未恢复，已知重复任务在 invoke 前拒绝；callback 将任务转为 repeat 的情况也拒绝。

signal wait 恢复 `+0x328a84 → +0x328b4c/+0x328bac/+0x328c1c`：在 controller mutex 下处理 counter，用 monotonic remaining duration 转成 realtime deadline，保留 realtime 的微秒截断／饱和和 owned wrapper 的上限。62 组控制比较完整 guest/TLS、返回值及有序 clock/futex/free/invoke，覆盖超时、signal、spurious wake、停止、跨 segment 和 W32 溢出。**时钟和 futex 结果仍为显式合成环境输入；这些不是 f13 冻结或线上时钟证据。**

`run_startup_worker` 把 support、context、dispatch 和正常 argument 清理组合起来。8 组控制在同一次 native 运行中先执行主线程，再显式调度其生成的 executor 或空闲 queue worker；Python 则从自己独立的 fresh ELF 输入重新生成参数，再使用独立 worker TLS。双方全部主 image、guest、主线程及 worker TLS、generation、分配和副作用一致。executor 增加 128／23 字节分配；空闲 queue 无额外分配。worker 返回时只 free 自己的 argument，support wrapper 仍保留在 pthread TLS。**OS thread-exit 析构尚未执行；保留 support 不能写成所有线程资源均已释放。**

主线程非空 enqueue／growth、线程创建失败／异常、竞争 guard、executor cancellation、repeat insertion、未恢复的实际任务正文仍有明确拒绝边界。新增 22 个拒绝检查覆盖错误地址／锁／deadline、超界、未知对象及回调失败，并证明 guest 页回滚；**已调用的外部环境服务不随 guest 页自动回滚**。这不是 native 失败清理、并发调度或完整取消的等价性证明。

## 复现与研究接口

Matching ELF 和 libc 必须由本地私有路径提供。公开仓库只含实现、offset／count／boolean 证据，不包含样本、解码常量、key／payload、设备或会话数据。

```text
python -B python/verify_vm9_branch_eq.py --library /private/libmetasec_ml_71332.so --output /private/branch-eq.json
python -B python/verify_vm9_startup_init.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/startup-init.json
python -B python/verify_vm9_startup_workers.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/startup-workers.json
python -B python/verify_vm9_condition_wait.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/condition-wait.json
python -B python/verify_vm9_queue_callable.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/queue-callable.json
python -B python/verify_vm9_executor_poll.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/executor-poll.json
python -B python/verify_vm9_startup_worker_loop.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/startup-worker-loop.json
```

`initialize_startup_caller` 接受 pages、entry SP、return、thread pointer、image base、VM module 和 allocator／thread-create／析构注册／condition 服务，返回 steps、exit offset、32 槽和已执行回调清单。`attach_worker_support` 接受独立 worker argument、kind、key-create／set-specific 服务，返回下一次 dispatch 的参数地址。`initialize_executor_context` 接受 context 地址及 emulated-TLS getter，初始化后续 executor poll 所需字段。新增 `run_queue_callable`、`poll_executor`、`wait_signal_controller`、`run_executor_context` 接受明确的 free／invoke／clock／futex 服务；`run_startup_worker` 再接受 argument、kind、独立 thread pointer、pthread key 服务和 emulated-TLS getter。任务 body、停止条件及 OS 退出由调用方提供，不应以无操作回调代替未知初始化逻辑。它们都是研究组件，尚无可用的 Medusa 请求头返回值。

脱敏原始控制摘要：[分支](evidence/vm9_branch_eq_native_20261005.json)、[启动](evidence/vm9_startup_init_native_20261005.json)、[worker](evidence/vm9_startup_workers_native_20261005.json)。

新增脱敏控制摘要：[condition wait](evidence/vm9_condition_wait_native.json)、[queue](evidence/vm9_queue_callable_native.json)、[executor](evidence/vm9_executor_poll_native.json)、[同次启动与空闲 worker](evidence/vm9_startup_worker_loop_native.json)。256 组新控制／22 个拒绝检查通过；主线程 4 组／13 个拒绝和 worker support/context 24 组／10 个拒绝再次通过，见 [受影响回归](evidence/vm9_worker_scheduler_regression.json)。上述 worker 调度批次未改共享 VM 解释器；随后首表初始化批次新增的乘法指令见下文。

此前另有一个明确标注为 **native-only** 的 [guest 调度探针](evidence/vm9_executor_native_wait_boundary_20261005.json)：在同一 fresh native 运行中，主线程发布三个 worker 后，显式调度第一个 executor worker、提供独立 guest TLS 和虚拟 clock，贯通 support、context 和 poll，停在 `+0x3485c0` 的 `pthread_cond_timedwait` 前。额外分配为128／23字节。它没有运行 wait、创建 host thread或完成 Python worker；clock 是调度探针的显式输入，不是 f13 冻结或线上签名证据。

最新 [native-only 默认任务前段探针](evidence/vm9_default_task_prefix_boundary.json) 在绑定 memset／strlen GOT 后，以 2,000,000 条原生指令预算继续同次启动生成的非空 queue worker。只观察到第一个 caller `+0x280590` 进入，尚未观察到任何默认 caller 的 VM 返回位置；其嵌套 VM entry 为 `+0xedcf0/+0xee3b0`，新增一次 16384 字节分配。多个 VM entry 不等于多个默认 caller 已完成。该探针因指令预算耗尽结束，不证明无限循环，也没有验证 Python 默认任务。这项旧探针的预算边界已被下述更长的 fresh 返回验证推进，原探针本身仍仅证明前段。

## 第一个默认 caller 与首表完整初始化（2026-10-05）

`run_first_default_caller` 已恢复 `+0x280590 → VM +0xedcf0 → +0x281598 → +0x32a0a0`，再执行 `+0x280890` 的完整 initializer：一次 `+0x280970 → VM +0xee3b0`，七次 `+0x2809f8 → VM +0xeea70`（包含最后一次 tailcall）。首段为 61,633 步，后七段各 125,576 步；这八次返回属于第一个默认 caller，不能算成八个默认任务。

| 新增范围 | Native 对照 | 拒绝检查 | 实际边界 |
| --- | ---: | ---: | --- |
| arena prefix／显式 once gate | 14 | 7 | 两种基址、三种 gate state、两种分配偏移；prefix 停在首个 nested caller 之前 |
| OP17/sub57 W32 无符号乘法 | 240 | — | 全部寄存器索引、溢出、忽略上半字、hidden backing 有／无；普通 32 槽不变 |
| 第一个 caller／两个 nested caller 前置与边界 | 20 | 5 | 全部 34 个初始 backing word、物理前置栈；首回调包或完整 nested 返回 |
| 完整首表 initializer | 2 | — | 16 次 nested 返回：每次 32 个终止槽及整个 guest heap；最终全部主 image 和分配顺序 |
| 第一个默认 caller cold／hot 完整返回 | 4 | — | 两种基址；cold 每次八次 nested 返回，hot 跳过；32 槽、虚拟栈、heap／image 和 allocation／broadcast 时序 |
| 剩余五个 caller 的前置／首回调 | 40 | — | 两种基址 × 两种栈预填值 × 五个 caller × 两个边界；正文停在首个未知 initializer 之前 |

**纠正旧提交 `1b8aa32` 的完成声明。** 当时只实现了 0x4000 字节分配／清零／八个指针发布，却将 once 写成完成值 -1；旧 verifier 没有比较完整 initializer 的完成状态。现已将前段拆为 `initialize_arena_boot_prefix` 与 `begin_once_arena_boot`：后者保持 once=1，表示 pending。`call_once_arena_boot` 只有完整 initializer 返回后才 lock、写 -1、unlock、broadcast，拒绝把 `ArenaBootPrefixResult` 当成完成。旧 evidence 文件同名更新并保存纠正来源。allocator 输出不要求页对齐，完整 fresh 控制实际使用 guest+0x4300。

首表与第一个 caller 的 Python 输入来自各自 fresh ELF、函数入口栈、TLS 和显式 allocator，不来自 native 输出或入口前导快照。`prepare_initialization_caller` 独立生成 wrapper 和 generic VM ABI；完整退出会检查 TLS canary 并将终止槽写回 backing，供后续 nested caller 复用。新恢复的 OP17/sub57 将两个 W32 无符号操作数相乘，低／高 32 位分别符号扩展到 hidden slot 32／33。

仍保留明确的环境边界：分配地址由 allocator provider 提供；broadcast 在两边使用同一个显式服务；这里只比较串行且无竞争的 matching libc mutex。once=1 的等待路径拒绝执行。没有真实 host thread、并发 worker 或 OS condition runtime 完成证据。完整首表初始化也不等于真实 jemalloc arena／OS region boot。

新增复现命令（在本目录执行）：

```text
python -B python/verify_vm9_arena_boot.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/arena-gate.json
python -B python/verify_vm9_multiply.py --library /private/libmetasec_ml_71332.so --output /private/multiply.json
python -B python/verify_vm9_default_task_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/default-prefix.json
python -B python/verify_vm9_arena_initializer.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/first-initializer.json
python -B python/verify_vm9_first_default_caller.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/first-caller.json
python -B python/verify_vm9_remaining_default_callers.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/remaining-prefix.json
```

对应脱敏证据：[纠正后的 gate](evidence/vm9_arena_boot_native_20261005.json)、[乘法](evidence/vm9_multiply_native_20261005.json)、[caller 前段](evidence/vm9_default_caller_prefix_native_20261005.json)、[完整首表](evidence/vm9_first_arena_initializer_native_20261005.json)、[第一个 caller](evidence/vm9_first_default_caller_native_20261005.json)、[其余五个前段](evidence/vm9_remaining_default_callers_prefix_native_20261005.json)。受影响回归为 fresh root 8／11、parser 142／5、同次空闲 worker 8／6（native／negative），见 [回归摘要](evidence/vm9_initializer_regression_20261005.json)。

## 第二个默认 caller 的完整返回（2026-10-05）

第二个 `+0x280610 → VM +0xede10` 使用 once `+0x3e0a30` 和 initializer `+0x280a74`，发布到 `+0x3e09f0`。其嵌套 caller 为 `+0x280b54 → VM +0xeee60`（54,721 步），再执行七次 `+0x280bdc → VM +0xef520`（各 38,536 步），包括最终 tailcall。`+0x281638/+0x28164c` 封装的 memset／memcpy 已根据本地 native 实现恢复。

两种基址的四个 cold／hot 组合都通过，比较 32 槽、虚拟栈、heap、全部主 image、once 状态与分配／broadcast 时序。两个 nested caller 的前置／完整返回另通过 12 个控制；9 个异常案例确认未知布局、busy once、锁已持有、空／未映射分配、broadcast 失败、tagged return、未映射栈和 canary 改变均拒绝，guest 页及 VM base 恢复。外部 provider 的副作用不由 guest transaction 回滚。

研究接口 `run_default_initialization_caller(..., table_index=0|1)` 选择已恢复的前两项；`run_first_default_caller` 保留第一个 caller 的入口。此阶段当时仅接受两项；后续六项验证后扩展为 0..5，超出范围仍拒绝。Native 输出仍只用作 expected output，allocator 与 broadcast 仍是显式环境服务。

```text
python -B python/verify_vm9_arena_initializer.py --table-index 1 --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/second-initializer.json
python -B python/verify_vm9_second_initializer_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/second-nested.json
python -B python/verify_vm9_first_default_caller.py --table-index 1 --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/second-caller.json
```

证据：[第二张表逐个返回的 16 次对照](evidence/vm9_second_arena_initializer_native_20261005.json)、[第一个 caller 的四组回归](evidence/vm9_first_default_caller_regression_20261005.json)、[第二项 nested 与拒绝检查](evidence/vm9_second_nested_callers_native_20261005.json)、[第二个 caller](evidence/vm9_second_default_caller_native_20261005.json)。这项阶段证据只比较两个 caller；后续六项串联结果见下文，完整 worker 仍未验证。

## 六项默认初始化正文与串联（2026-10-05）

`run_default_initialization_caller` 已扩展为 `table_index=0..5`，六项均完成；`run_default_initialization_task` 恢复 `+0x280554` 的外层顺序：前五项普通调用，第六项恢复外层 SP／FP／return 后 tailcall。它是已验证的串行默认任务正文，还没有接回同次 fresh 主线程发布的非空 worker。

| 顺序 | 默认 caller | Initializer | 第一个 nested caller／VM | 重复七次的 caller／VM | Python nested 步数（首段／后段） |
| --- | --- | --- | --- | --- | --- |
| 1 | `+0x280590` | `+0x280890` | `+0x280970 / +0xee3b0` | `+0x2809f8 / +0xeea70` | 61,633 / 125,576 |
| 2 | `+0x280610` | `+0x280a74` | `+0x280b54 / +0xeee60` | `+0x280bdc / +0xef520` | 54,721 / 38,536 |
| 3 | `+0x280690` | `+0x280c58` | `+0x280d38 / +0xef910` | `+0x280dc0 / +0xeffd0` | 44,353 / 30,856 |
| 4 | `+0x280710` | `+0x280e3c` | `+0x280f1c / +0xf03c0` | `+0x280fa4 / +0xf0a50` | 39,745 / 69,256 |
| 5 | `+0x280790` | `+0x281020` | `+0x281100 / +0xf0e40` | `+0x281188 / +0xf1500` | 47,809 / 74,376 |
| 6 | `+0x280810` | `+0x281204` | `+0x2812e4 / +0xf18f0` | `+0x28136c / +0xf1fb0` | 58,177 / 163,976 |

六项单独对照共 **24 个 native case**（六项 × 两基址 × cold／hot）。cold 默认 caller 为 39 步，hot 为 23 步；每个 cold 完成八段 nested VM。第三至第六项的 verifier 还在每次 nested 返回处比较全部 32 槽和完整 guest heap；前两项有各自单独的逐次 initializer 返回证据。旧报告中的 `all_six_default_callers_complete=false` 表示那份单项报告没有验证整链，不能用它代表更新后的项目结论。

整链另有 **4 个 native case**（两基址 × cold／hot）。cold 每次提供六个不同的 0x4000 字节区域，完成六个 caller 和 48 次 nested 返回；hot 的六个 once 均完成，因而没有分配或 broadcast。每个默认 caller 返回时比较 32 槽、虚拟栈、完整 guest heap 和全部六个区域，最终比较全部主 image 页；ordered allocator／broadcast、各 once 状态及第六项 tailcall 栈均一致。两个 cold 合计观察到 96 次 nested 返回，但不是 96 个独立默认 caller。

增加 **5 个整链拒绝／回滚检查**：第三项 once busy、第三次 allocator 返回空、第三次 broadcast 失败、未映射栈和 tagged return。前两项已执行后第三项失败，整条 guest transaction 也恢复原页。外部 provider 已发生的副作用不会被回滚。现有第二项 9 个拒绝案例在扩展后再次通过（非法 index 改为 6）。

Native oracle 可选择只在 wrapper／PLT 区间安装观察 hook；VM 指令本身仍由 Unicorn 执行。第三项的完整逐指令观察和区间观察报告完全一致，用作这项诊断优化的控制。它提高验证速度，不是 Python signer 性能优化结果，也没有删去 allocator／broadcast 或返回边界的检查。

```text
python -B python/verify_vm9_first_default_caller.py --table-index 2 --bounded-hooks --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/caller-3.json
python -B python/verify_vm9_first_default_caller.py --table-index 3 --bounded-hooks --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/caller-4.json
python -B python/verify_vm9_first_default_caller.py --table-index 4 --bounded-hooks --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/caller-5.json
python -B python/verify_vm9_first_default_caller.py --table-index 5 --bounded-hooks --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/caller-6.json
python -B python/verify_vm9_default_initialization_task.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/default-task.json
```

证据：[六个独立 caller](evidence/vm9_all_default_callers_native_20261005.json)、[完整默认任务](evidence/vm9_default_initialization_task_native_20261005.json)。这里只推送脱敏状态、offset／count／boolean，不推送私有 ELF、初始化后的解码表或 native memory。没有 JVM 或 native 输入快照进入 Python；ELF 字节码、显式合成入口栈／TLS、已映射 allocator 区域、无竞争 matching libc mutex 和 provider broadcast 仍是研究运行条件。

**本节完成的是有界串行默认任务正文。** 同次主线程发布的 worker 与正文整合已由下一节推进；真实 allocator global／arena／OS region boot、OS thread-exit TLS 析构和 fresh 请求签名仍未验证。不能把六项默认 caller 的完成解释为独立 Python Medusa 已完成。

## 同次 fresh 非空 worker 完整任务与 argument 清理（2026-10-05）

`run_default_queue_worker` 已将串行正文接回主线程实际生成的第二个 worker（index 1）。Native 从 `+0x28040c` 启动，在调度边界运行 `+0x3260a4 → +0x326578 → +0x280554`，完整执行六项正文，进入一次 queue wait，再由显式停止输入退出并清理 argument。Python 独立生成同一批 descriptor、queue 和任务，使用独立 worker 栈及 TLS。验证没有把 native startup 输出、入口页或寄存器灌入 Python。

新入口的栈关系来自 wrapper ABI：worker 入口 SP 为 S，queue SP 为 `Q=S-0xd0`，任务存储为 `S-0xc0`，任务 FP 为 `S-0x80`，返回地址为 `image+0x326620`。queue 推导 X19～X26，X27/X28 从明确的入口值保留。`+0x329f68` 及 matching bionic 的解锁保存帧会留下一个由第六项 tailcall 读取的未覆盖槽；模型按 ABI 构造这些保存字。主线程栈残留及 native 快照不作为替代输入。

**4 个 native case 全部通过**（两种加载基址 × 两种线程 ID）。每个 case 比较六次 caller 返回的全部 32 槽、实际虚拟栈、完整 guest 对象及全部六个 0x4000 区域；最终比较全部主 image、主线程和 worker TLS、pthread generation、22 次分配及有序副作用。每次六项正文有 48 次嵌套 VM 返回，argument 仅 free 一次，wrapper/support 未被 argument 清理释放，仍由 pthread TLS 持有。

新增 **8 项拒绝／回滚检查**覆盖错位栈、不支持的保存寄存器、错误 queue callable、空／多任务队列、未知默认目标、busy once 和首次分配失败。guest 页及 VM base 均还原，失败不释放 argument；provider 的外部副作用不回滚。另有 **8 组空闲 worker／6 项旧调度拒绝检查**回归通过。

```bash
python -B python/verify_vm9_startup_worker_loop.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --default-queue --output /private/startup-default-worker.json
```

证据：[同次启动与非空默认 worker](evidence/vm9_startup_default_worker_native_20261005.json)、[空闲 worker 回归](evidence/vm9_startup_worker_regression_20261005.json)。这里验证的是显式 allocator／映射区域、无竞争 mutex、provider broadcast、虚拟 futex 和显式停止服务下的组合；未比较整个 interpreter 物理 scratch 栈，未创建 host thread，未执行真正的分配器 free 或 OS thread exit。**有界非空 worker 的任务执行和 argument 清理已完成，完整独立 Medusa 仍未完成。**

## 匹配 libc 的 key 清理与空 support 退出析构（2026-10-05）

新增 `vm9_allocator.pthread_key_clean_all` 恢复匹配 libc `+0x685a0` 的串行 key 清理阶段：按 index 0～140 检查 active generation、TLS generation、非零 value 和 destructor，再次读取 generation 后先清空 value，随后调用析构；有调用时重复，最多四轮。失效／过期 generation 及没有析构的 slot 不会像 `pthread_getspecific` 那样清 value。callback 重新发布当前 value、发布后续 key 或删除后续 generation 的行为均按当前状态继续遍历。

`destroy_empty_worker_support` 恢复 `+0x32ce6c → +0x32ccf0` 的空向量路径：条件向量容量、引用向量容量、support、wrapper 按 native 顺序释放；null wrapper 和 null support 分支也已对照。非空向量在任何 free 前拒绝。`run_worker_thread_key_cleanup` 将这项析构接入 key dispatcher；未恢复的 destructor target 会拒绝并还原 guest 页，provider 的外部副作用仍不回滚。

独立控制 **20 组 key cleanup + 8 组 support 析构 + 3 项拒绝／回滚**通过，使用两个 image base 和明确的合成 callback。额外 **1 组同次 fresh 非空 worker 组合**在 `+0x326108` 正常返回位置显式调度真实 libc key 清理器，再执行真实 `+0x32ce6c`；Python 由独立生成的 worker 状态运行同一 key 阶段。该组合仍核对六项默认 caller／48 次嵌套返回、image／guest／双方 TLS／generation 和有序副作用。最终 support TLS value 为零，free 顺序为 argument→support→wrapper，各一次。8 组空闲 worker／6 项旧拒绝检查再次通过。

```bash
python -B python/verify_vm9_thread_key_cleanup.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/thread-key-cleanup.json
python -B python/verify_vm9_startup_worker_loop.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --default-queue --thread-key-cleanup --image-base 0x122c0000 --thread-id 137 --output /private/default-worker-key-cleanup.json
```

证据：[key 清理与空 support](evidence/vm9_thread_key_cleanup_native_20261005.json)、[同次默认 worker 与 key 清理](evidence/vm9_default_worker_key_cleanup_native_20261005.json)。组合中 OS key 清理的调度边界是显式输入；没有运行 `pthread_exit` 的其余线程注销、线程栈 unmap 或 host thread termination。**本节的空 support key 析构路径已完成，不能据此宣称完整 OS thread exit。** emulated-TLS、fallback 链、非空 support 和实际 registry 析构由下一节推进；真实 allocator 和 fresh 请求仍未验证。

## Emulated-TLS、fallback 链与非空 support（2026-10-05）

`destroy_emulated_tls_array` 已恢复 `+0x3439bc`：非零延迟计数先减一，再调用 set-specific 重新发布数组；native 不检查该服务的错误返回，模型保留这一行为。延迟为零时跳过空 slot，经 payload 前 8 字节找到原始分配块并 free，最后 free 数组。每次非空 slot 的 free 后重新读取 capacity，slot 内的指针不清零。14 个 native case 覆盖空／非空数组、64 位延迟计数、set-specific 失败被忽略、free 后容量缩小／增长。

`run_emulated_thread_destructors` 已恢复 `+0x342854`：通过实际 descriptor 获取链头，保存 successor，在 callback 前把节点从链头移除，callback 后 free 节点并重新读取链头，最后清零注册 flag。12 个对照覆盖空／单／多节点、callback 新增节点、callback 清头、getter 返回另一个链头地址。这里的任意 callback 和直接控制 getter 仍是明确的合成服务；后面的组合改用实际独立 Python getter。

`destroy_worker_support` 已恢复 `+0x32ce6c → +0x32ccf0` 的有界非空向量：condition/mutex pair 先解锁再 broadcast；引用对象在 normal mutex 内设置 exit bit 4 并 broadcast，解锁后重新读取向量 pointee，递减共享计数。old count 为零时按 vtable+0x10 调用明确的 shared destructor provider。最后依次 free 两个向量容量、support、wrapper。16 个 native case 覆盖 shared/private mutex、多个 pair、计数零／正值、别名引用、broadcast 更换 pointee、混合向量。实际 concrete shared 零引用析构体仍未恢复，不能把传入 provider 算成它已完成。旧 `destroy_empty_worker_support` 保留空向量的拒绝边界，并复用完整的向量实现。

`destroy_scoped_tls_tree` 恢复实际已注册的 `+0x268cf0 → +0x269060/+0x269068`：先处理左子树，随后读取右子树，再 free 当前节点；析构本身不清理树 header。10 个 native case 覆盖空／单／三节点、左链以及 free 左节点时替换右子树。`run_worker_thread_key_cleanup` 自动执行这个已知 callback；其他 fallback callback 必须提供已实现服务，否则拒绝，不替换成无操作函数。

新增 **6 组同次 fresh 注册→key 清理组合**，真实 native 从 `+0x34265c` 创建 fallback/emulated-TLS，再运行匹配 libc 的完整 key dispatcher；Python 从独立 fresh ELF、TLS、generation 和显式 allocator 输入运行注册及退出。1／3 个 callback 按 LIFO 执行，数组先延迟一次再 free；两组混合控制还包含明确构造的空 support key。没有 native 输出页或寄存器作为 Python 输入。显式 heap 的分配块全部释放，guest／全部主 image／TLS／generation／分配与副作用顺序均相同。

另有 **4 组实际 TLS registry fresh 初始化→注册→退出组合**，native 执行 `+0x269880`，注册并实际调用 `+0x268cf0`，Python 执行已恢复的对应初始化和树析构；覆盖空树与明确构造的三节点树。该场景 emulated-TLS key 先于 fallback key，首轮数组 defer 保持 TLS 可用，fallback 运行完毕后下一轮再释放数组。这里没有合成 destructor callback；getter/allocator/pthread 环境仍是显式组件。树节点的填充属于合成控制输入，不能称为实际请求生成的节点。

上述共 **62 个 native case／13 项新增拒绝与回滚**通过。拒绝检查覆盖数组越界／动态增长越界、循环链／树、callback 或 broadcast 失败、缺少 set-specific／getter／未知 callback、未持有或竞争 mutex、缺少 shared 零引用服务；guest 页回滚，外部 provider 影响不回滚。此前 20 组 key／8 组空 support／3 项拒绝回归，以及同次默认 worker 的六项任务／48 次 nested return／key 清理组合再次通过。

```bash
python -B python/verify_vm9_tls_exit_destructors.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/tls-exit-destructors.json
```

证据：[TLS 退出析构与组合](evidence/vm9_tls_exit_destructors_native_20261005.json)、[受影响回归](evidence/vm9_tls_exit_regression_20261005.json)。公开报告只有合成 case、offset／count／boolean 与样本 hash，没有 ELF、native 内存、请求或签名 payload。**三个 key target 及已知 registry callback 的有界退出组件已恢复；完整 OS thread exit 与独立 Medusa 仍未完成。** 未执行 host pthread_exit、真实 allocator 清理、线程列表注销或栈/OS region unmap；未知 callback、并发、实际 shared 对象析构仍是剩余边界。

## 实际 executor shared 析构与 guest pthread_exit（2026-10-05）

本轮恢复与旧的合成 shared callback 分开记录。真实 `+0x326710` 构造器发布的 32 字节 owner 使用 vtable `+0x372670`；shared count 在 `owner+8`，weak count 在 `owner+16`，payload 在 `owner+24`。`release_executor_shared` 对应 `+0x329eb4`，可选不释放 weak 的模式对应 `+0x329e64`。旧 shared count 为零时，实际 `+0x326b04` 经 payload vtable 的 `+8` 调用 `+0x3269cc`；成功的显式 thread join 后清空 payload 的 `+16` handle。weak count 非零时减一，旧值为零时由实际 `+0x326b14` free owner。普通 payload 析构不会 free 静态 executor 本体。

**16 组 native 对照**从双方各自 fresh ELF／TLS 输入运行真实构造器再释放；覆盖旧 shared count 为 1／0／u64 最大值、weak 为 0／1／最大值、空 thread handle、shared-only 和实际已注册 `+0x326984` 析构体。完整 guest、主 image、TLS、分配／create／register／join／free 顺序均一致。这里的 create／join／allocator 是明确的环境服务。`+0x326984` 在真实构造器中注册到 process `__cxa_atexit`；本轮验证其函数体，不把它改称为应用实际注册的线程 callback。这个 executor owner 的类型布局不适用于 support 的关联状态对象；不能用其 vtable 填补此前非空 support 测试的合成 shared callback。

匹配 libc 的样本 SHA256 为 `d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。`vm9_thread_exit.py` 恢复以下实际函数体：

| 顺序与入口（libc 相对 offset） | 恢复行为 |
| --- | --- |
| `+0x6b23c`／`+0x6b2a4` | libc 32 字节线程析构节点的注册／LIFO 执行；先 pop、实际 callback、free，再重读 head；descriptor 为 `+0xdb3a8` |
| `pthread_exit +0x68138` | 先运行 libc 线程析构，再写 pthread `+0x70` 返回值；执行 `+0x58` cleanup 链及 matching key 清理 |
| pthread `+0x78` | 非零 signal-stack 指针触发 disable 和 0x5000 字节 munmap；native 忽略 OS 返回值，仍清指针 |
| pthread `+0x50` | 串行 CAS 0→1；可 join 等状态执行 terminal exit 并保留列表／线程 mapping；state 3 进入 detached 分支 |
| `+0x6837c` | 在 libc `+0xe01d0` list mutex 下重接 next／previous，必要时更新 `+0xe01f8` head；保留当前线程的 links |
| `+0x1be0c` | detached 分支清 tid address、阻塞信号、munmap pthread `+0x20/+0xa8` 的区域，再执行 terminal guest exit |

**54 组 native 对照**在两个 image bases 下覆盖各线程状态、链表头／中／尾、signal stack、joinable 保留区域、detached 回收、OS 错误、callback 动态追加／清 head、实际 registry 树析构、libc 真实注册→退出和 support／emulated／fallback key 组合。另有真实 `+0x326984` 经 fallback 链执行的控制；其 owner/payload 是明确生成的合成状态，真实构造器证据属于前述 16 组，二者不能混称。

`GuestOS.unmap_exact` 仅回收完整 owned guest mapping；Python 实际删除页和 mapping record，Unicorn 实际 `mem_unmap`。对照还比较回收前的完整 region 字节，因此覆盖了 pthread 本体位于待回收区域内的情形。最后一次 munmap 后模型不再读取 pthread。未知／部分 mapping、未知 callback、循环链、竞争 mutex、未知 vtable、缺少 join 或 join 出错等 **11 项拒绝／回滚**通过；guest 页和 mapping record 回滚，外部 provider ledger 不回滚。

同次 fresh 主线程启动 → 非空 queue worker → 六项默认正文／48 次 nested return → argument free → **完整 guest 可 join pthread_exit 分支**，另有 **1 组组合 native 对照／14 项拒绝检查**通过。该控制中的 libc 析构 head 和 cleanup 链为空，support key 非空；成功释放 support/wrapper 后，pthread state 变为 1，执行虚拟 terminal exit。该生成 worker 使用显式 TLS／create／allocator，未实测 host thread、真实线程注销或 allocator 退出。

API `run_pthread_exit(guest_os, ..., get_libc_tls, free, os_call, ...)` 要求显式提供 libc TLS getter、allocator 和 OS 服务；恢复过的 registry／executor callback 自动分派，其他 callback 无 provider 则拒绝。OS 服务接受操作及 ABI 字段，并提供返回值／guest errno；terminal exit 返回可检查的 `GuestThreadExitResult`，不会终止宿主 Python。thread cleanup 节点不由此函数 free；libc 析构节点会 free；两种 ownership 不混用。

从仓库根目录复现：

```bash
python -B platforms/bytedance/tomato/python/verify_vm9_pthread_exit.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/pthread-exit.json
python -B platforms/bytedance/tomato/python/verify_vm9_startup_worker_loop.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --default-queue --pthread-exit --image-base 0x122c0000 --thread-id 137 --output /private/worker-pthread-exit.json
```

公开证据：[70 个组件 native case／11 项回滚](evidence/vm9_guest_pthread_exit_native_20261005.json)、[同次 fresh worker 及回归](evidence/vm9_guest_pthread_exit_regression_20261005.json)。既有 62 个 TLS 退出 case／13 项拒绝、20 个 key case／8 个空 support case／3 项拒绝重新通过；70 个 Python 文件语法检查通过。公开内容只有合成标签、offset／count／boolean 和样本 hash。

## Matching libc 冷启动：映射与早期 boot（2026-10-05）

本阶段将先前停在 syscall 167 的诊断推进到 **真实 native `malloc` 冷启动返回**。路径仍为 `libc+0x1bb08 → +0x8f00c → +0x8e350`，没有 malloc hooks、JVM 或 native 初始化快照作为输入。这里的“真实”指匹配样本的 ARM64 函数体；OS 输入仍是明确的合成服务，尚不是完整 Python allocator。

真实执行先查询 `brk(0)`、申请 256 KiB 匿名 RW mapping，再通过 `prctl(0x53564d41, 0, base, length, name)` 命名。随后申请一页并设为只读，读取明确构造的 `/proc/stat`；CPU 数量读取会重入真实 `malloc`。对齐映射会先释放不对齐的申请，再申请扩展区间并裁掉前后缀。探针最初在重入入口重复清空 key 表，导致 TSD 错误；现在 key fixture 只在首次入口应用，后续实际 key 创建和重入状态完整保留。该探针错误不能当作目标 libc 的初始化缺陷。

**10 组 native 控制**覆盖两个主 image 地址、0／32／4096／8192 字节申请、1／2／4 个合成 CPU 和匿名命名失败。全部返回有效 owned request span；初始化标志 `+0xdb6a0` 变为 0，arena count/table/arena-zero 发布，chunk 常量一致，实际重入 malloc 可见；命名失败仍保留 mapping 并更新 errno。执行有 200,000 条 native 指令上限，所有这些控制在返回处结束。不是绕过失败分支，也不是预算耗尽后的完成推断。

Python owner 新增和恢复内容：

| Owner / 函数 | 已验证行为 |
| --- | --- |
| `GuestOS.name_exact / protect_exact` | 整个 owned mapping 的名称与权限 metadata 原子更新 |
| `GuestOS.unmap_range` | 单个 owned mapping 内按页裁剪，保留剩余内容、名称、权限及描述符；不能跨 mapping 或洞 |
| `GuestOS.unmap_exact` | 保持原来的完整映射要求；线程退出 partial-unmap 仍明确拒绝 |
| `vm9_libc_mapping.map_allocator` `+0x7f56c` | 明确 mmap 结果、命名成功／失败、errno；命名失败不撤销 mapping |
| `map_aligned_allocator` `+0x7f600` | 首次对齐、重新申请、前缀／后缀裁剪；仅写 flag 的一个字节 |
| `sbrk` `+0x1e6c8` | fresh／cached break、增减、溢出、实际返回缓存和 errno；按二进制的 unsigned 判断处理 shrink |
| `configuration_preinit` `+0x8ce70` | 已恢复实际 NULL／空字符串分支；非空配置解析明确拒绝 |
| `vm9_libc_boot.initialize_allocator_mutex` `+0x932ec` | 实际 normal attr 的 mutex 初始化，写 40 字节，保留后续 padding |
| `initialize_base_tree` `+0x89460` | 仅写 root 与两个 sentinel 指针 |
| `extent_boot` `+0x89410` | normal mutex 初始化后，仅清除 `+0xe6928` 的一字节 |
| `preinit_prefix` `+0x8e250` | 从实际入口恢复线程发布、空配置及 base／DSS／chunk／extent，在 `+0x8e2c4` 调用 arena/bin 前停止 |
| `base_boot / dss_boot / chunk_boot` | `+0x7dc7c / +0x7f46c / +0x7f13c`，使用匹配 libc 全局偏移和明确 break 服务 |
| `initialize_rtree` `+0x94ef4` | 1..64 bit 层级、回调地址、节点及缓存索引，保留未写 padding |

**42 组 mapping／sbrk native 对照 + 56 组早期 boot native 对照**比较返回值、guest/TLS、全局字段、mapping metadata、保留页和有序 OS 调用，均从各自 fresh ELF 输入开始。其中两组从实际 `+0x8e250` 入口同次 fresh 贯穿已恢复的早期组件，比较线程发布、base／DSS／chunk／extent 全局状态；只证明 `+0x8e2c4` 前缀，未执行 arena/bin。另有 4 项保留检查和 23 项拒绝／回滚检查；跨页 mutex/tree、radix tree 层级边界、错误 break、缺页、无效 OS 返回及未恢复 munmap 错误路径均覆盖。Guest 页／记录／mapping 游标在拒绝时回滚；外部 provider ledger 不能回滚。

`protect_exact` 只维护 metadata；通用 Python byte-page 读写不会自动执行权限检查。native verifier 会实际调用 Unicorn `mem_protect`。mapping helper 仅支持当前隔离地址策略与有界页大小／power-of-two 对齐。NULL mmap 是明确的 native 控制结果，在此有界 owner 内不创建地址 0 的 mapping；未恢复的 munmap logging／abort 路径明确拒绝，不能以 RET 或默认成功填补。早期 boot 只覆盖实际 normal attr；不模拟 mutex 竞争或任意 pthread ABI。

复现（样本必须私下提供，hash 错误即拒绝）：

```bash
python -B platforms/bytedance/tomato/python/verify_vm9_libc_mapping.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-mapping.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_boot.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-boot.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_cold_malloc.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-cold-malloc.json
```

原有 shared／pthread_exit 的 **70 组 native 对照／11 项拒绝**重新通过，包括保留 `unmap_exact` 的 partial-unmap 拒绝；[回归摘要](evidence/vm9_libc_cold_mapping_regression_20261005.json)。

公开证据：[mapping／sbrk](evidence/vm9_libc_mapping_native_20261005.json)、[早期 boot](evidence/vm9_libc_boot_native_20261005.json)、[native cold malloc](evidence/vm9_libc_cold_malloc_native_20261005.json)。这些只有控制标签、offset／count／boolean 和样本 hash；不包含 ELF、native 页、请求、设备数据或密钥。先前 [cold boundary](evidence/vm9_allocator_cold_boundary_20261005.json) 保留为历史定位证据，不能用它代表当前停止位置。

上述为 2026-10-05 阶段结果。arena/bin、tcache、main/static TSD、真实 base allocation 和默认空配置 preinit 的后续结果见下节；旧证据保留作为历史边界。

## Matching libc arena／base allocation 与冷启动前缀（本阶段）

**本 preinit 历史阶段只完成默认空配置；新的默认 public malloc 冷启动与任务组合见后续章节，独立 fresh Medusa 仍未完成。** 同次 fresh 的 `+0x8e350` 已执行真实 base allocation、initial arena 构造／发布、main/static TSD，以及初始化 mutex 的获取／释放，停止在 CPU 查询前的 `+0x8e41c`。成功状态是 `flag = 1`，尚未贯通完整冷初始化返回的 `flag = 0`。这些结果使用 fresh ELF/TLS 与明确的虚拟 OS 输入，没有 native 入口快照或初始化后页供给 Python。

实现见 [vm9_libc_boot.py](python/vm9_libc_boot.py)、[vm9_libc_base.py](python/vm9_libc_base.py) 和 [vm9_libc_mapping.py](python/vm9_libc_mapping.py)。当前已恢复：

- `+0x75dc0` bin 几何／redzone、`+0x7dce8` bitmap 层级，以及 `+0x7cf2c` 的 36 个 bin、page-mark array 和 large／huge class counts。
- `+0x99378` tcache capacity table，包括真实 W32 shift／modulo-32 行为；`+0x99938` main/static TSD、实际 `libc+0xe0200` generation table 和已有状态转换。缺失 TSD 的 fallback 分支仍拒绝。
- `+0x7cce8` 初始 arena 完整布局、mutex／tree sentinel、统计和 36 个 controls；`+0x8e20c/+0x8e0f8` 的现有 table slot 构造／发布。arena table resize 分支仍拒绝。
- `+0x7d998` 真实 base extent allocation：64 字节 rounding、size-class 查找、冷 mapping、热分割、exact consumption、descriptor 回收与 accounting。新 descriptor 使用 mapping 前 128 字节；tree root／link 使用 matching libc 布局，不迁移旧 checkpoint 的全局地址。
- `preinit_complete_with_base_allocator()` 同次执行默认 `+0x8e250` 至返回，成功状态 `flag = 2`；`cold_init_until_cpu_query()` 再组合 main TSD 和真实初始化锁，成功状态 `flag = 1`，停在 `+0x8e41c`。

| 本阶段范围 | Native 对照 | 拒绝／回滚 | 边界与比较 |
| --- | ---: | ---: | --- |
| arena/bin、bitmap、tcache、static TSD、arena constructor | 94 | 9 | 两个基址；跨页／redzone／边界 option、key exhaustion；孤立分配调用仍是显式 base provider |
| 真实 base allocator 与同次 fresh 组合 | 46 | 10 | 返回、全部 guest／TLS／global、mapping 页／records／cursor、有序 OS 调用；default preinit 返回与 cold prefix 均执行实际 base allocator |
| atfork 注册、static TSD 迁移 | 24 | 8 | 两个基址；链表、NULL、TSD 状态和 alias／padding；public／internal allocation 是显式测试边界 |
| available-slab 树选择／删除 `+0x75d44` | 12 | 3 | 两个基址；空树、单／多节点、counter wrap；无 allocation provider，真实树／counter／padding 比较 |
| 真实 native cold-malloc 路径追踪 | 10 | — | 真实重入 malloc、CPU 文件解析、atfork 和 TSD 收尾，返回 `flag = 0`；malloc hooks 为 0，OS 为有界虚拟输入 |

前两组共 **140 个 native 控制／19 项拒绝**，注册／迁移组件为 **24／8**，其后增加 available-slab helper **12／3**，后二者共享组件报告但分开计数。这些数量不与不同输入边界的 native-only 完整 malloc 控制合并为“Python 完成数量”。同次 fresh prefix 控制只种初始 inactive-key fixture，不用 Python boot 输出预种 native。页、mapping records 和 cursor 在拒绝时整体回滚；外部 provider ledger 不回滚。

### atfork 与 TSD 收尾的准确边界

`register_atfork()` 恢复 `+0x67374` 的真实 48 字节节点布局、prepare／parent／child／DSO 字段、normal mutex 和 head／tail append；NULL allocation 的普通返回是 ENOMEM=12。它没有执行 fork callbacks，且依赖显式 public malloc provider，不能冒用 base allocation 代替 public malloc。

`migrate_static_tsd()` 恢复 `+0x99c78` 的 main-key 路径：经显式 `+0x8e0ec` internal allocation 得到 128 字节对象，按实际五组 16 字节加 8 字节复制共 88 字节，保留其余 padding，再执行 setspecific／getspecific、state 0/1/2/其他转换和 `+0x44` 清零。自别名与向前重叠复制已与 native 比较。NULL、key 发布失败、fallback list 和 logging／abort 分支仍拒绝；该 void 函数返回寄存器不是语义返回值。

真实 binary 的 `+0x933ac` 只有 `mov w0,#0; ret`。这可以按样本实现返回 0，但不能描述为已恢复一套额外 mutex 初始化逻辑。

### 前阶段确认的 native 分配路径

没有 malloc hook 的 native 控制记录了有序入口与受控 request size：CPU 查询进入 `get_nprocs +0x2669c`，文件缓冲触发 public malloc 重入；当前样本路径随后进入 `+0x79fa4 → +0x787dc`，atfork 又请求 48 字节，TSD 迁移经 `+0x8df44 → +0x79fa4` 请求 128 字节。`+0x787dc` 先调用 `+0x75d44` 从 available-slab 树取最小地址节点；该 helper 现已恢复，空树时返回 NULL，不执行 allocation。NULL 使 caller 转到 `+0x78d7c`，释放 bin mutex／获取 arena mutex，再尝试 `+0x7779c` extent allocation。没有可用 extent 时进入 `+0x765b0`；`+0x7ed7c` 先尝试 chunk cache，miss 后默认 `+0x7edc4` callback 经 `+0x7f600` mapping，再由 `+0x7e14c` 注册，随后执行 `+0x772b0` page 标记与 `+0x7dd70` bitmap 初始化；全部 10 个 native cold 控制实际观察到这条新 region 路径。这些主体的有界默认分支已在下节 region／small 阶段恢复；非空 chunk cache 仍待恢复；有界 public tcache 的新进展见后节。`+0x75f38` 是 redzone 填充 helper，不能当作冷 refill 入口。

`python_preinit_complete = false` 表示全部配置／分支尚未完成，与已验证的 `default_empty_preinit_complete = true` 不冲突。非空配置 `+0x8ce70`、TSD fallback、arena table resize、真实 CPU 文件服务和完整 public malloc 冷启动组合仍未覆盖。atfork 和 TSD 组件通过不能证明 `cold_init_until_cpu_query()` 已跨过停止点。

复现（需要私下提供匹配 hash 的 ELF，输出路径保留在私有目录）：

```bash
python -B platforms/bytedance/tomato/python/verify_vm9_libc_arena_boot.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-arena-boot.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_base.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-real-base.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_runtime_boot.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-runtime-boot.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_cold_malloc.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-cold-path.json
```

公开证据：[arena／tcache／TSD](evidence/vm9_libc_arena_boot_native_20261006.json)、[真实 base 与 fresh 组合](evidence/vm9_libc_real_base_native_20261006.json)、[atfork／TSD 迁移](evidence/vm9_libc_runtime_boot_native_20261006.json)、[native 冷启动有序路径](evidence/vm9_libc_cold_path_native_20261006.json)。mapping 抽取公共 body 后的 **42 个 native／20 个 owner 检查**与 early boot 的 **56／7**均回归通过，见[回归摘要](evidence/vm9_libc_arena_base_regression_20261006.json)。公开材料只包含控制标签、offset／count／boolean、受控 size 和样本 hash，不包含 ELF、初始化页、请求、设备、token 或密钥。

## 同次 fresh region、slab 与内部小对象入口（本阶段续进）

**默认 arena 0 的新 region、清洁 slab 和 raw/internal small allocation 已贯通；完整 public malloc／tcache、完整 cold init 的 `flag = 0` 与 fresh Medusa 仍未完成。** 新 owner [vm9_libc_region.py](python/vm9_libc_region.py) 从 fresh ELF、显式虚拟 OS 与真实 base allocation 构造状态，不接收 native 初始化页或分配返回值。这里恢复的是 matching libc 函数体在 guest 内的行为；OS mapping 由 GuestOS 和明确的 syscall provider 管理，尚非真实 Android OS 启动。

恢复范围：

- `+0x765b0` 默认 cold region：先尝试 `+0x7ed7c/+0x7ea48` 的空 chunk-cache 分支；miss 后释放 arena mutex，执行默认 `+0x7edc4` callback 的空 cache 分支，再调用已验证的 `+0x7f600` aligned mapping。成功后写真实 chunk header，注册 radix reference，重锁 arena，更新 mapped／metadata accounting 和首尾 page 标记，发布 free-extent 节点。
- `+0x7e14c/+0x94e78/+0x7de34` 的真实 radix node allocation／发布／leaf overwrite，经 `_allocate_staged` 调用真实 base allocator。`+0x9503c` 向 child allocator 传入 parent level，分配长度可能大于 child 索引范围；高地址控制按实际行为比较全部保留 mapping 页。NULL allocation 留下 link=1，直接注册函数返回 1；再次遇到 pending link 的等待分支仍拒绝。
- `+0x7779c` extent lower bound，以及清洁 `+0x772b0/+0x76f3c/+0x76f10` 的 tree remove、page accounting、remainder split／insert 与 class page 标记。dirty cleanup 分支仍拒绝。
- `+0x787dc` 的串行 cold slab 获取，接真实 region／extent、class／counter 和 `+0x7dd70` bitmap 初始化；`+0x79fa4` hot/cold small allocation，接 bitmap pop、bin statistics、正常 mutex 和 zero-fill。
- `allocate_internal_small()` 恢复 `+0x8df44` 的正数小对象入口：`flag=3` 时实际获取初始化锁、执行默认 preinit、释放锁，再从 arena 0 分配并按 W2 更新 allocated bytes。正常 preinit 失败返回 NULL、保留实际 partial writes；unsupported 分支整体回滚。成功 fresh 入口状态为 `flag=2`，它不执行 public malloc 的 CPU／TSD／tcache 冷初始化。

| 新阶段对照 | Native 控制 | 覆盖与限制 |
| --- | ---: | --- |
| 同次 fresh preinit → initial region | 14 | 两个主 image 基址；chunk16/18/20、两次 region、misaligned trim、name failure、禁用 DSS 后的普通 mmap failure |
| 同次 fresh preinit → radix references | 14 | key 0、low／high key、overwrite、neighbor／cross-root 和真实 base mmap failure；value 为明确的控制输入 |
| 同次 fresh preinit → direct/internal small sequence | 24 | 正数 unaligned sizes、8/32/48/128/7168/14336 字节、zero-fill、65 次跨 bitmap-word、slab 耗尽、多 region，以及内部 allocation accounting |
| 真实 `+0x8df44` fresh 入口 | 4 | 从 `flag=3` 直接调用；成功分配与 preinit mmap 失败，均比较 partial/global 状态与返回 |

共 **56 组 native 对照／26 项拒绝与回滚检查**。matching libc 固定加载基址，主 image 使用两个重定位基址。所有 native allocator 函数正常执行，malloc hooks 和 allocation provider 均为 0；仅有显式 syscall 服务与直接调用序列 continuation。比较返回对象、guest、相关 libc globals／TLS、全部保留 owned mapping 页、metadata／cursor 和有序 OS 调用。受控测试写入的对象内容仅用于比较，不进入公开 JSON。

拒绝检查覆盖 spare chunk、非默认 callback、非空 chunk cache、DSS fallback、contended mutex、pending radix node、registration 失败的未恢复 cleanup、junk fill、dirty extent、损坏 slab／bitmap、未知 internal state 和晚发生的 OS provider error。失败时 guest pages、mapping records 和 cursor 不变；外部 provider ledger 不回滚。普通 native NULL／错误返回与这些拒绝分开处理。

复现：

```bash
python -B platforms/bytedance/tomato/python/verify_vm9_libc_region.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/libc-fresh-region-small.json
```

公开[对照证据](evidence/vm9_libc_fresh_region_small_native_20261005.json)仅含样本 hash、控制标签、offset／count 和 booleans。native 输入快照、ELF、对象数据和请求内容没有发布。

**region／raw small 阶段的外层冷启动停止点为 `+0x8e41c`／`flag=1`。** 当时真实 raw/internal 分配已经可用，public tcache 创建、arena 绑定、empty-bin refill 与 accounting 尚未恢复；下一节记录其新的有界实现，该阶段 CPU 查询整体尚未接回；更新结果见“实际 FILE 读入、CPU 查询与默认冷启动自然返回”。非空配置、primary／secondary DSS、非空 chunk cache、dirty cleanup、junk/redzone fill、large/huge allocation 和并发 publication 未完成，不能用 base allocation 代替这些调用。

## Matching libc tcache 与有界 public small（2026-10-05）

`python/vm9_libc_tcache.py` 在同次 fresh cold prefix 生成的 static TSD、arena 和映射状态上，恢复默认 tcache 创建及有界 public small 分配。该阶段新增 **52 组 native 对照和 24 项拒绝／回滚检查**。上一节 region／raw internal 的 56／26 是独立阶段的控制，不能把两个阶段数量当作签名成功数。

已恢复的实际路径：

- `+0x8dda0`：单 arena 的真实 mutex、引用计数与 TSD arena 绑定。非 current TSD 返回 arena，但不向 TSD 发布。
- `+0x98c54`：matching pthread key 的 TSD 读取、state 0／2 迁移、默认 tcache 开关读取与 cache 创建。此函数本身不保存返回值到 wrapper `+0x10`；由 public malloc 的 caller 保存。
- `+0x98490 → +0x7a668 → +0x79fa4`：64 字节对齐的清零存储，默认 backing class 为 7168 字节；实际调用上一阶段 region／slab 分配，计入 arena internal allocation。没有外部 allocator 返回值。
- `+0x98428`：持有 arena mutex 的 circular cache list 发布，包含已有 head 的插入和完整 bin/list 指针初始化。
- `+0x97ecc → +0x7970c`：空 small bin 的批量补货、冷／热 slab bitmap pop、bin/arena counters，以及失败后的部分列表压缩和 count/floor 更新。
- `+0x8f00c`：在同一初始化 owner 的 `flag=1` 重入状态，或显式 ready 状态，执行 0～14336 字节 public malloc。包括零长度按 1 字节归类、tcache caller 发布、已缓存对象 pop、空 bin 补货、关闭 tcache 的 direct 路径、清零、TSD allocation accounting 和 NULL/ENOMEM。

控制从 fresh `+0x8e350` 实际执行到 `+0x8e41c`，随后只用明确的 caller continuation 选择上述函数；**没有执行 CPU 查询，也没有获得完整 cold-init return**。两个 ready 控制显式把 flag 置为 0，只验证 ready 分配分支，不证明自然初始化达到了 flag 0。其他控制保持 `flag=1`。

52 组控制按两个主 image 基址各 26 组运行：默认／重复创建、关闭 cache、TSD state 0／2、单次／重复／非 current arena 绑定、直接 create、chunk16／20、misaligned trim、命名失败、禁止 DSS 的 mapping failure；public 的默认请求、`[0,1,31,127,4095,7169,14335]`、65 次小对象、slab 耗尽、多 region、关闭 tcache、显式 ready 与 TSD 状态；另外含 NULL/ENOMEM 和部分补货失败。清零控制先把未消费的 128 字节 cache 对象写入 `0xA5`，后续实际返回必须全零。

所有成功控制比较返回、guest、相关 libc globals／TLS、每一页保留的 owned mapping、mapping records／cursor 和有序 OS calls。native 没有 allocator return hook，也没有使用 Python boot 输出预种 native。OS 仍是显式虚拟服务。公开证据见 `evidence/vm9_libc_fresh_tcache_native_20261005.json`，只包含受控 case 标签、样本 hash、offset、count 与 boolean。

24 项拒绝检查覆盖多 arena、contended mutex、缺失 arena／TSD、损坏 capacity／count、large cache backing、junk、非空 cache 关闭时的析构、晚发生的 provider 错误、尚未初始化的 public entry、另一线程的初始化 owner、profiling、GC 第 228 次事件、非空／large／超大 batch／错误 slab 的 refill。拒绝时 guest pages、mapping records 和 cursor 不变；已经调用的 external provider ledger 不回滚。

一个针对 radix allocation 的失败诊断在 300000 条原生指令预算内未返回，停止在 `+0x94ea0～+0x94eb4` 的 pending-link 等待边界。该次失败不是部分补货控制，也不能证明无限循环。正式部分补货控制允许真实 radix 节点先分配，再令后续 region mapping 失败，52 组成功控制不包含该未返回诊断。pending radix 和 failed-registration cleanup 继续明确拒绝。

复现命令：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_tcache.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-tcache-report.json
```

owner API 为 `bind_thread_arena`、`create_thread_cache`、`get_thread_cache`、`refill_small_cache_bin` 和 `allocate_public_small`。它们接收同一个 `GuestOS`，原子提交 guest pages／mapping records／cursor；输入必须由真实已恢复的 boot 路径生成。不是独立 signer API。

**该有界 public-small 阶段的外层 Python cold prefix 停在 `+0x8e41c`；当前自然返回进展见下方新增章节。** 接下来的实际 native 路线已确认是 `sysconf +0x1d2e4 → get_nprocs +0x2669c → fopen +0x57cd8 → fclose +0x56c78 → free +0x1bac0`；allocator dispatch 的 free 目标为 `+0x91990`。cached small free 的新进展见下一节；还需恢复实际 stdio／文件 OS 输入，使 CPU 查询中的分配及释放相互闭合，随后接 atfork 的 48 字节 public allocation、arena table 收尾与 `+0x99c78` 的 128 字节 internal TSD migration。

完整 public allocator 仍不支持 multi-arena selection、large/huge、GC、profiling、cache 析构、并发和此前 region 的未恢复分支。本节控制本身没有证明 full cold-init flag 0；新的默认冷启动对照见下方新增章节。fresh Medusa、线上全头矩阵、其他平台与最终产品仍未完成。

## Matching libc cached small free（2026-10-05）

`release_cached_small()` 已恢复实际 `free +0x1bac0 → +0x91990` 的 NULL 与未满 clean small bin 路径，新增 **16 组 native 对照和 13 项拒绝／回滚检查**。`C free` 返回类型为 void，不把 native 遗留的 X0 当作功能返回值。非 NULL 路径读取实际 page tag/class、计入 TSD deallocation、把对象放回 cache vector、更新 count/event；bitmap 保留 allocated 状态，直到后续真正从 cache 向 arena 释放。

每个主 image 基址运行 8 组：NULL、128／4096 字节、跨六个 size class、释放后直接复用、清零复用、批量逆序释放及重取、TSD state 2 迁移。复用控制必须返回原指针；默认复用保留显式写入的 `0xA5`，打开 zero 选项后的复用必须全部清零。对照比较所有有定义的 allocation 返回值、guest、libc globals/TLS、每一页保留映射、映射记录／cursor 和有序 OS calls，不对 void free 的 X0 作数值比较。此前 tcache 验证器的 default 与 poisoned-zero 控制也通过了共享执行器回归。

13 项拒绝检查覆盖对象内部地址、bitmap 标记为 free 的 slot、非法／huge 指针、错误 page tag、profiling、缺失 tcache 的 direct arena release、free junk、full/corrupt bin、重复入 cache、GC 和缺失 TSD。拒绝时 guest pages、mapping records 和 cursor 不变。完整 bin flush、直接 arena release、large/huge、profiling／GC 和 free junk 仍未恢复；不能从本阶段推广为完整 `free()`。

公开证据：`evidence/vm9_libc_cached_small_free_native_20261005.json`。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_free.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-free-report.json
```

新的 native 冷启动诊断进一步确认 CPU 查询实际执行 `fopen +0x57cd8 → mode parse +0x5786c → FILE 获取 +0x749dc → stdio 初始化 +0x74868 → __atexit_register_cleanup +0x75550 → fgets +0x573e4 → fclose +0x56c78 → free +0x91990`。诊断中的完整 native cold return 成功，并不表示 Python 已接回这条路线。coarse 控制证据见 `evidence/vm9_libc_cpu_stdio_frontier_native_20261005.json`；OS ledger 的 preceding-observed-entry 只记录先前出现的入口，不能用它推定 syscall 的动态调用栈。

该 cached small free 阶段当时的下一步是恢复 stdio／FILE 构造、cleanup 注册和文件 OS 输入；其 stdio 构造结果见下一节，实际读入与自然冷启动返回见再后的新增章节。CPU 查询没有用直接返回 CPU 数替代。

## Matching libc stdio、只读 FILE 和缓冲区构造

新增 `python/vm9_libc_stdio.py`、`python/vm9_libc_file.py`，通过 **100 组 native 对照／40 项拒绝与回滚检查**：stdio 构造 **38／13**，private recursive mutex、只读 FILE 和 buffer 构造 **62／27**。每组均使用两个主 image 基址之一，各自从 ELF／独立受控 TLS 建立输入。native 实际执行 `+0x8e350` 至 `+0x8e41c` 后，通过明确的 continuation 调用本节函数；Python 也先执行同次 fresh prefix。**没有继续运行整个 CPU 查询，没有自然 cold return／flag 0，也没有 fresh Medusa 输出。** inactive-key fixture 仅在第一个 preinit 处应用一次，之后不重置已创建的 keys。

stdio 初始化 `+0x74868` 为 3 个标准 FILE 和 17 个静态备用 FILE 连接 extension。FILE stride 为 `0x98`，extension stride 为 `0x68`；extension 的 `+0..+0x37` 清零，`+0x38` 的 40 字节 mutex 初始化为 recursive type 1（首 u16 `0x4000`），`+0x60` 写 1，而 `+0x61..+0x67` padding 保留。`+0x749dc` 从现有 glue 查找 flags 为 0 的 FILE，先写 1 保留，再初始化 native 实际写入的 core 字段和 extension；没有额外清零其余字段。控制验证重复初始化、连续获取全部 17 个备用 FILE，以及 poison/padding 保留。无空闲 FILE 时，静态定位到的 `malloc(0xa1f)` 和新 glue 发布仍拒绝；不能将现有 pool 获取推广为完整增长支持。

`+0x75550 __atexit_register_cleanup` 已恢复 fresh 4096 字节匿名页和 existing-tail 覆写。fresh header 的 count 为 1、capacity 为 170；slot 0 写 callback 与两个零参数，再以实际 mprotect outcome 更新整页保护。existing chain 沿 next 到尾页，先 RW 再覆写 slot 0，随后尝试 RO。cleanup mmap 失败写 errno 并提前返回，但外层 stdio 初始化仍发布 initialized flag；existing-tail RW 失败提前返回，最终 RO 失败则按 native 行为忽略失败并发布 cleanup flag。GuestOS 对 pages、mapping records、cursor 做同一个 transaction；未知／foreign/cyclic chain 和晚发生的 provider 异常拒绝时回滚 guest 状态，**不会撤销 provider 已发生的外部调用**。退出时执行 cleanup callback 尚未恢复。

原 Python fixture 仅应用 RELATIVE relocations。新 stdio fixture 从 ELF 定义符号解析并应用 `__sF` 的 **7 项**绑定：GLOB_DAT `+0xd8f00`；ABS64 `+0xdb418/+0xdb4b0/+0xdb548/+0xdb608/+0xdb610/+0xdb648`，分别使用 ELF 的 symbol value 和 addend。它们属于装载输入，不能归因于 stdio 构造器，也不是 native 输出快照。其余不参与本阶段的 ELF 符号绑定未被本补充修改，未声称建立了通用完整 ELF loader。

private recursive mutex 恢复 `+0x68cf8 → +0x68890` 的 uncontended 获取、同 owner depth 增减，以及 `+0x68d5c` 的释放。owner tid 从 `TP+8 → pthread+0x10` 读取。depth 饱和返回 EAGAIN 11，错误 owner unlock 返回 EPERM 1；相应 guest 状态与 native 一致。shared、normal/type-mismatch、waiter／futex、缺失 tid 和不一致状态不冒充已完成的并发实现。

只读 `fopen +0x57cd8` 连接 mode parse、FILE 获取和实际 openat outcome，并写入对应 cookie/callback/fd。`r/rb/rx` 的 flags 为 0，`re` 为 `0x80000`；只读 x 后缀不会启用 create/exclusive。失败释放 FILE reservation，fd 大于 32767 时调用 close 并写 EMFILE 24。未分配缓冲的 readonly `fclose +0x56c78` 已闭合 FILE recursive lock、close callback、flags/counters/orientation 清理和 unlock；close 的 EINTR 按 matching wrapper 返回成功并保留 errno 4。对照包括重复打开、关闭后复用、重复关闭／EBADF、fd 0／32767／32768、打开与关闭失败，以及已持有 FILE 锁时的嵌套关闭。

`+0x597b8 → +0x5986c` 的 regular-file buffer 构造已接到实际 fstat 和既有 public small allocator。fstat provider 显式返回 `(kernel_outcome, 128-byte-stat)`；regular block size 1024／4096／8192 均有对照。fstat 失败或 block size 为 0 时选择 1024 字节默认缓冲，只有 native 实际写入的字段才更新；zero-block 控制验证旧 FILE block 字段保留。成功 buffer 指针与大小、flags、所有保留映射页、allocator globals/TLS 和 OS 顺序与 native 一致。关闭 DSS 的 mmap/ENOMEM 控制验证分配失败时改用 `FILE+0x77` 的内嵌单字节缓冲。character/isatty/ioctl、负值／过大 block size、非法 stat/provider、已存在 buffer、foreign callback 和 profiling 的晚拒绝分支均有回滚验证。

公开证据：`evidence/vm9_libc_stdio_native.json`、`evidence/vm9_libc_readonly_file_native.json`。比较所有有定义的返回值、guest/stdio/allocator globals、TLS/key state、每页保留映射、有序 OS calls，以及 mapping records/cursor/protection；void 构造器和 cleanup 的遗留 X0 不参加返回值比较。OS 服务仍是显式虚拟输入，未打开宿主 `/proc/stat`，也没有 hook 替代这些 control 中的 native malloc。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_stdio.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-stdio-report.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_file.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-file-report.json
```

**该 stdio 构造阶段当时的下一步是恢复实际读入和 CPU 解析；现已由下方新增章节完成默认分支的组合验证。** 本节的旧构造控制未读 FILE 内容；更新控制恢复只读带缓冲 close。ungetc/auxiliary-buffer 和 write/update/append/seek 仍拒绝，fresh Medusa 仍待独立验证。

## 实际 FILE 读入、CPU 查询与默认冷启动自然返回（2026-10-06）

新增 [vm9_libc_cold.py](python/vm9_libc_cold.py)，并扩展既有 FILE/free/atfork owner。生产入口为 `initialize_default_malloc()` 和 `allocate_default_small()`；两者在同一个 GuestOS transaction 内组合真实初始化及 allocator bodies，不用 allocation provider 代替内部 malloc。`brk/openat/fstat/read/close/mmap/munmap/prctl` 仍由显式虚拟 OS 输入提供，未打开宿主 `/proc/stat`。

| 验证范围 | Native 对照 | 拒绝／回滚 | 公开证据 |
| --- | ---: | ---: | --- |
| fgets／refill／read 与 buffered fclose/free | 46 | 19 | [readonly stream](evidence/vm9_libc_readonly_stream_native.json) |
| get_nprocs 实际 FILE 解析 | 24 | — | [CPU query](evidence/vm9_libc_cpu_query_native.json) |
| 默认冷启动自然返回与 fresh public small malloc | 26 | 8 | [default cold return](evidence/vm9_libc_default_cold_return_native.json) |
| free／runtime boot／stdio／readonly FILE 回归 | 152 | 64 | [本轮回归汇总](evidence/vm9_libc_default_cold_regression.json) |

实际调用链为 `fgets +0x573e4 → refill +0x5a960 → read callback +0x75090`。恢复 EINTR 重试及 errno、EOF/error flags、FILE pointer/count/offset、换行、截断、嵌入 NUL、无换行的最后一行、已有缓冲和部分读入后错误。buffered `fclose +0x56c78` 在 close 错误时也执行真实 cached-small release；它和公开 free 共用同一 body，不另建释放模型。持续 EINTR 等超出有界策略的输入明确拒绝，guest transaction 不发布部分结果；外部 provider 副作用不由 guest 回滚。

`get_nprocs +0x2669c` 从 ELF 核实 `/proc/stat`、`re` 和 `cpu%u%c`，通过 fgets256 读取，再按首个 space 截断和实际 conversion-count 语义计数。控制覆盖空文件、打开／读取失败、短读、EINTR、非匹配行、十进制正负号及 uint32/uint64 溢出；该实现不是通用 scanf。打开失败返回 1，成功打开的空文件返回 0。CPU stack guard 从 ELF 的 defined-symbol relocation 绑定，变化时明确拒绝。

默认 cold controls 从实际 `+0x8e350` 运行到自然 return。fresh public controls 从 `+0x1bb08` 开始，仅用虚拟 caller return 串联后续请求，不跳过初始化正文。CPU 文件生命周期后，atfork 的 48 字节节点经真实 public allocation 构造，arena table 经真实 base allocation 创建并发布，`+0x99c78` 的 128 字节 TSD migration 经真实 internal allocation 完成。`+0x933ac` 是经 ELF 指令核实的 `mov w0,#0; ret`，没有输入一个任意 no-op provider。

**新发现：fresh ELF 的 atfork mutex `+0xdb380` 实际类型为 recursive `0x4000`。** 旧 atfork component 控制曾明确将其改成 normal mutex，那些控制不能证明 fresh 的真实类型分支。新的默认 cold 组合保留 ELF 类型，使用已恢复的递归 lock/unlock 与 guest TLS；旧 normal 分支回归保持通过。

26 组控制为两基址各 8 个 cold 输入和 5 个 fresh public 请求组合。请求覆盖 0、128、4096、14336 字节，以及同次 `[128,48,4096,14336]` 的连续分配。每次自然 cold 控制都实际观察 `+0x8e41c/+0x8e51c/+0x99c78` 各一次，并检查 ready flag 为 0、dynamic TSD 已发布及 main marker 清零。比较有定义的返回、guest 输出、stdio/allocator globals、TLS/keys、所有保留 mapping 页、有序 OS 调用和 mapping records/cursor/protection。临时栈 scratch 不由 native 输出提供，完整物理栈不在比较范围。

报告分别记录 `full_case_set_verified`、`full_default_cold_matrix_verified` 和 `full_fresh_public_small_matrix_verified`；仅运行 `--case fresh_128` 时三个 full 标记均为 false，即使所选冷启动成功。所有本轮公开报告保留 `standalone_medusa_complete=false` 与 `current_online_header_matrix_verified=false`。历史报告的 false 代表其自身控制范围，应结合本节的新证据读取。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_stream.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-stream-report.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_cpu_query.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-cpu-report.json
python -B platforms/bytedance/tomato/python/verify_vm9_libc_cold.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-cold-report.json
```

**此前默认任务 allocator 的 size guard 已实测定位为 public large 的 `+0x8f6ec → +0x7a3c8`；新的有界恢复见下一节。** 默认任务的 allocator consumer 要求六次 0x4000 字节请求，而当前 public-small body 上限为 0x3800。两个同次 fresh native 探针在自然 flag0 后都返回非空的 16384 字节分配，Python 则在 size guard 明确拒绝。这两个是 native-only 定位探针，未比较 Python large allocation 的 bytes，不计入上表 96 个 Python/native 对照。证据：[large frontier](evidence/vm9_libc_large_frontier_native.json)。该阶段的两个 native-only 探针是恢复前的定位证据；下一节记录已恢复的实际 large 分配，默认任务正文的 allocator 接入仍需单独验证。

完整 allocator 仍缺 large/huge、full-bin/GC、profiling、multi-arena、cache 析构、非空配置/DSS/dirty、并发等待及相应诊断分支。真实线程/OS 输入创建、未知 callback/support 关联状态、fresh Medusa 签名、新线上全头矩阵与 f13、无 JVM Rust、搜索非空/分页、其他平台及最终 Pages/Actions 产品仍待验收。

## 自然 cold 启动后的空 large-cache 分配（2026-10-06）

新增 [vm9_libc_large.py](python/vm9_libc_large.py) 与 `allocate_default_large()`，恢复 `+0x8f6ec → +0x7a3c8 → +0x77984/+0x77a68` 的有界 clean allocation。已有 region owner 提取共享 `+0x76f3c/+0x76f10` extent split/accounting；small slab 继续由自身标记函数处理，large 使用 `+0x77138` 的首尾标记，保留 interior page marks 和 zero-bit，更新 free extent tree、已用页／region accounting、arena large 统计和 size-class 统计。没有把 large 分配当作 small bitmap pop 或 base allocation。

原生空 large-cache 分支不批量 refill，也不增加 cached-pop 次数：它将 low-water 写为 -1，直接分配一次，然后更新 cache GC event 和 TSD allocated bytes。新实现遵循这个分支，暂不恢复非空 large cache pop、large free、uncached large、junk/zero option、GC 与 huge。

**12 个 Python/native 对照／8 项拒绝与回滚检查通过。** 两基址分别覆盖 14337、16384、20481、65536 字节、同次六次 16384 字节及四十次 65536 字节跨 region 分配。每个序列从 actual fresh public malloc 经自然初始化开始，比较有定义返回、完整 stdio/allocator/TLS/keys、所有保留 mapping 页、有序 OS calls 和 mapping records/cursor/protection。回滚覆盖 small/negative/over-limit 请求、非空 large bin、GC event、junk/zero option 和 profiling；晚期 GC 拒绝发生在实际 extent split 后，确认这些中间页／树／统计不发布。

共享代码回归另通过 **356 native controls／141 项拒绝与回滚检查**，含 region 56/26、tcache 52/24、此前自然 cold/stream/CPU/free/runtime boot/stdio/readonly FILE 的 248/91。证据：[public large](evidence/vm9_libc_public_large_native.json)、[large 回归](evidence/vm9_libc_public_large_regression.json)。此回归重新验证旧控制，不与旧轮次重复累加为独立覆盖率。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_large.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/libc-large-report.json
```

**本 large 分配阶段当时只证明六次 0x4000 分配序列；其后默认任务正文组合已由下一节的新控制验证。** 旧任务 verifier 的默认 native malloc PLT 返回显式 provider 分配，该历史控制边界保持不变；新控制显式选择 actual libc malloc，验证 owned mappings／records、六项 VM、once/broadcast 和最终状态。该旧 large 报告的 `default_initialization_task_allocator_composed=false` 仅描述自身范围；新任务组合报告为 true，完整 worker/root、Medusa 和线上矩阵仍为 false。

## 默认六项 VM 与真实 malloc 正文贯通（2026-10-06）

`initialize_default_task()` 在一个 GuestOS transaction 内执行既有六项默认任务。allocation callback 通过已有 staged bridge 进入真实 allocator bodies：首次 flag3 触发 default cold initialization，随后每次 0x4000 请求走 recovered public large，而不是显式返回一个已映射区域。任务完整返回才发布页、mapping records/protection 和 cursor；异常不发布部分启动状态，外部 provider 效果仍不由 guest 回滚。

新 [验证器](python/verify_vm9_default_task_allocator.py) 让 native main malloc PLT 保留 LR/参数，转入 matching libc ELF 中定义的 malloc symbol。共享 oracle 新增的 `real_malloc=True` 与替代 allocator handler 不可混用；默认 false 保留历史 component 控制。每组实际观察六次 main malloc PLT、六次 `+0x7a3c8`，通用替代分配器调用数为 0；`+0x8e250/+0x8e41c/+0x8e51c/+0x99c78` 各实际到达一次，最终 flag0。

每组完整观察六个顶层 caller 返回。对每一项，native 独立计数一个 initial nested return 和七个 repeated nested returns，合计 48；Python 也返回六组各八段。比较每项返回的全部 32 槽、虚拟栈、主 image 全页和全部 allocator-owned mapping 页；最终比较 guest 输出、libc/stdio/allocator globals、TLS/key state、有序 OS calls、mapping records/cursor/protection，以及六次 once/broadcast 的状态和顺序。matching libc uncontended mutex 正文也实际执行，24 项 mutex ledger 与 once 顺序一致。完整物理 libc 栈不在 byte 比较范围，虚拟 OS／broadcast 仍是明确的研究输入。

**输入栈的边界已修正。** 初始私有组合探针沿用接近 TLS 的旧栈；六项对象/槽均匹配，但最终 TLS 后半段出现栈保存值型差异。单独改用与 TLS 分离的 64 KiB 栈后，两基址的完整 TLS 与最终状态均通过，正式 fixture 保留这个布局。没有复制 native TLS 结果，也没有删掉 TLS 比较来消除差异。此控制输入布局证明有界组合，不代表真实 OS 线程创建已恢复。

四个拒绝／回滚控制覆盖第三项 busy once、第三次 broadcast 失败、未映射栈与 tagged return。前两项分别已完成两项和三项实际任务工作后才拒绝，确认所有 guest pages、OS-owned mappings/protection/cursor 与 VM base 不变；外部 OS/provider 调用轨迹不重置。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_default_task_allocator.py --library C:/private/libmetasec_ml_71332.so --libc C:/private/matching-libc.so --output C:/private/default-task-allocator-report.json
```

**下一步仍是同次主线程 startup→独立 worker TLS→真实 allocator→默认任务→argument/TLS 清理的组合，然后接 root/signature。** 当前组合以一个显式受控线程入口开始；另一线程缺失 TSD 的 fallback、多 arena 选择、cache/full-bin/GC、未知 callback 和实际 OS 输入仍需分别验证。不能用该任务完成结果替代 fresh Medusa 或当前线上全头矩阵。Rust、搜索非空/分页、抖音/起点和最终 Pages/Actions 下载产品仍待后续完成。

## 继续顺序

继续恢复 matching libc 的真实 allocator 冷启动，将当前显式 allocator／TLS／OS 服务逐项替换为已验证实现，并将 startup、`+0x256e50` 配置构造和既有 root factory 接到外层 signer。未识别 callback、support 关联状态类型和真实线程创建仍需真实来源，不以空回调填补。

默认 empty-config Python 冷启动现已自然返回 `flag=0`；真实 FILE 生命周期、CPU 解析、atfork allocation、arena table 和 TSD migration 已组合验证。0x4000 public large 分配分支现已通过有界对照；实际 malloc 正文与默认六项任务现已组合通过；接下来将自然 ready 的 allocator 状态接回同次主线程启动生成的独立 worker TLS，贯通 worker/退出清理后接 root/signature。真实 OS/TLS 创建与完整 allocator 分支仍是未完成边界。

随后用新的请求输入生成 Medusa，重新验证全头线上矩阵与 f13 时间戳分支。无 JVM Rust、非空搜索／分页、抖音／起点和最终 Pages／Actions 下载产品仍需各自完成验收。
