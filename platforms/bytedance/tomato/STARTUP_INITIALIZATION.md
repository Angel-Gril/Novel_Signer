# 外层启动 caller 与 worker 调度／清理

当前独立 Python 已恢复 `+0x28040c → VM +0xa7050` 的默认主线程路径、worker TLS support、executor context，以及 queue／executor 的有界串行调度。空闲和默认非空 queue worker 均已从同次 fresh 启动贯通等待、停止、正常返回和 argument 清理。非空 worker 执行全部六项默认初始化及 48 次嵌套 VM；worker 返回时 support 仍由 pthread TLS 持有。显式 key 清理阶段已进一步恢复 emulated-TLS 数组、fallback 链、实际 TLS registry 树析构和有界非空 support 向量。已恢复真实 executor shared owner 的零引用／weak 引用释放，以及 matching libc 的 guest `pthread_exit`：线程析构、cleanup handlers、线程状态、detached 注销和 owned mapping 回收。一个同次 fresh 非空 worker 已贯通完整 guest 可 join 退出分支。**真实 OS 线程创建／终止、未识别 callback、非空 support 的关联状态具体析构、真实 allocator boot、独立 fresh 请求 Medusa 和新的线上全头矩阵仍未通过。**

实现见 [vm9_startup.py](python/vm9_startup.py) 和 [vm9_thread_exit.py](python/vm9_thread_exit.py)。此前的独立 root factory 见 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md)，本次启动结果不能替代请求签名验收。

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

## 继续顺序

继续恢复 matching libc 的真实 allocator 冷启动，将当前显式 allocator／TLS／OS 服务逐项替换为已验证实现，并将 startup、`+0x256e50` 配置构造和既有 root factory 接到外层 signer。未识别 callback、support 关联状态类型和真实线程创建仍需真实来源，不以空回调填补。

无 allocator hooks 的 fresh native `malloc` 探针已确认：`libc+0x1bb08 → dispatch+0x8f00c → cold init+0x8e350`。第一次 OS 依赖是 `brk(0)`；提供明确的 program-break 输入后，请求 0x40000 字节匿名 RW mapping；接入现有 GuestOS 后推进到 syscall 167。这个探针仅定位下一依赖，尚未生成 Python allocator boot 或 Medusa 签名，也未作为组件完成证据。脱敏诊断：[cold boundary](evidence/vm9_allocator_cold_boundary_20261005.json)；它记录 post-SVC PC 和三组显式 OS 输入边界，不含 native 页。

随后用新的请求输入生成 Medusa，重新验证全头线上矩阵与 f13 时间戳分支。无 JVM Rust、非空搜索／分页、抖音／起点和最终 Pages／Actions 下载产品仍需各自完成验收。
