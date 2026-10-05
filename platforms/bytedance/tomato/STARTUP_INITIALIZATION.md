# 外层启动 caller 与 worker 调度／清理

当前独立 Python 已恢复 `+0x28040c → VM +0xa7050` 的默认主线程路径、worker TLS support、executor context，以及 queue／executor 的有界串行调度。空闲 worker 已从同次 fresh 启动贯通等待、停止、正常返回和 argument 清理。默认初始化任务的六个 caller 及 `+0x280554` 的完整串联已通过 fresh cold／hot 对照。**同次主线程启动→非空 worker→默认任务→退出的组合、OS thread-exit 析构、真实 allocator boot、完整线程执行、独立 fresh 请求 Medusa 和新的线上全头矩阵仍未通过。**

实现见 [vm9_startup.py](python/vm9_startup.py)。此前的独立 root factory 见 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md)，本次启动结果不能替代请求签名验收。

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

**本阶段完成的是有界串行默认任务正文。** 真实 allocator global／arena／OS region boot、主线程发布的 worker 与正文整合、OS thread-exit TLS 析构和 fresh 请求签名仍未验证。不能把六项默认 caller 的完成解释为独立 Python Medusa 已完成。

## 继续顺序

下一步将 `run_default_initialization_task` 接回同次 fresh 启动生成的非空 queue worker，验证 startup→worker support→queue invoke→六项正文→argument 清理；继续使用独立生成的 ELF／栈／TLS／allocator 输入。随后恢复 OS thread-exit support/emulated-TLS 析构，将 startup、`+0x256e50` 配置构造和既有 root factory 接到更外层 signer。再贯通真实 allocator boot／arena／OS region，用新的请求输入生成 Medusa，重新验证全头线上矩阵与 f13 时间戳分支。无 JVM Rust、非空搜索／分页、抖音／起点和最终 Pages／Actions 下载产品仍需各自完成验收。
