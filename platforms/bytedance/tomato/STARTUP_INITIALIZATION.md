# 外层启动 caller 与 worker TLS support

当前独立 Python 已恢复 `+0x28040c → VM +0xa7050` 的默认主线程路径，以及两类 worker 在第一次 dispatch 前的 TLS support 转移。**真实 allocator boot、完整线程执行、独立 fresh 请求 Medusa 和新的线上全头矩阵仍未通过。**

实现见 [vm9_startup.py](python/vm9_startup.py)。此前的独立 root factory 见 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md)，本次启动结果不能替代请求签名验收。

## 验证结果与输入边界

| 验证范围 | Native 对照 | 拒绝／回滚检查 | 已比较内容 |
| --- | ---: | ---: | --- |
| OP45 寄存器相等分支 | 308 | — | 两种基址、全部寄存器索引、正负位移边界、taken／not-taken、32 槽无写入 |
| 主线程 caller／默认 enqueue | 4 | 13 | 86 步、32 个终止槽、guest、全部主 image、TLS、generation、分配及有序副作用 |
| executor／queue worker support 前段 | 16 | 6 | 冷／热 key、两种基址和线程 ID、唯一引用清空、TLS 发布、generation、dispatch 参数 |

主线程每次使用 16 次分配、3 次成功的 guest thread-create 请求、2 次析构注册、1 次 condition wake，没有 free。线程 entry 分别是 `+0x326a2c`、`+0x3260a4`、`+0x3260a4`。Python 生成了线程参数、共享 executor、两个 queue 和第一个 queue 的 48 字节任务向量。它在 `+0xa71c8` 退出。

两边分别创建 fresh ELF 与显式 fixture 输入。Native 退出内存和寄存器仅作为 expected outputs；Python 没有读取 native 函数或 VM 入口快照，也不执行 native 指令。worker 对照独立构造逻辑 argument／support 输入，没有用主线程 native 输出灌入 Python。worker 冷 key 控制显式占用 generation 的前两个槽；这些合成表值在 native 入口写入，避免覆盖 libc 的已解析重定位页。

主线程的 thread-create 环境只发布 guest handle 并记录 entry／argument，**不运行 worker、不创建 host thread**。有序比较排除了 pthread 输出的临时物理 scratch 地址，仍比较真实发布的 handle、entry、argument、顺序和其他副作用；报告字段 `physical_thread_output_scratch_compared=false` 明确记录该范围。未比较完整物理栈。

## OP45 修正的关键证据

启动 VM 在 `+0xa7158` 的分支之前，native／Python 的全部 32 槽一致。旧解码将第二寄存器高位取自 bit 25，错误比较 R2／R1；native 的 `+0x16ecec` handler 用 bit 21，实际比较 R2／R17。两者相等时跳到 `+0xa7180`，选择 `+0x281408 → +0x28054c` 的 RET 清理回调。

该 handler 恢复的是 64 位寄存器 equality。此前按 `sub=0/33/53` 分别解释为 nonpositive／zero／inequality 的猜测已移除：这些位属于寄存器和位移。新 verifier 使用合成指令直接对照 handler，同时完整启动 caller 证明 dispatch 也经过该 handler。生产实现没有针对 bytecode PC 的特例、trace hook 或 branch hook。

`vm_full.py` 是共用解释器，因此本次重新运行已有回归：[vm9_startup_regression_20261005.json](evidence/vm9_startup_regression_20261005.json)。fresh root 的 8 组、旧 component 的 4 组／16 段 VM／76 条子树、state owner 的 52 组／6 个拒绝、parser digest 的 142 组／5 个拒绝均通过。旧 component 仍保留自己的 native 入口输入边界，没有被重新标成独立启动。

## Worker 所有权与仍未执行的路径

`attach_worker_support` 对应 `+0x326a2c/+0x3260a4 → +0x32cc40 → +0x326120`。冷路径创建 support key，析构入口为 `+0x32ce6c`，完成串行 guard 发布；热路径复用 key。native 随后先清空 argument 的唯一 wrapper 引用，再将 wrapper 发布到当前线程的 TLS。

executor 对照停在 `+0x326b18`，尚未初始化其 emulated-TLS context 或执行 `+0x326b84`。queue 对照停在 `+0x291934`，尚未运行 callable、消费任务向量、等待 condition 或执行清理。下一处 queue callable 为 `+0x326578`，包含取出／移动任务、解锁、invoke、析构和等待循环，仍需恢复。

主线程的非空 queue／growth、线程创建失败／异常处理、竞争 guard、condition 的 errno 路径均明确拒绝。13 个 caller 和 6 个 worker 的拒绝检查证明 unsupported 输入不会提交 guest 页；**已调用的外部环境服务不会自动回滚**，这不是 native 失败清理等价性或完整线程取消的证明。

## 复现与研究接口

Matching ELF 和 libc 必须由本地私有路径提供。公开仓库只含实现、offset／count／boolean 证据，不包含样本、解码常量、key／payload、设备或会话数据。

```text
python -B python/verify_vm9_branch_eq.py --library /private/libmetasec_ml_71332.so --output /private/branch-eq.json
python -B python/verify_vm9_startup_init.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/startup-init.json
python -B python/verify_vm9_startup_workers.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/startup-workers.json
```

`initialize_startup_caller` 接受 pages、entry SP、return、thread pointer、image base、VM module 和 allocator／thread-create／析构注册／condition 服务，返回 steps、exit offset、32 槽和已执行回调清单。`attach_worker_support` 接受独立 worker argument、kind、key-create／set-specific 服务，返回下一次 dispatch 的参数地址。它们都是研究组件，尚无可用的 Medusa 请求头返回值。

脱敏原始控制摘要：[分支](evidence/vm9_branch_eq_native_20261005.json)、[启动](evidence/vm9_startup_init_native_20261005.json)、[worker](evidence/vm9_startup_workers_native_20261005.json)。

## 继续顺序

先恢复 executor context、queue 任务执行／等待／清理，并把 startup、`+0x256e50` 配置构造和既有 root factory 接到更外层 signer。然后贯通真实 allocator boot／arena／OS region，用新的请求输入生成 Medusa，并重新验证全头线上矩阵。无 JVM Rust、非空搜索／分页、抖音／起点和最终 Pages／Actions 下载产品仍需各自完成验收。
