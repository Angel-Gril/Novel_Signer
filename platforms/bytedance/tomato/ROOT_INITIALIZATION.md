# Root 构造与 caller 独立初始化

2026-10-04 的旧 nonreusing allocator 证据，以及 2026-10-06 的新 actual allocator 证据，分别验证了控制经过的 `+0x257578 → +0x257084 → +0x257308 → VM +0x991c0` 默认路径。Python 从 fresh ELF、显式 TLS／配置引用和受控环境输入构造 root，**不读取任何 native 函数或 VM 的入口快照**。这消除了此前 root VM 输入前导的依赖，但尚未得到 fresh-input Medusa 请求签名。

生产实现见 [vm9_root.py](python/vm9_root.py)，差分验证见 [verify_vm9_root_fresh.py](python/verify_vm9_root_fresh.py)，脱敏证据见 [vm9_root_fresh_native_20261004.json](evidence/vm9_root_fresh_native_20261004.json)。历史 component 对照见 [STATE_OWNER_INITIALIZATION.md](STATE_OWNER_INITIALIZATION.md)。

## 实际 allocator 的独立 root factory（2026-10-06）

[vm9_root_allocator.py](python/vm9_root_allocator.py) 现已把 matching libc 的自然冷启动、实际 small/large malloc、small-cache half flush、small-cursor GC、empty extent release 接入 `+0x257578` factory。它复用既有 root／TLS／singleton／registry／配置／state owners，在一个 GuestOS transaction 中发布成功结果。Python 从独立 ELF／TLS／引用／栈和显式虚拟 OS 输入开始，没有 native 快照、替代 malloc 返回值或提前清零 GC event。

[严格差分 CLI](python/verify_vm9_root_allocator.py) 的 **10 native／8 rollback** 已全部终态通过。八组是两基址 × SDK 缺失、30、负值、带符号后缀；另两组同时改变栈位置、映射起点和 TLS canary。每组自然返回，均为 **206 次实际 malloc PLT、93 次实际 free PLT、3 次 small-cache flush、1 次 GC**；root VM 716 步，在 `+0x99f04` 退出，root count=1。全部 32 个 VM 槽、guest 对象、全部主 image 页、观察的 TLS／libc globals、全部 retained mapping 页，以及 allocation／free／registration／clock／wake、OS 次序、映射属性／cursor 均一致。证据见 [actual root](evidence/vm9_root_actual_allocator_native_20261006.json)。

`+0x9833c` 的 small GC 共 **28 native／8 rollback** 通过，见 [GC 证据](evidence/vm9_libc_gc_native_20261006.json)。正 watermark 共用 `_flush_small_bin`，保留 `count-low+(low>>2)`；负 watermark 调整 fill；每次按实际 W-register variable shift 更新 fill，并更新 low、cursor、event。公开旧 malloc/free owner 默认仍在 event=228 拒绝，只有显式接入该 GC owner 的 bridge 继续执行；large cursor GC 仍拒绝。此前 165/42 的满缓存前段和 170/54 的 GC 前段只是历史定位记录，已被完整 actual-root 对照推进，保留其 [旧满缓存证据](evidence/vm9_root_actual_allocator_frontier_20261006.json) 和 [旧 GC 证据](evidence/vm9_root_actual_allocator_gc_frontier_20261006.json)。

本次完整差分还恢复三项可观察 ABI 输入：malloc `+0x1bb0c` 留下的 operator-new frame／return slots、`+0x163e00` 留下的 TLS canary，以及 small refill `+0x7973c` 的 cache spill。最后一项在 singleton 的显式 caller SP、当前 TSD/cache 和真实 refill 条件下生成；随后 TLS tree `+0x269190` 复制其上七字节为 pair padding。所有值均由本次 Python 输入／分配状态推导，不能从 native expected memory 填入。未比较所有物理栈页。

拒绝控制覆盖未对齐栈、缺失 TLS、mapping provider 失败、首次分配 observer 失败、GC 后分配失败、第 93 次 free 后失败、第 206 次 malloc 后失败和超长属性。晚期失败已完成实际 GC；guest 页面、owned mapping records／cursor 和 VM image base 全部回滚。外部 provider／observer 已产生的效果不会回滚，调用方仍须遵守明确的虚拟环境服务契约。

**这仍是有界 root factory 的通过证据。** 它尚未在同次主启动／非空 worker 之后组合验收，诊断 scope 排除、缺文件／日志／socket、无 waiter 和串行 guard 条件仍在；realloc、large cursor GC、非默认配置、host 多线程等没有因此恢复。fresh Medusa 请求输出与新的线上矩阵仍未通过。

受影响回归 **90 native／55 rollback** 全部终态通过（旧 fresh root、small flush、cached free、默认 tcache 边界），见 [回归证据](evidence/vm9_root_actual_allocator_regression_20261006.json)。

## 历史 nonreusing allocator 对照（2026-10-04）

| 对照项 | 结果 |
| --- | --- |
| Fresh-input factory 控制 | 2 组 image bases × SDK 缺失、30、负值、带符号后缀，共 8 组 |
| Root VM | 716 步，退出于 `+0x99f04` |
| 完整 factory 分配／释放 | 206 / 93；包括 factory、264-byte root 前缀、全部当前 VM 子树和 factory 收尾 |
| VM 终止状态 | 全部 32 个虚拟槽一致 |
| 对象与全局状态 | guest 对象区、全部主 image 页、TLS、2256-byte pthread generation table 一致 |
| 有序副作用 | allocation、free、clock、析构注册和 wake 次序一致；2 次注册、9 次 wake |
| Caller 前置拒绝 | 9 个案例，页面回滚且 VM image base 恢复 |
| Factory 失败回滚 | 分配入口与 VM 中途各 1 个案例；页面回滚且 VM image base 恢复 |
| Python 输入 | 新 ELF 加载／relocation、显式配置输入、TLS fixture；native 执行只生成期望输出 |

八个控制使用与既有 native oracle 相同的 **nonreusing malloc/free** 边界。属性、clock、不可用日志／文件／socket、mkdir EEXIST、无 waiter wake、诊断 scope 排除和单线程 guard 也均是明确的控制条件。此结果没有恢复实际 jemalloc 的全部 boot、arena／OS region 运行状态，也没有证明 JNI、可用日志端点、真实文件配置、多线程或所有配置分支。

页面事务不回滚已经执行的外部回调。Factory 中途失败的证据明确记录 `external_effects_rolled_back=false`；这描述旧 callback allocator 的隔离测试边界；新 GuestOS bridge 回滚自己持有的 guest 状态，不回滚 provider／observer 的外部效果。

## Caller ABI 与构造依赖

`construct_root_caller` 对应 `+0x257308`，设 caller 的输入栈为 `entrySP`，VM 工作栈为 `stack=entrySP-0x5a0`。

| 字段 | Python 生成规则 |
| --- | --- |
| object／source reference 参数 | `stack+0`、`stack+8` |
| descriptor | `stack+0x10 = image+0x258520`；`stack+0x18 = stack+0x570` |
| return word | `stack+0x20` |
| register backing | `stack+0x458`；未写入的槽保留函数输入页中的字节 |
| 初始化槽 | R0=0；R4..R7=stack／两组 image tables／descriptor；R29=`(stack+0x440)&~15`；R31=return |
| TLS canary | `entrySP-0x28`，从显式 thread pointer+0x28 读取，退出前再次检查 |
| caller 保存的物理寄存器 | 显式 frame pointer、X28、X19 输入；完整 root 组合从自身 frame 和 object 地址推导 |

`construct_initialized_root` 复用既有 `construct_root_configuration_layout`，生成 264-byte root 及其 30 次嵌套分配，再复制第三个配置引用，进入 caller，最后释放临时引用。它恢复了此前遗漏的第三个引用 count 增加与减少。

进入 caller 前，`+0x25c324/+0x163ddc/+0x24bca4/operator-new` 在旧 nonreusing 控制的 register backing 留下 14 个已建模物理 word。实际 allocator 的新增 spills 与显式 TLS canary 见上节。Python 按当前 entrySP、ELF return offsets、container 分配地址和 object 字段推导它们，不导入稍后的 native 栈快照。这里只恢复已证明可观察的 ABI 字段，不声称完整模拟所有物理栈页。

`construct_root_reference` 对应更早的 `+0x257578` factory：分配 root／空字符串／count，复制三个配置引用，调用完整 root，发布输出 root reference，再按 native 顺序清理四个临时引用。输出 root count 为 1。所有冷 TLS、singleton、parser、state owner 等依赖均接到既有 Python 组件和显式环境回调。

## 同次采样的证据使用

Native oracle 和 Python 模型各自从 fresh ELF／fixture 开始。Python 输入在 native 对照启动前已独立建立。Native 退出页面、寄存器和有序副作用仅用于比较；没有将它们写回模型输入。

VM 终止虚拟槽在 `+0x257368`、native caller epilogue 前读取。完整构造器随后清理临时引用，会覆写三个物理 backing word，因此不能把清理后的物理栈当作 VM 的终止虚拟槽。构造器／factory 收尾分别核对对象、引用 count、全局状态和副作用。

旧 [verify_vm9_root_vm_prefix.py](python/verify_vm9_root_vm_prefix.py) 仍保留同次函数入口的 component 差分。现有 4 个控制现在覆盖 16 段 VM 和 76 条子树，包含 root caller、完整 root constructor；这份旧证据仍明确标记其 native 输入边界。独立 factory 的 8 组 fresh 对照是另一个 verifier，不能混用两种输入边界。

这些证据支持：默认 root 构造链可以由 Python 生成；caller 不能把未写寄存器槽全部清零；第三配置引用必须计数；VM 退出与清理后栈必须分别取证；同次对象匹配需要同时核对全局／TLS／有序副作用。证据不支持“当前线上 Medusa 已完成”或“16/24 套签名全部恢复”。

## 复现与接口使用

从番茄目录运行，matching ELF/libc 由本地私有路径提供：

```text
python -B python/verify_vm9_root_allocator.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-actual.json
python -B python/verify_vm9_libc_gc.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/gc.json
python -B python/verify_vm9_root_fresh.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-fresh.json
python -B python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-components.json
```

Verifier 检查目标 ELF SHA256，并把输入内容保留在进程内。公开 JSON 只含 counts、offsets、长度和比较结果，不含 ELF、解码常量、配置 key／payload、真实设备／会话或请求响应。

研究接口按由内到外排列：`RootCallbacks` 承接当前 root VM 回调；`construct_root_caller` 生成 caller 并返回 32 个槽；`construct_initialized_root` 从 constructor 输入生成 root；`construct_root_reference` 从 factory 输入发布 root/count。调用方传入 pages、entry SP、thread pointer、image base、VM interpreter、allocator／free 和环境服务。返回的 root 对象是后续 signer 初始化的依赖，尚不是请求头签名或下载接口。

## 仍需继续

外层启动 caller 和两类 worker 的 TLS support 前段已通过独立对照，见 [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md)。executor context 组件也已恢复；同次 fresh 启动／默认非空 worker／actual allocator／guest 可 join 退出，以及本文件独立 actual-root factory 已分别通过。下一步先在同次启动状态上组合 root，再接入更外层 signer constructor／handle 初始化；实际 detached worker／host OS 线程和未恢复 allocator 分支仍独立保留边界。然后必须用新的请求参数贯通 Medusa body，对照签名输出，并重做当前线上全头矩阵与时间戳实验。

无 JVM Rust signer/download、当前非空搜索与分页、抖音／起点闭环、最终 Pages／Actions 搜索下载产品仍未完成。
