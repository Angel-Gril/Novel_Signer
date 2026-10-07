# JNI cold once 控制、启动 mask 与导入依赖

本报告保留 once/mask 与初期导入控制的原始计数。后续原始 JNI 返回、同次默认任务
及 B selector 进展见 [启动/worker 报告](REQUEST_JNI_STARTUP_WORKERS.md)；下文停止点
不代表当前组合的最新停止点。

> 本机验证记录：2026-10-08（Asia/Shanghai）。日期来自本机时钟，样本为既有 v7.1.3.32 ELF。
> **34 组 native/Python 对照、9 项负控制通过；另 4 条原始启动前缀及 4 条导入对照观察通过。**
> 完整 Python bootstrap 对照仍为 **0**；完整独立 Medusa、fresh 签名及线上全头矩阵未完成。

## 1. 本轮恢复的控制层

在 [此前 cold caller 组合](REQUEST_JNI_COLD_ONCE.md) 上，新增两个 Python owner：

```python
read_cold_java_switch(pages, *, image_base, entry_stack_address,
                     acquire_environment, invoke_jni, wake_condition)
check_cold_java_switch_mask(pages, *, image_base, entry_stack_address,
                           mask, acquire_environment, invoke_jni, wake_condition)
```

它们恢复 `+0x165588 → +0x1655E0 → +0x32A0A0 → +0x165644/+0x165648 → +0x165658`
的有界正常路径，以及 `+0x165560` 的完整 uint64 mask 判定。
`+0x1658DC` 的启动 predicate 将 mask 固定为 `0x200`，随后 tail-call 同一判定。
返回结构分别提供缓存 word、进入前 once 值、是否运行 initializer，以及 mask/匹配结果。
这是控制层的诊断 API；完整物理返回 ABI 和 Medusa 签名不在返回值中。

| once 值 | 实际控制 |
|---|---|
| `0xFFFFFFFFFFFFFFFF` | 跳过 once mutex 和 initializer，读取缓存 |
| `0` | lock、写 1、unlock、运行 JNI caller、lock、写全 1、unlock、broadcast |
| `1` | 原生进入 `pthread_cond_wait` 循环；当前 Python 明确拒绝 |
| 其他非零值 | 原生仍进入/离开 once mutex，跳过 initializer，读取原有缓存 |

初始化回调在锁外、once 为 1 时运行；完成值在 wake 前发布，wake 时锁已释放。
匹配条件为 `(mask & ~word) == 0`，两个操作数均为 64 位。
零 mask 也先调用 getter；不能将其改写为无需初始化的立即成功。
已验证 Long 缺方法时写 0，而 NULL object/dispatcher 异常时保留原缓存。
缓存完成后的读取无需 JNI/acquisition/wake 服务，两个基址均测试了传入 None 的路径。

## 2. 栈数据和比较点

getter 入口 SP 为 S：getter frame 为 `S-0x30`，once wrapper frame 为 `S-0x70`。
wrapper 将自己的 `frame+0x10` 和 getter frame 写入 `frame+8/+0x10` 的两个 live 链接。
once 再建立 0x40 frame，thin wrapper tail-call 原始 cold caller；没有直接写结果跳过 caller。
mask body 先建立 0x20 frame，再调用 getter。native/Python 的 JNI variadic 参数在实际消费时比较。

caller 的 env/context pair 在 `+0x165680` 消费时比较。caller 返回后，该临时区被后续
mutex/broadcast 调用复用，不能作为 getter 终态的有效窗口。终态继续比较所有主 ELF 页、
guest 前 0xA000 和仍有效的 wrapper 链接；未消费的 GP/SIMD、canary/saved registers
及完整物理栈仍不作等价声明。两侧均从 fresh ELF/重定位和 fixture 输入开始，不使用
native 入口前导快照。

## 3. 正式验证数量与边界

| 证据 | 数量 | 证明范围 |
|---|---:|---|
| native/Python getter/mask 差分 | 34 | 两个基址 × 17 profiles；包括 cache、64 位 mask、异常、共享位和计数回绕 |
| Python 负控制 | 9 | 栈/mask 范围、once 等待、锁争用、缺 acquisition/JNI/wake、晚期 wake 失败 |
| 原始 JNI_OnLoad 启动前缀 | 4 | 两个基址 × A/B；A 到通用 VM prelude 结束前，B 到构造器返回后 |
| 未绑定/绑定 memcpy 导入观察 | 4 | 两个基址 × 单一导入变量；A 从 NULL callback 目标推进到 pthread_create PLT |
| 完整 Python bootstrap 对照 | **0** | 尚未验证完整 loader/全部 ctor/JNI_OnLoad/startup 的 Python 等价 |

34 组组件对照执行实际 ctor 和 JNI initializer，以两个显式 driver continuation 连接
initializer 与 getter/mask；不是完整 Android loader。matching libc 执行真实 normal mutex
和 condition broadcast，futex wake 的无等待者返回 0 为显式 OS 服务。
condition u32 增 4，私有/共享操作分别为 129/1，count 为 0x7FFFFFFF；计数回绕已对照。
9 个失败均回滚 guest 页；缺 wake/晚期 wake 错误仍保留已发生的外部 JNI 事件。
这不是 native C++ exception/unwind 等价，等待与真正线程并发均未实现。

14 组旧 caller 组合、4 个旧负控制及 4 条旧入口观察也重新执行通过，输出留在私有工作区。

## 4. 同次原始启动向后推进

原始 JNI_OnLoad 观察只使用一个显式 driver：ctor exit → ELF 定义的原始入口。
cache publication、JavaVM/TLS/JNI、cold once/Long/cleanup 在同次 native execution 执行。
引用对象、TLS subsystem globals/OS keys、allocator/JavaVM/JNI/clock/exit/OS 服务仍为显式输入。

A（word=0）进入 `+0x28040C`，在 `+0x168324` 使用 bytecode `+0xA7050`、metadata
`+0x35D670`、callback table `+0x35D690`。四条前缀中的 A 在 `+0x1684F0` 前停止；
定义的 prelude slots 已核对，这两条观察没有执行第一条 VM 指令。

B（word=0x200）进入 `+0x2A0028`，实际 `+0x2A02D4 → +0x2A9754` 已返回。
构造器清 u32/+8 的 u64，并通过显式 memset 清 `state+0x6050` 的 0x280 字节；
随后将 `state+0x6010` 写到 `state+0x6058`。**不能把整个 0x62E0 区域描述为清零。**
当前 fixture 的 `image+0x3E1EB8` descriptor 仍为 NULL，后续 `+0x2A9718` 的 dispatch
和 descriptor 发布来源待恢复。这里只证明构造器的 native 前缀，不证明 B 的完整 VM。

永久 JNI table 从 guest+0xA000 移到 +0x6000，TPIDR_EL0 的存储从 +0xD000 移到 +0x3000，
避免 B 大栈覆盖永久环境输入。未移动的旧 fixture 不能直接用于完整 B 分支验证。

## 5. A 分支导入绑定缺口的单变量观察

同一输入下，当前基础 ELF loader 只做 relative relocation 和指定的 defined-symbol 绑定。
样本包含 16 个 undefined `memcpy` 的 `R_AARCH64_ABS64`（257）slot，未绑定时仍为零。
A 的首个 `+0x2813E8` packet 目标为 0，size=8；在该 wrapper 前停止并验证此输入缺口。

按 ELF symbol/relocation 解析这 16 个 slot，将它们明确绑定到已有 memcpy 服务的 PLT。
PLT 地址从 `.rela.plt`/`.plt` 派生，并核对为 `+0x347F60`；没有绑定其他导入变量。
ABS64 的符号加 addend 语义另按 Arm 官方 AAELF64 规范核对，来源：
`https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst`。
A 随后执行两次 size=8 的 packet 复制，继续到 ELF 解析出的 `pthread_create +0x348000`
入口前。这两条 bound 观察已经执行部分 startup VM，但**未验证 VM 返回**，也没有
执行 pthread_create 或创建 OS 线程。

因此下一处 A 缺口是 thread-create 服务与 startup/worker 的接合；B 缺口是 descriptor
全局的实际发布。导入绑定是显式服务适配，不是完整动态链接器或 actual libc memcpy 对照。
不能把未绑定 fixture 的 NULL 分支当作真实 App 的崩溃、限制或无限循环。

## 6. 复现和证据使用

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cold_mask_fresh_20261008.py --library C:\AI\6\libmetasec_ml_71332.so --libc C:\AI\6\_vlibc.so --output platforms/bytedance/tomato/evidence/vm9_jni_cold_mask_fresh_20261008.json
python -B platforms/bytedance/tomato/python/verify_vm9_jni_startup_prefix_20261008.py --library C:\AI\6\libmetasec_ml_71332.so --libc C:\AI\6\_vlibc.so --output platforms/bytedance/tomato/evidence/vm9_jni_startup_prefix_20261008.json
```

两组证据将 sample/libc hash、基址、profile、原生路径、driver 数、比较窗口和未完成项
一起记录在 [getter/mask JSON](evidence/vm9_jni_cold_mask_fresh_20261008.json) 与
[启动/导入 JSON](evidence/vm9_jni_startup_prefix_20261008.json)。它们可用来证明具体控制流、
排除错误的 mask/缓存语义和定位加载输入缺口；不能证明 fresh 签名能通过线上服务器。
私有 .so、设备标识、认证材料和完整进程快照不随公开报告提交。

下一步先接 A 的 pthread_create/startup worker，并追 B 的 +0x3E1EB8 publication；
再恢复/组合完整 JNI_OnLoad 控制、全部必要 loader/init/TLS/allocator 输入，验证 fresh
Medusa 签名与全头服务器矩阵。无 JVM Rust、非空搜索/分页、抖音/起点及最终
Pages/Actions 搜索下载产品仍待后续完成。
