# JNI dispatch 初始化、类引用与 A/B once 启动边界

2026-10-07。本阶段恢复 `+0x26E19C` 和 `+0x26F154`：从 fresh ELF/guest 输入
解码方法元数据，经显式 JNI 服务完成注册尝试、静态方法查找及类引用发布。
**56 个原生/Python 对照、9 个负控制通过**。另有 **6 个原始 JNI_OnLoad
探针**，单独计数，没有执行完整 Python bootstrap 对照。
后续另追加两个经过实际TLS获取的原始入口探针，范围和复现见第6节。

原始入口探针已经观察到 `+0x26E19C` 返回。四个受控 warm-switch 探针停在
后续 startup 入口；两个保留 cold-switch 的探针经匹配 libc 的真实 mutex
进入 once initializer，并停在 TLS acquisition 调用前。**完整独立 Medusa、
真实 Android JVM、完整 JNI_OnLoad 返回及线上签名仍未验证。**

## 1. 已恢复的输入、数据和分支

| 地址 | 实际行为 |
| --- | --- |
| `+0x26E19C` | JavaVM publication 后调用的 JNI dispatch 初始化 |
| `+0x382550..+0x3825B8` | 以本函数地址派生 delta 的 encoded guest 表 |
| `+0x3DEE68/+0x3DEE70/+0x3DEEB0` | 默认 ELF 中的 native 方法名、签名、静态方法名 |
| `+0x3DEE6C/+0x3DEEAC/+0x3DEEB4` | 三组 uint32 lazy decode 标记；任意非零值跳过解码 |
| `+0x26E684` | 写入 24-byte JNINativeMethod 的 callback 地址；body 未执行 |
| `+0x3DEEC0` | 默认表指向的静态方法 ID 输出 slot |
| `+0x3DEEB8` | 默认表指向的类引用输出 slot |
| `+0x26F154` | 原始引用保留／NewGlobalRef／DeleteLocalRef 规则 |

native 方法名为 `a`，静态方法名为 `b`，两者使用从实际 ELF 解码的签名：
`(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;`。实现从 encoded
表和 XOR mask 读取输入；不固定解码结果，不用 native 输出填充 Python 页。

三组 lazy decode 先执行。class_name 为 NULL 时不调用 JNI；已有输出保持。
非空类名按原始 vtable 顺序执行：

1. `FindClass`（slot `0x30`）。结果为 NULL 时保留既有输出并返回。
2. 第一次 `GetSuperclass`（slot `0x50`）。结果为 NULL 时同样提前返回。
3. 第二次 `GetSuperclass`。若返回非空，注册一个 callback，并删除该 ancestor
   的 local reference；若为 NULL，则跳过注册和这次删除，继续方法查找。
4. `GetStaticMethodID`（slot `0x388`）作用于**最初 FindClass 得到的类**，
   方法名为 `b`。结果包括 NULL 都按原顺序写入方法 ID slot。
5. 对最初类执行 `+0x26F154`，把返回引用写入类 slot。

`RegisterNatives`（slot `0x6B8`）返回状态没有参与原始分支。注册失败控制仍
继续查找、引用保留和发布；这不能证明 Java 层注册成功。中间 superclass
没有额外 DeleteLocalRef，模型保持实际清理顺序。

引用保留读取 GetObjectRefType 的低32位：type==2 直接保留原引用，其余值
都调用 NewGlobalRef 后 DeleteLocalRef，含 type 0/3/unknown 和 NULL reference。
NewGlobalRef 返回 NULL 也执行删除。NULL environment 则返回 NULL，无 JNI调用。
这些是实测 native 分支；模型不补充未执行的异常检查或额外引用清理。

JNI provider 为每次调用读取 live environment/vtable/function。table-switch
控制在 FindClass 服务后替换 table，后续调用跟随新表。输出和 lazy 状态也
允许显式 guest relocation；没有把唯一默认地址当成计算结果。

## 2. 56 个对照与9个负控制

- 34 个初始化对照：两个基址各17个，覆盖完整 cold decode、全/部分 warm
  decode、NULL 类名、NULL environment+类名、两次 superclass 的失败分支、
  注册错误、缺失方法 ID、NULL global 引用、弱/未知引用类型、live vtable
  替换及 encoded 目标重定位。
- 18 个引用保留对照：NULL environment/reference，local/global/weak/invalid/
  negative type、高32位不参与类型判断、NULL NewGlobalRef 结果。
- 4 个 publication→初始化的同次原生组合：JavaVM global 从0经原始
  `+0x271998 → +0x27BE88` 发布，再进入原始 initializer。中间 host
  continuation 明确属于测试编排，不当作完整 JNI_OnLoad caller。
- 9 个负控制：NULL environment 的非空类名、不对齐 SP、缺 environment/stack
  页、NULL function、缺 provider、越界 provider 输出、负 reference，及方法 ID
  暂存后发生的 JNI拒绝。guest 页回滚，已发生的外部 JNI 服务效果不回滚。

比较 fresh guest 前 `0xA000`、所有主 ELF 页、服务参数/返回和顺序；发生注册
时比较 entry SP-`0xA0` 的完整24字节方法表。独立引用对照另比较返回 X0。
未比较完整物理栈、所有寄存器和整个 ABI；initializer 是 void，未把其保留
X0解释成成功返回码。无 allocator/OS 输出快照或 padding masking。

## 3. 六个原始 JNI_OnLoad 探针

入口均为原始 `+0x27B41C`，通过原始 publisher 和 initializer。JNI 类名来自
原始 ELF lazy decode，为 `com/bytedance/mobsec/metasec/ml/MS`。Java 类 handle、
GetEnv、其余 JNI方法、clock/decimal 服务仍是显式输入；不是 Android JVM。
136/320字节 reference 的字段为 warm fixture，未执行其完整 cold 构造。
JNI_OnLoad defined GLOB_DAT 通过 ELF symbol 绑定，未 stub 掉原始 JNI_OnLoad。

| 控制（两个基址各一次） | 停止位置 | 可支持的结论 |
| --- | --- | --- |
| switch=0、once已完成 | `+0x28040C` 前 | 真实 initializer 返回；mask `0x200` 的分支选择此 startup |
| switch=`0x200`、once已完成 | `+0x2A0028` 前 | 同上，另一个分支选择此 startup |
| switch once保持初始状态 | `+0x26EDC4` 前 | 原始 call_once、matching-libc mutex 和实际 initializer 前缀执行 |

前四个显式设置 once `+0x3D1570` 为 uint64 全1；缓存 switch `+0x3D1578`
由 fixture 提供。它们不能证明 cold GetABSwitch 已完成。

后两个保留 once 的真实初始0，执行 `+0x32A0A0 → +0x165644 → +0x165648
→ +0x165658`，并实际执行 matching-libc pthread_mutex_lock/unlock。
停止时 common mutex `+0x3E2EB8` 已解锁，once 为1（正在初始化）；initializer
尚未完成、predicate尚未返回。TLS获取 body、Java getter和后续 startup
body尚未执行。探针只保存原生观察，**不计入56个 Python 对照**。

最初未提供这条 mutex 路径时，oracle经其未绑定 PLT 跳到未映射地址。补入
matching-libc 真实 mutex 后到达上述边界；这不是目标应用死循环或崩溃的证据。

## 4. 复现与调用接口

样本 SHA-256：

- libmetasec：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`
- matching libc：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`
- 基址：`0x122C0000`、`0x775C205000`。

私有二进制不随仓库分发。在仓库根目录执行：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_initialization_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_initialization_fresh_20261007.json
```

[vm9_jni_environment.py](python/vm9_jni_environment.py) 提供
`initialize_java_dispatch(pages, image_base=..., entry_stack_address=...,
environment_pointer=..., class_name_address=..., invoke_jni=...)` 和
`retain_global_jni_reference(pages, environment_pointer=..., reference=...,
invoke_jni=...)`，各参数为 keyword-only。

pages 必须包含调用者构造的映射与重定位 ELF 输入；SP需16字节对齐。
`invoke_jni(pages, function_address, argument_tuple)` 为显式服务，接收 live
环境指针和实际参数，返回 signed int32 或 uint64。缺服务或未映射页明确拒绝。
初始化返回诊断数据（解码长度、引用、是否尝试注册/查找等），不代表真实
Java 注册结果、签名输出或完整 JNI_OnLoad 返回。

- [验证器](python/verify_vm9_jni_initialization_fresh_20261007.py)
- [机器证据](evidence/vm9_jni_initialization_fresh_20261007.json)
- [此前 publication](REQUEST_JNI_PUBLICATION.md)
- [此前 TLS/JavaVM 获取](REQUEST_JNI_ENVIRONMENT.md)

## 5. 如何使用这份证据与后续缺口

逆向报告可引用本证据证明本 hash 对应版本的 encoded decode、调用次序、
条件分支、具体输出写入、引用清理，以及原始 JNI_OnLoad 到达的上述边界。
复核时保留基址、fixture输入、服务和比较窗口，区分组件对照与原始入口观察。
它不能证明线上服务器接受签名、Android类加载成功或 novel download可用。

下一处是 cold switch once initializer 的 TLS获取与 JNI getter：
`+0x165658 → +0x26EDC4 → +0x26E70C/+0x270854`，然后才是后续真实
startup VM。注册的 `+0x26E684` callback、非零 JavaVM 下 shared factory 的
JNI分支、真实请求 FindClass/URL/headers转换仍未贯通。

当前 owning-session 没有注入探针 VM/env：低基址仍957步 synthetic返回，
高基址仍965步缺 JavaVM 拒绝。完整独立 Medusa、fresh请求签名、线上全头
矩阵、无JVM Rust、搜索非空和分页、抖音/起点闭环及最终 Pages/Actions
下载产品仍未完成。


## 6. 后续：原始 cold switch initializer 已经经过 TLS 获取

本节保留此前停在dispatcher前的证据；后续actual dispatcher与独立Long转换组件见
[REQUEST_JNI_DISPATCH.md](REQUEST_JNI_DISPATCH.md)，原始入口尚未完成Long/once。

另两个原始 JNI_OnLoad 探针在同一次 native invocation 内自然执行 publication、
JNI初始化、A/B call_once、实际 TLS acquisition，停在 `+0x26E70C` 前。
它们没有 host continuation，没有执行该地址既有 oracle 返回 stub；它们的
**完整 Python bootstrap 对照数为0**，与此前56个组件对照／6个入口观察分开。

前导为 `+0x27B41C → +0x27BE88 → +0x26E19C → +0x32A0A0
→ +0x165648/+0x165658 → +0x26EDC4`。随后真实 emulated-TLS、
`+0x26EEEC/+0x17CAAC/+0x34265C` 构造、环境获取和析构注册执行。
OS thread-specific slot开始为空，从实际 native 分配得到 array；每次执行共有
6个显式 allocator malloc请求，大小为128、16、39、16、24、23字节。三次
GetEnv为 JNI_OnLoad 的初始获取、TLS owner构造和获取完成前的调用。

此时 once `+0x3D1570` 仍为1；getter在 `+0x1656A0` 传入的前五个register
words为 `0x1000000E, 0, 0, 0, 0`。尚未调用 dispatcher、取得 Java getter结果、
执行 `+0x270854` 的转换，或完成 once并进入后续startup VM。

JNI/JavaVM返回值、pthread OS服务、allocator仍为显式fixture。136/320 reference
依旧warm；emulated-TLS subsystem 的全局状态和OS keys也预先提供，只有当前
线程的TLS slot从空开始。**不是完整 TLS全局/OS/arena 冷启动，也不是 Android
JVM或纯Python完整bootstrap。**没有向现有owning-session注入这些输入。

复现与机器证据：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cold_switch_tls_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_cold_switch_tls_fresh_20261007.json
```

- [cold switch TLS原始入口探针](python/verify_vm9_jni_cold_switch_tls_fresh_20261007.py)
- [两条原生观察证据](evidence/vm9_jni_cold_switch_tls_fresh_20261007.json)

后续需恢复 `+0x26E70C → +0x26E944` 的实际 JNI dispatcher、variadic参数与
异常处理，再恢复 `+0x270854` 的返回值转换和缓存依赖。对该调用使用旧oracle
stub不能证明getter恢复、once完成或fresh签名。
