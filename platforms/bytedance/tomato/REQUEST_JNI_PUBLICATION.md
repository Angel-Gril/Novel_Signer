# JavaVM 发布、encoded caller 与 JNI_OnLoad 原始入口探针

2026-10-07。本阶段恢复 `+0x271998 → +0x27BE88` 的 JavaVM 发布调用。
新增 **54 个原生/Python 对照、11 个负控制**，另有 **4 个原始 JNI_OnLoad
探针**；四个探针没有执行 Python 完整 bootstrap 对照，计数单独保存。

发布后的六个连续对照在同一次原生执行中调用真实 TLS acquisition，比较与
Python 完整最终 payload。JavaVM/OS 服务仍为显式控制输入。完整 JNI_OnLoad、
真实请求转换、独立 Medusa 和线上签名仍未完成。

## 1. 实际发布点与调用关系

| 地址 | 本阶段验证的行为 |
| --- | --- |
| `+0x374F90` | ELF relative relocation 指向 JavaVM storage `+0x3DEED8` |
| `+0x27BE88` | 从参数块第一个 uint64 读取 VM 指针，通过 GOT 写入 storage |
| `+0x271998` | 保存原 caller FP/LR，RET 进入 callback，传递参数块及加偏移的 FP/LR |
| `+0x26ECB4` | publication wrapper 调用它取得自己的 frame pointer；执行其原始 body |
| `+0x27B41C` | 原始 JNI_OnLoad 入口；本阶段仅原生探针，完整 Python body 未恢复 |
| `+0x27B750/+0x27B7A8` | JNI_OnLoad 内部入口 wrapper 与实际注册前 body |
| `+0x27BB10` | 原始 GetEnv call，version 为 `0x10006` |
| `+0x27BCA0` | 成功探针在此停止，publication 已执行；下一处调用 `+0x26E19C` |

`+0x27BE88` 使用参数块中的值发布，允许零值，也不会构造或验证 JavaVM vtable。
这段发布行为与现有 TLS acquisition 的 GetEnv/attach/detach 服务分开。
当前 owning-session 高基址请求仍没有 JavaVM 输入，原来的 NULL 拒绝保持。

当 X1、X2 均按 **uint64 大于4096** 时，wrapper 用 `X1-0xE9` 和 `X2-0xD5`
替换自己的 saved FP/LR。其余分支保持原值；4096与4097、uint64最大值已有控制。
wrapper 的 X0 是参数块地址或自己的 frame 地址，属于这条 void callback 的
保留寄存器行为，不能解释为 JNI_OnLoad 返回码。

`+0x271998` 从原 caller FP/LR 生成上述编码参数，并通过 RET 转入 callback。
它保留的80字节栈区域还含前导 spill 留下的原 FP 和输入 X6。它在 callback
入口的 X29 为0；callback 的条件替换随后恢复原 caller FP/LR，使调用链回到
原 continuation。低值或 uint64 加法回绕导致编码参数不超过4096时，完整
Python publication 调用组合拒绝；独立 adapter 控制仍验证其实际编码输出。

## 2. 后续对象会读取的栈 word

publication wrapper 调用 `+0x26ECB4` 时，较早的 `+0x26ECD0` 先 spill X6/X7。
后面的 **`+0x26ED3C` STP X7,X6 会覆盖该位置**，最终保留 X6。这个 word 位于
getter entry SP-0x28，即 publication wrapper entry SP-0x48。

随后的 acquisition 临时对象会保留 ownership byte 后的7字节 padding；这些
bytes 可以来自这个 word。实现因此恢复最终 X6 写入，并覆盖非零/max-uint64
控制和非零 X6 的连续 temporary-attach 控制。没有固定 native 输出字节，也
没有 masking。其余不被本组件读取的深层 obfuscation spill/完整 ABI 尚未比较。

## 3. 54 个对照、11 个负控制

从私有 ELF 和独立 guest fixture 开始，不使用 native 输入快照。

- 28 个 wrapper 对照：条件阈值、uint64、NULL/opaque VM值、替代 storage、参数
  与 storage alias、prologue/source alias、最终 X6 spill。
- 10 个 adapter 对照：普通、低值、uint64回绕的原 FP/LR，以及不同 X6。
- 10 个完整 adapter→publication 对照：两种基址、不同 FP/return sentinel、
  NULL/non-NULL VM值和替代 storage，实际原生返回。
- 6 个 publication→TLS acquisition 连续对照：两种基址的 warm、fresh TLS slots
  与 temporary attach。JavaVM全局初始为0，由原始 publisher 写入，再进入原始
  acquisition；Python也经恢复的 callback 发布。中间 host continuation 是显式
  fixture 编排，不宣称整个 JNI_OnLoad 的调用框架已经恢复。
- 11 个负控制：SP/uint64/NULL/缺页/GOT storage 错误和不可编码的 caller FP/LR。
  guest pages 在拒绝时回滚。

比较 guest payload 前 `0xA000`、全部主 ELF 页、wrapper 的32字节保留 frame、
getter 的 live word、adapter 的80字节保留 frame及返回 X0/FP/LR/SP/参数。
连续控制另比较分配和 JavaVM/pthread 服务顺序。未比较完整物理栈、全部寄存器、
Android JVM、cold JNI_OnLoad 或 whole-native request。

样本 SHA-256：

- libmetasec：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`
- matching libc：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`
- 基址：`0x122C0000`、`0x775C205000`。

## 4. 四个 JNI_OnLoad 原生探针的范围

两基址各运行 GetEnv失败和成功各一次，入口是原始 `+0x27B41C`。fixture 明确
提供 warm 136/320字节 reference 的被读取字段、GetEnv、decimal parser 和 clock
服务；没有执行完整 cold singleton 初始化或真实 Android JVM。

`+0x375010` 是定义在本 ELF 中的 JNI_OnLoad GLOB_DAT relocation。探针从 symbol
metadata解析并绑定到当前image的入口，使原始 memcpy 可以读取该入口的指令。
默认 relative-only loader 不提供这个定义符号的绑定；本阶段没有把可选探针
绑定扩大为项目全部 ELF loader 已完成的结论。

decimal 服务读取原始 ELF lazy 解码后的字符串，得到5256；没有把5256作为
代替字符串解析的服务返回常量。正常选择过程经 `+0x271998` 到达原始
`+0x27B750`，GetEnv成功后再次选择并调用 `+0x27BE88`。

观察结果：

- GetEnv=-1：原始 JNI_OnLoad 返回 uint32 `0xFFFFFFFF`，JavaVM storage 保持0；
  timer/lazy globals 仍可能产生副作用，不能宣称失败无副作用。
- GetEnv=0：原始 publication 执行，VM指针写入storage，探针停在 `+0x27BCA0`。
  这个停止不是整个 JNI_OnLoad 的正常返回。

后续是 `+0x26E19C` 的 JNI 注册/环境相关调用，然后该路径可能调用
`+0x28040C` 的启动入口。需继续恢复该实际初始化顺序和等价 JNI 服务，避免
把当前无JavaVM的启动 fixture 当成真实Android bootstrap已完成。

## 5. 复现与作为逆向证据使用

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_publication_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_publication_fresh_20261007.json
```

实现与证据：

- [vm9_callbacks.py](python/vm9_callbacks.py)：`prepare_encoded_callback_frame`。
- [vm9_jni_environment.py](python/vm9_jni_environment.py)：`publish_java_vm_wrapper`、
  `publish_java_vm_callback`；已有 get/construct/destroy/acquire 接口保持。
- [验证器](python/verify_vm9_jni_publication_fresh_20261007.py)。
- [发布与入口证据](evidence/vm9_jni_publication_fresh_20261007.json)。
- [先前 TLS/JNI 环境报告](REQUEST_JNI_ENVIRONMENT.md)。

证据可支持：VM发布的具体写入点和来源、callback编码/返回规则、实际读取的
栈word、发布后TLS获取的连续行为，以及指定warm fixture下原始JNI_OnLoad的
GetEnv失败返回和成功publication顺序。引用应保留样本hash、输入、比较窗口、
显式服务和探针停止位置。它不能支持完整Python JNI_OnLoad、独立Medusa、线上
全头矩阵、小说搜索/正文下载或最终产品可用。

当前同次owning session仍是低基址957步synthetic返回，高基址965步因缺少VM
停在attach `+0x26EF7C`。本阶段没有向该组合注入探针的VM/env值。接下来继续
`+0x26E19C`、实际startup与JNI服务闭环，再恢复真实请求输入和FindClass后续
行为。fresh签名、无JVM Rust、搜索分页、其他平台及Pages/Actions产品仍待完成。
