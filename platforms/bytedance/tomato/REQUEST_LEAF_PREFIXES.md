# Request leaf prefixes: sampled diagnostics and stack evaluator

后续TLS／JNI组件及六个组合控制已通过，详见
[REQUEST_JNI_ENVIRONMENT.md](REQUEST_JNI_ENVIRONMENT.md)。本报告的30/6前导证据
仍停在acquisition入口；新增路径使用显式provider继续至FindClass调用前，
不扩大本报告旧控制的证据范围。

2026-10-07。本阶段恢复 `+0x28ddd0 → +0x28e788` 的采样/参数初始化，以及
`+0x28b05c` 的九组 lazy 全局和调用前状态。新增 **30 个原生对照、6 个负控制**。
未采样的诊断路径可自然返回；其余路径只验证实际调用前导，事务明确不提交。
**完整 callback、JNI 获取、Medusa signer 和线上下载仍未完成。**

原生样本 SHA-256：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。
两个基址：`0x122c0000`、`0x775c205000`。本阶段只有私有 ELF 输入、独立构造的
组件内存和离线执行，没有服务器请求或线上签名输出。

## 1. 验证方式与 JNI 测试边界

[原生组件证据](evidence/vm9_request_leaf_prefixes_fresh_20261007.json) 从原始
ELF/relative relocation 与 fresh guest 页开始。原生 evaluator 执行到
`+0x26edc4` 调用前停止；原生采样路径执行到 `+0x28f0f4` 调用前停止。
Python 独立生成输入槽、lazy 全局和模式参数，observer 仅导出暂存观测供比较。
**不将原生输出写回 Python，也不提供虚拟 JNI 结果。**

现有 `verify_vm9_signer_objects.native` 默认在 `+0x26edc4` 写入 `env` 参数，
这属于既有组件测试服务。此前探查得到的 `env=0` 返回结果不能证明真实
`+0x26edc4` body、TLS 初始化或 JavaVM 获取已经恢复。本阶段在该函数入口前
停止，所以报告明确保存 `native_jni_acquisition_stub_used=false`；这里的 false
表示没有使用该 stub，**不表示真实 JNI 获取 body 已经通过**。

比较窗口为 payload `0xA000`、相关初始化槽及 `+0x3e1000` 全页；不比较整个
原生栈、保存寄存器、canary、TLS、OS 或所有调用副作用。暂存窗口等价只是
前导证据，不能替代完整 callback 返回后的内存和生命周期证据。

## 2. `+0x28b05c`：Java 线程栈 evaluator 前导

这是线程栈检查依赖，尚无证据将它视为 Medusa 密码算法本体。
`+0x383860` 的原 ELF encoded table 先经本函数地址参与的 ORN/AND/XOR 计算解码；
两个基址的 delta 均为 `0xffffffffff5f4a58`。各表项必须匹配本样本的
name/flag/source/mask 地址，否则明确拒绝。

九组 lazy 名称按以下顺序初始化。flag 为0时 decode 并发布1，任何非零 flag
均保留原值并跳过解码。控制还覆盖非1的 warm flag，以及保留已修改 name 字节。

| index | name offset | flag offset | 解码内容 |
| --- | --- | --- | --- |
| 0 | `+0x3e1520` | `+0x3e1534` | `java/lang/Thread` |
| 1 | `+0x3e1538` | `+0x3e1548` | `currentThread` |
| 2 | `+0x3e1550` | `+0x3e1568` | `()Ljava/lang/Thread;` |
| 3 | `+0x3e156c` | `+0x3e157c` | `getStackTrace` |
| 4 | `+0x3e1580` | `+0x3e15a4` | `()[Ljava/lang/StackTraceElement;` |
| 5 | `+0x3e15b0` | `+0x3e15cc` | `java/lang/StackTraceElement` |
| 6 | `+0x3e15d0` | `+0x3e15e0` | `getClassName` |
| 7 | `+0x3e15f0` | `+0x3e1608` | `()Ljava/lang/String;` |
| 8 | `+0x3e160c` | `+0x3e161c` | `getMethodName` |

若入口 SP 为 S，则 frame=S-60，输入 count 为 S-b0 的4字节、method-name pointer
为 S-90、descriptor pointer 为 S-88。S-b0 开始的72字节窗口同时覆盖原生保存
的 encoded name 槽和未改 padding。重要的槽序关系为 frame-18保存 index4、
frame-10保存 index3；来自 LDP 的第二个槽不能误按第一槽解释。

真实 `+0x26edc4` 的输出 pair 位于 S-e0，临时 environment 槽位于 S-f0。
在调用前它们仍保持 fresh 字节，本阶段不自行清零或写入 env。10个对照涵盖
cold、全部 warm、两种混合 warm，以及 count=0/2/uint32_max。没有证明后续
非空 JNI 栈遍历、比较、exception 清理或整个 evaluator 的返回值。

## 3. `+0x28ddd0 → +0x28e788`：诊断采样与模式参数

formatter 使用 X4，即四个 uint64 参数中的最后一个，作为采样序列；读取
`+0x3839e8` 的 uint64 divisor。原 ELF 值为10。只有 remainder=0才进入模式构造。
这不是本阶段的时间戳校验结论，也不能用于判断服务端签名是否参与风控。

Python 保留 AArch64 UDIV 的零除语义：quotient=0，remainder=sequence。
因此 divisor=0/sequence=0仍进入构造，divisor=0/sequence=1直接返回。
控制还覆盖 divisor=1、序列9/10/11/20/uint64_max和 mode=uint32_max。

若 formatter 入口 SP=S，则 local=S-1b0：参数依次在 local+50、+48、+40、+38，
mode 为 local+34 的4字节；顺序对应实际 STP/STR。未采样路径只保留这些写入，
自然返回，无模式解码或分配。API 的 `False` 只表示未选中 formatting，
**不比较也不模拟原生未约定的 X0 返回值**。

采样分支进入 `+0x28e788`。它 lazy 解码 `+0x3e1ad0` / flag `+0x3e1adc`，
文本为 `{"x0":{0}}`，并将 uint32 mode 写入其入口 SP-60。下一真实调用为
`+0x28f0f4`：X0=format pointer、X1=mode argument pointer、X8=80字节 formatter
对象的目标地址。格式对象与后续144字节转换对象目前只定位，未注入完成内容。

20个 formatter 对照中，10个未采样路径自然返回，10个采样路径在 builder 前
停止。Python 采样路径缺少 builder 时明确拒绝，并连同内部 mode 前导一起回滚。

## 4. 同次 owning session 组合

[当前请求组合证据](evidence/vm9_request_diagnostic_continuation_20261007.json)
把以上模型接回同次 Python outer/request/allocator；没有 native 输入前导快照。

| 基址 | 外层 VM 停点 | 新的内部调用前导 | 当前缺口 |
| --- | --- | --- | --- |
| `0x122c0000` | 945 / `+0xffb48` | `28dc38 → 28ddd0 → 28e788`，sequence=0/divisor=10/mode=0 | `+0x28f0f4` 实际 formatter/转换 |
| `0x775c205000` | 965 / `+0xf8fd0` | `28bb5c → 28b05c`，九组 lazy，全程 count=2 | `+0x26edc4` 实际 JNI 获取 |

外层步数没有增长；只恢复了缺口函数内部的受支持前导。新增事务未提交，
完整 callback 未返回，whole-native outer/request 等价仍未验证。此前阶段
见 [REQUEST_EVENT_GATE.md](REQUEST_EVENT_GATE.md)。

## 5. 复现和关键证据用途

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_leaf_prefixes_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_leaf_prefixes_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

可以把本证据用于说明 encoded 地址表、九组初始化顺序、ABI 槽位、warm 保留行为、
采样条件、uint32模式值和内部下一调用位置。引用时应同时附样本 hash、基址、
停止位置、输入和比较窗口，明确标注这是调用前导对照。

真实 URL/headers/JNI 转换、fresh Medusa 签名、新的线上全头矩阵、无 JVM Rust
下载链路、非空搜索与分页、抖音/起点闭环、最终 Pages/Actions 产品仍未完成。
后续须恢复 formatter/转换和 TLS/JavaVM 获取，再回到真实请求验证。


## 后续：mode完整组件

上述 `+0x28f0f4` 是本页前导阶段的历史边界。后续有界mode构造/渲染/转换/
清理已由38个原生控制验证，并接回同次owning allocator。低基址最新缺口
为五参数 `+0x28e86c`，高基址仍`+0x26edc4`。本页30个前导控制刻意不提供
allocator/free，在实际mode构造前停止；不把它们改称完整mode控制。
当前详见 [REQUEST_MODE_FORMAT.md](REQUEST_MODE_FORMAT.md)。


## 后续：五参数 event format

后续22个原生控制/19个负控制已恢复五参数formatter与转换/临时清理，
最新同次组合低基址停止于event emission `+0x28ff44`；高基址仍真实JNI
`+0x26edc4`。本页前导控制仍保持独立范围。详见
[REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。


## 后续：warm发布与当前返回边界

后续warm event emission已由40个原生控制/14个负控制恢复；低基址同次
owning session的synthetic请求VM模型在957/+ffb78返回，event callback
及request页状态已提交，record数2、33 allocations/18 frees。高基址仍
965/+f8fd0的真实JNI `26edc4`。本页旧停止点属于其阶段历史；完整Medusa
签名与whole-native request仍未通过。详见
[REQUEST_EVENT_EMISSION.md](REQUEST_EVENT_EMISSION.md)。
