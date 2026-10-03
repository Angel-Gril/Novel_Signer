# 当前桥接器初始化、A/B 配置与 handle 发布

已找到并修正初始化失败的来源：`MS.b(0x1000000e)` 应返回 `MSC.GetABSwitch()`，旧桥接器错误地返回冻结毫秒时间。APK 默认 A/B 值是 `2`。此前时间取整只是在错误配置输入下避开 bit 5，不能解释为 native 对时间的要求。**当前 Medusa 的完整独立 Python 初始化仍未完成。** 新证据见 [vm9_ab_switch_initialization_20261003.json](evidence/vm9_ab_switch_initialization_20261003.json)；下方历史对照保留用于追溯。

## 0. A/B 回调纠正与最新验证

同一 APK 的 `classes16.dex` 在文件偏移 `0x684a56` 调用 `MSC.GetABSwitch()J`；`classes24.dex` 的 getter 在 `0x68e0cc` 读取 `MSC.a:J`。class 的 encoded static value 位于 `0x34f820`，字节 `01 06 02` 表示 long 初值为 `2`。两个本地 DEX 与 APK 对应条目的 SHA-256 一致。这是默认值证据，真实 App 对 `SetABSwitch` 的运行时覆盖尚未捕获。

JNI 启动将回调结果保存到 native 全局 `base+0x3d1578`。真实 store 是 `+0x1656c0: str x0,[x8,#0x578]`；WriteHook 报告的 `+0x1656b8` 是邻近执行位置，不能当成 store 指令地址。初始化 VM `+0x706c0` 的 indices 311–313 执行：

```text
+0x70b9c: R1 = u8[global]
+0x70ba0: R1 = R1 & 0x20
+0x70ba4: if R1 == 0, goto +0x70cb4; else +0x70ba8
```

旧桥接器成功、失败采样的初始化基本块有 46,802 条相同前缀，首次控制流分歧位于此条件之后。只读探针没有改变旧控制组的 Medusa 摘要。恢复回调语义后：

| A/B 输入 | 冻结时间 | callback-1 | Medusa 原始长度 |
| ---: | ---: | --- | ---: |
| 2 | 1791023800000 | 发布 | 802 |
| 2 | 1791023800999 | 发布 | 800 |
| 2 | 1791023801000 | 发布 | 800 |
| 2 | 1791023999535 | 发布 | 801 |
| 1791023999535（重现旧误配） | 1791023999535 | 不发布 | 0 |
| 34（相对 2 仅设置 bit 5） | 1791023999535 | 不发布 | 0 |
| 0 | 1791023999535 | 发布 | 801 |

未取整的新时间详情请求生成 802 字节 Medusa，HTTP 200、`code=0`，响应 24,341 字节，SHA-256 为 `41ca4dfee2a329e67bf8fa9546052f16595be9b3eb840dfe0f3839ff375a0e69`。这是修正桥接器的线上证据。

默认 A/B=2 的发布 helper 位于 `+0x28c268`，通过 `+0x28c308` 先后调用 `0x2000001` 和 `0x2000002`，两次使用同一已构造 root。旧误配时间值的历史控制才走 `+0x2a8760`，不能把它当成默认路径。定位 helper 不等于恢复对象的全部 constructor 状态。真实 Python 桥接入口在同一输出目录完成“配置 2 成功 → 配置 34 失败 → 配置 2 再成功”：失败清空旧签名，两次成功摘要相同，URL 和 Khronos 对应本次输入。对象关系和新建内存对照见 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md)。

Python `initialize_ab_switch` 和 `evaluate_ab_switch_gate` 用新建内存页恢复这个全局及三指令分支，在两种加载地址下通过 18 个与实际 bytecode 的对照、3 个异常拒绝。它们不复制捕获状态，也不构造完整 signer。见 [vm9_startup_switch_python_20261003.json](evidence/vm9_startup_switch_python_20261003.json)。

## 1. 历史误配下的失败位置

保持同一个详情 URL、native artifact、固定 PID 和随机源，改变冻结时间：历史时间 `1790261112000` 能签出 804 字节 Medusa，`1791023999535` 则未发布 callback-1 signer handle。桥接器轮询 20 次仍未就绪，原代码把 `0x4000002` 返回的 app manager 当作 signer handle。

失败样本中的写入和读取连起来是：

```text
app manager = 0x128a3000
+0x15dd50 写入 [manager + 0x10] = 0x12297248
+0x2a6600: ldr x8, [x0]        -> 0xffff006b00000001
+0x2a6604: ldr x9, [x8,#0x60]  -> UC_ERR_READ_UNMAPPED
```

该地址邻域在成功采样中有字符串与引用计数写入；不能把固定地址当成跨采样恒定的对象，更不能向它注入“合法虚表”来宣称初始化完成。旧桥接器捕获 JNI 异常后仍可退出 `0`，因此验收还必须检查返回头、请求 URL 和时间戳。

APK 中同一 `classes16.dex` 的 SHA-256 与被分析的 DEX 一致。`s4.a(J)V` 在文件偏移 `0x682d40` 将收到的 `long` 保存到 `s4.a:J`，并注册 `r4` 网络回调；`r4` 使用该字段调用签名 tag `0x3000001`。`d0.run()` 的就绪轮询 tag 是 `0x4000004`。证据记录了这些局部指令字节，不依赖 JADX 的整方法控制流，也不声称辅助解码器的全部指令标签正确。

## 2. 桥接器修正与回归

私有桥接器现在要求初始化发布 callback-1 handle，缺失时返回 `SIGNER_INIT_UNAVAILABLE`。这一检查没有替换 guest 对象、虚表或 callback 结果。

Python 桥接调用也改为每次使用独立日志和 rounds 路径；失败时保存日志并清空可供下游读取的旧签名。成功输出必须对应本次 URL，且 `X-Khronos` 等于冻结时间的秒值。底层 rootfs 仍要求串行运行。

同一输出目录的回归结果：

| 调用 | 结果 | 旧签名状态 |
| --- | --- | --- |
| 历史成功输入 | 804 字节 Medusa，进程退出 0 | 保存本次输出 |
| 未初始化输入 | 进程退出 1，明确初始化失败，日志保留 | 清空；没有非法内存读取 |
| 新时间、新 `_rticket` | 802 字节 Medusa；详情 HTTP 200、`code=0`、24,335 字节 JSON | 保存本次输出 |

另一个修正前的新时间控制也被详情接口接受：801 字节 Medusa，HTTP 200、`code=0`、24,363 字节 JSON。原始响应及签名留在私有采样中，公开记录只包含长度和 SHA-256。

## 3. 历史时间输入对照（A/B 回调误配）

以下保持同一 URL、PID、随机源和 native revision，每次从重新创建的 rootfs 启动。基准时间为 `1791023800000` 毫秒。**旧桥接器也把每个时间值传给 A/B 回调，所以并非 native wall-clock 的单变量实验。** 原始数据见 [vm9_handle_initialization_20261003.json](evidence/vm9_handle_initialization_20261003.json)。

| 偏移（毫秒） | 是否发布 signer handle | Medusa 原始长度 |
| ---: | --- | ---: |
| 0 | 是 | 228 |
| 1 | 是 | 228 |
| 15 | 是 | 228 |
| 16 | 是 | 228 |
| 999 | 否 | 0 |
| 1,000 | 否 | 0 |
| 2,000 | 是 | 228 |
| 4,000 | 否 | 0 |
| 8,000 | 是 | 228 |
| 16,000 | 是 | 801 |
| 199,535 | 否 | 0 |

`0/1/15/16` 的 Medusa 摘要相同；这反驳了“任意非零毫秒偏移都会失败”。`+999` 在同一个秒值内已经失败，因此也不能归因于仅有秒级变化。`+2,000` 成功而 `+4,000` 失败，不支持简单的整秒规则。这里是 11 个时间输入对照，**不是 16 个 VM 分支的恢复，也不能据此选择适用于所有请求的时间取整规则。**

## 4. 对下一步实现的意义

追加的单变量对照保留失败 wall-clock 输入 `1791023999535`，只在就绪轮询期间推进 guest 单调时钟：控制组不推进，实验组每轮推进 550 毫秒，共 20 轮、11 秒。两组都未发布 callback-1 handle，并返回 `SIGNER_INIT_UNAVAILABLE`。这排除了“单独推进轮询期间的单调时钟即可修复”这一具体假设，不能外推为所有启动时钟策略都无关。

最新对照把“时间相关”解释修正为 A/B bitmask 回调误配，并定位 callback 发布 helper。下一步需在正确 A/B 输入下恢复完整 signer constructor、allocator 全局启动和剩余 callback，再用同次采样验证。签名 VM 必须接收真正构造的对象，不能拿 app manager 或捕获地址充当 fresh-input 状态。

本轮新鲜输出的 `X-Argus` 是 4 字节秒时间戳的小端编码，`X-Ladon` 也解码为 4 字节。这是实测短形态，不能用“返回了六个头名称”证明通用长形态 Argus/Ladon 算法已被当前接口验证。阅读接口接受也不能替代搜索接口验收。

当前仍未完成独立 Python Medusa、无 JVM Rust 下载链路和当前版本非空搜索。新鲜详情请求成功属于 Java/Unidbg 桥接证据。
