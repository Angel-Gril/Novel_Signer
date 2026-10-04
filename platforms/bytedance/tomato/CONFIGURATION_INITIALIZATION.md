# 配置初始化、88 字节构造与 root 推进

截止：2026-10-04。恢复了匹配 ELF 的已观察默认配置路径，**完整独立 Medusa 尚未完成**。

本轮将 `+0x26194c → +0x261c54 → +0x261cb0 → +0x262608` 连接为 Python 模型。root 的较早 native 输入前导仍保留，但该组合不再读取 native 构造器入口或 parser 入口快照来生成其内部状态。四次控制中，root 从第 513 步推进至 **第 605 步 / `+0x99cd8`**，下一处待恢复是 `+0x258500 → +0x2698f0`。

## 代码与调用边界

实现位于 [vm9_configuration_init.py](python/vm9_configuration_init.py)，复核入口为 [verify_vm9_configuration_init.py](python/verify_vm9_configuration_init.py) 与 [组合 verifier](python/verify_vm9_root_vm_prefix.py)。调用方需提供 mapped guest pages、matching relocated ELF、thread pointer、entry SP、VM interpreter，以及显式 allocator/free/singleton 服务。

| Python 函数 | native 入口 | 结果与用途 |
| --- | --- | --- |
| `copy_string_reference` | `+0x15f580` | 清 destination 后重新读取 source，发布指针并增加 u32 count；保持 self/部分重叠语义 |
| `assign_owned_string_reference` | `+0x162944` | 先释放旧引用，再发布 object 和新 count |
| `string_equals_cstring` | `+0x24880c / +0x247374` | declared length 与外部 C string 的终止 NUL 必须精确匹配 |
| `strings_equal` | `+0x1a7e10` 的 flag bit0=1 | 精确二进制比较，内部 NUL 不截断；flag0 的 clone/转换路径未恢复 |
| `get_guest_identifier` | `+0x172dbc` | 从 guest pointer table 得到地址；按实际读点解码与发布 lazy flag，不嵌入 identifier 文本 |
| `publication_container_size` | `+0x25c71c / +0x24b6fc` | 从 begin 到 sentinel end 计算 linked iterator distance |
| `release_parsed_reference` | `+0x2633f0 / +0x2633cc` | 递减 count，按顺序释放 count、message graph、wrapper |
| `initialize_configuration_context` | `+0x261cb0` | 生成 caller 输入、解析配置、赋值、selector 比较与 cleanup，返回 `ConfigurationResult` |
| `initialize_configuration_wrapper` | `+0x261c54` | 执行初始化，按阈值条件生成两个保存的栈帧 word |
| `construct_initialized_configuration` | `+0x26194c` | 生成 88-byte layout、variadic argument block、派生 dispatch 和已观察的初始化路径 |

参数中的 identity 是 string object；configuration 是独立的 88-byte 对象。它们不能互换，也不能把 identity 当作结果 context。`ConfigurationResult` 提供 status、parser_steps、matched_selector；四次当前控制为 selector0/status6。这不是 HTTP 响应或 Medusa 签名输出。

## 三处关键纠正

`+0x261cb0` 的最深工作 SP 是 **entrySP-0x340**。其中 parsed/source/key reference 分别在 entrySP-0x130/-0x140/-0x150，后续工作区用于不同 selector 分支。`+0x262608` 从最深 SP 进入；不能使用旧的 -0x300 偏移，也不能用 native VM 入口输出弥补这个偏差。

`+0x25c71c` 没有从 controller 第二个 word 读取 count。它经过 `+0x24b6fc → +0x24b568` 构造 begin/end iterators，并使用 table 的 equality/advance 方法计算距离。当前 begin 与 end 同为 sentinel，长度为0；controller 第二个 word 保留未初始化字节并不表示非空。合成差分另外覆盖0/1/2/16-node 链表，环或未知 iterator table 被拒绝。

`+0x26ecb4` **不是 TLS getter**。该混淆 helper 从自己保存的栈帧取出 caller X29；`+0x261c54` 中 X29=entrySP-0x30。两个原始参数都大于4096时，在该 frame 写入 first_word-0xe9 与 second_word-0xd5。这会重写保存的 frame/return 地址，完成 `+0x271998` 的 continuation。故 wrapper 验证在实际 `+0x261cac` 退出指令取结果；不能把入口保存 LR 所指地址或嵌套 callback 的返回当作结束。构造器同理在实际 `+0x261b90` 退出点验证，并核对 SP 恢复。

## ownership 与初始化

引用减法使用 native `subs; b.gt` 的有符号条件。`0x80000000-1` 回绕为 `0x7fffffff`，但带 signed overflow 的 branch 不保留引用。新差分先暴露该错误，随后同时修正 string 与 parsed reference 的 cleanup：判断原始 signed count 是否大于1，仍写入回绕后的 u32 值。NULL count 不操作；释放 count 后才重新读取 object，随后清 count slot 并执行 guest deleting destructor。已验证释放前 bytes 和有序 allocator 状态。

配置初始化按 native 顺序：copy source reference → 构造 empty key reference → Python 生成 parser caller → parser/unpack → 清理 key/source → identity 检查 → 赋值 configuration+0x18 result reference → 写 +0x40 标量 → 检查 publication 容器 → selector 比较 → 释放 parsed reference。真实 decoded 配置、字段名称、identifier、key 或 wire payload 没有进入公开代码或证据。

完整构造组合复用已有 layout owner，清零64-byte argument block，并通过 `+0x261b98` 的两项 variadic 复制语义放入 identity/configuration。dispatch 数值来自 guest ELF 的 lazy decoded constant；没有嵌入解码后的常量文本。仅接受已恢复 target 路线。物理寄存器 spill frames 未逐字节复现，实际有效工作区和派生 frame words 由模型生成。

## 验证结果及证据强度

[helper 证据](evidence/vm9_configuration_init_native_20261004.json)：**166 组 fresh native 差分 / 5 个拒绝与页面回滚案例**。覆盖两个 image bases、copy alias、自复制、u32/signed count 边界、二进制内部 NUL、长度/内容不等、nullable payload、parsed graph cleanup、iterator distance、identifier cold/ready 及保存 frame getter。所有适用案例比较 guest、全部主 image pages、allocator 状态、有序副作用与释放前 bytes；scalar/pointer 返回值按对应 ABI 比较。

[组合证据](evidence/vm9_root_vm_prefix_native_20261004.json)：两个 bases × SDK 缺失/30，**4 次 fresh controls / 16 段 VM 对照 / 60 条完整子树对照**；原先第513步前缀也保留为回归检查。

| 对照路径 | allocations | explicit frees | 已验证结果 |
| --- | --- | --- | --- |
| `parser` 与 `parser_caller` | 119 | 47 | 3318 steps，全部32个终止虚拟槽匹配 |
| `configuration_context` | 125 | 69 | status6；包括结果赋值、selector 与 recursive cleanup |
| `configuration_wrapper` | 125 | 69 | status6、两个派生 frame words 与实际 continuation |
| `configuration_constructor` | 134 | 69 | 已观察的88-byte构造路径、参数块与初始化返回 |
| `root_advanced` | 138 | 70 | 第605步 / +0x99cd8，停在 +0x2698f0 前 |

上述组合路径均核对 guest、全部主 image pages、TLS、2256-byte generation table，以及 allocations/frees/clock/registration/wake 有序副作用。root 未声称全部32个 terminal slots 匹配：它还没退出。修改后的流组件另外回归通过原有 **174 / 9**，详见 [STREAM_REFERENCE.md](STREAM_REFERENCE.md)。

可用这些证据排除错误的 stack ABI、identity/configuration 参数、container 布局、reference 释放条件和 callback 返回点。数据来源被分层记录：合成组件从 fresh ELF 和测试内存开始；constructor 子树从同次更早的 native 输入入口开始；root 组合从 native VM 输入前导开始，但自行生成后续 constructor/parser 所需状态。任何一层都不能升级为当前线上独立 signer 的证明。

## 复现

从番茄目录运行，ELF/libc 留在私有路径：

```text
python -B python/verify_vm9_configuration_init.py --library /private/libmetasec_ml_71332.so --output /private/configuration-init.json
python -B python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-parser.json
python -B python/verify_vm9_stream_cipher.py --library /private/libmetasec_ml_71332.so --output /private/stream-regression.json
```

匹配 ELF 的 SHA256 在 verifier 中强制核对。原始 native 代码只由 Unicorn oracle 执行，生产模型没有调用 native 构造器或 JVM。它仍需要 caller 提供初始内存与环境服务，不能直接当作下载器 signer 使用。

## 剩余边界

这是已观察的默认模式、空 publication 容器和 selector0 控制。file-provider、非空配置树的 publication、diagnostic 失败路径、其它 selector 的完整组合验证、其它 dispatch 分支仍未覆盖。未知模式拒绝并回滚 guest pages；allocator/free 是外部副作用，页面事务不能撤销这些账本。运行使用共享 VM image base、串行 guard 与无竞争 mutex 边界，未提供宿主并发原子性或通用 OS 运行时。

下一段已定位到 `+0x2698f0`：其构造分配152-byte mutex state，现有 `construct_mutex_state` 已覆盖 `+0x17d7e0 / +0x32a330`；之后 `+0x269988` 进入 **VM +0xa46a0**，需恢复 caller/VM/callback 并接回 root。较早的 root/全局/TLS/OS 初始化输入仍要独立生成。

完整当前线上 fresh-input Medusa、无 JVM Rust signer/download、搜索非空与分页、抖音/起点闭环，以及最终 Pages 小说搜索下载网页和 Actions 工具包，均仍未完成。该报告不包含新增线上成功结论或最终产品发布声明。

后续 [owner/state初始化报告](STATE_OWNER_INITIALIZATION.md) 恢复了 +0x2698f0 的构造前缀（52 / 6），新增VM +0xa46a0已到173步 / +0xa4950，待恢复+0x25ee84；该VM组件尚使用native入口输入前导快照，未接回root。
