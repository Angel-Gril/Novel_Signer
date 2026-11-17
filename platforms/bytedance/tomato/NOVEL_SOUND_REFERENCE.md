# novel-sound 对六神／七神研究的参考范围

分析固定在 [ch6vip/novel-sound 的 8af547f](https://github.com/ch6vip/novel-sound/tree/8af547f310ad42f7698d2cb8d847d0f0ee9989d1)，日期为 2026-11-17。
这是源码与离线算法的参考，不能替代本项目当前 Android 样本的业务捕获或线上验签。

## 能提供什么

该项目有本地 Rust 实现：Argus、Ladon、Gorgon，加上 Khronos 时间戳，确实覆盖通常所说的“四神”。

| 部分 | 上游实际行为 | 对本项目的意义 |
| --- | --- | --- |
| Argus | 默认 ArgusBean551；SM3、Simon、有序 Protobuf、551 framing、AES-CBC | 可对照字段类型、顺序和封装，不能直接替换当前样本算法 |
| Ladon | 本地 34 轮 ARX；可传入四字节随机量 | 可做固定输入对照 |
| Gorgon | 本地旧 8404 方案；Manager 默认关闭，注册 key 时开启 | 应按接口判断适用性；源码关于“当前已不用”的注释不是普遍的线上结论 |
| Khronos | 秒级时间戳；req-ticket 为该时间乘 1000 | 检查同次请求的时间一致性 |
| SS-STUB | 对实际 body 字节做 MD5；无非空 body 时不生成 | 对照压缩、序列化和摘要的先后顺序 |
| Medusa、Helios | 签名目录中未发现生成器；Medusa 在播放请求里被显式移除 | 不能补齐当前普通 Cronet 六头链 |

默认 GET 组合为 `x-ss-req-ticket`、`x-khronos`、`x-ladon`、`x-argus`。
非空 body 另有 `x-ss-stub`。头的数量不能自动视为六神／七神已实现；应对照目标请求的实际键集合。
另外的 `sign/abogus.rs` 属于另一签名路径，不等于 Medusa 或 Helios。

主要入口：[sign/mod.rs](https://github.com/ch6vip/novel-sound/blob/8af547f310ad42f7698d2cb8d847d0f0ee9989d1/rust/src/sign/mod.rs)、
[argus.rs](https://github.com/ch6vip/novel-sound/blob/8af547f310ad42f7698d2cb8d847d0f0ee9989d1/rust/src/sign/argus.rs)、
[upstream/client.rs](https://github.com/ch6vip/novel-sound/blob/8af547f310ad42f7698d2cb8d847d0f0ee9989d1/rust/src/upstream/client.rs)。

## 我们已有的部分与关键差异

本仓库已有 `rust/src/signer/{argus,gorgon,ladon,sm3,simon,protobuf}.rs`，
并由 `signature::legacy_headers` 组合四类旧签名头。因此“四神”的基础组件并非新的缺口。
当前 Medusa 能力仍由 `status::current_medusa` 明确返回不可用；参考项目不改变这个边界。

两套 Argus 的差异需要保留：本仓库现有实现使用 SHA-256 和 AES 内层；参考项目使用 SM3 和 Simon，
并有不同的 551 尾部和 padding 路径。相似的 Protobuf 字段或外部前缀不能证明两者适配同一 SDK。
`legacy_headers` 当前还固定旧版本字符串，并没有完整 POST body 输入；不能据此声称当前整请求 signer 已完成。

优先对照的输入为原始 query 字节、实际发送的 body 字节、时间戳、随机量、SDK/应用版本和设备字段。
参考项目的 `register_key` 先压缩 JSON，再以压缩后的字节计算签名；其上层请求逻辑也区分了播放请求的
Argus 字段 16。该字段的实际设备语义仍需目标样本证明。

## 离线对照的限制

本次通过仓库外的最小 Rust harness，直接引用上游原始密码模块及原始 `crypto_vectors.rs`，
执行 `cargo test --offline --jobs 1 --test upstream_crypto_vectors`：13 项通过，0 失败、0 跳过。
覆盖 Argus551/legacy、Ladon、SM3、Simon、Protobuf 和注册相关密码函数。
测试未运行上游应用或网络请求，也未覆盖 Gorgon 生成器或 Manager 的整请求行为。
为减少构建开销，harness 将签名模块使用的 `url::form_urlencoded` 直接绑定到同版本
`form_urlencoded 1.2.2`，未构建完整 URL/IDNA、HTTP 或 Flutter 依赖。
源文件摘要与测试范围见 [脱敏记录](evidence/novel_sound_reference_20261117.json)。

`generate_headers_at` 便于固定时间、Ladon 随机量和 Argus nonce，但不是所有选项下都完全确定：

- Argus nonce 为零时，`argus_get_sign` 仍会改用随机量；确定性对照应使用非零 nonce。
- 开启 Gorgon 后，其生成器自行读取当前时间并生成随机字节，不使用传入 Manager 的固定时间和随机量。
- `crypto_vectors.rs` 的 Argus551 测试从黄金输出恢复 nonce，再重新生成。这验证该条件下的字节一致性，
  不能证明当前 Android 的全部输入已经恢复。
- 黄金向量的独立 Go 来源属于上游声明；本次没有独立复核该 Go 生产者。

离线向量通过也不等于线上接受，不证明 Medusa/Helios，不证明完整 Android 请求的数据关联。

上游 [LICENSE](https://github.com/ch6vip/novel-sound/blob/8af547f310ad42f7698d2cb8d847d0f0ee9989d1/LICENSE) 为 GPLv3，
本仓库为 MIT。本轮只保留来源与分析；没有将上游实现或黄金向量复制进本仓库。

## 接续方向

先用上游原始密码模块和原始向量做隔离的离线核对，再选择可比的单个 primitive 或字段布局。
当前 Android 的首要任务仍是定位 Cronet 请求与安全因子回调之间的条件，取得同一业务请求的六头数据链，
再做 native/Python 整请求差分和独立 signer 验证。
