# 配置密码组件与 parser 回调验证

截止 2026-10-04：配置解密 callback 的 **mode 0 路线**已经由 Python 生成并通过 fresh native 差分，该里程碑将 parser 从 325 步推进到 612 步；后续 [流运算对照](STREAM_REFERENCE.md) 已推进到 725 步。完整独立 Medusa 尚未完成。本页记录内存接口、验证方法与适用范围。

## 已恢复接口

| Python 接口 | Native 偏移 | 验证范围 |
| --- | --- | --- |
| `construct_cipher_schedule` | `+0x241e9c` | 16/24/32-byte key，guest 表驱动的加密/解密 schedule；保留无效 size 的原生部分写入 |
| `encrypt_cipher_block` / `decrypt_cipher_block` | `+0x2422ec` / `+0x242640` | 16-byte block、原地及部分重叠；schedule 与 tables 均来自调用方 pages |
| `decrypt_cipher_cbc` | `+0x242b18` | IV 更新、分次调用、长度检查与 caller stack scratch |
| `process_cipher_blocks` | `+0x25ab1c` | ECB/CBC 解密分发；模式 2/3 尚未恢复；mode >3 的原生不处理分支 |
| `initialize_cipher_context` | `+0x25aa48` | 当前验证 mode 0；先清零 0x210-byte context，再读取 descriptor/key |
| `checked_forward_copy` | `+0x276b9c` | 两次真实 singleton getter，零环境检查路径及逐字节向前复制 |
| `decrypt_configuration_reference` | `+0x259dbc` | 完整 mode 0 callback：clone、构造、复制、解密、裁剪、string/reference/count 和清理 |

源码：[vm9_cipher.py](python/vm9_cipher.py)、[vm9_cipher_callback.py](python/vm9_cipher_callback.py)。两者的实现没有调用宿主 AES 库，也没有嵌入 native 的 S-box/T 表；独立 AES 库仅用于 verifier 的交叉验证。调用者必须加载匹配 ELF 的 guest tables；这不是无需私有 ELF 的最终 signer。

## 内存与调用约定

pages 以 `address >> 12` 为索引，每页 4096 字节。string object 为 24 bytes：vtable `+0`、u32 capacity `+8`、u32 length `+0xc`、payload pointer `+0x10`。reference 为 16 bytes：string pointer 和四字节 count 的 pointer。NULL string reference 也有初值 1 的 count。

cipher context 中 enc schedule 位于 `+0`，dec schedule 位于 `+0xf0`，u64 rounds 位于 `+0x1e0`，CBC IV 位于 `+0x1e8`。上层 constructor 按原生 byte loop 清零 0x210 bytes。无效 key size 仍写 rounds 与前四个 key words，然后返回 -1；这不是异常回滚。

`+0x259dbc` 的 X0/X1 是 data/key string object，X2 是 IV object，X3 是 mode pointer，隐藏 X8 指定 output reference。模型显式接收这些地址及 callback 入口 SP；work SP 为 entry SP 减 0x320。native X0 的最终代码地址没有输出语义，verifier 对照实际 reference/string/count。

key 的临时 clone 用于长度检查；初始化 descriptor 保留原 key object pointer，schedule 在 clone allocation 之后读取该原对象。测试在分配时改变 key 来源，并覆盖 clone malloc NULL，排除了把 clone payload 当实际 key 的错误实现。

`checked_forward_copy` 第一次 getter 后读取 payload `+0x10`，第二次 getter 后在需要时读取 `+0x18`。第一字段为零或第二字段为零时进入已恢复路线；两个字段均非零的线程/环境检查明确拒绝。getter 通过回调边界接入完整 [136-byte constructor](SIGNER_CONSTRUCTION.md)。复制是逐字节向前读写，目标落在源后方时可能改写后续源字节，不能用宿主 memmove 替代。

## 裁剪与状态行为

- 空 key/data 生成 NULL string reference，count=1。
- clone 后 key size 不为 16/24/32，或 data length 不整除 16，生成 NULL reference 并清理 temporary key。
- mode 0 解密后只检查末字节；0..16 表示裁去相应字节数，前面的 padding 字节不被验证。末字节大于 16 时生成 NULL reference。测试覆盖 0、16、17 及不一致的其余 padding。
- temporary data buffer 在 reference 发布之前释放，随后清理 temporary key。测试比较释放前 bytes，避免 free poison 掩盖错误。
- ECB dispatcher 对声明长度非整块的输入仍处理向上取整的完整 block；CBC 返回 -1。上层 callback 自身检查 data length，因此不能把末端 dispatcher 的宽松规则直接推广给 callback。

未恢复的初始化模式、未知 guest jump/indirect target、超界数据、未映射内存和非零环境分支拒绝。页面事务回滚的范围是 pages；显式外部 allocator/registration 账本不属于回滚保证。没有把异常伪造成一个可用签名。

## 验证与复现

| 证据 | 结果 | 输入与边界 |
| --- | --- | --- |
| [cipher native 差分](evidence/vm9_cipher_native_20261004.json) | 256 组 / 11 个拒绝回滚例 | 两个 image bases、fresh synthetic keys/data、同 CPU 多次调用、独立 AES 交叉验证 |
| [callback native 差分](evidence/vm9_cipher_callback_native_20261004.json) | 200 组 / 12 个拒绝回滚例 | 完整 callback、context builder、forward overlap、分配时来源变更和 malloc NULL；warm singleton 是明确组件输入 |
| [同次采样 parser/构造对照](evidence/vm9_root_vm_prefix_native_20261004.json) | 4 次 fresh native controls，8 段 VM 与当前 36 条构造/配置/密码子树对照 | 两个 bases × 属性不存在/SDK30；Python 串接冷 TLS/key/析构注册、配置树和 lazy publication |

每组 cipher sequence 不把 native schedule 输出喂给 Python。callback 比较全部 guest 对象 bytes、全部主 image pages、context、分配/释放顺序、释放前 payload 和 getter 调用次数。native 与 Python 都使用明确的 allocator effects，不能据此推导 Android 真机 allocator 等价。

解密里程碑的组合 parser 推进至第 **612 步 / `+0x9b03c`**，wrapper `+0x263584` 调用 `+0x2592b8` 前。Python 从同次 native VM 入口的前导输入快照开始，之后不在子组件间注入 native 输出。另外显式比较可能落在 native 栈区的 16-byte 输出 reference、0x210-byte context 和 copy destination；这些范围不能由普通 guest 区对照代替。全程 93 次分配、23 次显式 free；guest、主 image、隔离 TLS、2256-byte generation 表、registration/wake 和有序 allocation/free/clock/registration/wake 一致。root 仍第 513 步 / `+0x99b40`，停在 88-byte 前缀 `+0x261a1c`。

```text
python python/verify_vm9_cipher.py --library /private/libmetasec_ml_71332.so --output /private/cipher.json
python python/verify_vm9_cipher_callback.py --library /private/libmetasec_ml_71332.so --output /private/callback.json
python python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-prefix.json
```

纯 Python 模型需要 caller pages 与显式 allocation/free/singleton callbacks。verifier 另外需要 Unicorn、pyelftools 和 PyCryptodome；同次组合验证需要匹配 libc。公开仓库不附 ELF、解码常量、实际 key、设备票据或原始 payload。

## 如何作为逆向证据使用

这组证据可以支持具体且可复现的判断：guest table 与 schedule 布局正确；原生清零/复制/读取次序正确；临时 clone 与实际 key 的来源不同；末字节裁剪不是完整 padding 校验；`+0x259dbc` 的冷 singleton 初始化副作用已贯通。对每一判断都应引用对应入口、测试输入类型、比较对象和明确边界。

不能由这些结果声称完整 Python 启动或线上签名已成功。native 前导快照、串行 guard、diagnostic scope 与 OS 边界仍存在，callback 初始化模式 1/2/3 未恢复。当前搜索非空响应/分页、无 JVM Rust 下载器和其他平台亦没有被本轮实验证明。

后续 `+0x2592b8 → +0x258fd8 → +0x243dac` 的独立流运算/string/reference 路线已由 [STREAM_REFERENCE.md](STREAM_REFERENCE.md) 恢复验证；它不是相邻 `+0x259324` 的 AES 加密 callback。当前 parser 到达 725 步，下一处为 `+0x248dd8` 的 fill/resize，再扩展 parser 和 88-byte 初始化。完整 root 前导恢复后，才可重做独立当前 Medusa、服务器矩阵与最终工具验证。
