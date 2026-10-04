# 流密码状态、配置引用与 parser 后续路径

截止 2026-10-04：`+0x2592b8 → +0x258fd8 → +0x243dac` 已由 Python 生成并通过 fresh native 差分，组合 parser 已推进到 **725 步 / `+0x9b200`**。此结果继续依赖同次 native VM 入口前导快照，不代表完整独立 Medusa。

## 函数与内存接口

源码：[vm9_stream_cipher.py](python/vm9_stream_cipher.py)。该路线与相邻 `+0x259324` 的 AES 加密 callback 分开处理。

| Python 函数 | Native 偏移 | 参数与作用 |
| --- | --- | --- |
| `construct_stream_state` | `+0x243cac` | `state_address, key_address, key_size, drop`；按 guest 内存顺序构造 RC4 permutation，执行 discard |
| `process_stream_bytes` | `+0x243d50` | `state_address, source_address, output_address, length`；逐字节更新状态，支持原地和前向重叠行为 |
| `transform_stream_bytes` | `+0x243dac` | 显式 key/source/output/length 和 `entry_stack_address`；状态放在 entry SP 减 0x150 |
| `transform_configuration_reference` | `+0x258fd8` / `+0x2592b8` | data/key string object、隐藏输出 reference、入口 SP、image base 和 allocator；完整配置 string/reference 生命周期 |
| `release_string_reference` | `+0x166e74` | NULL count、保留引用和删除 string 的清理；未知 deleting-destructor target 拒绝 |

state 为 **0x108 bytes**：u32 first index `+0`、u32 second index `+4`，256-byte permutation `+8`。string/reference ABI 与 [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) 一致。组件直接读写 caller pages，没有调用宿主 ARC4 库；PyCryptodome 仅用于 verifier 的独立 oracle。

KSA 先逐字节初始化 permutation，再按原生顺序读取 key 与交换字节；key 与 state 重叠时不会提前缓存 key。PRGA 每字节重读 guest indices，保存 indices、交换 permutation、读取 source 后读取选中的 keystream byte，再写 output。保留这些顺序才能对照别名与 overlap。

raw helper 的 W2 key size 为零时 ARM UDIV 返回零，remainder 变成 i，因而仍读取 256 个 key bytes。这一行为已单独对照；上层配置 reference helper 自身拒绝空 key/data，不能把 raw helper 的行为当成上层零 key 规则。

## 上层引用生命周期

`+0x2592b8` 的第一条指令直接跳到 `+0x258fd8`。X0/X1 是 data/key string object，隐藏 X8 是 output reference。非空输入依次分配 24-byte string、length+1-byte 零填充 payload、4-byte count。构造 temporary shared reference 后，重新读取原 key/data 的 pointer 与 length，执行 drop=0 的流运算，再 copy reference，将 count 从 1 加到 2，清理 temporary reference 后回到 1。原生最终 X0 不是这里的语义结果。

empty key/data 只生成 NULL string reference 与 count=1。释放流程先做 u32 count 减一，再按有符号值判断：正数保留两个 wrapper words；零或负数先 free count，然后经 guest vtable 的 deleting destructor 清理 string payload 与对象。NULL count 不处理 object。释放前 bytes 与 poisoned free 顺序都有 native 对照。普通 guest bytes 之外，同次组合测试还显式比较可能在 native 栈中的 output reference。

allocator 在第三次分配时改变原 key/source 的案例证实：运算使用分配后的源内容。页面事务不能回滚调用方外部 allocator 账本；未知 target、超界/unmapped 输入及未恢复的分配失败路径按明确异常拒绝。

## 对照结果与复现

[流组件证据](evidence/vm9_stream_cipher_native_20261004.json)：**174 组 native 差分 / 9 个拒绝与页面回滚案例**。覆盖两个 image bases、1/2/16/20/32/255/256-byte key、drop=0/1/256/3072、单次与分次处理、0/1/16/165-byte 长度、跨页、原地和部分重叠、key/state alias、raw zero divisor、完整 reference 与删除，以及分配时来源变更。每个 sequence 共用同一 native CPU/allocator；所有中间 guest bytes、主 image pages、allocator 状态及释放前 bytes 一致。单次包装另外显式比较位于 entry SP-0x150 的整个 264-byte state。native 输出从未作为 Python 输入。

初次单字节包装验证失败的原因已定位：旧 oracle 的通用 `REGS` 只含 X0–X4，而此 helper 的长度参数在 **X5**。新 verifier 明确加载 X5；复测上述向量与独立 ARC4 输出一致。这是 oracle 参数装载修正，不是对 native 算法添加特殊例外。

[组合证据](evidence/vm9_root_vm_prefix_native_20261004.json)：4 次 fresh native controls，8 段 VM、36 条构造/配置/密码子树比较。parser 贯通 AES mode-0 解密、两次 checked copy、RC4 reference、结果 clone 及删除分支后，到第 **725 步**，在 `+0x2635ac → +0x248dd8` 之前停止。100 次分配、26 次显式 free、全部主 image、guest、隔离 TLS、2256-byte generation 表及有序副作用一致。单独的 stream reference 子树每次有 3 次分配，无显式 free；temporary count 2→1 保留 payload。

```text
python python/verify_vm9_stream_cipher.py --library /private/libmetasec_ml_71332.so --output /private/stream.json
python python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-prefix.json
```

pure Python state/block 模型只需要 caller pages；reference 构造还需 matching ELF 的 vtable/empty descriptor 和显式 allocation/free。native verifier 需要 Unicorn、pyelftools、PyCryptodome；组合对照另需匹配 libc。公开材料不包含真实 key、明文、密文、设备信息或 ELF。

## 证据用途与下一处

这组对照可以证实 `+0x2592b8` 的实际跳转、RC4 state 布局及运算、X5 的调用约定、输入读取次序和 reference ownership。它不能证明完整 root/88-byte 初始化、current Medusa 或线上接口已经独立可用。

下一处 `+0x248dd8` 先清 string length，再尾调用 `+0x247a08` 的 fill/resize 路线，需恢复扩容与清理的效果后继续 parser。native 后续还观测到 `+0x256088`，它也尚未由本轮 Python 路线恢复。root 仍第 513 步；完整 Python 前导、当前搜索非空/分页、无 JVM Rust、抖音/起点及最终 Pages/Actions 工具仍未完成。
