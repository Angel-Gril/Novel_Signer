# 48 字节 owner、152 字节 mutex state 与后续 VM 前缀

截止：2026-10-04。已恢复 `+0x2698f0` 的构造前缀，后续 VM 仍未退出。**独立 Medusa 尚未完成**。

继 [配置初始化](CONFIGURATION_INITIALIZATION.md) 推进 root 到605步之后，本轮检查 `+0x2698f0 → +0x269988 → VM +0xa46a0`。root 主流程仍停在605步；新增的 VM 组件独立推进到 **173步 / +0xa4950**，下一处是 `+0x26a4ec → +0x25ee84`。二者不能合并成 root 已经退出的结论。

## 生产模型与 ABI

[vm9_objects.py](python/vm9_objects.py) 的 `construct_mutex_backed_string_owner_prefix` 输入 pages、object/source string 地址、native W2 flag、image base 与 allocator。返回 `MutexBackedStringOwnerPrefix`，包含 owner、cloned string、count 和 mutex 地址；边界在 `+0x269988` VM caller 前。它不执行该 caller 或 VM body。

| owner offset | 构造前缀生成的字段 |
| --- | --- |
| +0x00 | relocated vtable +0x35d2c0 |
| +0x08/+0x10 | string object/count reference |
| +0x18 | NULL 结果字段 |
| +0x20 | 152-byte mutex state pointer |
| +0x28 | W2 的低8位 |
| +0x29..+0x2f | 保留原来的7字节 padding |

原生次序是：发布 owner vtable → 分配24-byte string并 clone source → 分配4-byte count → 清结果字段 → 分配152-byte状态 → 全区 memset → 调用 `+0x17d7e0 / +0x32a330` → 发布状态 pointer → 写 flag。状态构造复用现有 `construct_mutex_state` owner，避免第二份 mutex 语义。

独立 `construct_mutex_state` 会保留末尾3字节 padding；本次调用在它之前 memset 了整个152-byte区，所以此处3字节必须为零。这不能被“所有新分配内存默认清零”的假设替代：owner 的7字节 padding仍需保持输入。

string payload 的分配失败是可恢复分支：native clone 生成 empty fields，随后仍可构造引用和 mutex。该情况作为成功路径差分核对；不能把所有 allocation NULL 一概判成同一种 abort。string object/count/mutex 的未知 operator-new NULL 路线由模型拒绝。

## 新 VM 前缀

[组合 verifier](python/verify_vm9_root_vm_prefix.py) 新增 `state_vm` 与 `state_owner_prefix`。VM +0xa46a0 的已恢复 callback 有：

| wrapper | target | Python 行为 |
| --- | --- | --- |
| +0x26a4c8 | +0x167e54 | 两次 guest lazy masked decode |
| +0x26a4dc | +0x268eb0 | 复用单 live mutex 的 scoped writer 获取与 TLS node 发布 |
| +0x26a4ec | +0x25ee84 | 明确停止；该 getter 尚未恢复 |

该 VM 的 native入口 SP 为 caller entrySP-0x6d0；其 callback scratch 由 VM入口 SP 减0x1c8派生，使用原始 padding，并在 allocation 后按实际读点读取。没有移植 native node 输出或强制清零 scratch。

当前四次 `state_vm` 对照仍使用同次 native **VM 入口输入前导快照**，与已经由 Python 生成 caller 的配置 parser 不同。`+0x269988` caller 的完整前导尚未建模，也未把该 VM body 接回 root。未知 callbacks 保持明确边界。

## 验证与证据

[构造前缀证据](evidence/vm9_state_owner_native_20261004.json)：**52 组 fresh native 差分 / 6 个拒绝与页面回滚案例**。两个 image bases，synthetic string lengths 0/1/7/32/165，flags 0/1/255/256/0xffffffff，以及 payload malloc NULL。比较完整 guest、全部主 image pages、有序 allocator/live blocks、进入 caller 时的 object argument、owner padding与mutex padding。拒绝案例为 unmapped owner/source、显式长度边界与三个 operator-new NULL 点。

[同次组合证据](evidence/vm9_root_vm_prefix_native_20261004.json) 现为 **4次fresh controls / 16段VM / 60条完整子树**，两个 bases × SDK缺失/30。每次 owner prefix有4次分配；`state_vm` 前缀有1次TLS node分配、无free，173步停止。guest/image/TLS/2256-byte generation表与allocator/clock/registration/wake有序副作用一致。该 VM 尚未退出，因此不宣称32个 terminal slots的退出对照。

已有 root_advanced仍为605步 / +0x99cd8，138次分配/70次free；parser仍为3318步退出、119/47及全部32个terminal slots匹配。新增前缀没有改变这些已发布结果。证据只含offsets、counts和comparison flags，未发布decoded constants、输入配置、真实请求或设备数据。

## 复现

从番茄目录运行，matching ELF/libc保存在私有路径：

```text
python -B python/verify_vm9_state_owner.py --library /private/libmetasec_ml_71332.so --output /private/state-owner.json
python -B python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-parser-state.json
```

页面事务仅回滚 guest pages；allocator账本是外部副作用。该前缀可用于检查owner布局、W2截断、clone失败、mutex初始化和padding来源，不能单独输出 Medusa，也不能证明线上服务器已经接受当前签名。

## 下一处依赖

native控制确认 `+0x25ee84` 经 `+0x26cd0c` 进入cold shared-reference初始化 `+0x26cdc4`，再做结果引用、环境字段getter与 `+0x248908` 格式化。当前观测shared temporary reference非NULL。不能跳过该cold路径、假设reference为空或使用捕获到的格式化输出作模型输入。SHA-1 reference `+0x258780` 已有模型；下一步先恢复shared-reference/getter和格式化，再补该 VM 剩余callbacks、caller前导与root组合。

完整当前fresh-input Medusa、无JVM Rust下载链路、搜索非空/分页、抖音/起点闭环、最终Pages搜索下载网页与Actions工具均未完成。
