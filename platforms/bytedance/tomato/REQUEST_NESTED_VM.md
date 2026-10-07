# 番茄 request nested VM：fresh 前缀、字段和调用证据

更新：2026-10-07。范围严格绑定到私有样本 SHA-256：

```text
712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c
```

本轮可复核结论：在显式 native object/x8、fresh guest 页和 ELF 重定位输入下，
Python 已恢复 request dispatcher 的正常路径，执行 10 次 STORE64、op17
sub-dispatch、OR64 和 signed MOVhi，并与原生 ARM64 对照到 `image+0x16e32c`。
没有使用 native 前导页、堆或寄存器快照作为 Python 输入。

这是一段研究组件链。真实 URL、headers 和 JNI 对象转换、整个 request VM 返回、
完整独立 Medusa、当前线上验签和无 JVM Rust 下载器仍未完成。对应公开证据的
`complete_python_medusa`、`fresh_input_signer_output_verified`、
`current_online_header_matrix_verified` 和 `no_jvm_rust_signer_complete` 均为 `false`。

## 1. 原生边界与已验证行为

| 原生位置 | 输入/操作 | 已验证结果 |
| --- | --- | --- |
| `+0x256ed4 / +0x168324` | 显式 object/x8 caller 和 defined VM backing slots | 复用已有 fresh caller/prelude 模型；生成需要的地址和槽位 |
| `+0x16d7d0` | `image+0x99020` 的 word `0xff7bdc0f` | 正常 dispatcher 解码；next 为 `+0x171138` |
| `+0x171138` | VM op26；基址槽、源槽和 signed displacement | 10 次 STORE64，覆盖 `image+0x99024..+0x99048`，进入 `+0x16855c` |
| `+0x16855c` | 从当前 stream 加载 `w21`，取 sub 字段 | 当前 word `0x01c10b11` 为 op17/sub44，选择 `+0x16a5a8` |
| `+0x16a5a8` | 使用 `x21` 的 source/destination 字段 | `R[16] = R[7] | R[0]`，下一跳 `+0x16e158` |
| `+0x16e158` | VM op52，signed MOVhi | word `0x58f30ff4`；`R[19] = 0xfffffffffed30000` |
| `+0x16e32c` | 下一条 word 已位于 `image+0x99054` | 已定位并验证到达；body 尚未恢复 |

OR64 的间接出口指令是 `+0x16a610: br x8`。之前未提交实验的观察器通过异常
停止 native 执行，绕过了 `oracle.native` 的 normal-return 内存导出，留下空的
比较值；修正版在分支目标入口直接读取 emulator 内存。这个修正解决的是验证器
采样问题，不能拿旧实验的断言失败证明 OR 运算错误。

## 2. VM word 字段

所有 word 均为 little-endian uint32；下面位号从最低位 0 起算。不同 opcode 的
位重排各自归属自己的 decoder，不共用标准五位字段假设。

### STORE64：op26 / `+0x171138`

```text
base_slot   = ((word >> 22) & 0x0f) | (((word >> 31) & 1) << 4)
source_slot = ((word >> 27) & 0x0f) | (((word >> 21) & 1) << 4)
disp16      = ((word >> 16) & 0x001f) | ((word >> 6) & 0x03e0)
            | (((word >> 6) & 1) << 10) | ((word << 4) & 0x7800)
            | ((word >> 11) & 0x8000)
address     = (R[base_slot] + sign_extend_16(disp16)) mod 2^64
[address]   = R[source_slot]
```

原生先读当前和下一条 word，再推进 stream；之后读源槽并写 payload。因此当
payload 覆盖下一条 word 时，当前 dispatch 使用已经读入的旧 next-word selector。
模型按这个顺序执行，不能在末尾重新读被覆盖的 word。

每次迭代还发布 base/source scratch 和 disp16 scratch，读取 frame 中的 shared
reference、scratch pointer 和 return key，然后选择下一 handler。当前循环的 10
个位移依次为 `136, 128, 120, 112, 104, 96, 88, 80, 72, 64`。

### op17 sub-dispatch：`+0x16855c`

```text
word = uint32([uint64([x19])])
op   = word & 0x3f
sub  = (word >> 6) & 0x3f
x21  = word
```

该 block 从 `image+0x3798e0` 读取 sub-dispatch table pointer，结合 `x4/x5` 和
frame return key 选择目标，不推进 stream，也不写 guest 内存。

### OR64：op17/sub44 / `+0x16a5a8`

```text
word  = x21
src_a = (word >> 22) & 31
src_b = (word >> 27) & 31
dst   = (word >> 12) & 31
R[dst] = R[src_a] | R[src_b]
```

`x21` 与 stream 中的当前 word 是不同输入。独立控制故意把 stream word 改为
`0xcafebabe`，保持合法 `x21`，原生和模型仍匹配，证明 handler 消费的是寄存器。
原生先读 left、写 `x22` scratch，再读 right；如果 scratch 与 right 槽位别名，
第二次读取必须看见 scratch 的写入。目标槽与 source 的别名也按原生顺序处理。

### signed MOVhi：op52 / `+0x16e158`

```text
imm16 = ((word >> 16) & 0x001f) | ((word >> 21) & 0x03e0)
      | (((word >> 6) & 1) << 10) | ((word << 4) & 0x7800)
      | ((word >> 6) & 0x8000)
dst   = ((word >> 22) & 15) | (((word >> 11) & 1) << 4)
R[dst] = sign_extend_32(imm16 << 16) mod 2^64
```

MOVhi 先写 destination scratch 和 backing slot，再加载 next word、推进 stream，
发布 immediate/scratch 字段并选择下一 handler。立即数 `0x8000`、`0xffff` 的
高位扩展必须保留，不能把结果当作 zero-extended uint32。

## 3. Python 调用边界

| 模块/函数 | 用途 | 返回/停止范围 |
| --- | --- | --- |
| `vm9_request_caller.prepare_request_vm_caller` | 由显式 object/x8、stack、TLS 和保存寄存器生成 caller/defined backing | 返回 fresh caller frame；不转换 URL/JNI |
| `vm9_request_dispatcher.prepare_request_dispatch_frame` | 计算 nested VM ABI 地址 | 返回 dispatcher frame |
| `vm9_request_nested.execute_request_nested_prefix` | 初始化所需 prelude 字段，组合 dispatcher、STORE64 loop、sub-dispatch 和 OR64 | 返回组件结果，停在 `+0x16e158` |
| `vm9_request_nested.movhi_request_word` | 在同一 pages 上继续一条 signed MOVhi | 返回 next handler；当前 sample 为 `+0x16e32c` |
| `vm9_request_nested.store_request_word` | 独立一条正常 STORE64 | 返回写入顺序、字段和 target |
| `vm9_request_nested.subdispatch_request_word` | 独立 sub-dispatch | 返回加载的 word、寄存器更新和 target；无写入 |
| `vm9_request_or64.apply_or64` | 独立 OR64 | 消费显式 `word_register`；返回写入和 target |

pages 为现有 `page_number -> bytearray(4096)` 映射。模型本身不调用 native/JVM；
native 只用于验证。对照运行器依赖项目已有的 Unicorn、pyelftools 环境，以及上述
SHA-256 的私有 `.so`。仓库不分发该样本或捕获状态。

`execute_request_nested_prefix` 的 caller backing 必须先由显式输入生成；它额外
生成 loop 读取的 `frame-0x38` 和 `frame-0x10` 指针。其他 generic prelude spills
没有借助快照补齐，也没有声称恢复。未知下一跳或 store budget 耗尽时，整个
helper 的 staged pages 不发布；单条 handler 的缺页失败同样不发布部分写入。

## 4. 对照矩阵和复现

| 证据组 | 数量 | 主要控制 |
| --- | --- | --- |
| OR64 direct | 12 | 两加载基址；实际 ELF table / synthetic table；x21 与 stream 不同；source/destination 和 scratch 别名 |
| STORE64 direct | 12 | 两加载基址；正/负、`-32768`/`32767` 位移；source/base 相同；覆盖 next word |
| sub-dispatch direct | 6 | 两加载基址；sub 0、44、63；显式 table/key 输入；无内存写入 |
| MOVhi direct | 12 | 两加载基址；0、`0x7fff`、`0x8000`、`0xffff` 等立即数；不同 dst/scratch 字段 |
| fresh caller composition | 6 | 两加载基址 × 三对象/x8 profile；页填充 A5/5A/3C；原始重定位 ELF table |
| 拒绝/回滚 | 8 | 错误 opcode、非 uint32 x21、缺失 table、非法/耗尽 loop budget |
| 原 dispatcher 回归 | 6 | 原有两基址 × 三 caller profile |

direct component 控制比较完整 65,536 字节 guest 内存、规定的寄存器和写入顺序。
组合控制比较 loop 每次输出、OR/MOVhi 边界寄存器、25 个规定内存范围，以及
从 store loop 开始的 61 次写入；没有把未建模的 generic frame padding 当作
“全栈一致”。独立 sub-dispatch 的 synthetic sub 0/63 控制只证明 table 索引及
目标选择，不证明对应真实 sub-handler 的 body。

PowerShell 中用环境变量指定匹配的私有样本路径：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_or64_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_or64_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_nested_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_nested_fresh_20261007.json
```

公开证据：

- [OR64 fresh differential](evidence/vm9_request_or64_fresh_20261007.json)
- [STORE64/sub-dispatch/MOVhi 和 fresh caller 组合](evidence/vm9_request_nested_fresh_20261007.json)
- [此前 dispatcher 对照](evidence/vm9_request_dispatcher_fresh_20261007.json)
- [此前 native-only loop 出口定位](evidence/vm9_request_nested_handler_exit_fresh_20261007.json)

## 5. 如何在后续逆向中使用

把 native offset、样本 hash、decoder、同次内存顺序和 fresh 差分放在一起引用，
可以为以下判断提供关键证据：

1. 区分 caller 初始化、opcode handler、op17 sub-dispatch 与最终 signer 输出。
2. 从源码公式复建当前 ABI 字段，验证重定位后 table/return-key 的计算。
3. 判断 register alias 和读取时序导致的差异，避免把 native 轨迹值注入模型。
4. 在同一组 independently generated pages 上继续 `+0x16e32c`，无需拿原生入口
   快照填补本轮已经恢复的正常路径。

后续每次延伸都要保留本轮对照作为回归，并以新的 target、寄存器/写入差分和
未知分支拒绝为验收条件。这组证据不能用于宣称完整 request VM、Medusa、当前
服务器接受或其他平台算法已经完成；抖音与起点必须用各自样本和目录验证。
