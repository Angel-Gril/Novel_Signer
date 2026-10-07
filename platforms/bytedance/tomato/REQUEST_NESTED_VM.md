# 番茄 request nested VM：fresh 前缀、字符串 getter 和调用证据

更新：2026-10-07。范围严格绑定到私有样本 SHA-256：

```text
712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c
```

当前可复核结论：Python 已恢复 `+0x16e32c` 的正常 OR immediate，并在
独立生成的 caller、ELF 重定位和显式 reader/string 输入上，执行完整的
`+0x256ed4 / VM +0x99020` 字符串 getter。它完成 acquire → clone → release，
在 bytecode `image+0x99150` 退出；原生 caller 的返回另有独立观察。
28 组新增 native/Python 对照和 7 个负控制通过，没有把 native 快照作为模型输入。

当前同次 Python outer/request 已继续恢复相等性、signed 格式化、字符串清理、
serial guard 和显式 memory imports。低加载基址 `0x122c0000` 推进至
**919 / +0xffae0**，下一处 `+0x285f60 → +0x2914d0`；高加载基址
`0x775c205000` 推进至 **793 / +0xf87bc**，下一处 `+0x2859e0 → +0x32a330`。
新增 56 个组件原生对照、11 个负控制和 6 个 prefix 回归通过，详见
[REQUEST_STRING_CALLBACKS.md](REQUEST_STRING_CALLBACKS.md)。高基址仍未完成 getter
组合，外层分支差异仍无 whole-native 对照。

整个 request VM、真实 URL/headers/JNI 转换、完整独立 Medusa、fresh 签名和当前
线上矩阵仍未完成。Python 没有完整建模 native caller epilogue/ABI 返回；独立
getter 对照使用显式 malloc 服务和 matching-libc 的真实 mutex，外层使用现有
matching-libc allocator 模型。这两个证据范围必须分别引用。

## 1. 原生边界与已验证行为

| 原生位置 | 输入/操作 | 已验证结果 |
| --- | --- | --- |
| `+0x256ed4 / +0x168324` | 显式 object/x8 caller 和 defined VM backing slots | 复用已有 fresh caller/prelude 模型；生成需要的地址和槽位 |
| `+0x16d7d0` | `image+0x99020` 的 word `0xff7bdc0f` | 正常 dispatcher 解码；next 为 `+0x171138` |
| `+0x171138` | VM op26；基址槽、源槽和 signed displacement | 10 次 STORE64，覆盖 `image+0x99024..+0x99048`，进入 `+0x16855c` |
| `+0x16855c` | 从当前 stream 加载 `w21`，取 sub 字段 | 当前 word `0x01c10b11` 为 op17/sub44，选择 `+0x16a5a8` |
| `+0x16a5a8` | 使用 `x21` 的 source/destination 字段 | `R[16] = R[7] | R[0]`，下一跳 `+0x16e158` |
| `+0x16e158` | VM op52，signed MOVhi | word `0x58f30ff4`；`R[19] = 0xfffffffffed30000` |
| `+0x16e32c` | op48 OR immediate，word `0x9840caf0` | `R[1] = R[19] \| 0x6560`；推进 stream 至 `+0x99058`，下一 handler 为 `+0x16f8e0` |
| `+0x25705c → +0x32a444` | shared reader acquire | receiver `+0x88` 的 reader；无竞争 count 加 1 |
| `+0x257068 → +0x2483e0` | clone 24-byte StringObject | 复制 receiver `+0x118` 的声明长度，保留嵌入 NUL，追加终止零字节 |
| `+0x25705c → +0x32a4fc` | shared reader release | count 和 mutex 状态恢复；release 同样使用 `+0x25705c` |
| `image+0x99150` | getter VM exit word | Python VM 退出；原生 caller 确实返回，但 Python 完整 native ABI 尚未建模 |

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

### OR immediate：op48 / `+0x16e32c`

```text
src   = (word >> 27) & 31
dst   = (word >> 22) & 31
imm16 = ((word >> 16) & 31) | ((word >> 1) & 0x7fe0)
      | ((word >> 6) & 0x8000)
R[dst] = R[src] | imm16
```

正常分支出口是 `+0x16e47c: br x8`；本轮不恢复 repair 路径。当前 word 解码为
src=19、dst=1、imm=0x6560。原生先读 source、发布 source scratch、写 destination，
再发布 destination/immediate scratch 和 stream；别名控制按这一顺序比较。

getter 的第一 target 并不直接取自 `image+0x35b650`。`+0x99058` 加载
`+0x35b658` 的地址基值，结合 signed MOVhi 和 ORi，最终在 `+0x99060` 解引用
`image+0x381c50`，取得 `image+0x32a444`。未知 target 负控制修改这个实际槽位
为 `image+0x32a445`，确认模型在分配前拒绝、guest 页不发布。

### receiver 与 StringObject 布局

| 地址 | 字段 |
| --- | --- |
| `receiver+0x88` | shared reader/mutex 起点 |
| `receiver+0x110` | reader count，uint32；即 reader 起点再加 `0x88` |
| `receiver+0x118` | source StringObject 起点 |
| `StringObject+0x00` | uint64 vtable，当前为 `image+0x34f5f8` |
| `StringObject+0x08` | uint32 capacity |
| `StringObject+0x0c` | uint32 declared length |
| `StringObject+0x10` | uint64 payload pointer |

clone 使用声明长度而非 C-string 长度。正常分配 length+1，空串也分配 1；负 int32
length 不分配，malloc NULL 的结果有单独原生控制。native X0 返回保留的
`image+0x257050` marker，Python virtual R0 为 0，不能把二者混作同一返回值。

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
| `vm9_request_nested.ori_request_word` | 独立 OR immediate | 返回字段、写入、寄存器更新和下一 handler |
| `vm9_request_nested_callbacks.nested_getter_inputs_from_request` | 解码 `+0x285978` packed ABI，计算 native frame 输入 | 生成 getter inputs；未知 target 拒绝 |
| `vm9_request_nested_callbacks.execute_nested_string_getter` | fresh caller/prefix、ORi 和剩余 semantic VM、三个回调 | 返回 callback ledger、32 slots、word trace 和 exit；只在全部成功后提交 guest 页 |

pages 为现有 `page_number -> bytearray(4096)` 映射。模型本身不调用 native/JVM；
native 只用于验证。对照运行器依赖项目已有的 Unicorn、pyelftools 环境，以及上述
SHA-256 的私有 `.so`。仓库不分发该样本或捕获状态。

`execute_request_nested_prefix` 的 caller backing 必须先由显式输入生成；它额外
生成 loop 读取的 `frame-0x38` 和 `frame-0x10` 指针。其他 generic prelude spills
没有借助快照补齐，也没有声称恢复。未知下一跳或 store budget 耗尽时，整个
helper 的 staged pages 不发布；单条 handler 的缺页失败同样不发布部分写入。

`nested_getter_inputs_from_request` 读取 packed 的 function/output/receiver 三个
uint64。原生 wrapper 在 `+0x285978` 加载 x9/x8，设置 x0，压入 16 字节 LR frame。
由 outer frame 计算 nested 输入：

```text
entry_stack_address = request_frame.native_stack_address - 0x190
return_address      = image + 0x285988
saved_frame_pointer = request_frame.native_stack_address - 0x60
saved_x28           = request_frame.register_backing_address
saved_x19           = request_frame.register_backing_address - 8
```

这些物理 frame 公式另由 6 个真实 outer-prefix 控制、30 个 callback 入口观察验证；
4 个独立 wrapper 控制验证 packed 传参与原生返回。Python 未复制 oracle 输出作为
inputs，也未恢复完整 wrapper/caller epilogue。

剩余 VM 复用 `vm_full.VM`，但所有 virtual slots 直接读写同一 guest backing，
不能用与间接内存写入失同步的独立 R 列表；jump base 保留 `+0x99020`，执行 PC
从 `+0x99058` 开始，常规控制执行 54 步。执行结束或失败时恢复模块的临时 image
base。guest 事务回滚不等于任意外部分配服务的副作用也回滚。

外层 hook 沿原 `_PageTransaction` 链调用 owning session 的 allocate；不复制出
脱离 session 的页，也不向实际 receiver 注入 reader 或 source string。低基址
控制复制了该轮 constructor 的 8 字节字符串，分配 9 字节，核对输出摘要、
终止零字节及 reader count 恢复。整个 outer/request 组合仍不是 native 差分。

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

本轮新增矩阵：

| 证据组 | 数量 | 主要比较 |
| --- | --- | --- |
| ORi | 12 | 两 image base、立即数、source/destination/scratch 别名；寄存器、有序写入和完整 guest 页 |
| getter | 12 | 空串、UTF-8、嵌入 NUL、跨页、高 reader count、malloc NULL、负 length；三 callback 的参数和 32 slots、stream、virtual stack、0xA000 字节 payload |
| request wrapper | 4 | 两基址 × 空串/嵌入 NUL；实际 caller ABI、原生返回、payload 和分配序列 |
| 拒绝/回滚 | 7 | budget、output/source 缺页、超长 source、reader wait、实际 target 槽变异 |
| outer-prefix frame 回归 | 6 | 两基址 × 三请求控制，30 个物理 callback frame 入口 |
| same-session continuation probe | 2 | 低基址 getter 完成并停在 816；高基址更早停在 641，仍未贯通 |

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_or64_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_or64_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_nested_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_nested_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_nested_callbacks_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_nested_callbacks_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_prefix_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_prefix_callback_abi_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

`TOMATO_MATCHING_LIBC` 指向 matching 私有 libc；SHA-256 必须为
`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
每个 runner 在执行前校验对应样本。仓库不包含这两个二进制。

公开证据：

- [ORi/getter/wrapper fresh differential](evidence/vm9_request_nested_callbacks_fresh_20261007.json)
- [outer-prefix 物理 callback frame](evidence/vm9_request_prefix_callback_abi_fresh_20261007.json)
- [same-session 两条未完成的 continuation](evidence/vm9_request_diagnostic_continuation_20261007.json)
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
4. 用独立生成的 guest backing 完成 acquire/clone/release，并从 constructor 的
   actual receiver 接回 owning allocator，避免用 captured source 或返回值补洞。
5. 将完整 getter 的局部原生差分与外层未完成的组合分开，定位剩余分支，而不把
   VM entry 数量、退出 marker 或单个字符串输出当作 Medusa 签名。

后续每次延伸都要保留本轮对照作为回归，并以新的 target、寄存器/写入差分和
未知分支拒绝为验收条件。这组证据不能用于宣称完整 request VM、Medusa、当前
服务器接受或其他平台算法已经完成；抖音与起点必须用各自样本和目录验证。

## 6. 下一处边界与未验证内容

此前 `%d|%s` 与 C-string equality 边界已恢复，并接回同次 owning allocator。
低基址已推进到 `+0x285f60 → +0x2914d0`，高基址到
`+0x2859e0 → +0x32a330`。当时高基址的 NULL memset target 已追到真实 ELF
`+0x382c80` ABS64 relocation，并按解析出的 PLT service 绑定；不是填入 native
输出以跳过函数。

新的 ABI、正常和拒绝控制、resolver、原生/helper 返回差别及完整复现见
[REQUEST_STRING_CALLBACKS.md](REQUEST_STRING_CALLBACKS.md)。matching-libc realloc
仍未实现；本次低基址 growth 未触发该路径。真实请求转换、完整 request 返回和
签名仍未完成，不能把两个不同 stop 合并成请求成功。

后续 clock/raw state/guard release/shared pointer getter 已继续推进 outer 请求；
最新 stop 和证据见 [REQUEST_CLOCK_STATE.md](REQUEST_CLOCK_STATE.md)。本文的
StringObject getter 证据范围不变，pointer getter 不代表该 StringObject getter。
