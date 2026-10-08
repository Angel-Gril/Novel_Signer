# 原始 JNI 返回、同次 worker 析构与 B factory / descriptor 发布

记录日期：2026-10-07 UTC。文件名沿用本机试验标签 `20261008`；标签不是新增的 UTC 日期。
2026-10-08 UTC 追加 reader u32 原语的 258 个差分与 7 个回滚控制，见第 6.1 节。
同日追加 section dispatcher 与部分 handler 的 202 个对照、12 个回滚，见第 6.2 节。
同日追加有符号 i32 原语的 1336 个对照、10 个回滚，见第 6.3 节。
同日追加 vector/type 的 102 / 372 个对照、34 个回滚，见第 6.4 节。
同日追加 function/global import 的 254 个对照、14 个回滚，见第 6.5 节。

本检查点验证了 **A 原始 JNI_OnLoad 返回、同次 worker 的六个默认 caller、TLS 析构
及 guest joinable pthread_exit**。B 原始 constructor/factory 在两个基址自然返回并各
发布 121 个非空 descriptor；Python lookup 通过实际生成 root 的组件对照。分配器、
虚拟 worker、JNI 和 OS 服务仍显式。独立 Python factory、完整 Python bootstrap、fresh
请求签名与线上矩阵仍未完成。

## 1. 正式证据与计数

| 证据 | 数量 | 已验证行为 |
|---|---:|---|
| A 原始 JNI_OnLoad 返回 | 2 | 两个基址，原始入口自然返回 `0x10006` |
| 同次 JNI → 默认 worker 入口 | 2 | 同次 thread-create argument，到达 `+0x280554` 前 |
| memset 导入单变量控制 | 4 | 两个基址 × 未绑定/绑定，在相同 wrapper 停止点核对目标 |
| 同次 worker 完整默认任务 | 2 | 每次六个 caller、48 个嵌套返回、六块 arena、六次完成 broadcast |
| 同次任务清理/worker wait 边界 | 2 | task cleanup 后到达 condition wait PLT 前 |
| 同次 worker wait/stop/return/free | 2 | 实际 libc wait + 显式 EINTR/stop，正常返回并释放 argument；support 保留在 TLS |
| 同次 JNI → worker TLS 析构 | 2 | 清空实际 support slot，依次释放 argument / payload / wrapper |
| 同次 JNI → guest joinable pthread_exit | 2 | 实际 libc exit body，joinable 状态 0→1，到显式 syscall 93 exit |
| allocator 区域碰撞控制 | 1 | 原 pool 覆盖 TLS 后 canary 失配，停止于 fail 分支调用前 |
| B 短输入哈希 native/Python 差分 | 20 | 两个基址 × 0..8 字节及高位移位控制 |
| B 短 selector lookup 差分 | 30 | 合成桶/碰撞/空返回、short/long stored key、实际 ELF selector |
| B Python 拒绝与回滚控制 | 6 | 长 query、坏栈、缺页、循环、超限等 |
| B 原始 constructor/factory 返回与发布 | 2 | 每次自然返回，121 个非空 descriptor，2330 次受控分配 |
| B 实际生成 root 的 lookup 组件对照 | 242 | 每个基址 121 个；Python 消费 native 生成 root，未实现 Python factory |
| B 独立 Python blob XOR prefix | 82 | 80 个边界控制与 2 个实际 ELF blob；reader 前停止，不用 native 快照 |
| B blob XOR 拒绝/回滚 | 8 | ABI/长度上限、codec 地址溢出/缺页、目的跨缺页等 |
| Python XOR → 实际 B reader 自然返回 | 2 | 每次 1658 次受控分配，reader 返回 0；无 Python reader / AST 对照 |
| B reader u32 原语 native/Python 差分 | 258 | 两个基址各 129 项；自然返回和整个 guest 内存一致 |
| B reader u32 拒绝/回滚 | 7 | ABI/地址上限、输入缺页和部分输出跨缺页；原页保持不变 |
| B reader section/部分 handler 差分 | 202 | 194 项合成输入、8 项实际 ELF section 输入；返回、guest/global 状态、回调参数与时机一致 |
| B reader 未恢复分支/guard 回滚 | 12 | type/import、五类 special custom、缺页/重叠/遍历上限和坏服务结果明确拒绝 |
| B reader i32 原语 native/Python 差分 | 1336 | 两个基址各 668 项；第五字节全值、正负边界、失败保留输出和 guest 输入/输出区一致 |
| B reader i32 拒绝/回滚 | 10 | 有界 ABI、缺页、成功输出地址无效；部分输出跨缺页仍保持原页 |
| B reader word-vector 扩容差分 | 102 | 两个基址各 51 项；新增元素、容量、复制、分配/free 与指针发布顺序一致 |
| B reader type section 差分 | 372 | 368 项合成输入、4 项实际 ELF 输入；回调参数与当时的 type cells 一致 |
| B reader vector/type 拒绝/回滚 | 34 | 23 项 vector、11 项 parser guard；所有原页保持不变 |
| B reader function/global import 差分 | 254 | 248 项合成输入、6 项实际 ELF 输入；含混排计数、回调失败和完整 1/2/3/7/12 组合 |
| B reader import 拒绝/回滚 | 14 | 默认关闭、坏服务、缺页/重叠/上限、table/memory 和晚到的未恢复分支均全页回滚 |
| 完整 Python bootstrap 对照 | **0** | 未验证全部构造器、全局/TLS/allocator/JNI/worker 的独立生成 |

证据文件：

- [A 原始启动与默认任务](evidence/vm9_jni_A_default_worker_20261008.json)
- [A stop-only 控制](evidence/vm9_jni_A_worker_stop_20261008.json)
- [A 同次 TLS cleanup / guest exit](evidence/vm9_jni_A_worker_exit_20261008.json)
- [B 合成 root 的短 selector](evidence/vm9_alternative_short_descriptor_20261008.json)
- [B 实际 factory / 发布与生成 root 对照](evidence/vm9_alternative_factory_native_20261008.json)
- [B 独立 blob XOR prefix](evidence/vm9_alternative_blob_xor_fresh_20261008.json)
- [Python XOR 输入交接实际 reader](evidence/vm9_alternative_reader_native_20261008.json)
- [独立 Python reader u32 原语](evidence/vm9_alternative_reader_varuint32_fresh_20261008.json)
- [独立 Python section 与部分 handler](evidence/vm9_alternative_reader_sections_fresh_20261008.json)
- [独立 Python reader i32 原语](evidence/vm9_alternative_reader_varint32_fresh_20261008.json)
- [独立 Python type/vector](evidence/vm9_alternative_reader_types_fresh_20261008.json)
- [独立 Python function/global import](evidence/vm9_alternative_reader_imports_fresh_20261008.json)

原有 13 项 A 启动控制已重新回归通过；计数仍沿用各自证据，不另算新的控制。
这些计数不与此前 once/mask 组件对照相加为完整 signer 对照。

## 2. A 原始返回、同次默认任务与 exit

实际执行链为：

```text
.init_array component +0x271940
  → explicit ctor-exit driver
  → original JNI_OnLoad +0x27B41C
  → cold once / JNI / Long / cleanup
  → A startup +0x28040C / VM +0xA7050
  → queue creation and task submission
  → JNI_OnLoad returns 0x10006
  → explicit virtual worker driver
  → same-run argument → +0x3260A4 → +0x326578
  → default task +0x280554
  → six actual callers +0x280590 .. +0x280810 / 48 nested returns
  → task return +0x326620 → actual task cleanup +0x167310
  → actual matching-libc pthread_cond_wait
  → explicit futex EINTR and queue stop publication
  → argument free → actual worker normal-return boundary +0x326108
  → explicit driver continuation
  → matching-libc key cleanup +0x685A0
      or guest pthread_exit +0x68138 → key cleanup
  → actual support TLS slot clear → payload free(48) → wrapper free(8)
  → key cleanup return +0x6866C
  → cleanup-only return to driver STOP
      or joinable state 0→1 → explicit syscall 93 exit
```

`pthread_create` 是显式服务，发布三个 deferred guest handle：executor `+0x326A2C`
和两个 queue worker `+0x3260A4`。JNI 返回后只调度第一个 queue worker。两个 queue
submission 的 matching-libc signal 实际执行；无等待者 futex 返回为显式 OS 服务。
主 TP=guest+0x3000，worker TP=guest+0x7000；worker pthread/TLS 状态显式初始化，
legacy emulated-TLS OS slot 清零。主/worker 顺序复用 SP=guest+0xEF00，无真实并发。
JNI table 位于 guest+0x6000。

每次完整任务执行六个真实 caller，每个有八次嵌套返回。六个 once control
`image+0x3E09E8+i*0x48` 都成为 `0xFFFFFFFFFFFFFFFF`；实际 libc broadcast 六次，
所有观测 canary 对一致。六块 16 KiB arena 由受控服务提供。清理边界只统计任务
返回到首次 wait 之间的 `+0x167310`，不把后面的 argument 清理算成第二次 task cleanup。

实际 wait 的显式 OS 服务核对 syscall 98、operation 128、expected 4、NULL timeout，
以及 queue+0x30 mutex 已释放，再清 queue+0x88 的 active byte 并返回 -4（EINTR）。
worker 自然返回 0；argument 的 64 字节 block 一次进入 owned free 并填入 0xD7。
stop-only 控制在此结束，因此仍观察到 support 保留在 TLS。

新的 TLS/exit 观察增加第三个 driver：worker 正常返回→libc cleanup/guest exit。
析构对象直接由实际 TLS slot 找到，不另造 support。每次恰好三次 owned free，顺序
为 argument(64)、payload(48)、wrapper(8)，三个 block 的终态 poison 都核对。实际
support slot 清零；guest pthread_exit 写线程返回值 0，并把 joinable 状态从 0 改为 1。

完整 guest exit 使用显式 libc TLS getter，提供清零的 `__cxa` 线程析构链头。私有负
观察定位到未清零链头仍为 fixture poison，`+0x6B2C4` 会尝试读 poison pointer；这不
证明 App 崩溃，也不计入正式控制。这里未执行非空 `__cxa` 链、detached list removal、
真实线程创建/终止或 stack mapping 回收。allocator、JavaVM、JNI、clock、exit、OS、
warm reference、TLS subsystem globals/OS keys 仍显式。旧 startup 组件的 Python exit
验证不能替代本次原始 JNI 组合的完整 Python bootstrap，对照数仍为 0。

## 3. memset 导入与 allocator 碰撞归因

基础 loader 未解析全部 undefined ABS64 导入。按实际 ELF symbol/relocation 提取
memcpy/memset slot，绑定已有服务 PLT `+0x347F60/+0x347F20`；不是把所有导入默认成功。
B factory 观察实际绑定 memcpy 16 项、memset 17 项。strlen 的目标同样按 ELF 解析。

首个任务路径 `+0x280590 → VM +0xEDCF0 → nested VM +0xEE3B0 → wrapper +0x281610`
读取 packet 的 target、destination、**一字节** fill 和 length。四条单变量控制停在
`+0x281620` branch 前；完整任务观察实际执行 callback。不能要求 fill 所在整个
64 位 word 都为零。

原小块 allocator 将 16 KiB arena 放入永久 JNI/TLS 范围，后续 VM 写入改变 worker
canary。碰撞控制保留原分配，在第六个嵌套返回处失配，停在 `+0x280A70` 的 stack-check
fail 调用前。正控制只隔离六块大 arena：guest+0x10000，总长 0x18000。没有绕过
canary 检查。真实 libc allocator/arena/OS region 生命周期尚未在本组合中贯通。

## 4. B 原始 factory、publication 与短 selector

原始 `.init_array` 成员 `+0x29ECAC` 在 `+0x29F2C8` 调 `+0x2A95E0` wrapper，进入
实际 factory `+0x2CBDC8`。constructor 同次生成输入：ELF blob `+0x387D20`、长度
`0x37FD0`、16 个 callback、22 个 prototype 及 hidden output pointer。两个基址的
native 观察都从此 constructor 直接开始，不执行 Android loader 或完整 `.init_array`。

受控 page allocator、2 MiB 独立栈、matching-libc memcmp/normal mutex、显式 gettid
137 和 register-only exit 服务下，两次均验证：

- factory 返回 `+0x2A9610`，wrapper 返回 `+0x29F2CC`，root 写入 `+0x3E1EB0`；
- 实际 root bucket count 为 163，121 次 lookup 发布 121 个非空 descriptor；
- 最终 121 个不同全局槽位均匹配；constructor 在 `+0x2A0024` ret，SP 恢复；
- 每次 2330 次受控分配、4 次 exit 注册，注册的 exit callback 未执行。

此前 2000 万条预算末端捕获为 `+0x2DBF80`，位于 factory 的 vector body。
`+0x2DBF7C` 每次推进 12 字节，新增记录观察到有限区间持续推进；完整运行合计
54533 次此循环边界，在 6000 万条预算内自然返回。预算上限不是实际执行指令总数，
也不能用预算耗尽证明无限循环。此前 `+0x32A9C8` string-copy body 的未映射栈写入
由独立 2 MiB 栈解决，未跳过该 body。

发布 probe 按实际 ELF `str x0, [x8, #imm]` 解码有效地址。忽略 `#imm` 会让 index 35
误读另一全局 slot；当时 actual lookup 与 Python value 已一致。更正后所有发布及
lookup 对照通过。这是探针地址计算缺口，不是 lookup 算法失败。

纯 Python owner：[vm9_alternative_startup.py](python/vm9_alternative_startup.py)。

```python
hash_short_descriptor_name(payload)  # raw bytes 长度 0..8
lookup_short_descriptor(
    pages, root_address=root, name_address=name,
    entry_stack_address=stack, max_nodes=4096,
)
```

短哈希对应 `+0x2AA744`，lookup 对应 `+0x2A9620 → +0x2AA528`。root[0] 为 descriptor
array，root+0x20 为 buckets，root+0x28 为 count。bucket 指向 predecessor，next 指向
node；node 保存 next、cached hash、libc++ string 与 descriptor index。已对照 power /
non-power 桶、碰撞链与桶边界、short/long stored key。4..8 字节的 `first_u32 << 3`
必须先 uint32 截断再加 length。超过八字节、循环、超限或缺页明确拒绝并回滚。

原有 20+30 控制使用合成 root/bucket 输入。新 242 个组件对照则明确消费**同次 native
生成的 root/array/hash node**，`native_input_snapshot_used=true`。它们不计入独立 signer
或 Python bootstrap fresh-input 证明。诊断 scope 仍由既有 oracle 替代；原始 JNI B
分支组合、B VM、Python factory 和完整 B 输入生成仍未完成。

## 5. B factory 的独立 Python XOR 前导

`decode_factory_blob_xor` 恢复 `+0x2CBDC8` 入口到 `+0x2CBF24` reader 调用前的原地
XOR；实现位于同一个 [Python owner](python/vm9_alternative_startup.py)。本函数不构造
reader、root、hash node 或 descriptor。除此前八个寄存器参数，factory 还接收两个
栈参数：codec table pointer 和 count。record 为 24 字节，使用选中 record 的 byte +2。

```python
decode_factory_blob_xor(
    pages, blob_address=blob, blob_size=size,
    codec_table_address=table, codec_table_count=count,
)
```

size 非零时，row 为 `size % count`；count 为零时，native 保留除法商 0，所以 row 是
**size**，不能误写为 row 0。size=0 完全跳过 codec 和 blob 读写；选中字节为零时也
不读取 blob。非零 key 按字节 XOR 整个有界 blob。目的页或 codec 缺页、ABI/地址溢出和
长度超限明确拒绝；page transaction 原子提交，失败后所有页保持原状。

两个基址各测试 40 个合成输入：长度 0/1/7/8/9/31/32/33/63/65、count=0/3、零/非零
key，覆盖 native 的 8/32 字节批处理与 tail。另两条实际 ELF blob 对照从文件独立
初始化 Python/native 输入，选中字节从 actual constructor 的 MOV/STRB 指令读取，
不从 native decoder 输出或 factory 快照取得。82 条都比较完整 blob 和整个 guest
区域；8 条拒绝回滚通过，另验证 zero-size 不解引用未映射的不用输入。

这是新的 fresh-input **prefix 组件**证据，`native_input_snapshot_used=false`，与消费
native root 的 242 条 lookup 证据分开。下一处为 `+0x31B360` reader，再到 `+0x2CD5A4`
解析和 `+0x2CAFD0` root/descriptor 构建；完整 Python factory 与 B VM 仍未完成。

## 6. Python XOR 输入交接 actual reader

后续两基址 native 观察从 fresh ELF 及 Python XOR 结果开始，直接调用 actual
`+0x31B360` reader。reader 自己构造 callback/parser scratch，进入 `+0x324444` 包装
和 `+0x324188` 内部解析；输出对象由 fixture 显式清零，分配器和 2 MiB 栈仍显式。
两个观察都满足：1658 次受控分配，reader status=0，自然 ret 到 driver STOP，SP 恢复，
没有 factory publication / destructor 注册或 B VM 执行。输出只导出 12 个 vector 的
used/capacity 字节数，不导出 native node、原始 blob 或内存快照。

这证明 Python XOR 结果可被该实际 reader 接受；不证明 Python reader、AST/node 构造
或其 cleanup 已恢复。`native_input_snapshot_used=false` 只描述输入生成；native 输出
没有作为独立 Python factory 的输入发布，也没有完整 Python AST 对照。完整 factory
原观察在 reader extension 后回归通过，保持独立 242 个 root lookup 计数。

下一步恢复 `+0x31B360 → +0x324444 → +0x324188` reader 的状态、节点和清理，随后
`+0x2CD5A4 → +0x2CAFD0` 的解析/root 构建。完整 Python bootstrap 对照仍为 0。

### 6.1 Reader u32 原语（2026-10-08 UTC）

同一个 Python owner 新增 `read_reader_varuint32`，恢复实际 `+0x324870`；输入为
有界 guest 地址区间和输出 word 地址。成功写入 uint32，结果包含消费字节数和
输出写入标志。接受冗长编码；截断或五个 continuation byte 返回 0 并写零。第五
字节已终止但大于 0x0f 时返回 0 且不触碰输出地址，结果 value 为 None，保留
已有输出。不能把这两种失败都处理成清零，也不能读取本来不访问的输出指针。

两个基址各 129 条合成输入控制覆盖各整数宽度、uint32 上界、所有边界值截断、
冗长编码、第五字节溢出、忽略第六字节、后随字节、反向区间、输出与输入重叠，
以及 64 个固定 seed 的字节序列。每项比较真实函数自然返回和整个 guest 区域，
包含两个未映射的不用输出指针。7 条拒绝/回滚控制覆盖 ABI、地址上界、缺页及
部分输出跨缺页；页面事务只有成功写入时提交。

证据 `native_input_snapshot_used=false`；Python 不使用 native 输出、reader/AST
对象或 factory 快照。这只是读取原语，`+0x324188` section 状态/排序/handler、
节点/AST/callback 和 cleanup 仍未恢复；完整 Python bootstrap 对照仍为 0。

### 6.2 Section 状态与部分 handler（2026-10-08 UTC）

同一 owner 新增 `run_reader_sections`，恢复 `+0x324188` 的 section id/长度读取、
重复非零 id 拒绝、排序、临时 payload end、精确消费检查，以及成功/失败时的游标
和 limit 恢复。普通解析失败返回 1，并保留 native 可观察的部分状态；未恢复分支
或 guard 失败抛出异常、全部页回滚。所有读取均有 section/input 边界与遍历上限。

排序表从 fresh ELF 独立解码，在实际 native rank 函数写入的同一地址核对：
`[0,1,2,3,4,5,7,8,9,10,12,13,11,6]`。section 12 排在 section 10 前；非零 id
必须严格递增，section 0 可重复且不更新 previous id。id 13 虽有 rank，实际 dispatch
仍拒绝。没有替换为标准格式解析器，也没有凭 section 外观假定兼容性。

已恢复的 handler 范围：section 0 的通用 custom 跳过与 marker 解码、section 3 的
function type-index 列表和 imported-count 加法、section 7 的 export name/kind/index、
section 8 的 start index、section 12 的 data count。section 7 的 kind=4 仍读取其
index 后拒绝；kind>4 在读取 index 前拒绝。保留 uint32 索引回绕和 data-count 写入
发生在 callback 成功后的实际顺序。长度 6/8/7/15 的 custom marker 使用实际 ELF
输入解码，原生比較执行 matching libc `memcmp`；`dylink`、`dylink.0`、`linking`、
`target_features` 与 `reloc` 开头的特殊处理明确未恢复，遇到时拒绝。

202 项对照为两个基址各 101 项：各 97 个合成控制，加 4 个从 fresh ELF 独立 Python
XOR 提取的实际 section 输入（3/7/12 分别及三者组合）。真实 section 3 含 121 个
函数索引、section 7 含 121 个导出项；fixture imported-count 显式为 0，不证明完整
模块的 import/type 语义。全项核对自然返回、整个 guest 区域、rank/custom decoder
全局写入及每次 callback 的所有参数、当时 cursor 和 section end。包括输出错误、
非规范长度、重复/乱序、截断、越界、callback 失败、uint32 回绕与 warm rank 输入。

Callback vtable 是**显式的纯状态服务**：Python/native 同样接收受控 uint32 返回值，
实际节点构造 callback 尚未执行。Python 不使用 native node、内存快照或输出作输入；
证据 `native_input_snapshot_used=false`。12 项拒绝/回滚单独记录，未宣称 native 的
未恢复 handler 已被对照。完整 reader、AST、factory/B VM 与 Python bootstrap 仍
未完成。后续 i32 读取已恢复，见第 6.3 节；下一步恢复 section 1 `+0x32298C` 的 type vector、section 2
`+0x322CF8` 的 import，再接 special custom、实际节点/callback/cleanup。

### 6.3 有符号 i32 读取（2026-10-08 UTC）

同一 owner 新增 `read_reader_varint32`，恢复原生 `+0x324e0c`。返回值描述消费
字节数、有符号值和是否写入输出；原生输出仍是 little-endian 32-bit word。
接受 1..5 字节与冗余编码，第五终止字节仅允许 `0x00..0x07` 或 `0x78..0x7f`。
截断、连续五个 continuation 或非法第五字节返回 0，**不访问或清零输出**。
这与 u32 原语的部分失败路径不同，不能共用其失败写入规则。

两个基址各 668 项，共 1336 个对照：每基址覆盖全部 128 种单字节终止值、全部
256 种第五字节、int32 正负边界与各编码宽度边界、截断、冗余编码、确定性生成
输入、后续字节、输入/输出重叠及跨页。30 个原生控制在失败路径使用 NULL、未
映射或超出 word 边界的输出地址，证实输出未访问。所有自然返回和 guest 输入/
输出比较区的 0xA000 字节一致，不使用 native 输出或内存快照。10 个 guard/缺页拒绝检查保持所有原页，
包括输出跨缺页时已经暂存的部分写入。扫描会发生 uint64 地址回绕的输入明确拒绝。

首轮差分全部通过，但验证脚本漏接底层缺页 `ValueError`，在拒绝检查中结束；
修正验证脚本后重新运行正式批次。没有修改原生函数、跳过失败样例或改变读取语义。
该原语没有构造 type vector 或节点；后续 vector 和 section 1 见第 6.4 节。
section 2、完整 AST/factory/bootstrap 仍未完成。

### 6.4 Type vector 与 section 1（2026-10-08 UTC）

同一 owner 新增 `grow_reader_word_vector`，恢复 `+0x324540` 的有界追加语义：
header 为 begin/end/capacity 三个指针。空间足够时只清零新增单元并移动 end；
空间不足时请求 `max(size + additional, 2 * capacity)` 个 8-byte 单元，清零新增
区间、复制旧元素、发布三个指针后记录旧块 free。闲置容量与旧块内容保持原样。
原生为 void helper，其偶然的 X0 返回不作为语义比较；验证其自然返回、内存和效果。

`run_reader_sections` 通过可选、显式的 `vector_allocate(size)` 服务恢复 section 1
`+0x32298c`。服务提供已映射、对齐且不与保留区域重叠的分配地址；Python 不执行
真实 malloc/free，free 只记录逻辑效果，不 poison/unmap 页。缺少该服务时，type
分支继续明确拒绝；此前 12 项 section 拒绝控制的旧名称和计数保留为历史证据。

Type handler 先核对 count/剩余字节，再调用 slot `+0x18`。每项读取 form `0x60`，
resize state `+0x28` 的 parameter vector 与 `+0x40` 的 result vector，再调用
slot `+0x20`，传入 type index、两组 count/pointer。缩小时只改 end；count=0 仍保留
容量，但传给 callback 的 pointer 为 NULL。值仅接受 -5..-1 与 -17..-16，存为
符号扩展的 64-bit word。`-21` 前缀会消费第二个 i32，随后拒绝；第二个值正负、
截断或缺失都经过实际 native 对照，没有假定标准类型格式兼容性。

两个基址各 51 个 standalone vector 控制、186 个 core/type 控制，共 102 / 372 项。
Type 其中 368 项为合成输入，4 项为独立 Python XOR 提取的实际 ELF section 输入：
section 1 单独及与 3/7/12 组合。真实 type payload 为 102 bytes、含 16 个定义；
单独每基址 17 次 callback，组合 260 次；各 4 次受控分配、2 次逻辑 free。
fixture imported-count 显式为 0，不证明完整 import/type/AST 语义。

全项比较自然返回、guest 输入/输出区的 0xA000 字节、rank globals、每次回调的
全部参数、cursor/end 和当时的两组 type cells，以及分配/free 时的 header 与效果
顺序。覆盖全部 128 种单字节 type 终止值、复用/收缩/重分配、空 vector、冗余
编码、非法类型、截断、回调失败、重复 section 和组合排序。34 项 guard/未恢复
分支拒绝保持原页，其中包括 type 已解析后遇到 import 的整批回滚；这些 guard
不宣称与原生异常/故障路径对照。证据不导出真实类型正文、名称、blob 或内存。

callback 仍为显式纯状态服务，type cells 以不可变值交接；实际 AST callbacks、
真实 allocator boot、wrapper cleanup、完整 reader/factory/B VM/bootstrap 尚未
完成。下一处为 section 2 `+0x322cf8` 的 import，再接其余 handler 和实际 AST。

### 6.5 Section 2 函数与全局变量 import（2026-10-08 UTC）

同一 owner 为 `run_reader_sections` 新增 `enable_function_global_imports=True`，
恢复 section 2 `+0x322cf8` 的 function kind 0 与 global kind 3。默认保持旧调用
行为，明确拒绝 import。未恢复的 table kind 1、memory kind 2 仍拒绝并全页回滚，
包括前面已经成功解析 type 或 function import 的情况。

先读取 count 并检查剩余字节，再逐项读取两个 length/name 和 kind；名称按原生
行为作为不透明字节跨度，不做 UTF-8 校验或复制到正式证据。function 读取 u32
type index，调用 slot `+0x28`，成功后递增 state `+0x90`。global 读取 i32 type，
接受 -5..-1 与 -17..-16，再读取只允许 0/1 的 mutable，调用 slot `+0x40`，成功后
递增 `+0x9c`。两个计数按 uint32 回绕，混排的总 entry index 与各类 imported
index 独立。`-21` 消费第二个 i32 后拒绝；失败不调用该项 callback。

function callback 共八个参数（含 object），使用 X0..X7；global callback 共九个
参数，最后一个位于 caller SP。实际 `+0x323024` 使用 `strb`，因此仅比较 bool
字节，栈槽的其余填充字节不属于该参数。`ReaderCallbackEvent.import_counts`
提供回调发生前的 function/table/memory/global 四个不可变 uint32 值。

两个基址各 127 项，共 **254 项 native/Python 对照**，248 项合成输入与 6 项独立
Python XOR 后的实际 ELF 输入。真实 section 2 payload 为 316 bytes、40 项，含
18 个 function 与 22 个 global。每基址分别验证 section 2 单独、2/3/7/12、
1/2/3/7/12 组合，回调数为 40 / 283 / 300；最后一组 4 次计划分配、2 次逻辑 free。
section 3 的函数 index 已计入前面的 18 个 import，未用 native 节点或快照喂给 Python。
table/memory 初始计数显式设为 19/23，核对这两个未处理计数不被修改。

比较自然返回、guest 输入/输出区的 0xA000 字节、rank globals、每次回调的全部
参数、cursor/end、四类计数、内部名称字节、type cells 和 vector effects。覆盖
空/二进制/非 UTF-8/长名称、冗余编码、截断、非法 kind/type/mutable、计数回绕、
回调失败、部分成功后失败、精确消费、重复和排序。14 个模型 guard/未恢复分支
控制全页回滚；不宣称比较原生故障路径、整个 stack/TLS 或实际 AST callback。
旧 section 的 202/12 和 vector/type 的 102/372/34 均重新通过，JSON 与原证据
逐字节一致。正式证据不发布真实名称、payload、请求、设备信息或会话历史。

callback 仍为纯状态服务，实际 AST/callback/cleanup、真实 allocator、完整 reader/
factory/B VM/bootstrap 未恢复。下一处为 table helper `+0x321844` 与 memory 所需
u64 reader `+0x3249b0`，再接其余 handler 和 parse/root 构建。

## 7. 复现、证据用途与后续验收

私有 `.so` 不纳入仓库；验证器核对样本摘要。从仓库根目录运行：

```text
python -B platforms/bytedance/tomato/python/verify_vm9_jni_A_default_worker_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <A-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_jni_A_worker_stop_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <worker-stop-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_jni_A_worker_exit_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <worker-exit-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_factory_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <factory-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_reader_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_blob_xor_20261008.py --library <private-metasec.so> --output <blob-xor-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_short_descriptor_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <B-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varuint32_20261008.py --library <private-metasec.so> --output <reader-u32-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_sections_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-section-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varint32_20261008.py --library <private-metasec.so> --output <reader-i32-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_types_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-type-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_imports_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-import-evidence.json>
```

A observation ranges 跳过 VM dispatcher 热点，只保留服务、启动/caller/callback 边界。
VM 指令仍原生执行，没有替换结果。各验证器恢复 monkeypatch，同一进程要求串行；
输出仅合成 guest 状态、偏移、计数和比较结果，不导出 native 内存或 selector 正文。

这些证据证明导入/内存依赖、JNI→默认任务→cleanup/exit 控制流、once 发布顺序，以及
B 实际 descriptor 生成/发布与短 selector 布局。它们不能证明 fresh Medusa 输出、
服务器认可、全部 OS 析构或独立 Python/Rust signer。

下一步恢复 B reader 的 table/memory import、其余 handler、special custom 和实际 node/callback，随后解析/root 生成，再把原始 JNI /
worker / cleanup 接入独立 Python 启动与真实 allocator/arena/OS 输入。B VM、fresh
签名和线上矩阵仍待通过。无 JVM Rust 下载链路、非空搜索/分页、抖音/起点闭环及
最终 Pages/Actions 搜索下载产品仍未完成。
