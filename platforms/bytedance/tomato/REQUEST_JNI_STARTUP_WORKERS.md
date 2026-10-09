# 原始 JNI 返回、同次 worker 析构与 B factory / descriptor 发布

记录日期：2026-10-07 UTC。文件名沿用本机试验标签 `20261008`；标签不是新增的 UTC 日期。
2026-10-08 UTC 追加 reader u32 原语的 258 个差分与 7 个回滚控制，见第 6.1 节。
2026-10-09 Asia/Shanghai 追加实际 AST/清理的 308 个差分与 54 个回滚，见第 6.12 节。
同日追加 data record 创建/追加的 148 个对照与 105 个回滚，见第 6.14 节。
同日追加 data payload 的 104 个 AST 对照、34 个 length 参数对照与 30 个回滚，见第 6.15 节。
同日追加 data expression/tree 的 148 个对照与 36 个回滚，见第 6.16 节。
同日追加 element 回调/嵌套清理的 282 个对照与 159 个回滚，见第 6.17 节。
同日追加 element 结果类型/嵌套表达式的 230 个对照与 133 个回滚，见第 6.18 节。
同日追加 section dispatcher 与部分 handler 的 202 个对照、12 个回滚，见第 6.2 节。
同日追加有符号 i32 原语的 1336 个对照、10 个回滚，见第 6.3 节。
同日追加 vector/type 的 102 / 372 个对照、34 个回滚，见第 6.4 节。
同日追加 function/global import 的 254 个对照、14 个回滚，见第 6.5 节。
同日追加 u64 的 1438 个对照/10 个回滚、table/memory 的 234 个对照/15 个回滚，见第 6.6 节。
同日追加 section 4/5 定义的 266 个对照、18 个回滚，见第 6.7 节。

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
| B 实际 AST callback / 临时清理差分 | 308 | 两个基址各 154 项；实际 vtable 执行，32 项使用真实 ELF 类型输入 |
| B 实际 AST callback / 清理保护回滚 | 54 | slot/relocation、未知 ownership、别名、循环、缺页及资源限制，全页不变 |
| B data record 容量预留/搬移/析构 | 176 / 30 | 两个基址，合成嵌套 ownership、反向搬移与非 deleting 析构 |
| B data record 创建/追加 | 148 / 105 | 两个基址，合成 flags/u32/容量/释放组合，字段断言与全页回滚 |
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
| B reader u64 原语差分/回滚 | 1438 / 10 | 两个基址各 719 项；两种前缀的第十字节全值、失败输出写入语义和 guest 输入/输出区一致 |
| B reader element/data 与 expression 对照/回滚/abort 边界 | 450 / 33 / 16 | 444 项合成、6 项含真实 ELF data；非空元素列表仅观察 abort 调用边界 |
| B reader 特殊 custom 元数据对照/回滚 | 860 / 32 | 850 项合成、10 项真实 ELF custom；含两个全部实际 section 组合 |
| B reader table/memory import 差分/回滚 | 234 / 15 | 228 项合成输入、6 项实际 function/global 输入加合成 limits；19 字节 descriptor 与回调时状态一致 |
| B reader section 4/5 定义差分/回滚 | 266 / 18 | 260 项合成输入、6 项实际 function/global 输入加合成定义；数量/条目回调、索引回绕与 19 字节 descriptor 一致 |
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
- [独立 Python reader u64 原语](evidence/vm9_alternative_reader_varuint64_fresh_20261008.json)
- [独立 Python table/memory import](evidence/vm9_alternative_reader_import_limits_fresh_20261008.json)

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

### 6.6 U64 与 table/memory import（2026-10-08 UTC）

`read_reader_varuint64` 独立恢复 `+0x3249b0`。最多消费十字节，接受冗余编码；
第十终止字节只允许 0/1，其他终止值返回 0 且不访问输出地址。截断或十个连续
continuation 则返回 0 并清零 8 字节输出。两个基址各 719 项，共 **1438 个对照、
10 个 guard/回滚**，包含 `80`/`ff` 两种九字节前缀下的全部 256 种第十字节。
覆盖各宽度边界、截断、尾随字节、输入/输出别名及失败时未映射/null/顶端输出。
比较 guest 输入/输出区的 0xA000 字节；地址回绕和缺页 guard 不作为原生故障对照。

`run_reader_sections` 新增 `enable_table_memory_imports=True` 和显式
`import_scratch_address`。工作区须映射 32 字节、8 字节对齐，且不与 input/state、
u32 scratch、现有 type vector 或后续计划分配重叠。前 19 字节暂存 limits，末尾
8 字节供 u64 读取；`ReaderCallbackEvent.import_limits` 从暂存内容读取并冻结为
`(minimum, maximum, has_maximum, flag_bit1, flag_bit2)`。未启用时，旧 API 仍拒绝
table/memory。function/global 的启用开关保持独立；本阶段仍使用纯状态 callbacks。

Table 使用 `+0x321844` 路径：i32 type 仅接受 **-21/-17/-16**，其中 -21 直接作为
type，不消费第二个 i32。flag 只接受 0/1/4/5，minimum 与可选 maximum 用 u32
读取并零扩展成 64-bit 字段；位 2 被忽略。Memory 使用 u64 读取两界限，接受相同
flag 范围，将位 2 写入 descriptor 的 `+18` 字节。两条路径都拒绝位 1，`+17`
字节为 0；`+16` 表示有 maximum。这里记录字节行为，未据此宣称标准格式兼容。
parser 在纯状态服务下接受 minimum 大于 maximum，实际 AST 是否拒绝尚未验证。

Table slot `+0x30` 共九参数，最后一个 descriptor pointer 从 caller SP 读取完整
8 字节；memory slot `+0x38` 共八参数，pointer 在 X7。验证器仅把这个临时原生栈
指针转换为模型工作区指针，并核对全部 **19 字节 descriptor 内容**、其余参数、
名称字节、cursor/end、四类 import count、type cells 和 vector effects。未宣称
临时栈地址相同，未比较整个 stack/TLS，也未执行实际 AST callbacks。成功 callback
之后，对应 table/memory uint32 count 才递增，并按 uint32 回绕。

两个基址各 117 项，共 **234 个对照、15 个拒绝/回滚**；228 项为合成输入，6 项
把独立 Python XOR 后的实际 function/global 输入与两个合成 table/memory 项组合。
样本没有真实 ELF table/memory import，相关实际输入对照数明确为 **0**。每基址
import 单独、2/3/7/12、1/2/3/7/12 组合分别有 42 / 285 / 302 次 callback，四类
import count 为 18/1/1/22；完整选取组合有 4 次计划分配、2 次逻辑 free。失败、
非法类型/flags、各界限截断/溢出、四类混排、回调拒绝、计数回绕和临时区重叠均覆盖。

旧 section 202/12、function/global import 254/14 与 vector/type 102/372/34 回归
全部通过，JSON 与原证据逐字节一致。首轮并发的 vector/type 回归在 600 秒限时
结束，确认没有残留进程后单独重跑，314.28 秒完成全部控制；未修改解析逻辑。
实际 AST/callback/cleanup、真实 allocator、其余 sections/special custom 和完整
reader/factory/B VM/bootstrap 仍待恢复，完整 signer 与线上矩阵尚未完成。

### 6.7 Section 4/5 table/memory 定义（2026-10-08 UTC）

`run_reader_sections` 新增独立的 `enable_table_memory_sections=True`，复用已有
32 字节 `import_scratch_address` 和 table/memory descriptor 解析。此开关默认
关闭，与两类 import 开关独立。启用定义不会启用 import，启用 import 也不会启用
定义；单独解析定义不要求启用 import。未启用及 guard/服务异常仍全页回滚。

原始 dispatcher 和指令核对修正了私有交接的地址错位：`+0x323108` 是已恢复的
section 3，section 4 实际为 **`+0x3231e4`**，section 5 为 **`+0x3232dc`**。
section 4 先读取 u32 count、检查剩余字节，调用数量 slot `+0x58`；逐项复用
`+0x321844` 的 table 语义，调用 slot `+0x60`，参数是 import table count 加
entry index（uint32 回绕）、type（符号扩展至 uint64）和 descriptor pointer。
section 5 的数量/条目 slots 是 `+0x68` / `+0x70`，逐项使用同一 u64 memory
界限解析，索引加 import memory count。空定义也发送数量回调；成功的定义回调
不递增任何 import count。callback 拒绝或解析失败提交原生可见的部分 parser 状态。

Table 仍接受 -21/-17/-16，界限使用 u32 零扩展；-21 不消费第二个 i32。Memory
界限使用 u64。两者 flags 仍接受 0/1/4/5，table 忽略位 2，memory 把它保存在
descriptor offset 18。`ReaderCallbackEvent.import_limits` 也在定义条目回调冻结
19 字节暂存内容。仅转换临时原生 descriptor 指针，比较全部内容与其余参数，
不宣称模型工作区等于原生栈地址，也不比较整个 stack/TLS。实际 AST 规则仍未知。

两个基址各 133 项，共 **266 个 native/Python 对照、18 个拒绝/回滚**。260 项
为合成输入，6 项把独立 Python XOR 后的真实 function/global 输入与合成定义组合。
原样本既没有 section 4/5，也没有 table/memory import，真实定义输入对照数为
**0**。组合 2/4/5、2/3/4/5/7/12、1/2/3/4/5/7/12 每基址分别 46 / 289 / 306
次回调，import counts 为 18/0/0/22；最后一组 4 次计划分配、2 次逻辑 free。
四类合成 import 后的定义也验证了索引从 1 起算，且保留四个 import counts。

覆盖缺失/截断/溢出 count、type、界限、非法 flags、冗余编码、min 大于 max、
空数量回调失败、条目回调失败、前项成功后解析失败、精确消费、重复与排序拒绝，
以及 scratch 缺页/重叠、计划 type 分配重叠和 callback 异常的全页回滚。独立
开关与旧 API 默认关闭经过检查；最小用例先观察到原生接受而旧 Python handler
拒绝，随后通过相同对照。allocator/free 与 callbacks 仍是显式服务。

旧 section 202/12、function/global import 254/14、table/memory import 234/15、
vector/type 102/372/34 均重新通过，四份 JSON 与此前正式证据逐字节一致。
本轮同时最多运行两个 native 验证进程，均在各自限时内自然结束。

证据见 [section 4/5 对照](evidence/vm9_alternative_reader_table_memory_sections_fresh_20261008.json)。
当时下一处为 section 6 `+0x323464`，其恢复结果见下节。随后 instruction/data/special custom、实际
AST/callback/cleanup 和 parse/root 构建。完整 reader、factory、B VM、Python
bootstrap、独立 signer 与线上矩阵仍未完成。

### 6.8 有符号 i64 与 section 6 初始化表达式（2026-10-08 UTC）

同一 owner 的 `read_reader_varint64` 恢复 `+0x324f6c`。最多十字节，接受冗余编码；
第十终止字节只接受 **0/127**。截断、十个 continuation 或非法终止均返回零，
不访问也不修改输出。两个基址各 740 项，共 **1480 个原生/Python 对照、10 个
保护/回滚检查**，包括两种九字节前缀下全部 256 个第十字节、符号宽度边界、
冗余编码、截断、尾随字节、输入/输出别名及失败时未映射输出。扫描回绕、缺页
和输出越界按模型保护边界拒绝，不宣称原生故障路径一致。

`run_reader_sections` 新增默认关闭的独立 `enable_global_section=True`，恢复
section 6 `+0x323464`。`global_scratch_address` 须映射 16 字节、8 字节对齐，
与 input/state、u32/import scratch、现有和未来 type storage 不重叠。前八字节
作为显式 caller local/result 初值，后八字节用于表达式临时读取；启用 global
不启用 imports 或 section 4/5，反向亦同。保护和服务异常全页回滚，普通解析/
callback 拒绝提交原生可见的部分 parser 状态。

Section 6 读取 u32 count 并检查剩余字节，即使 count 为零也调用 `+0x78`。
条目 type 接受 -5..-1、-17/-16；-21 消费第二个 i32 后拒绝，mutable 仅接受
0/1。回调依次为 `+0x80(index, sign-extended type, mutable)`、`+0x88(index)`、
初始化表达式 callbacks、`+0x90(index, final uint64 bits)`。index 加 state
`+0x9c` 的 imported global count 并按 uint32 回绕；定义不递增 import count。

表达式 `+0x32365c` 跟随 **GOT `image+0x3750b0` 的实际指针**读取操作码 kind，
不把该样本 relocated table 地址当作固定 owner。每个 opcode 先调用 `+0xC0`
发送 kind 的 uint32 字值。kind 1 是 end（`+0xC8`），2/3 是 i32/i64
（`+0xE0/+0xE8`），4/5 是原始四/八字节位值（`+0xD0/+0xD8`）。i32 和四字节
常量的最终结果零扩展至 uint64。未映射的非零普通 opcode 使用 `-opcode`；
`FC/FD/FE` 消费 u32 subopcode 并发送
`-((opcode << 9) | min(subopcode, 511)) & 0xffffffff`，随后拒绝不支持的 kind。
允许多个常量，最后一个成功常量保留到 end；缺少 end 失败。独立
`max_initializer_ops` 限制表达式操作数，与 global entry 上限分开。

**End-only 表达式不写结果。** Caller 逐项先仅写 type 的低四字节，高四字节保留
此前 local 内容。验证器在原生 section 6 入口、栈调整前为该 local 注入明确的
八字节合成 ABI 初值，Python 使用同值。覆盖不同初值以及 i64 后接 end-only；
这不证明自然栈初始化，也不比较整个 stack/TLS。实际 AST callbacks 仍为纯状态服务。

两个基址各 195 项，共 **390 个原生/Python 对照、26 个保护/回滚检查**；380 项
纯合成，10 项包含独立 Python XOR 后的真实 section 6。实际 payload 133 字节、
22 个定义，均使用 i64 常量；单独 section 6、2/6、2/3/6/7/12、1/2/3/6/7/12
每基址分别 **155 / 195 / 438 / 455** 次 callback。最后一组有 4 次计划分配、
2 次逻辑 free，import counts 为 18/0/0/22。另有两项把真实选取组合加上合成
section 4/5，459 次 callback；样本仍没有真实 section 4/5。

合成覆盖各 type/mutable、count/type/常量截断和非法终止、所有表达式 callback
拒绝、多常量、end-only、非法 opcode、prefix 截断和 subopcode 上限 511、
GOT table 重定位及条目覆写、重复/排序、uint32 索引回绕与服务异常。旧 section、
两类 imports、section 4/5 和 vector/type 回归重新通过，五份 JSON 与既有证据
逐字节一致。最小 i64 和 section 6 在生产修改前先取得原生成功/Python 缺失的
失败对照，恢复后相同控制通过。最多同时运行两个重型 native 验证器。

证据见 [i64 对照](evidence/vm9_alternative_reader_varint64_fresh_20261008.json)和
[global/initializer 对照](evidence/vm9_alternative_reader_globals_fresh_20261008.json)。
剩余 instruction/data/special custom、实际 AST/callback/cleanup、parse/root、
完整 reader/factory/B VM/bootstrap、独立 signer 和线上矩阵仍未完成。

### 6.9 Section 10 元数据、局部类型与指令字读取（2026-10-08 UTC）

同一 owner 通过默认关闭的独立 `enable_code_section=True` 恢复 section 10
`+0x323ca8`。原始 dispatcher 和实际指令确认了边界；旧私有反编译曾把这个
入口误并入 section 9，因此本轮不沿用其错误的函数归属。修改前，空 section 与
单字函数体先取得原生完成、旧 Python handler 拒绝的最小失败对照。

读取 u32 body count 后先写 state `+0xa8`，随后检查剩余字节和 state `+0xa4`
的 function count 是否一致。空 code section 没有数量回调。逐体读取 body size、
第二个 u32 元数据和 local group count；先调用 `+0xb0(groups)`，再调用
`+0xa8(index, offset, remaining_body_bytes, metadata)`。index 加 imported function
count，按 uint32 回绕；offset 相对本 section 的 count 起点，remaining body
bytes 是声明 body size 减去读取这两个头字段的字节数，按 uint32 回绕。

逐组读取 local count 与 signed type，发送 `+0xb8(group_index, count, type)`。
local counts 的累计和大于 uint32 时，在读取该组 type 前拒绝。Type 符号扩展
至 uint64，只接受 -5..-1、-17/-16；-21 消费第二个 i32 后拒绝。接着用
`+0x168(uint32_bits)` 顺序发送原始四字节指令字，要求最终 cursor 精确等于
body end，最后调用 `+0xf8(index, remaining_body_bytes)`。这个长度值包含 local
groups 的编码字节，后续并不再扣减。第二个 u32 的业务含义仍未确认。

**这里读取指令字，不执行指令。** Native 使用 section limit 而非 body end
检查四字节是否可读；因此可能跨过声明 body end 再拒绝。若 section 剩余不足
四字节，native 发送零字、保持 cursor，并重复直到 callback 拒绝。合成控制
在首个或第三个零字拒绝，核对不推进的部分状态。模型的 `max_code_words`
默认 65536，按整个 code section 计算，包含这些不推进的重试；超过预算则
明确拒绝并全页回滚，避免纯成功 callback 无限循环。缺页、服务异常、未启用
和 traversal guards 同样全页回滚；普通解析/callback 失败提交部分状态。

两个基址各 114 项，共 **228 个原生/Python 对照、15 个保护/回滚**，其中 222
项纯合成、6 项含独立 Python XOR 后的真实 ELF code。实际 payload **218682
字节、121 个 body、54533 个指令字**；样本 code 的 local groups 均为零，非空
groups 用合成输入证明。单独 code 的 function count 121 是显式状态输入；
与真实 section 3 组合时从函数 section 读取。10、3/10、1/2/3/6/7/12/10
组合每基址分别 **54896 / 55017 / 55351** 次 callback，code slots 均为
121 次 `+0xb0`、121 次 `+0xa8`、0 次 `+0xb8`、121 次 `+0xf8`。完整选取
组合有 4 次计划分配、2 次逻辑 free，import counts 为 18/0/0/22。

验证器把输入放到已映射的 ELF blob 工作区，避开小型 guest state/stack 区，
逐字节比较完整选取输入；仍核对 guest 的 0xa000 字节、rank globals、全部
callback 参数/状态/计数/type cells 和 vector effects。纯 code 用例不启用
global 验证模式；只有实际含 section 6 的组合注入已说明的八字节合成 local
初值。输出不发布真实元数据、指令字或名称，不比较整个 stack/TLS。

合成控制覆盖 count 不一致、各字段截断/冗余编码、全部有效类型、非法/扩展
类型、locals 累计溢出、body end 越界与长度回绕、各 callback 拒绝、跨 body
预算、索引回绕、重复/排序和独立开关。旧 global、type/vector、section 和
import limits 回归重新通过，四份 JSON 与既有证据逐字节一致。

证据见 [code section 对照](evidence/vm9_alternative_reader_code_fresh_20261008.json)。
Section 9/11 后续进展见第 6.10 节；special custom、实际 AST/callback/cleanup、
指令执行与 parse/root、完整 reader/factory/B VM/bootstrap、独立 signer 和线上矩阵仍未完成。

### 6.10 Section 9/11 与独立 expression helper（2026-10-08 UTC）

同一 owner 新增默认关闭的独立 `enable_element_section` / `enable_data_section`，
恢复 section 9 `+0x323a04` 的空元素列表和 section 11 `+0x323fb4` 的 data 段。
修改前，原生空 section 9 和单个 passive data 正常返回，旧 Python 拒绝对应
handler，随后最小实现通过同一对照。两类 section 使用独立的已映射、八字节对齐、
不重叠 `expression_scratch_address`；保护现有和后续 type storage 以及其他工作区。

它们调用的 `+0x3215f0` 与 global initializer `+0x32365c` 不同：从 GOT
`image+0x3750b0` 取得 opcode 表，每次先发送 `+0xC0(kind)`，kind 0 发送
`+0xF0()` 后继续，kind 1 发送 `+0xC8()` 并结束；kind 2/3/4/5 对应
`+0xE0(i32 bits)` / `+0xE8(i64 bits)` / `+0xD0(raw f32)` / `+0xD8(raw f64)`。
此 helper 不写结果字，也不要求 global 的合成 caller-local 初值。非零未映射 opcode
和 FC/FD/FE subopcode 仍按 uint32 kind 编码并拒绝不支持的 kind。
`max_expression_ops=4096` 按每个 expression 限制；超限或缺页/服务异常整页回滚。
普通解析或 callback 拒绝保留原生可观察的部分状态。

Section 9 先发 `+0x100(count)`，flags 只接受 0..7，低两位等于 2 时读取 table
index，发送 `+0x108(index,table_index,flags)`；bit 0 为零时使用
`+0x110(index)` / expression / `+0x118(index)`。低两位非零且 bit 2 为零
时只接受 elemkind byte 0；bit 2 为一时读取 signed type，只接受 -21/-17/-16，
其中 -21 不读取 secondary。低两位为零时使用 -16。随后发送
`+0x120(index,type uint64 bits)` 与 `+0x128(index,element_count)`。
非空列表在原生 `+0x323ca4` 调用 `abort`（PLT `+0x347f50`），不是普通解析失败。
两个基址、全部八种 flags 共 **16 项**到达该调用边界；只拦截边界，不执行 abort。
Python 对照前序 callback 参数/cursor，然后明确拒绝并保持所有页面不变。

Section 11 的 segment count 与 state `+0xac` data count 比较，0xffffffff 为未指定；
没有数量 callback。Flags bit 1 为一时读取 memory index，发送
`+0x140(index,memory_index,flags)`；bit 0 为零时使用
`+0x148(index)` / expression / `+0x150(index)`。读取 u32 payload size，
检查 section limit 后先推进 cursor，再发送
`+0x158(index,payload_pointer,payload_length)`。本批旧 status-only parser/oracle
遗漏实际第三项 length；旧证据不能证明完整 ABI。修复及新增参数对照见第 6.15 节。
Payload 内容保持 opaque，验证器比较完整字节。
索引从零开始，不加 function/table/memory import count。

两个基址各 225 项，共 **450 个原生/Python 对照、33 个保护/回滚**；444 项合成，
6 项含独立 Python XOR 后的真实 ELF data。真实 section 11 为 **4001 字节、3 段**，
payload lengths **3632/352/0**。11、12/11、1/2/3/6/7/12/10/11 组合每基址
**18/19/55369** 次 callback；完整组合保持 4 次计划分配、2 次逻辑 free，
import counts 18/0/0/22、121 个 code body 和 54533 个原始指令字。
样本没有 section 9，实际 ELF element 输入对照为 0。

覆盖 flags、索引、reference types、各种常量、kind 0、非法/prefixed opcode、
GOT 重定位/覆写、截断、数量/长度不一致、callback 拒绝、排序/重复、独立开关、
scratch 别名/缺页、预算、现有及后续 type storage 冲突。只在含 section 6 的完整
组合注入 global 已说明的合成八字节初值，不发布真实 payload 或名称，不比较整个
stack/TLS。旧 globals、code、sections、import limits 回归重新通过，四份 JSON
与既有证据逐字节一致。

证据见 [element/data 对照](evidence/vm9_alternative_reader_segments_fresh_20261008.json)。
Special custom 后续进展见第 6.11 节。实际 AST/callback/cleanup、指令执行与 parse/root、完整 reader/factory/
B VM/bootstrap、独立 signer 和线上矩阵仍未完成。

### 6.11 Section 0 特殊 custom 元数据（2026-10-08 UTC）

同一 `run_reader_sections` owner 新增默认关闭的
`enable_special_custom_sections`。五类最小输入在修改前原生正常返回、Python
明确拒绝，修改后同一对照通过。独立、已映射、八字节对齐的
`custom_scratch_address` 保护 input/state、其他 scratch、现有与后续 type
storage、lazy decoder 源/目标、opcode 表的 GOT 指针及启用的 expression opcode 表。表重定位到 custom
工作区或直接覆盖 GOT 指针的负控制先复现旧代码错误放行，再修复；表尾部分重叠也回滚。
`max_custom_records=4096` 按每个 custom section 汇总子段、列表条目和内部数对，
新 section 重置预算，超限明确拒绝且所有 model pages 不变。

`+0x322700` 的名称匹配先处理长度 6/8 的 dylink/dylink.0，再判断 reloc 前缀，
最后处理长度 7/15 的 linking/target_features。长度 7/15 的 reloc 不应写对应
marker 的懒解码状态。所有特殊处理器均不发送 AST callback；无论成功或解析
失败，state `+0x8c` 恢复原 flag。已知子段失败也恢复外层 limit；普通解析失败
提交原生可观察的部分 cursor/state，guard 失败回滚。

| 类型 / 原生入口 | 已恢复的元数据规则 |
| --- | --- |
| dylink / `+0x321f08` | 四个 u32，随后字符串数量及长度/opaque span |
| dylink.0 / `+0x321b2c` | u32 tag/size 子段；tag 1 为四个 u32，2 为字符串列表，3 为字符串/u32，4 为两个字符串/u32 |
| target_features / `+0x322060` | 数量、每项一个不校验的 prefix byte、长度/opaque span |
| reloc 前缀 / `+0x321990` | section index、数量及 kind/offset/index；数量先检查剩余字节，部分 kind 另读 signed i64 addend |
| linking / `+0x322130` | 版本必须为 2；tag 5/6/7/8 分别解析 segment info、init pairs、comdat 与 symbol records |

Reloc 无 addend mask 为 `0x7f81c34c7`，signed i64 mask 为 `0x63cb38`；kind
大于 34 或未命中任一 mask 时失败。Linking tag 5 alignment 小于 32，tag 6
每项两个 u32，tag 7 每项字符串/flags/内部数量及 u32 数对。Tag 8 的 symbol
kind 0/2/4/5 读 index，`flags & 0x50 != 0x10` 时读 name；kind 1 读 name，
bit 4 未设置时再读三个 u32；kind 3 读一个 u32；kind 大于 5 只消费 kind/flags。
两种子段处理器均跳过未知 tag，并要求已知 tag 准确消费到声明末尾。

私有反编译把 linking 的 abort 后相邻 section 0 函数误并入结果，原始 Capstone
确认函数边界。`+0x3226fc` 的 abort 条件与前面的 kind mask 判定矛盾；**94 项**
动态对照到达 `+0x3225c8` 再检查，均保持 kind 0/2/4/5，本批没有到达 abort。
这是本批观察，不构成全局不可达证明。

两个基址各 430 项，共 **860 个原生/Python 对照、32 个保护/回滚**：850 项合成，
10 项包含独立 Python XOR 后的真实 ELF custom。三个 payload 分别为
**1758/3240/177 字节**；分别、三个 custom 组合以及全部实际 section 组合均通过。
全部实际组合顺序为 **1/2/3/6/7/12/10/11/0/0/0**，每基址匹配 **55369** 次
callback、4 次计划分配、2 次逻辑 free、import counts 18/0/0/22、121 个 body、
54533 个原始指令字及 data lengths 3632/352/0。仅含 global 的组合使用此前已
说明的合成 caller-local 初值；custom 不增加 AST 回调。Opcode 表保护增加后，
两个完整组合重跑结果不变。

覆盖各类截断、子段长度、未知 tag、alignment、symbol kind/flags、全部 0..34
reloc 类型及非法类型、i64 addend 边界、名称匹配顺序、flag 恢复、记录预算和
scratch 别名/缺页。全项核对返回、guest/input、rank/custom decoder memory、
callback 参数/状态/type cells/limits 与逻辑分配效果；不比较整个 stack/TLS，
不发布真实名称/正文。旧 globals/code/segments/sections/import limits 回归全部
通过，五份新 JSON 与既有证据逐字节一致。证据见
[custom 对照](evidence/vm9_alternative_reader_custom_fresh_20261008.json)。
实际 AST/callback/cleanup、指令执行与 parse/root、完整 reader/factory/B VM/
bootstrap、独立 signer 和线上矩阵仍未完成。

## 6.12 实际 AST callback 与临时清理（2026-10-09 Asia/Shanghai）

同一 `vm9_alternative_startup.py` 增加三个独立有界入口：
`run_reader_ast_callback`、`destroy_reader_ast_type_node`、`cleanup_reader_callback`。
**308 个原生/Python 对照、54 个保护/回滚**通过；两个基址各 154 项，276 项
合成、32 项使用独立 Python XOR 后的真实 ELF 类型输入。原生调用从 fresh ELF
重定位后的实际 vtable 取出地址，每次函数自然返回到合成驱动并恢复 SP。
原生节点的间接析构调用也实际执行。仅 malloc/free 和 memcpy/memset 是显式
主机服务；此次没有把 AST callback 替换成状态服务。

| Slot / 入口 | 已恢复的行为 |
|---|---|
| +18 / +31b6b0 → +31e75c | 预留 64 字节 type 容量，不增加 size；容量足够时不改 header |
| +20 / +31b6d0 | 忽略 index，复制 params/results 两个 u64 输入到临时 vector，再复制到 owned type node；释放临时 results/params |
| +a0 / +31d6d4 | 向 output+c0 追加 u32 start index；扩容为 max(size+1, capacity×2) |
| +b0 / +31d974 | 写 callback+78 的 u32 local group 数量，清零 +7c word |
| +168 / +31e5d8 → +32136c | 向 output+108 byte buffer 追加四字节，保留非四字节对齐的旧长度 |
| +321260 | 64 字节 type node 的非 deleting 析构：先 results，再 params；重置 end 后 free，不释放节点本身 |
| +31b458 / +3202f0 | 五组临时节点反向析构/释放，两棵树按 left/right/payload/node 后序释放，最后清理 byte buffer |

Type 扩容反向移动旧节点，清零旧节点的六个 owned vector 指针，保留 index，
不复制 padding；先发布新 header，再反向析构旧节点并 free 旧块。Type entry
新节点的 index 字段为零。Start 扩容在发布/free 前写入新 word；raw-word helper
先 zero-fill 和发布扩展，再由 caller 写 word。所有 w-register 参数按 u32 截断。

临时列表按 callback+e0/c8/b0/98/80 的 40/24/40/48/64 字节 stride 清理；
支持实际 +372590/+372568/+372540/+372518/+3724f0 节点 vtable。两棵树按
callback+68、+50 的顺序处理，使用有界 64 字节节点和 u64 payload vectors。
Buffer 为 callback+30。原生清理留下 dangling begin/capacity/tree root，模型
保留相同行为，调用者只能消费 free 效果一次。独立 64 字节记录列表与输出 AST
仍由外层 owner 保留；`+31b360` 的完整 wrapper 清理尚未恢复。

每个结果保存 allocation/destruction/free 逻辑效果及该时刻的容器内存。
全部 guest 对象、输入与分配内容（含 padding）、每次副作用的容器状态和顺序
一致；不比较整个 native stack/TLS。分配服务只计划已映射、对齐、互不覆盖的
地址，不修改内存或真实分配；free 不 poison/unmap，不证明 allocator boot。

Callback 必须使用实际 vtable、+8 helper 为零，+18 指向 0x120 字节输出 header
前缀，+20 等于 output+108。本批仅 type/start/raw-word 容器可以持有存储；其它
输出容器需要保持空。Local group count 入口不访问 output。`max_nodes=4096` 限制节点
和新增 type capacity；`max_vector_bytes=16*1024*1024` 限制每个 buffer。
显式 `reserved_regions` 保护其它借用存储；树循环、共享子树/列表、未知 vtable、
错误 relocation、缺页、别名和超限均全页回滚。非法 slot 类型、attached parser
指针及未恢复输出容器三个保护先复现 RED，再收紧入口；最初四个行为 RED 来自
状态服务缺少实际 reserve/type/start/cleanup 写入。
最终审查再复现两个错误 slot 绑定，并增加 requested-slot relocation 校验；
完整 308 项对照和 54 项保护重跑通过。旧 type/vector 102/372 个对照与 34 个
回滚、section 202 个对照与 12 个回滚全部通过，两份新 JSON 与既有证据逐字节一致。

这批实际输入由独立 fixture 解码得到类型参数，再驱动实际 callback；不构成完整
reader AST 对照，不导出真实类型内容或原生内存快照。五个 callback 尚未接入
`run_reader_sections`。本批之后，+160 的 176 字节节点移动由第 6.13 节恢复；其它 AST callback、
wrapper/parser composition、parse/root、完整 reader/factory/B VM/bootstrap、
独立 signer 和线上矩阵仍未完成。证据见
[实际 AST/清理](evidence/vm9_alternative_ast_fresh_20261009.json)。

## 6.13 Data record 容量预留、搬移与析构（2026-10-09 Asia/Shanghai）

同一 `vm9_alternative_startup.py` 的 `run_reader_ast_callback` 增加 slot `+160`，
并增加 `destroy_reader_ast_data_record`：**176 个原生/Python 对照、30 个回滚**。
两个基址各 88 项，全部合成；实际 ELF 只提供原始函数与重定位后的 vtable，
输入不来自原生快照。Slot `+160 → +31e5b4 → +320fb0` 自然执行，单记录
析构调用实际 `+2cc1ec`；每次返回核对 SP。修改前两项原生成功/Python 缺失
行为复现 RED，修改后 GREEN。此次不恢复 data record 创建。

| 偏移 | 176 字节记录中已确认的布局 |
|---|---|
| +00 | byte payload vector |
| +18 / +60 / +88 | u64 标量 |
| +20 | 内嵌 64 字节 type node，实际 vtable +3724f0 |
| +28 / +68 / +90 | u32 标量 |
| +30 / +48 | 内嵌 type params/results u64 vectors |
| +70 | 16 字节元素 vector |
| +98 | 56 字节子记录 vector；每个子记录 +10 是 owned u64 vector |

56 字节子记录的 00/28 u64 与 08/30 u32 在 `+31fdb4` 中按标量复制。
该复制路径的 +10/+18/+20 为 u64 vector header；析构读取其 begin，重置 end
后 free。其余字段不新增 ownership。未初始化的 spare capacity 不作为活动节点。

Reserve 按 u32 count 请求 `count×176` 容量，容量足够时不改 header，始终不增加
size。`+320e78` 反向移动活动记录，转移 00/30/48/70/98 五组 vector 并清零
源端，复制六个标量、设置目标 type vtable；2c/6c/94 padding 保留分配区初值。
先发布新 header，再反向调用旧记录 `+2cc1ec`，最后 free 旧块。

单记录析构倒序释放每个 +98 子记录的 +10 payload，重置 +a0 并释放子记录块；
随后清理 +70 vector，重置内嵌 type vtable，依次清理 results（+48）、params
（+30）、byte payload（+00）。每个非空 begin 的 vector 在 free 前把 end 重置为
begin；begin/capacity 留下 dangling 值，不释放 176 字节记录自身。原生 void X0
不作为返回协议。逻辑效果只能消费一次，不得把已析构存储再次作为活动对象。

对照覆盖空/非空、容量足够/扩容、非空零容量、u32 截断、重复 reserve、
空而已分配/丰富/混合嵌套 vectors、倒序析构、padding、保留 data 的临时 callback
清理。全部 guest 前 0xa000 字节、效果顺序及每个效果时的根 owner 内容匹配；
不比较整个 native stack/TLS。`output+f0` 加入共用 ownership graph，保护其它
活动输出、临时节点、树、borrowed regions、image 和未来分配的存储。
`max_nodes=4096` 汇总 type/data/子记录/临时树节点，并限制新增 type/data
容量；`max_vector_bytes=16*1024*1024` 限制每个 vector 和分配。错误 slot/type
绑定、部分记录/容量、反向/未对齐指针、共享/重叠/缺页、无分配服务与超限拒绝，
全部 model pages 不变；非法原生内存路径不作安全模拟。
审查还先复现非空、零容量但地址未映射的 vector 被接受并产生 free 的 RED，
随后共用 claim 要求空存储指针也位于映射页内；旧的合法非空零容量控制保持通过。
修复后完整重跑 176/30，全部原生正向结果与首次完整运行一致。旧 AST 308/54、
type/vector 102/372 与 34 个回滚、section 202 与 12 个回滚通过；三份新回归
JSON 与既有证据逐字节一致，parser 函数及无关 AST 方法未改。

Callback 仍必须 detached（+8 为零），使用实际 vtable、0x120 字节输出 header
前缀和一致的 raw target。仅 type/start/data/raw-word 容器可持有已验证存储。
分配服务仍为纯地址计划，free 不 poison/unmap；allocator 异常/boot、其余
AST callback、data record 创建、attached parser/wrapper、parse/root、完整
reader/factory/B VM/bootstrap、独立 signer 和线上矩阵未完成。
本批旧 AST 验证器的未恢复 slot 保护当时转到 +158；后续恢复 +158 后改为
+148（见第 6.15 节），旧证据的计数与验证范围不变。
证据见 [data reserve/析构](evidence/vm9_alternative_ast_data_fresh_20261009.json)。

## 6.14 Data record 创建与追加（2026-10-09 Asia/Shanghai）

`run_reader_ast_callback` 恢复实际 slot `+140 → +31e1d4`：**148 个原生/Python
对照、105 个保护/回滚**，两个基址各 74 项。全部输入合成，原始 ELF 仅提供
代码/vtable；不使用 native 输入快照。最小空容器创建先复现原生正常返回而
Python 拒绝的 RED，随后实现；空容器/spare capacity/丰富旧记录扩容三项 GREEN。

参数为 `(index,memory_index,flags)`，index 忽略，后两项按 w-register 截断为
u32。分类值为 `(flags&3)==3` 时的 2，否则 `flags&1`；+18 u64 等于分类值与
`memory_index<<32` 的组合。新记录内嵌 type vtable 为 +3724f0，index 0、params
空、results 含一个 owned u64 `0xffffffffffffffff`。+88 u64 为
`0x00000000ffffffff`；00/30/70/98 vectors、60 u64、68/90 u32 清零，
2c/6c/94 padding 保留目标原值。构造/复制的 GOT +375090 必须绑定 +3724e0。

| 阶段 | 原生分配与释放顺序 |
|---|---|
| A / B | allocate 8 原始 results，再由 +31e888 allocate 8 临时 type results；两块均写 -1，然后 free A |
| C | +31eea4 allocate 8 临时 data 内嵌 results，写 -1 |
| D（满容量） | +320c24 allocate max(size+1,capacity×2)×176 新记录块 |
| E | +320d5c → +31eea4 allocate 8 最终 record results，写 -1 |
| 发布与旧块清理 | 扩容反向搬移旧记录并清零源 vectors，发布新 header，倒序 +2cc1ec、free 旧块；spare 仅增加 end |
| 临时清理 | free C，再 free B；原生内联清理不额外 emit destroy |

创建入口复用已验证的搬移/析构/事务 owner。原生使用实际 vtable BLR dispatch，
同一 Unicorn 内连续执行 callbacks、最终 data 析构及临时 callback cleanup；
每次核对 SP 与自然返回。guest 前 0xa000 字节、allocation/destruction/free
顺序及每个副作用时的根 owner 内容与 Python 一致；独立字段断言另外核对所有
新建记录，不依赖原生快照。未比较整个 native stack/TLS。

覆盖 flags 0..7、高字截断、忽略 index、空/有 spare/满容量、丰富/已分配但空/
混合旧 ownership、非空零容量、连续创建、reserve/create 组合、创建后倒序析构、
保留 data 的 callback cleanup。105 个保护包括 slot/GOT/attached/未知 type/
共享 child/部分记录/节点与字节预算/错误参数，并在 growth 的五次分配和 spare
的四次分配逐次检查缺页、未对齐、部分映射、callback/output/旧块/child/borrowed/
image 别名和重复地址。70 项到达第二次或更晚的计划分配才拒绝，所有原页不变；
不执行非法原生内存路径。分配必须纯地址计划；free 是只能消费一次的逻辑效果。

旧 AST **308/54** 和 data reserve/析构 **176/30** 回归通过，两份 JSON 与旧
证据逐字节一致。此次只有 `run_reader_ast_callback` 行为改变；共享 ownership
方法、parser 函数和旧 AST 验证器未改。旧 data 验证 helper 仅增加可选函数绑定，
默认仍校验 slot +160；旧证据中的创建未实现标志描述该历史批次的验证范围。

本批结束时剩余 +148/+150 expression/tree 路径、+158 payload、其它 AST callbacks、attached
parser/wrapper、parse/root、完整 reader/factory/B VM/bootstrap、独立 signer 和
线上矩阵尚未完成。特别是实际 +323fb4 data parser 在 +32415c 向 +158 传入
index/pointer/length，当时 status-only parser/event 省略第三项；后续独立 RED、
payload 与 ABI 修复见第 6.15 节。本批未接入 parser。
证据见 [data 创建/追加](evidence/vm9_alternative_ast_data_create_fresh_20261009.json)。

## 6.15 Data payload 写入与 parser length 参数修复（2026-10-09 Asia/Shanghai）

同一 `vm9_alternative_startup.py` owner 恢复实际 slot `+158 → +31e53c`，并修复
section 11 在 `+32415c` 调用时遗漏的第三项 length。先用最小输入分别取得
parser 参数不匹配、Python 拒绝实际 payload callback 的两个行为 RED；生产修改
后相同入口 GREEN。两个基址各 **52 个 AST 对照、17 个 parser ABI 对照**，
共 **104 / 34 个原生/Python 对照、30 个保护/回滚**。

参数为 `(index,payload_pointer,payload_length)`，index 忽略，length 使用完整
u64。长度为零时原生直接成功，保留原 payload 的 size/capacity/内容，不读 source，
也不要求存在 data record；模型仍执行已有 callback、vtable 和 ownership 预检。
非零时写入 output+f0 的最后一条 176 字节记录，调用 byte-vector helper
`+2db2b4` 调整长度：容量不足时 allocate max(length,capacity×2)，清零新增
长度区、复制旧内容、发布 begin/end/capacity、free 旧块，随后 memcpy payload。
容量足够时只调整 end，并在增长时清零新增字节；最终 payload 覆盖到新长度。

Source 必须是有界、完整映射的 guest span，并与全部 owned storage 分离；
在纯分配计划期间保留该 span，拒绝分配地址与 source（含尾部）重叠。复用已有
事务/ownership owner，不改共享 `_ReaderAstMemory` 方法。Free 仍为逻辑效果，
不 poison/unmap。Length 的高 32 位不截断；超出预算的 u64 长度直接拒绝。
零长度的非法 source/无活动记录、忽略 index、缩短/不变/原容量增长/重新分配、
丰富旧 ownership、reserve/create/write 连续组合及最终析构/临时清理均已对照。

**98 项 AST 输入合成、6 项使用真实 ELF payload；32 项 ABI 输入合成、2 项
使用真实 ELF section 11**。实际三段长度为 **3632/352/0**，由独立 Python
XOR、envelope 和 LEB 解码提取，不由模型 parser 或 native 快照提供 fixture。
实际 vtable/函数自然执行并核对 SP/返回；guest 前 0xa000 字节（含 padding）、
allocation/destruction/free 顺序与每个效果时的根 owner 内容一致。另有独立
payload size/capacity/内容断言；不比较整个 native stack/TLS，不公开实际字节。

Parser 现在发出 `+158(index,pointer,length)`，先推进 cursor。原生 oracle 捕获
三个参数，双方明确核对 length 与 pointer/cursor 的关系，按 length 比较 payload。
覆盖 0/1/127/128/257 字节、flags 0/1/3、callback 拒绝与实际 ELF 三段。
本次只修复参数，parser 仍调用显式 status service，尚未执行实际 AST callbacks。

30 个保护覆盖错误绑定/attached/无活动记录/部分 header、错误参数、u64 超限、
节点/字节预算、source 缺页或别名，以及分配计划的缺页、未对齐、owned/source/
borrowed/image 冲突；最后一项在已成功 create/write 后再次失败，仍保留该检查点
的全部页面。所有拒绝都全页回滚，不执行非法原生内存路径。

旧 AST **308/54**、data reserve/析构 **176/30**、data create **148/105**、
segments **450/33** 与 **16** 个 abort 边界重新通过，四份 JSON 与旧公开证据
逐字节一致；两个基址的全部实际 section custom 组合记录逐字段一致。旧历史
记录遗漏 length 的验证范围不变；旧 AST unsupported-slot guard 从 +158 转到
+148。旧 data helper 仅新增可选 fixture prepare 参数，默认行为不变。

本批结束时 +148/+150 expression/tree、其它 AST callbacks、attached parser/wrapper、
parse/root、完整 reader/factory/B VM/bootstrap、独立 signer 与线上矩阵尚未完成。
证据见 [payload 与 length ABI](evidence/vm9_alternative_ast_data_payload_fresh_20261009.json)。

## 6.16 Data expression frame、u32 修补与树节点删除（2026-10-09 Asia/Shanghai）

`run_reader_ast_callback` 恢复 slots `+148 → +31e4a4`、`+150 → +31e4f4`，
共 **148 个原生/Python 对照、36 个保护/回滚**，两个基址各 74 项，全部输入
合成。修改前分别观察到两个实际 callback 正常返回而 Python 拒绝；另有合法
u32 tree payload 的原生 cleanup 正常返回，Python 因旧八字节宽度拒绝，合计
三个行为 RED。修改后同一最小对照在两个基址 GREEN。

两个 callback 的单个 index 参数均忽略。Begin 设置 callback+28 为最后记录
内嵌 type（output.end-0x90），重置 +38 到 +30 begin，通过 +321570 得到
**u32 字节长度**（不除以 4），写入 record+88 低 32 位并保留高字。+31fee4
追加一个 16 字节 frame：前八字节来自 image+6e188，后两项为 u32 -1。
重置后有容量时直接写入；无容量时分配一项、发布 header、free 旧存储。
Begin 要求有活动 data record；不清除旧 frame 存储中的其它字节。

End 将 frame_count-1 作为 u32 key 交给 +32000c；在 callback+48 的树中按
key 寻找完全匹配节点。Node+28 payload 以 **4 字节步长**读取 u32 byte offsets。
+32151c 在每个 offset 写入修补前 raw buffer 的 u32 字节长度；长度不足时先
扩至 offset+4，新增区清零，容量不足则按 max(new_length,capacity×2) 分配，
复制/发布后释放旧块。未对齐 offsets、重复 offsets 和多次扩容均已对照。

删除前更新树 begin 和 count，再自然执行 +2695c0。模型恢复相同的 successor
转移、parent/left/right 链接、颜色和左右旋转，保留被删节点的原生遗留字节；
不使用 allocator 的另一种树布局。随后 reset payload end、free payload、free
64 字节 node，最后 callback+38 减 16。未匹配 key 时不删节点，仍弹出 frame。
模型要求非空 frame，并验证树 count/begin、root/parent、严格 key 顺序、0/1
颜色、无红色父子和一致黑高；结构/节点/字节预算、共享/循环、映射均有界。

共享 `_ReaderAstMemory.tree` 的 payload 检查宽度从 8 修正为 4，允许原生可
释放的奇数 u32 列表；已有按八字节构造的历史 fixture 仍是合法四字节倍数。
树 cleanup 的 left/right/payload/node 顺序不变。新增 erase/字节增长 helper
归属同一 AST owner，parser 函数及其它既有 ownership 方法未改。

146 项执行实际 vtable callbacks，2 项直接执行 +31b458 cleanup。验证所有
guest 前 0xa000 字节（含 padding）、SP/自然返回、allocation/destruction/free
顺序和每个效果时的根 owner 内容；独立断言另外计算 frame 数量、frame 常量、
record 起始字节长度及 raw 修补内容。测试包含完整黑树、红叶、红 sibling、
近/远子节点旋转、双子节点 successor、连续删除至空、create/raw-word/end/
data 析构和临时 cleanup；image 常量覆写也作为显式输入对照。未比较整个 stack/TLS。

36 个保护包括空记录/空 frame、slot/attached/参数、部分 frame/u32 payload、
tree count/begin/root parent/颜色/黑高/子 parent/重复 key、循环/共享/别名，
offset 预算和 u32 回绕，以及分配地址与 callback/output/frame/tree/payload/
image 冲突、未对齐、缺页、缺少计划和第二次分配重复地址。所有页面回滚，
包括已经完成第一处修补或扩容之后的失败；非法原生内存路径不执行。

旧 AST **308/54**、data reserve/析构 **176/30**、data create **148/105** 和
payload **104 AST / 34 ABI / 30 回滚** 全量回归通过，四份新 JSON 与旧公开
证据逐字节一致。旧 AST unsupported-slot guard 从 +148 改到仍未恢复的 +f0；
历史证据保留其原始验证范围。语法、隐私、链接、CLI 和精确十文件范围检查通过。

这些仍是 detached callback 的独立有界入口，parser 继续使用显式 status service。
其它 expression/AST callbacks、attached parser/wrapper、parse/root、完整
reader/factory/B VM/bootstrap、独立 signer 与线上矩阵尚未完成。
证据见 [data expression/tree](evidence/vm9_alternative_ast_data_expression_fresh_20261009.json)。

## 6.17 Element 回调与嵌套记录清理（2026-10-09 Asia/Shanghai）

同一 `run_reader_ast_callback` owner 恢复以下实际槽位；**282 个原生/Python
对照、159 个保护/回滚**通过，两个基址各 141 项，全部输入合成。修改前五个
实际 callback 均自然返回 0，Python 拒绝；实际 element/嵌套析构正常完成而
Python API 缺失，合计六个行为 RED。修改后同一最小 fixture 在两个基址 GREEN。

| Slot | 原生入口 | 恢复行为 |
| --- | --- | --- |
| +f0 | +31db94 | **零参数**，向 raw buffer 追加 u32 零 |
| +100 | +31dbcc | u32 count，为 output+d8 的 184 字节记录预留容量 |
| +108 | +31dbf0 | 忽略 index，截断 table index/flags，创建并追加 element |
| +110 | +31de48 | 保存 raw 起始字节长度，重置并追加 expression frame |
| +118 | +31de98 | 按最后 frame key 修补 raw、删树节点、弹出 frame |

Element header 在 output+d8/e0/e8，步长 **184**。+00 vector 拥有 **144** 字节
嵌套记录；+18 u64 来自 image+6e210；+20 低字为 flags 分类（低两位为 3 时
取 2，否则 flags&1），高字为 table index。+28 为实际内嵌 type，+38/+50 分别
拥有 params/results u64 vectors，+78 为 16 字节 locals，+a0 为 56 字节 children。
每个 child 的 +10 拥有 u64 vector。+90 初始为 u64 0x00000000ffffffff。

Reserve 容量足够时不变；不足则分配 count×184，+3205e8 倒序转移五组 vector，
清空源 header，复制标量和实际 type vtable，保留目标 +34/+74/+9c padding。
发布新 header 后倒序析构旧记录，再 free 旧 block。创建与 data 共享 sentinel
拷贝流程：original/type/temporary-element/final-results 各分配八字节；original
在临时 element 前释放。满容量时先分配 max(size+1,capacity×2)×184，再复制最终
results。发布、旧记录析构完成后，清理 temporary-element 和 temporary-type。
原生明确调用栈上临时 element 的 +2cc2b8；验证器让其自然执行，比较全部 free，
仅对 guest 拥有的记录记录 destroy 事件，不建模临时栈地址或整个 stack/TLS。

`destroy_reader_ast_element_record` 恢复非 deleting +2cc2b8：倒序释放 +a0 children
的内部 vectors，再释放 child block、+78 locals、内嵌 type results/params，最后
倒序执行 +00 的嵌套记录 +2cc470 并释放 nested block。嵌套布局为 +00 内嵌 type、
+50 locals、+78 children；自身依次释放 children/locals/type results/type params。
Vector end 在原生相同的时点 reset，vtable 恢复 +3724f0，record 自身保留。

Begin 忽略 index，callback+28 指向最后 element 的 type（end-0x90），保存 raw
u32 字节长度到 element+90 低字并保留高字；frame 常量来自 image+6e188。
End 复用已经恢复的 u32 fixup/实际 libc++ erase owner。两类表达式共享 frame、
raw/tree，不增加第二份树实现。非空 element 指令列表的 parser 原生 abort 边界
仍保留；本轮恢复的是 detached AST 入口，没有接入 parser status service。

280 项执行实际 vtable callback，2 项直接执行 element/嵌套析构。核对 guest
前 0xa000 字节（含 padding、移动源和删树遗留内容）、自然返回/SP、全部
allocation/destruction/free 顺序及每个效果时的根 owner 内容。独立断言另外核对
记录布局/分类/sentinel、两处 image 常量、frame 和起始长度、零字和 raw 修补。
覆盖 null/empty-owned/rich/mixed、多级嵌套、空 owned block、spare/full、连续
reserve/create、u32 截断、全部树旋转/后继转移以及 data/element 共享表达式组合。

159 项保护覆盖 slot/attached/参数/预算、未知 type、部分 element/nested/child、
嵌套共享/自别名与缺页；逐次破坏创建的五个或四个分配边界，并验证 reserve/
零字/begin/end 的分配失败，包括已经改写 active pointer 或 raw patch 后的失败。
所有原页面逐字节回滚；非法原生内存路径不执行。分配是纯地址计划，free 为逻辑效果。

旧 AST **308/54**、data **176/30**、create **148/105**、payload **104 AST / 34 ABI /
30 回滚**、data expression **148/36** 重新通过，五份 JSON 与旧公开证据逐字节
一致。原 unsupported-slot guard 从 +f0 迁移至仍未支持的 +120；历史证据保留。
Parser owner AST 未改，其余既有 ownership 方法除 callback 的 element 预检外未改。
语法、文档链接、隐私、CLI、精确十一文件和提交字节检查通过。

Remaining AST callbacks、attached parser/wrapper、parse/root、完整 reader/factory/
bootstrap、独立 signer 与线上矩阵尚未完成。见
[element 证据](evidence/vm9_alternative_ast_element_fresh_20261009.json)。

## 6.18 Element 结果类型与嵌套表达式（2026-10-09 Asia/Shanghai）

同一 AST owner 恢复 slots `+120/+128/+130/+138`，**230 个原生/Python 对照、
133 个保护/回滚**通过，两个基址各 115 项，全部输入合成。四个修改前 RED
均为实际 vtable callback 自然返回 0、Python 拒绝未支持槽位；同一最小输入
在修改后通过完整字节/效果对照。没有原生输入快照或公开私有 payload。

| Slot | 原生入口 | 恢复行为 |
| --- | --- | --- |
| +120 | +31dee0 | 忽略 index，把完整 u64 结果类型写至最后 element+18 |
| +128 | +31def4 | 忽略 index，u32 count 预留 +00 的 144 字节 nested vector |
| +130 | +31df1c | 创建 nested type/expression 记录并开始 frame |
| +138 | +31e18c | 复用 u32 修补/树删除并弹出 frame |

Reserve 经 +320a78，容量足够时不变；不足时分配 count×144、倒序转移四组
vectors（+10/+28/+50/+78），清零源 header，复制 +08/+40/+48/+68/+70 标量并
设置实际 type vtable。目标 +0c/+4c/+74 padding 保留。发布 nested header 后
倒序自然执行 +2cc470，再 free 旧 block；logical size 不变。+128/+130 预检
实际 type GOT source；slot、ownership、映射和资源预算都经过事务检查。

Nested begin 读取最后 element+18 的完整 u64，分配 original result 八字节，
经 +31e888 再分配临时 type result 八字节。临时 type 是新的 nested record，
初始 params/locals/children 为空，+08/+40/+48/+70 为零，+68 为
u64 0x00000000ffffffff。Spare 时直接转移临时 vectors；满容量经 +31f690
分配 max(size+1,capacity×2)×144，先创建最后一项，再倒序移动旧项、发布、
倒序析构和 free 旧 block。临时 result 的所有权已转入新项，没有第三次 result
复制或该 result 的临时 free。最后释放 original result。

随后 callback+28 指向新 nested record，+38 reset 至 frame begin，保存 raw
u32 **字节长度**到 nested+68 低字（高字保留），并追加来自 image+6e188 的
16 字节 frame/sentinel。Frame 分配发生在 nested 创建、旧记录清理和 original
free 之后。End 与已有 +118/+150 使用同一有界 u32-offset fixup、实际 libc++
erase、payload/node free 和 frame pop；没有复制另一套树实现。

既有 element 析构中 +2cc470 的逻辑抽为 `_ReaderAstMemory.destroy_nested`，
供 element 清理和 nested reserve/growth 共用；原有释放和 reset 时点一致。
新增 move helper 仍归同一 ownership/transaction owner，没有新增公开析构 API。
+120/+128 要求两个参数；+130/+138 的有界 API 各接受一个忽略参数。实际 section
9 parser 不发出 +130/+138：非空 element vector 在 +128 之后仍直接到原生
abort。因此这两个参数数量只是当前独立入口约定，不宣称已验证其 parser ABI，
也没有恢复非空 element 列表解析。Parser 函数 AST 未改，callback 继续 detached。

230 项全部执行实际 vtable；核对 guest 前 0xa000 字节（预填非零字节，含
padding、移走记录及删树遗留内容）、自然返回/SP、分配/析构/free 顺序及每次
效果的根 owner bytes。独立断言另外核对 full-u64 result、记录字段/容量、frame
常量与数量、起始字节长度和 raw 修补。覆盖 empty-owned/rich/mixed、非空零容量
指针、u32 count 截断、spare/full、两级 ownership、所有树旋转/后继转移、创建
后修补/删除再搬移、连续五次创建扩容、类型变更与共享 element expression。
整份 stack/TLS 不比较；临时 type 原生执行，其结果转移由 guest/效果对照验证。

133 项保护包括 slot/GOT/attached/参数、空活动 element/frame、未知/部分/共享
nested vectors、总节点/容量/字节预算，以及逐次失败的四个 growth 创建分配或
三个 spare 创建分配、reserve 分配、end 的两次 raw 分配。全部页面回滚，含
已移动/发布 nested、释放 original、写入 active pointer 或第一次 raw patch
之后才失败的情况。分配保持纯地址计划，free 为逻辑效果；非法原生路径不执行。

旧 AST **308/54**、data **176/30**、create **148/105**、payload **104 AST / 34 ABI /
30 回滚**、data expression **148/36**、element **282/159** 全部重跑，六份 JSON
逐字节一致。Unsupported-slot guard 从 +120 迁移至仍未恢复的 +c0；公共历史
证据保留。共享 element fixture 仅增加可选 nested_capacity，默认行为相同。
语法、链接/锚点、隐私、CLI、精确十一文件和提交字节检查通过。

其余 AST 回调、attached parser/wrapper、parse/root、完整 reader/factory/bootstrap、
独立 signer 与线上矩阵尚未完成。见
[nested expression 证据](evidence/vm9_alternative_ast_element_nested_fresh_20261009.json)。

## 6.19 Instruction predicate 与带类型常量（2026-10-09 Asia/Shanghai）

同一 AST owner 恢复六个槽位，新增 **398 个原生/Python 对照、122 个保护/回滚**。
全部输入合成，每基址 199 项，实际 relocated vtable `+372370` 执行原始入口。
八项行为 RED 在生产修改前确认；原生自然返回（包含 predicate 返回 1），Python
当时拒绝这些槽位。实现后同八入口 GREEN，完整验证和七组旧回归均通过。

| Slot / 原生入口 | 参数与结果 |
| --- | --- |
| `+c0 → +31da9c` | 一个忽略的 kind；active `callback+28` 为零或 frame 为空返回 1，否则 0；不解引用 active 指针 |
| `+c8 → +31dab4` | 无参数；仅一层 frame 时不操作，多层复用既有修补/树删除/pop；模型拒绝空 frame |
| `+d0 → +31db04` | 一个 u64 寄存器参数；追加 u32 tag 4，再追加低 u32 浮点原始位 |
| `+d8 → +31db28` | 一个 u64 寄存器参数；追加 u32 tag 5，再追加完整 u64 浮点原始位 |
| `+e0 → +31db4c` | 一个 u64 寄存器参数；追加 u32 tag 2，再追加低 u32 整数位 |
| `+e8 → +31db70` | 一个 u64 寄存器参数；追加 u32 tag 3，再追加完整 u64 整数位 |

原生 typed helpers `+32140c/+321490` 先追加四字节 tag，再分别追加四/八字节
value。两次增长可能分别分配、发布、释放，不能合成一次追加。实现复用既有
`_ReaderAstMemory.grow_bytes`；inner end 复用 `+118/+138/+150` 的同一 frame/raw/tree
修补与删除 owner。浮点只保留原始位，没有数值转换或 NaN 规范化。

两基址核对自然返回与 SP、guest 前 `0xa000` 字节（含预填充 padding）、
分配/析构/free 顺序及每个副作用时的 owner 字节。独立预期另外核对 0/1 status、
frame 数量、raw 内容、树节点数量及纯 predicate/单 frame end 的全页不变。
22 项对照包含返回 1。覆盖 active 为零、未映射非零指针、frame 空/非空、
未对齐 raw 长度、容量边界、高位截断、符号位/NaN bits、连续常量和各树删除形态，
以及 data/nested begin、常量、end 与析构组合。

122 个拒绝/回滚检查覆盖槽位绑定、attached 状态、参数/容量/所有权约束、
typed 常量和 inner end 的两次分配、重复/未映射/部分映射/别名地址以及晚期
修补写入失败。全页回滚，未执行无效 native 内存路径。分配仍为纯地址计划，
free 仍为待消费的逻辑副作用。完整 stack/TLS 不在字节比较范围。

旧 AST **308/54**、data **176/30**、create **148/105**、payload **104 AST /
34 ABI / 30 回滚**、expression **148/36**、element **282/159**、nested
**230/133** 全部重新通过；七份 JSON 与历史公开证据逐字节一致。共享 native
driver 只新增 fixture 显式期望 status，默认仍断言 0；旧 unsupported guard
从 `+c0` 移至仍未恢复的 `+b8`。生产 owner 中只有 `run_reader_ast_callback`
改变，ownership class、parser 与其它函数保持 AST 一致。

本检查点仍为独立 detached callback API；未接入 attached parser/wrapper。
其余 AST、完整 reader/factory/bootstrap、独立 signer 和线上矩阵仍未完成。见
[instruction 证据](evidence/vm9_alternative_ast_instruction_fresh_20261009.json)。

## 6.20 Local group 与函数结束回调（2026-10-09 Asia/Shanghai）

同一 AST owner 恢复两个槽位，新增 **252 个原生/Python 对照、37 个保护/回滚**。
每基址 126 项，全为合成输入；实际 relocated vtable `+372370` 共执行 348 次
callback。三项行为 RED 在生产修改前取得：原生 spare append、growth append 和
end 均自然返回 0，Python 当时拒绝槽位。实现后同三项 GREEN，完整正向对照通过。
另补五个 guard：两个 nested spare active、扩容后的容量预算和两种晚期发布失败；
37 项 guard 全部重新验证，252 项原生正向结果保留不变。

| Slot / 原生入口 | 参数与结果 |
| --- | --- |
| `+b8 → +31d984` | `(ignored_group_index, count, type_bits)`；先将低 u32 count 回绕加至 `callback+7c`，再向 active `+50` 追加 u64 type/u32 count/u32 cumulative，共 16 字节 |
| `+f8 → +31dbb4` | `(ignored_index, length)`；先清除 `callback+28` active，再向原 active `+70` 写低 u32 length，返回 0 |

原生 local group 不解释 type bits，也不根据 count 展开多个条目；零 count 仍追加
一条，完整 u64 类型位保留。spare 直接写 entry 并推进 end；容量满时分配
`max(size+1,capacity*2)*16` 字节，写入新条目、复制旧条目、发布 header 后释放
旧块。既有 `+b0` 只重置 declared groups 和累计 count，不清空 local vector。
end 保留 frame、修补树与 raw buffer，长度高位截断，邻接 padding 保持原值。

这两槽原用于 code 回调。本检查点仅接受当前 ownership 已识别的三类兼容布局：
data inline `record+20`、element inline `record+28`、element nested 144 字节
节点。active 必须准确指向 logical entry；已映射的 nested spare capacity 仍拒绝。
未接入 `+a8` code-begin 或 `output+30` 独立 function 容器；不宣称完整 code AST
或 parser/AST composition。实现只改 `run_reader_ast_callback`，复用现有 ownership
class；其它函数、parser、共享 native driver 均保持不变。

两基址核对自然返回/SP、guest 前 `0xa000` 字节、分配/析构/free 顺序及每个
副作用时的 owner 字节。独立预期另外核对 local bytes、declared/cumulative、
active/length、frame/tree 不变及纯 end 的全页预期。覆盖三个布局、第二个
nested、容量边界、零 count、u32 高位截断/累计回绕、完整类型高位、重复扩容、
reset/append/end、常量/predicate 和后续析构组合。local buffer 仍由既有
data/element/nested 析构释放，没有新增 destructor 或 ownership owner。

37 个 guard 覆盖错误绑定/attached 状态/参数、非法或 spare active、local header、
节点/字节预算、分配缺失与别名地址、late local publication 和先清 active 后写入
失败。全部原始页面回滚，未执行无效 native 内存路径。分配仍是纯地址计划，
free 仍为待消费的逻辑副作用；完整 stack/TLS 不在字节比较范围。

旧 AST **308/54**、data **176/30**、create **148/105**、payload **104 AST /
34 ABI / 30 回滚**、expression **148/36**、element **282/159**、nested
**230/133**、instruction **398/122** 全部重新通过，八份 JSON 与历史证据
逐字节一致。旧 unsupported guard 从 `+b8` 移至仍未恢复的 `+a8`。
其余 AST、attached parser/wrapper、完整 reader/factory/bootstrap、独立 signer
和线上矩阵仍未完成。见
[local group 证据](evidence/vm9_alternative_ast_local_fresh_20261009.json)。

## 6.21 Function 创建、类型缓存与清理（2026-10-09 Asia/Shanghai）

同一生产 owner 恢复实际 vtable `+50` function entry、`output+30` 所有权与
非删除式 function 析构，新增 **188 个原生/Python 对照、136 个保护/回滚**。
每基址 94 项，全为合成输入；162 项执行真实 relocated vtable，26 项只执行
真实 function 析构，共 286 次回调、238 个 function 创建。三项生产修改前行为
RED：原生 spare/full 创建自然返回 0，Python 拒绝槽位；原生 rich 析构成功，
Python 缺少接口。实现后相同三项 GREEN，完整对照通过。

| 入口 / 布局 | 已恢复行为 |
| --- | --- |
| `+50 → +31c7b8` | `(function_index, type_index)` 均截为 u32；从 output 类型数组选择 logical entry，向 `output+30` 追加 144 字节 function，并向 `callback+80` 追加独立 64 字节类型拷贝 |
| `+31eea4` | 复制类型 `+08` 的 u32、按 params/results 实际长度分配并复制；不复制 spare capacity 或 `+0c` padding |
| `+31f690` / `+31ed20` | function/cache 各自按 `max(size+1,capacity*2)` 扩容；向后转移旧 vectors，清源、发布，再倒序析构并释放旧块 |
| `+2cc470` | 记录地址在 X1；倒序释放 children 内部 vectors、child block、locals、results、params；重置 ends/type vtable，保留记录 |

新 function 的 `+40/+44` 保存 type/function index，`+48` 为零；locals `+50`
和 children `+78` 初始为空，`+68` 为 `0x00000000ffffffff`，`+70` 为零。
`+0c/+4c/+74` 保留 destination padding。function 与 cache 的两份类型各自
拥有 params/results，原 source 类型和容量空闲字节保持不变。两容器都满且
params/results 非空时，分配顺序是 function params、function results、function
block、cache block、cache params、cache results；原生临时 function 转移所有权后
不再释放这些 vectors。

复用原 `_ReaderAstMemory` 的 `move_nested/destroy_nested` 与
`move_types`/type destructor；抽取共享的 144 字节记录验证，供 function 和
元素嵌套记录使用。新增 `destroy_reader_ast_function_record` 仍在同一 owner，
不释放记录本身。现有 `+b8/+f8` 可使用 logical function active，拒绝已映射的
spare capacity。callback cleanup 释放 type cache，保留 output function 容器；
完整 output wrapper 清理仍待恢复。共享 native driver 仅增加可选 function 析构
序列，既有调用和证据不变，parser 及其它生产函数保持不变。

两基址核对自然返回/SP、guest 前 `0xa000` 字节（含预填 padding）、分配/析构/
free 顺序与每次副作用的 owner 字节。独立预期另核对源类型、params/results
字节、标量/索引/padding、两份独立指针、实际长度容量、分配尺寸序列，以及 local
累计/条数、active/end 和析构后的 vector ends。覆盖两容器的 spare/full/null/
nonnull-zero-capacity、空与非空类型、rich/empty/mixed children、u32 高位截断、
重复独立扩容、local/end、其它已恢复 output 与后续 cache cleanup。

136 项 guard 中，39 项覆盖绑定/attached/参数、logical type、headers、容量与
字节预算、record/children 别名、直接析构与 function spare active；89 项在六个
分配位置逐一验证非法地址、所有权别名与 prior plan 重用，8 项注入晚期写入
失败。所有原始页面回滚；不执行无效 native 内存路径。分配仍为纯地址计划，
free 为待消费的逻辑副作用；完整 native stack/TLS、真实 allocator/abort 不在对照内。

九组旧回归重新通过：AST **308/54**、data **176/30**、create **148/105**、
payload **104 AST / 34 ABI / 30 回滚**、expression **148/36**、element
**282/159**、nested **230/133**、instruction **398/122**、local **252/37**。
九份 JSON 与历史证据逐字节一致；旧 unsupported guard 仍为未恢复的 `+a8`。

同时纠正交接候选槽位：`+58 → +31c9f4` 是 table 容量预留（stride 48，output
`+48`），`+60 → +31cabc` 使用 descriptor 创建 table。Section 3 实际只发
`+50` entries，没有单独的 function reserve/count callback；本检查点没有恢复
table。下一步是 `+a8` code-begin。其余 AST、attached parser/wrapper、完整
reader/factory/bootstrap、独立 signer 和线上矩阵仍未完成。见
[function 证据](evidence/vm9_alternative_ast_function_fresh_20261009.json)。

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
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varuint64_20261008.py --library <private-metasec.so> --output <reader-u64-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_import_limits_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-import-limits-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_table_memory_sections_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-table-memory-sections-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varint64_20261008.py --library <private-metasec.so> --output <reader-i64-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_globals_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-globals-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_code_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-code-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_segments_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-segments-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_custom_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-custom-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_20261009.py --library <private-metasec.so> --output <reader-ast-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_20261009.py --library <private-metasec.so> --output <reader-ast-data-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_create_20261009.py --library <private-metasec.so> --output <reader-ast-data-create-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_payload_20261009.py --library <private-metasec.so> --libc <matching-libc.so> --output <reader-ast-data-payload-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_expression_20261009.py --library <private-metasec.so> --output <reader-ast-data-expression-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_element_20261009.py --library <private-metasec.so> --output <reader-ast-element-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_element_nested_20261009.py --library <private-metasec.so> --output <reader-ast-element-nested-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_instruction_20261009.py --library <private-metasec.so> --output <reader-ast-instruction-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_local_20261009.py --library <private-metasec.so> --output <reader-ast-local-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_function_20261009.py --library <private-metasec.so> --output <reader-ast-function-evidence.json>
```

A observation ranges 跳过 VM dispatcher 热点，只保留服务、启动/caller/callback 边界。
VM 指令仍原生执行，没有替换结果。各验证器恢复 monkeypatch，同一进程要求串行；
输出仅合成 guest 状态、偏移、计数和比较结果，不导出 native 内存或 selector 正文。

这些证据证明导入/内存依赖、JNI→默认任务→cleanup/exit 控制流、once 发布顺序，以及
B 实际 descriptor 生成/发布与短 selector 布局。它们不能证明 fresh Medusa 输出、
服务器认可、全部 OS 析构或独立 Python/Rust signer。

下一步恢复其余 B reader AST callback 并接入 parser/wrapper，随后解析/root 生成，再把原始 JNI /
worker / cleanup 接入独立 Python 启动与真实 allocator/arena/OS 输入。B VM、fresh
签名和线上矩阵仍待通过。无 JVM Rust 下载链路、非空搜索/分页、抖音/起点闭环及
最终 Pages/Actions 搜索下载产品仍未完成。
