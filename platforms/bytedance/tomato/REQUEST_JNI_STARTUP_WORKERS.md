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

## 6.22 Code-begin、双修补树与 child 追加（2026-10-09 Asia/Shanghai）

同一生产 owner 恢复实际 vtable `+a8 → +31d7d8`，新增 **284 个原生/Python
对照、100 个保护/回滚**，每基址 142 项。输入全部合成，全部执行真实 relocated
vtable，共 338 次回调、310 次 code-begin。生产修改前三项行为 RED 分别为
spare、frame/child 增长、双修补树：原生自然返回 0，Python 拒绝未恢复槽位。
相同三项实现后 GREEN。初版完整对照通过后，另两项精确预算 RED 发现重复计算
旧 child 的问题；修正后预算 6/10 的四项两基址对照和最终完整批次通过。

| 入口 / 布局 | 已恢复行为 |
| --- | --- |
| `+a8` 参数 | `(function_index, cursor_offset, ignored_body_bytes, metadata)`；按低 u32 index 减去 cache count 与 function count 的差，要求选择 logical function |
| active / function | 设置 `callback+28`；写 function `+48` metadata、`+68` 修补前 raw 长度、`+6c` cursor offset，均截为 u32；保留 `+70` |
| 两棵修补树 | 后序释放 `callback+48` 树及 payload，重置 header/frame end；经 `+32000c` 使用 `callback+60` 树修补 raw，再经 `+2695c0` 删除匹配相对索引的节点 |
| 16 字节 frame | image `+6e188` 的 8 字节常量、u32 `ffffffff`、旧 child 条目数；reset 后在既有容量内写入，或经 `+31fee4` 增长 |
| 56 字节 child | `+00 = 修补后 raw 长度 << 32`，`+08 = ffffffff`，`+10` 空 vector，`+28 = local 条目数 << 32 \| ffffffff`，`+30 = 0`；保留 `+0c/+34` padding |
| `+320340` 增长 | 按 `max(size+1,capacity*2)` 分配 child block；倒序转移旧 payload vectors 并清源、发布后释放旧块 |

复用 `_ReaderAstMemory`、function output、raw/frame/tree ownership。抽取
`apply_fixup` 供 code-begin 与既有 expression end 共用；`move_children` 转移
既有 56 字节 child。新增 child 的节点预算只加一，另检查新容量，避免再次计入
已经验证过的旧条目。生产 parser、其它函数/方法/API 和共享 native driver 不变。
旧 AST verifier 的 unsupported guard 从 `+a8` 移到仍未恢复的 `+58`。

两基址核对自然返回/SP、guest 前 `0xa000` 字节（含预填 padding）、所有分配/
析构/free 顺序与每次副作用时的 owner 字节。独立预期另核对相对 function
选择、metadata、修补前后 raw 长度、cursor、frame/child 原始字段、locals、active、
双树数量与 padding。覆盖 cache/function 数量差的 u32 回绕、高位截断、各类
空/满/spare/null/non-null-zero 容量、修补 payload 重复/未对齐/增长、红黑树旋转
与连续删除、重复 begin、已有 locals、可变 image frame 常量，以及创建/local/
常量/end、其它已恢复 output 和析构/cleanup 组合。

100 项 guard 包括 29 项绑定/attached/参数、logical function、headers、双树、
容量/节点/字节预算与 allocator 缺失，63 项在四个分配位置逐一检查非法地址、
所有权别名与 prior plan 重用，8 项注入晚期写入失败。四项预算 guard 还核对
相同输入在正常预算下可运行。全部原始页面回滚；不执行无效 native 内存路径。
分配为纯地址计划，free 为逻辑副作用；完整 native stack/TLS、真实 allocator/
abort 不在本对照范围内。

十组旧回归通过：AST **308/54**、data **176/30**、create **148/105**、payload
**104 AST / 34 ABI / 30 回滚**、expression **148/36**、element **282/159**、
nested **230/133**、instruction **398/122**、local **252/37**、function
**188/136**。十份 JSON 与历史证据逐字节一致。随后生产修改仅为 `+a8` 预算
条件；只读核对证明其它代码相同，旧原生 suites 没有执行 `+a8`，因此保留该
回归证据；最终 284/100 包含预算修正。

下一候选为 table `+58/+60` 和 `output+48` 所有权。其余 AST、attached parser/
wrapper、完整 reader/factory/bootstrap、独立 signer、fresh 签名与线上矩阵仍未
完成。见 [code-begin 证据](evidence/vm9_alternative_ast_code_begin_fresh_20261009.json)。

## 6.23 Table 预留、创建与显式栈 padding（2026-10-09 Asia/Shanghai）

同一生产 owner 恢复实际 vtable `+58 → +31c9f4` 和 `+60 → +31cabc`，新增
**184 个原生/Python 对照、77 个保护/回滚**。每基址 92 项，全部输入合成，
全部执行真实 relocated vtable，共 216 次回调、160 次 table 创建。生产修改前
四项行为 RED：既有记录 reserve 增长、高 u32 reserve no-op、spare/no-maximum
entry、output/cache 同时增长；原生自然返回 0，Python 拒绝槽位。实现后同一
四项在两基址 GREEN。后来新加错误 vtable GOT guard 另取得 RED，并修复绑定检查。

| 入口 / 布局 | 已恢复行为 |
| --- | --- |
| `+58` | count 截为 u32；仅在大于容量时按 count 分配 `output+48` 的 48 字节记录块，倒序复制、发布后释放旧块，无旧节点析构 |
| `+60` | `(ignored_index, full_u64_type, descriptor_pointer)`；新 kind 为 1、vtable 为 `+372518`，向 output 和 `callback+98` 缓存各追加独立 48 字节记录 |
| descriptor | 实际读取 24 字节，复制前 19 字节至 record `+18`；input `+10` flag 为零时，将 descriptor `+08` 改为 u64 `00000000ffffffff` |
| record 字段 | `+0c` 保存完整 u64 type；`+14` 保存 temporary stack padding；复制结束于 `+2a`，保留 destination `+2b..+2f` 五字节 |
| output/cache 增长 | 各按 `max(size+1,capacity*2)` 增长，倒序复制旧 records 并发布；output 只释放旧块，cache `+31ef9c` 另倒序调用旧节点 `+321368` 析构后释放 |

此前发现的 padding 依赖不能用固定 `a5a5a5a5` 替代。实际 `+31cabc` 从 entry
SP 减去 `b0`，临时 record 位于新 SP `+20`；type 写入新 SP `+2c`，descriptor
写入 `+38`，但 `+34` 的 4 字节没有初始化。两次重叠 SIMD load 仍将它复制到
两个新 record 的 `+14`。三项独立原生实验只改变该栈字为 `0/11223344/88776655`，
两个新 record 都保留相同值，type 和 destination 尾部不变。table vtable 的
实际 clone `+3210d0` 也复制这 31 字节，包括 padding；这是已观察的输入依赖。

因此 `run_reader_ast_callback` 新增可选 `entry_stack_address=None`；仅 `+60`
要求提供实际、16 字节对齐的 entry SP，并从映射 frame 的 SP-7c 读取 4 字节。
整个 `[SP-b0,SP)` frame 与借用的 24 字节 descriptor 在分配期间保留，不允许
与已有 owner、彼此或分配计划别名。缺少上下文拒绝执行。没有原生输入快照，
没有 guest 字节屏蔽，也没有虚构填充值。其它 native stack writes/TLS 不在此
API 的整体对照范围；parser/worker 组合必须为每次调用提供真实入口上下文。

唯一 owner 仍是 `_ReaderAstMemory`，新增 `move_tables`；callback 验证允许
`output+48` table 容器并检查 vtable/节点/容量。callback cleanup 已有 table
缓存所有权，output table 容器保留，完整 output wrapper 清理尚未恢复。共享
native driver 只在 fixture 明确提供 entry SP 时转发该可选参数；其它生产函数、
class methods、parser 和现有 API 默认行为不变。旧 AST unsupported guard 移至 `+68`。

两基址核对自然返回/SP、guest 前 `0xa000` 字节（含所有 padding）、分配/析构/
free 顺序和每次副作用的 owner 字节。独立预期核对 capacity/size、完整 u64
type、descriptor、stack padding、分配尺寸序列及借用输入。覆盖 null/spare/full/
non-null-zero、flag 0/1/9/生成值、高位 count/index/type、未对齐 descriptor、
连续 reserve/append、两容器独立增长、已有其它 output、函数/数据/element
析构和 cache cleanup，以及精确节点预算 5/12 的四项两基址对照。

77 项 guard 中，41 项覆盖绑定/attached/参数、缺失/非法/别名/部分映射栈、
descriptor/headers/节点/容量/节点及字节预算和 allocator；27 项逐个验证两次
分配的非法地址、frame/descriptor/owner/保留区/prior-plan 别名，9 项注入晚期
写入失败。五项预算 guard 配有正常预算下相同输入的正向对照；两个字节 guard
明确断言失败发生于 table 分配上限。所有原始页面回滚，不执行无效 native
内存路径。分配为纯地址计划，free 为逻辑副作用，真实 allocator/abort 未纳入。

十一组旧回归通过：AST **308/54**、data **176/30**、create **148/105**、payload
**104 AST / 34 ABI / 30 回滚**、expression **148/36**、element **282/159**、
nested **230/133**、instruction **398/122**、local **252/37**、function
**188/136**、code-begin **284/100**；十一份 JSON 与历史证据逐字节一致。
下一候选为 memory `+68/+70` 和 `output+60` 所有权；其余 AST、完整 wrapper、
attached parser、reader/factory/bootstrap、独立 signer、fresh 签名和线上矩阵
仍未完成。见 [table 证据](evidence/vm9_alternative_ast_table_fresh_20261009.json)。

## 6.24 Memory 预留、创建与独立缓存（2026-10-09 Asia/Shanghai）

同一生产 owner 恢复实际 vtable `+68 → +31ccec` 和 `+70 → +31cdb4`，新增
**272 个原生/Python 对照、65 个保护/回滚**。每基址 136 项，全部为合成输入，
执行真实 relocated vtable，共 304 次回调、248 次 memory 创建。生产修改前五项
行为 RED：reserve 增长、高 u32 count no-op、spare/default32、output/cache 同时
增长且显式 maximum、spare/default64。原生自然返回 0，Python 拒绝缺失槽位；
实现后完全相同的五项输入在两个基址通过。

| 入口 / 布局 | 已恢复行为 |
| --- | --- |
| `+68` | count 截为 u32；预留 `output+60` 的 40 字节记录，保持 size，倒序复制、发布后释放旧块，没有旧记录析构 |
| `+70` | `(ignored_index, descriptor_pointer)`；向 output 与 `callback+b0` 缓存各追加独立 40 字节记录，kind 2、vtable `+372540` |
| descriptor | 实际读取并复制完整 24 字节至 record `+10`；保留输入的 flags 与尾部字节，支持未对齐输入 |
| maximum | input `+10` 非零时保留显式 u64 maximum；为零时按 input `+12` 选择 `0x10000` 或 `0x1000000000000`，写 descriptor `+08` |
| padding | record `+0c..+0f` 保留 destination 原值；descriptor 全部初始化，创建不依赖未写入的栈字 |
| 两容器增长 | 各按 `max(size+1,capacity*2)` 扩容，倒序复制旧记录并发布；output 只 free，cache `+31f130` 另倒序调用旧节点 `+321368` 后 free |

唯一 owner 仍是 `_ReaderAstMemory`，新增 `move_memories`，扩展 output `+60`
的 stride、节点和容量验证。缓存的节点析构和 callback cleanup 复用既有 owner；
输出容器保留，完整 output wrapper 清理尚未恢复。memory API 无需显式入口栈
参数；三组旧 stack marker 对照均获得相同 descriptor。没有原生输入快照，
没有 guest 字节屏蔽。此 API 没有整体模拟 native stack/TLS、真实分配器或 abort。

两基址核对自然返回/SP、guest 前 `0xa000` 字节（含所有 padding）、分配/析构/
free 顺序及每次副作用的 owner 字节。独立预期核对 size/capacity、完整 descriptor、
两种默认 maximum、旧记录搬移、destination padding、分配尺寸序列、借用输入
与旧块字节保留。覆盖 null/spare/full/non-null-zero、maximum flag 0/1/9 与生成值、
memory64 flag 0/255 与生成值、高位 count/index、未对齐输入、连续 reserve/append、
两容器独立增长、已有 function/data/element 的析构和 cache cleanup，以及精确
节点预算 5/12 的四项两基址对照。

65 项 guard 包含 28 项绑定/attached/参数、descriptor/header/节点/容量/预算及
allocator 检查，25 项两次分配的地址与别名检查，12 项晚期写入失败，包括已有
容量下的 end 发布。五项预算拒绝配有相同输入在正常预算下的对照；两个字节
guard 明确断言 memory 分配上限。所有原始页面回滚，不执行非法原生内存路径。
分配仅为纯地址计划；free 为逻辑副作用，页面继续映射。

十二组旧回归全部通过：table **184/77**、AST **308/54**、data **176/30**、
create **148/105**、payload **104 AST / 34 ABI / 30 回滚**、expression **148/36**、
element **282/159**、nested **230/133**、instruction **398/122**、local **252/37**、
function **188/136**、code-begin **284/100**；十二份 JSON 与历史证据逐字节一致。
其它生产函数、现有 callback 分支、class methods、API 默认值、parser 和共享
native driver 不变；旧 unsupported guard 从 `+68` 移至未恢复的 `+78`。

下一步恢复剩余 AST/import callback 与 output wrapper，再接入 attached
`31b360 → 324444 → 324188` parser/AST/root。完整 reader/factory/bootstrap、独立
signer、fresh 签名和线上矩阵仍未完成。见 [memory 证据](evidence/vm9_alternative_ast_memory_fresh_20261009.json)。

## 6.25 Global 预留、创建与记录清理（2026-10-09 Asia/Shanghai）

同一生产 owner 恢复实际 vtable `+78 → +31d004`、`+80 → +31d028` 和独立记录
析构 `+2cc3b4`，新增 **328 个原生/Python 对照、120 个保护/回滚**，每基址 164
项，全部合成输入。共 334 次实际回调、182 次 global 创建，192 项控制包含
输出 global 的独立析构。生产修改前五项行为 RED：rich reserve 增长、高 u32
count no-op、spare/full-u64-type/mutable entry、output/cache 同时增长、rich
记录析构；原生自然返回，Python 拒绝缺失槽位或析构 API。实现后同一五项输入
在两个基址通过。global 原生批次完成于 10 月 9 日，十三组历史回归完成于
10 月 10 日；文件名中的 `20261009` 沿用原生批次标记。

| 入口 / 布局 | 已恢复行为 |
| --- | --- |
| `+78` | count 截为 u32，调用 `+31f90c` 预留 `output+78` 的 176 字节记录，保持 size；转移所有权、发布，再倒序析构旧记录并释放旧块 |
| `+80` | `(ignored_index, full_u64_type, mutable)`；新 global kind 3、vtable `+372568`，type 保存在 record `+0c`，mutable 只取低位并保存为 `+14` 的 u32 |
| 输出记录 | `+18` 拥有 inline type，`+28/+40` 为 params/results，`+68` 为 locals，`+90` 为 children；新 results 拥有一个完整 u64 type，末尾 `+a8` 初始化为零 |
| 创建分配 | 先建立三份 8 字节结果；原始份在第二份完成后释放，第三份转移给输出，第二份在 cache 追加后释放；两份临时数据均有真实副作用对照 |
| padding | destination `+24/+64/+8c` 各保留 4 字节；旧记录的标量和四个 vector header 转移，新位置保留自己的 padding |
| cache | `callback+c8` 独立拥有 24 字节 global 节点；全 u64 type/mutable 低位一致。输出与 cache 各按 `max(size+1,capacity*2)` 增长；cache `+31f2c4` 发布后倒序析构旧节点并释放 |
| `+2cc3b4` | 记录地址在原生 X1；倒序释放 child payload、child block、locals、type results、params；重置各 end 和 inline type vtable，保留外层记录及标量/padding |

唯一 owner 仍为 `_ReaderAstMemory`。新增 global 的记录验证、搬移和析构，搬移
复用已有 144 字节布局的 vector 所有权转移；新增
`destroy_reader_ast_global_record` 有界 API。output `+78` 检查节点、stride 与
容量。原生 driver 增加该析构入口、序列和观察，并保持旧控制行为；旧 unsupported
guard 从 `+78` 移至仍未恢复的 `+88`。其它生产函数、既有 callback 分支、API
默认值与 parser 不变；原有 class methods 仅调整 callback 的输出验证。

两基址核对自然返回/SP、guest 前 `0xa000` 字节（含所有 padding）、分配/析构/
free 顺序及每次副作用的 owner 字节。独立预期核对 size/capacity、完整 type、
mutable 低位、单结果、旧记录标量与 vector 转移、源 vector 清零、padding 和
分配尺寸。覆盖 null/spare/full、拥有空存储/rich/mixed 子节点、child 数量
0/1/3、高位 count/index/type/mutable、非空零容量指针、连续 reserve/append、
两容器独立增长、已有其它输出及其清理，精确节点预算 7/12 的两基址正向对照。

120 项 guard 包含 26 项绑定/attached/参数、布局/节点/别名/预算与 allocator
检查，64 项逐个验证五次分配计划的非法地址/owner/保留区/先前计划别名，
16 项 callback 晚期写入、9 项独立析构保护及 5 项析构晚期写入。七项预算
拒绝配有相同输入在正常预算下的对照；三个字节 guard 明确验证 reserve/output/
cache 的分配上限。全部原始页面回滚，无非法原生内存路径。纯分配计划与逻辑
free 保留映射；真实分配器、abort、整体 stack/TLS/OS 尚未纳入。

十三组历史回归全部通过：memory **272/65**、table **184/77**、AST **308/54**、
data **176/30**、create **148/105**、payload **104 AST / 34 ABI / 30 回滚**、
expression **148/36**、element **282/159**、nested **230/133**、instruction
**398/122**、local **252/37**、function **188/136**、code-begin **284/100**。
十三份 JSON 与历史证据逐字节一致。global expression `+88/+90`、imports、
完整 output wrapper、attached parser/AST/root、reader/factory/bootstrap、独立
signer、fresh 签名及线上矩阵仍未完成。见 [global 证据](evidence/vm9_alternative_ast_global_fresh_20261009.json)。

## 6.26 Global expression 与内联 AST 回调（2026-10-10 Asia/Shanghai）

同一生产 owner 恢复 `+88 → +31d45c`、`+90 → +31d4ac`，并在已有 local group /
function-end 的 active 验证中接纳 global 的内联 AST。新增 **212 个原生/Python
对照、54 个保护/回滚**，每基址 106 项，全部合成输入。共 414 次实际回调；
200 项包含 global 输出记录的独立析构。生产修改前五项行为 RED：begin 分配
frame、重置已有 frame、full-u64 end 与 fixup 增长、global active 的 local、
global active 的 function-end。原生均自然返回；Python 拒绝缺失槽位或未支持的
active 布局。实现后相同五项输入在两个基址通过。

| 入口 | 已恢复行为 |
| --- | --- |
| `+88` | 仅一个 ignored index 参数；选择最后一个 global 的 `+18` 内联 AST，保存在 `callback+28`。frame end 重置为 begin，当前 raw 字节长度截为 u32 写入 global `+80`，调用 `+31fee4` 添加哨兵 frame |
| frame | stride 16，前 8 字节来自 image `+6e188`，后 8 字节为全 ff；已有容量复用，零容量分配、发布再释放旧块。begin 不改 global `+a8` |
| `+90` | 参数为 `(ignored_index, full_u64_value)`；第二个参数完整写入最后一个 global `+a8`，调用 `+32000c` 修补当前 frame index 的 raw offsets、擦除树节点，然后 pop 16 字节 frame；保留 active |
| global active | 已有 `+b8/+f8` 接纳 global `+18` 的 144 字节内联布局；local 保留完整 u64 type、u32 count 和累计值，function-end 清 active、写 u32 length。原生消费者已有该行为，本轮只扩展验证边界 |

共享 frame/raw/fixup owner 继续承担 sentinel、raw 增长、树删除和释放；无第二份
语义实现。所有其它生产函数、class methods、API 参数默认值和 parser 不变，
原生共享 driver 不变；旧 unsupported guard 移至已核对仍未恢复的 `+98`。

两基址核对自然返回/SP、guest 前 `0xa000` 字节（无屏蔽）、有序分配/析构/free
及每次副作用的 owner 字节。独立预期核对 frame 数量/容量/sentinel、raw 内容、
u32 起点、full-u64 end、active 保留与清除、local count/type/累计值及剩余树数量。
覆盖 raw 长度 0/1/3/4/11/32、frame 空/spare/full 与重置、六种 end 位值、
不匹配 key、所有既有树删除形状和连续删除、raw 多次增长、覆盖 image constant、
四类 global 子所有权、完整创建/常量/结束/析构、连续 begin/end、已有其它输出。
精确节点预算 2 在两个基址通过。

54 项 guard 包含 28 项绑定、参数、attached、布局、树、所有权别名、预算与
allocator 检查，20 项 frame/raw 分配地址或别名保护，6 项晚期写入失败回滚。
三项预算拒绝配有相同输入的正常预算对照。全部原始页面不变；非法原生内存
路径没有执行。分配仍为纯计划、free 为逻辑效果；真实 allocator/abort/整体
stack/TLS/OS 不在此批证据内。

十四组历史回归通过，十四份 JSON 逐字节一致：global **328/120**、memory
**272/65**、table **184/77**、AST **308/54**、data **176/30**、create **148/105**、
payload **104 AST / 34 ABI / 30 回滚**、expression **148/36**、element **282/159**、
nested **230/133**、instruction **398/122**、local **252/37**、function **188/136**、
code-begin **284/100**。本节更新 global expression 的当前状态；前文旧批次
保留其验证时范围。其余 import/export AST callbacks、完整 output wrapper、
attached parser/AST/root、reader/factory/bootstrap、独立 signer、fresh 签名及
线上矩阵仍未完成。见 [global expression 证据](evidence/vm9_alternative_ast_global_expression_fresh_20261010.json)。

## 6.27 AST 字符串复制基础（2026-10-10 Asia/Shanghai）

import/export AST 入口共用 `+32a9c4` 字符串复制。本轮先恢复同一 owner 的
`copy_reader_ast_string` 与 `_ReaderAstMemory.copy_string`，通过 **68 个原生/Python
对照、12 个回滚**，每基址 34 项。修改前两项实际行为 RED 覆盖 22 字节 inline
和 23 字节 heap 输入：原生自然返回，Python 缺失入口。

source 首字节低位为零时直接复制全部 24 字节，包括 padding；低位为一时读取
完整 u64 length 和 data 指针，忽略 source capacity word。length <=22 时转为
inline，只写首字节和 length+1 字节 payload，保留其余 destination padding。
length >22 时分配 `(length+16)&~15`，写 capacity|1、length、pointer，再复制
length+1 字节。复制不会额外检查 payload 的最后一个字节。X0 返回值也与原生
一致：inline source 返回 destination，heap 转 inline 返回 destination+1，
新 heap 返回新 buffer。源存储为借用，目标为构造用的新存储；目标已有 heap
资源的释放不属于此入口，调用方必须通过所属对象释放复制结果。

两基址核对自然返回/SP、guest 前 `0xa000`（无屏蔽）、分配尺寸与副作用时
24 字节目标状态。独立预期验证返回地址、padding、容量与 payload；覆盖
长度 0/1/7/21/22/23/24/31/32/63/64/127、两种目标 padding、非零尾字节和
不相关的 source capacity。12 项 guard 覆盖 header/payload 重叠、分配与
source/destination/payload/image 别名、未映射/未对齐计划、缺失 allocator、
payload/分配字节预算及写入失败；全部原始页面回滚，未执行非法原生路径。

所有既有生产函数、class methods、callback、析构与 parser 经 AST 比较保持
一致；新方法尚未被旧回调调用。基础 AST **308/54** 与 global expression
**212/54** 两组回归通过，两份 JSON 逐字节一致。此批只证明字符串复制基础；
import/export 回调、字符串/对象析构组合、完整 output wrapper、attached parser、
reader/factory/bootstrap/signer、fresh 签名和线上验收仍未完成。分配为纯计划，
真实 allocator、异常和整体 stack/TLS/OS 未验证。

见 [字符串证据](evidence/vm9_alternative_ast_string_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_string_20261010.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-string-evidence.json>
```

## 6.28 Export AST 回调与专属输出清理（2026-10-10 Asia/Shanghai）

本轮恢复实际 `+98 → +31d500` export AST 回调，以及仅拥有 export 的
`cleanup_reader_ast_export_output`，直接对照原生 `+2cbadc`。**362 个原生/Python
对照、247 个回滚检查**通过，每基址 181 项。修改前 3 项实际行为 RED
覆盖短名称 spare append、长名称 type growth、已有多类 export 的输出清理；
原生自然返回，Python 缺失对应行为。

五个参数为 ignored index、kind、cache index、借用名称指针和完整 u64 length。
kind/index 取低 u32；kind 0..4 分别选择 callback `+80/+98/+b0/+c8/+e0`，
stride 为 `64/48/40/24/40`。独立节点克隆分别执行 `+321090/+3210d0/
+321120/+321170/+3211c0`：type 两个向量与 kind4 的向量深拷贝，capacity=size；
table 复制 `+c` 的 31 字节，memory 复制 `+10` 的 24 字节，global 复制
`+c` 的 12 字节。type/memory 的 `+c` padding、table 尾部 5 字节保持
目标原字节。kind4 的 `+8` 8 字节完整保留。

输出 `+a8` 为 40 字节记录：名称 24 字节、独立节点指针、u32 cache index，
最后 4 字节 padding 保留目标原字节。长名称有原始、第二临时、输出三份
独立分配。短名称保留入口栈未写入 padding，必须显式传入
`entry_stack_address`，读取 SP-90 的原始 header，并保留整个 90 字节 frame。
length=0 跳过名称指针读取；callback cache 保持不变。

扩容 `+320118` 先构造新项，再倒序复制旧名称并重新克隆旧节点，发布新
vector 后倒序清理旧记录，最后释放旧外块。记录清理先清零节点指针，调用
virtual deleting destructor，再释放 heap 名称。五类删除入口为
`+3212b0/+3212fc/+321300/+321304/+32132c`；回调最后删除临时节点，释放
第二临时名称与原始名称。export 专属输出清理同样倒序删除记录，重置 end
后释放外块，保留原 begin/capacity 的 dangling 值；逻辑释放只能消费一次。
该 API 要求其他输出 headers 全零，完整 output wrapper 尚未恢复。

两基址核对自然返回/SP、完整 guest 前 `0xa000`（无屏蔽）、每次分配/
析构/释放顺序及副作用时 owner bytes。独立预期覆盖五类节点、名称长度
0/1/22/23/24/31/32/64、spare/growth、连续混合 kind、两种 stack padding、
非零空容量指针、空向量/拥有空 buffer，以及精确 node budget 12/18。
247 项 guard 包括参数与实际绑定、所有权、名称/栈别名、预算、每次分配
分别注入无效地址/别名，以及 7 处晚期写入失败；全部原始页面回滚。
kind>4 的原生无效路径及其他非法原生路径均未执行。

共享原生 driver 新增 export 专属 wrapper 与五类 deleting destructor 的
观察；同一生产 owner 抽取字符串复制与节点存储释放，供新组合复用。
**16 组既有回归通过，16 份已发布 JSON 逐字节一致**：global、memory、table、
基础 AST、data、data create/payload/expression、element/nested、instruction、
local、function、code begin、global expression、string。unsupported guard 移至
尚未恢复的 `+28`。其余既有分支与 parser 的 AST 保持一致。

这批全部使用 synthetic fixture 和 fresh ELF，不使用原生输入 snapshot，
未发布私有 payload。分配为纯计划和逻辑效果；真实 allocator、异常以及
整体 stack/TLS/OS 未验证。import `+28/+30/+38/+40/+48`、完整 AST/output wrapper、
attached parser、reader/factory/bootstrap/signer、fresh 签名与线上验收仍未完成。

见 [export 证据](evidence/vm9_alternative_ast_export_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_export_20261010.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-export-evidence.json>
```

## 6.29 Import AST 回调与专属输出清理（2026-10-10 Asia/Shanghai）

本轮恢复五类实际 import AST 回调 `+28/+30/+38/+40/+48`，入口分别为
`+31b870/+31bb48/+31be3c/+31c144/+31c414`，并恢复仅拥有 import 的
`cleanup_reader_ast_import_output`，直接对照原生 `+2cbadc`。
**858 个原生/Python 对照、410 个回滚检查**通过，每基址 429 项。修改前
6 项实际行为 RED 覆盖五类回调与已有多类 import 的专属输出清理；原生
自然返回，Python 缺失对应行为。所有生产实现仍在同一 owner。

共同参数为 ignored index、module 指针/完整 u64 length、field 指针/完整
u64 length、一个 index/unused 参数，以及各入口的类型/descriptor 参数：

| slot | 最后参数 | 原生行为 |
|---|---|---|
| `+28` | function index / type index | 两者取低 u32；从 output type 选择源节点，保存 type/function index |
| `+30` | full u64 type / 栈上的 descriptor 指针 | table；无 maximum 时使用 **zero-extended u32 `ffffffff`** |
| `+38` | X7 的 descriptor 指针 | memory；无 maximum 时选择 `10000` 或 memory64 的 `1000000000000` |
| `+40` | full u64 type / 栈上的 mutable | global；mutable 读取低字节并保留 `&1` |
| `+48` | low u32 output type index | kind4；只复制所选 type 的 params 向量 |

输出 `+18` 为 64 字节记录：module string24、field string24、独立节点指针、
两个 u32 words。只有 `+28` 保存 indexes，其余四类 words 为零。名称先构造
原始存储，再复制到第二临时，最后复制到输出；两个长名称各自拥有三份
分配。length=0 不读取名称指针。节点同样先克隆到临时，再克隆到输出，
释放临时节点和第二/原始名称之后，才独立追加 callback cache。
type/kind4 的输出节点与 cache 向量均独立于借用的 output type；type 的
params/results 深拷贝，kind4 仅复制 params，capacity=size。

实际增长 `+31eb34` 先构造新项，再倒序复制旧名称并重新克隆旧节点，发布
新 vector 后倒序清理旧 import。清理先清零节点指针，调用 deleting
destructor，再释放 field 和 module 名称。cache 则独立扩容，并转移旧
type/kind4 向量所有权，发布后析构旧 cache 记录、释放旧外块；不会重新
分配旧 cache 的 nested vectors。table/memory/global 的实际复制字段与
padding 规则继续沿用所属节点 owner。

入口 frame 分别为 `e0/110/100/f0/100`；短名称与 table padding 必须来自
显式 `entry_stack_address`。table/global 超过 X7 的参数实际写入入口 SP，
模型保留该 incoming word 所占存储。原始/第二临时字符串与临时节点按
实际 frame 位置写入。混合 kind 的一组 fixture 在每次回调前显式初始化
入口 frame；它是合成输入，没有使用原生 snapshot。整个 stack/TLS/OS
仍未比较，也没有恢复未观察的寄存器保存等 stack 效果。

两基址核对自然返回/SP、完整 guest 前 `0xa000`（无屏蔽）、分配/析构/
释放顺序和每次副作用时 AST header owner bytes。独立预期核对名称与容量、
indexes、五类节点字段与 owned vectors、旧 cache 指针转移，以及借用
type/descriptor 不变。覆盖名称长度 0/1/22/23/24/31/32/64/128、四种 output
与四种 cache 状态、两种 stack padding、连续/混合回调、unaligned descriptor、
非零空容量指针、拥有非零容量的空节点向量、旧 heap 短名称转 inline，
以及五类各自精确 node budget 10。858 项中执行 868 次回调、48 次专属
输出清理，334 项含实际栈参数，2 项显式初始化每次调用的 frame。

410 项 guard 覆盖实际 entry/GOT/clone/delete/destructor 绑定、参数、所有权/
别名、逻辑 type index、frame/栈参数、节点与分配预算、callback cache 的
节点类别。21 次分配分别注入 15 类非法地址/别名，共 314 项（首项不含
prior plan）；另有 11 处写入失败和 9 组解除预算后正常通过的配对输入。
全部原始页面回滚，包含已经发布 output 后才失败的 cache append；非法
原生路径均未执行。分配为纯计划，释放为一次消费的逻辑效果。

专属清理要求其余所有 output headers 为零，倒序处理 import、重置 end
后释放外块，保留 dangling begin/capacity；完整 output wrapper 尚未恢复。
共享 driver 增加正确 ARM64 栈传参、显式 frame fixture 和 import 专属 wrapper；
生产 owner 抽取 `copy_node` 供既有 virtual clone 与新 cache copy 复用。
**17 组旧回归、17 份已发布 JSON 全部逐字节一致**，包含上一轮 export。
原 callback 分支、其它已有 class methods、API 和 parser 的 AST 保持一致；
unsupported guard 改为 callback API 未接纳的 `+10`。

全部使用 synthetic fixture 和 fresh ELF，不发布私有 payload，不使用原生
输入 snapshot。真实 allocator/异常、完整 AST/output wrapper、attached
parser/AST/root、reader/factory/bootstrap/signer、fresh 签名及线上验收仍未完成。

见 [import 证据](evidence/vm9_alternative_ast_import_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_import_20261010.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-import-evidence.json>
```

## 6.30 完整 Output wrapper 清理（2026-10-10 Asia/Shanghai）

`cleanup_reader_ast_output` 已恢复实际 `+2cbadc` 对 12 个 output vector headers
的完整清理。**330 个原生/Python 对照、214 个回滚检查**通过，每基址 165 项。
修改前 6 项实际行为 RED 覆盖全部容器混合、单独 kind4、空 import/export
节点指针，两基址自然返回；Python 当时缺失完整 wrapper API。全部实现仍在
`vm9_alternative_startup.py`，没有修改共享原生 driver 或已有 callback/parser。

原生依次清理 `+108/+f0/+d8/+c0/+a8/+90/+78/+60/+48/+30/+18/+0`。

| output offset | stride | 清理行为 |
|---|---|---|
| `+108/+c0` | 1 / 4 | raw/start 仅重置 end、释放外块 |
| `+f0/+d8` | 176 / 184 | 倒序调用 data/element 记录析构，含 nested vectors |
| `+a8/+18` | 40 / 64 | 倒序清零节点指针、deleting destructor、释放名称 |
| `+90` | 40 | 直接写 kind4 vtable、重置/释放内部向量，无 destructor 调用 |
| `+78/+30` | 176 / 144 | 倒序调用 global/function 记录析构 |
| `+60/+48` | 40 / 48 | memory/table 仅重置 end、释放外块，记录字节不变 |
| `+0` | 64 | 倒序 virtual non-deleting destructor，然后释放外块 |

所有外块和内部向量保留 dangling begin/capacity，end 重置为 begin；非零
零容量指针仍会到达 free。仅逻辑记录释放，必须消费一次。清理输出 object
本身、callback cache、retained records 与 attached parser 不属于 `+2cbadc`。
caller 必须将其他保留的地址范围显式列入 `reserved_regions`。

`+90` 在删除前以 GOT `+375088 → +372580` 构造 `+372590` vtable，不读取旧
vtable；已有旧 vtable 字节可以任意。table/memory 同样不读取 vtable 或
节点字段。import/export 的节点指针允许零，但对应名称仍清理；非零节点
保留实际五类节点/绑定/所有权验证。此选项仅完整清理启用，已有 callback
和专属 import/export 清理的默认 validation 保持一致。

验证比较自然 return/SP、无屏蔽完整 guest 前 `0xa000`、析构/deleting/free
顺序及每次副作用的 output header owner bytes。330 次实际 wrapper 共观测
1020 次记录/virtual 析构、896 次 deleting destructor 和 9424 次 free，零分配。
独立预期核对外容器释放顺序、end 重置与 dangling headers、名称 headers
不变、节点指针清零、kind4 vtable 与内部 end、table/memory 记录不变及借用
callback 字节不变。fixture 从合成输入生成，未使用原生 input snapshot。

覆盖每个单独容器、全部容器混合、rich/empty/mixed 嵌套内容、非零空容量
outer pointers、空但拥有容量的 vectors、连续记录与五类 import/export 节点、
空节点指针、inline/heap 名称和 heap 短名称、无意义旧 kind4 vtable、
opaque table/memory fields，以及混合/空节点/kind4 各自精确 node budget
24/14/2。两基址均通过。214 项 guard 包含 66 对容器之间有效的非零空
指针别名、内部向量/名称/节点别名与非法地址、绑定/预算、23 处中途写入
失败和 4 组解除限制后通过的配对输入。最大单块 384 字节通过、383 拒绝。
全部原始页面回滚，非法原生路径不执行。

新 API 复用已有记录析构 owner，只在 import/export validation 增加显式
`allow_null_node=False` 参数。AST 检查证明删去这个 opt-in 参数/分支/转发后，
整个既有 class 与基线一致；已有 callback/parser/API 行为保持一致。
受影响的旧 import/export 回归本轮重新串行执行，**两份 JSON 逐字节一致**，
共 1220 个旧对照和 657 个回滚。其他已有 owner 行为代码没有改动。

全部使用 fresh ELF 与 synthetic fixtures，私有 payload 不发布。真实
allocator/异常、整个 stack/TLS/OS、attached parser/AST/root、完整 reader/
factory/bootstrap/signer、fresh 签名及线上验收仍未完成。

见 [output 清理证据](evidence/vm9_alternative_ast_output_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_output_20261010.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-output-evidence.json>
```

## 6.31 Attached parser 与有界 AST module（2026-10-10 Asia/Shanghai）

`run_reader_ast_module` 首次贯通真实 `+31b360 → +324444 → +324188` 的有界
parser/AST 路径与临时清理。**214 项原生/Python 对照、83 项回滚检查**通过，
每基址 107 项。修改前 10 项实际入口 RED 覆盖短输入、空 module、混合
类型/函数/start、类型中途失败、start 后非法 section；两基址自然返回。
全部生产实现仍由 `vm9_alternative_startup.py` 所有，共享原生 driver 未修改。

目前贯通 generic custom、type、function、start、data-count 与空 export
sections（`0/1/3/7/8/12`）；实际 AST slots 为 `+18/+20/+50/+a0/+160`。
其余 handlers、非空 export、特殊 custom 和 retained-record 构建会回滚拒绝。
output 必须由 caller 提供空的 12 个 headers。导入/定义/表达式/code 等
独立 API 已有恢复，但还需要真实 caller frame 证据才能加入此组合。

| 入口/对象 | 已验证契约 |
|---|---|
| `+31b360` | callback 在 entry SP-`150`，保留 unwritten `+28/+78` padding；retained header 在 callback+`108` |
| `+324444` | parser 在 entry SP-`220`，callback+8 写 parser+8；parser+20 反向绑定 callback |
| prefix | 长度不足 4 的 cursor 为 0，4..7 为 4；达到 8 为 8；不校验 magic 内容 |
| status | 解析失败或 function/code count 不等返回 1；已生成的部分 AST 保留 |
| parser 清理 | 倒序释放 `+70/+58/+40/+28`，end 重置为 begin，begin/capacity dangling |
| callback 清理 | 复用实际 `+31b458`，独立 cache 按原生次序析构/释放；不释放 output |

parser `+8d..8f` padding 保留。显式 frame 输入来自独立合成页面；只比较
parser object 字段、callback/retained headers，saved registers 与整个 stack
不属于模型。caller 的 `varuint_scratch_address` 是显式模型 scratch，
不声称其地址/内容就是原生 caller 的 stack scratch。context 两参数按完整
u64 保留到 callback+`f8/+100`。attached 指针退出后仍 dangling，不清零。

回调与 parser 向量共用一个事务。parser 的 vector effects 与 AST effects
按实际交错顺序返回；实际 vtables、析构、cleanup 都执行，未替换为返回
status 的 AST stub。214 次 module 共观测 **1254 次 allocation、236 次
owned destructor、650 次 free**。自然 return/SP、未屏蔽 guest 前 `0xa000`、
每次副作用 owner bytes、完整 parser 退出字段、callback 清理字节、image
rank/custom globals、回调 arguments/cursor/limit 全部一致。独立预期核对
部分 type/function/start、data reserve、dangling headers、padding 与清理。

输入覆盖长度 0..8、不同 prefix/frame padding、多类型与 params/results
增长/缩小、function/cache 扩容、数量不匹配、所有 type truncation、非法
form/value/envelope、重复/逆序 sections、generic custom 与确定性生成组合。
全部合成，未将私有 payload 或 native snapshot 用作 Python 输入。

83 项回滚覆盖 frames/input/output/scratch/image 地址别名、错误 relocation、
非法预算、缺失映射、当前与之前 allocation 块重叠、7 个中途写失败、未贯通
handlers/非空 export/特殊 custom，以及 attached 双向绑定/输入/向量错误。
短输入也验证资源限制。非法原生内存路径不执行。`allocate` 必须只规划已
映射的对齐块，**所有规划地址均不得复用，包括已经逻辑释放的临时块**；
这是当前组合的明确限制。logical free 不 poison/unmap，effects 只能消费一次。

`run_reader_ast_callback` 和 `cleanup_reader_callback` 增加显式
`attached_state_address=None`；默认仍拒绝 attached state。只有上述五个
slots 允许 attached opt-in；parser vectors/input 保留并检查独立所有权。
`run_reader_sections` 的私有 `_ast_callback` bridge 只供 module 在 parser
事务中调用实际 AST；原有普通 callback 仍是 pure status service。
AST 结构检查删去这些精确 opt-ins 后，所有既有默认分支与提交基线相同。
旧 section 与 AST/cleanup 两组串行重跑，**510 项对照、66 项回滚通过，
两份历史 JSON 逐字节一致**；未重复声称其余未重跑的历史批次。

观测器初次漏记 function 扩容调用 `+2cc470` 的 144 字节析构，补齐后对照
通过；生产回调行为没有因此修改。整套证明仅覆盖 fresh ELF 和显式 host
allocation/free/memory service；真实 allocator/异常、整个 stack/TLS/OS、
其余 attached handlers、parse/root、完整 reader/factory/bootstrap、独立 signer、
fresh 签名与线上验收仍未完成。

见 [module 证据](evidence/vm9_alternative_ast_module_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-evidence.json>
```

## 6.32 Heap 名称函数 import 的 attached AST 组合（2026-10-10 Asia/Shanghai）

`run_reader_ast_module(..., enable_function_imports=True)` 现在贯通真实
`+31b360 → +324444 → +322cf8 → +31b870` 的函数 import 与临时清理。
**180 项原生/Python 对照、43 项回滚检查**通过，每基址 90 项。
修改前绑定 `a6ac2db` 的 6 项实际入口 RED 覆盖单条 import、三条扩容、
import 后 defined function/start；自然返回后原有 Python 组合拒绝并回滚。

该开关默认 `False`。开启时，完整函数 import 的 module 与 field 名称
必须**均不少于 23 字节**，让两个字符串 header 都走完整写入的 heap 路径。
短名称、其他 import kind 及未贯通 handlers 仍回滚拒绝。空 import section
和解析中途失败也验证；解析失败返回 1，已完成的 import AST 保留。
output 初始为空、allocation 地址不得复用等既有 module 限制继续适用。

| 对象/入口 | 本轮已验证契约 |
|---|---|
| parser state | module entry SP-`220` |
| function import callback | slot `+28`，entry SP 为 state-`100` |
| callback frame | `0xe0` 字节，从 state-`1e0` 开始 |
| caller frame 保留 | 开关开启即要求 `[state-1e0, state)` 完整映射，禁止 input/output/scratch/reservations/allocations 重叠 |
| import output | 两个独立 heap 名称、独立克隆 type 节点、type/import indexes；扩容时倒序克隆旧 records |
| 临时清理 | parser vectors 清理后再清理 callback import cache；保留 output 所有权 |

180 次 module 共观测 **6644 次 allocation、702 次 owned destructor、
496 次 deleting destructor、4430 次 free**。实际 parser、AST vtables 与
清理执行，未替换为返回 status 的 AST stub。自然 return/SP、未屏蔽 guest
前 `0xa000`、有序 effects 及各次 owner bytes、parser 退出字段、callback
清理字节、image globals、callback arguments/cursor/limit 全部一致。
独立预期另检查名称内容/容量、节点及 params/results 克隆、indexes、
部分输出、defined function 数量与 cache 清理。

输入覆盖名称长度 `23/24/31/32/63/64/127/128`、三种 caller padding、
空/params/results/rich 类型、1..4 条 import、output/cache 扩容及 spare
capacity、后续 defined functions、custom/start/data-count、最后一条 import
截断、重复/逆序/非法 section envelope，以及固定种子的生成组合。
全部 fixture 独立合成；不将真实 callback frame snapshot 喂给 Python。

43 项回滚检查覆盖 opt-in 类型/默认、两名称短边界、其他 import kind、
无效 type index、错误 vtable binding、caller frame 缺页/别名/下溢、预算、
10 个既有 allocation 复用和 5 个真实中途写失败。失败注入点最初选了三条
import 不会触发的 8 字节 end 写入；改为第四条复用 spare capacity 后，
确实命中并完整回滚。这是测试注入点修正，未据此修改生产行为。

`run_reader_ast_callback` 的显式 attached 允许集合增加 `+28`，仍要求独立
entry stack/frame 与双向 parser/callback binding。默认 detached 行为不变。
AST 结构检查只去除新增开关、frame 检查、slot 与 forwarding，证明全部
旧可执行分支与提交基线相同。旧 module 与独立 import 两组串行重跑，
**1072 项对照、493 项回滚通过，两份历史 JSON 逐字节一致**。

本轮没有恢复连续短名称的 caller 栈残留，也没有恢复 table/memory/global
imports、definitions、其余 expressions/code 的 attached 组合。整个原生
stack、saved registers、TLS/OS、真实 allocator/异常、parse/root、完整
reader/factory/bootstrap、独立 signer、fresh 签名与线上验收仍未完成。

见 [函数 import module 证据](evidence/vm9_alternative_ast_module_function_imports_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_function_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-function-imports-evidence.json>
```

## 6.33 Inline 名称函数 import 与真实 caller 栈写入（2026-10-10 Asia/Shanghai）

`run_reader_ast_module(..., enable_function_imports=True,
enable_inline_function_imports=True)` 现在贯通短名称、空名称和长短名称混用的
真实函数 import AST 路径。**448 项原生/Python 对照、64 项回滚检查**通过，
其中 12 项移动 module entry SP；282 项还独立推导并检查全部 inline padding。
修改前绑定 `c32ac6d` 的 12 项实际入口 RED 覆盖空/1/7/22 字节、连续扩容和
长短混用；真实 module 自然返回，原有 Python 组合拒绝并完全回滚。

新增开关默认 `False`，必须同时开启 `enable_function_imports`。原有
heap-only 模式及默认 module 行为不变。生产 owner 仍只有
`vm9_alternative_startup.py`；没有将 native frame snapshot 作为 Python 输入。

短名称只覆盖 24 字节 header 的长度、内容和终止字节，尾部 padding 会带入
caller 先前写过的栈字节。实际写入观测结合指令证明以下三处来源，生产按
当前 parser state、image base 和 type params/results 数量恢复它们：

| 原生写入 | 后续进入 import header 的值 |
|---|---|
| `+31e888` | type callback FP 为 state-`110`，LR 为 image+`31b778`；保存到 import frame+`20/+28` |
| `+31e88c` | 保存 x23 到 frame+`30`；params 非空时为 params 字节数，否则为 parser result-vector header（state+`40`） |
| `+32a1f8` | type params/results 至少一个非空时，allocator 包装器保存其 node pointer（state-`150`）到 frame+`10` |

连续 import 原本已经保留同一 caller frame，因此后续短名称继续保留前一条
名称未覆盖的字节。type 回调完成后补齐上述保存写入，再由既有真实字符串
构造/复制及节点克隆实现消费。附加 `[state-1e0, state)` 映射、地址别名和
allocation 限制继续适用。只恢复影响当前输出 padding 的 helper save stores；
整个 stack、其余 saved registers 与 TLS/OS 仍不属于模型。

448 次 module 共观测 **9508 次 allocation、1292 次 owned destructor、1106 次
 deleting destructor、6076 次 free**。真实 parser、AST vtables、临时和 cache
清理执行，未替换为 AST status stub。自然 return/SP、未屏蔽 guest 前
`0xa000`、有序 effects 和逐次 owner bytes、parser 退出字段、callback 清理、
image globals、arguments/cursor/limit 全部一致。另独立核对名称、节点及类型
向量克隆、type/import indexes、部分 AST、defined function 数量与 cache 清理。

输入覆盖 `0/1/7/8/15/16/21/22/23/24/32` 字节边界、三种 frame padding、
空/params/results/rich 类型、type 数量及向量增减、1..6 条 import、名称
增长/缩短/长短交替、output/cache 扩容与 spare capacity、后续 defined
functions、generic custom/start/data-count、截断/重复/逆序/非法 envelope
以及固定种子生成组合。两种额外 entry SP（含 frame 跨页）各在两个 image
base 上执行，证明 frame 指针来自当前 caller 布局。另 6 项私有原生对照验证
空 type 前后不同长度 generic custom，不计入上述公开 448 项。

64 项回滚包含原有 43 项 guard，以及 21 项 inline opt-in 类型/依赖、资源
预算、地址别名、下层独立页面缺失、其他 import kind/非法 type index 和
6 个实际写入失败。新增写失败覆盖三处 type helper saves、两个原始名称
headers 和 spare-capacity end 发布；所有页面逐字节回滚。非法原生内存路径
不执行。解析失败仍返回 1 并保留已完成 AST，output 所有权保留。

AST 结构检查只移除新增 opt-in、条件及 helper save stores，证明默认和
heap-only 可执行分支与 `c32ac6d` 相同。旧默认 module 与 heap-name import
两组串行重跑，**394 项对照、126 项回滚通过，两份历史 JSON 逐字节一致**。
未重复声称其他未重跑历史批次。原生批次之后仅澄清 docstring 模型边界，
可执行 AST 未改变。

其他 import 种类、definitions、其余 expressions/code 的 attached 组合、
parse/root、完整 reader/factory/bootstrap、真实 allocator/异常、独立 signer、
fresh 签名与线上验收仍未完成。

见 [inline 函数 import 证据](evidence/vm9_alternative_ast_module_inline_function_imports_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_inline_function_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-inline-function-imports-evidence.json>
```

## 6.34 Table/memory/global import 的 attached AST 组合（2026-10-10 Asia/Shanghai）

`run_reader_ast_module(..., enable_table_memory_global_imports=True)` 现在贯通
真实 module/parser 的 table、memory、global import AST 与清理。**406 项
原生/Python 对照、72 项回滚检查**通过，含 12 项 entry SP 移位。修改前
绑定 `8b8240f` 的 16 项实际入口 RED 覆盖三类单独 import、memory64 和
四类混合：原生自然返回，旧 Python 组合拒绝且全页面回滚。

新开关默认 `False`，独立于 function-import opt-in。开启后所有 import 的
module/field 名称均需至少 23 字节；混合 function import 仍需开启原有
`enable_function_imports`。短名称和零条目 type section 后的其他 import
继续回滚；type 节点的空参数/空结果向量已经支持。两个私有原生观察确认
零条目 type section 会把入口 `X22` 带入 global 第九参数，其高位不是
固定零值；当前模型未接收该寄存器，因此这个组合未开放。

callback entry SP 为 state-`100`；table/memory/global frame 分别为
`110/100/f0`。保留整个 `[state-210, state)`，与 input/output/varuint
scratch/reservations/allocations 独立，禁止重用任何已计划 allocation 地址。
descriptor 使用真实 SP+`8`（state-`f8`），首 19 字节由 parser 写入，尾
5 字节保留 caller 内容。table 节点 clone 只复制 descriptor 前 19 字节，
尾部保留 destination；memory clone 复制全部 24 字节。有界 AST 解析失败
返回 1 并保留已完成 import；guard 回滚全部页面。parser vectors 先清理，
callback caches 后清理，output 继续拥有其分配。

| 原生写入来源 | 恢复的当前 caller 内容 |
| --- | --- |
| `322f18` | table 第九参数写入 descriptor 指针 |
| `323024` | global 第九参数只覆盖低字节，保留原高字节 |
| `31b6d8` / `31b6dc` | type caller 的参数数量/type index，影响后续参数和 descriptor 尾字节 |
| `31e894` | type helper 保存 output pointer，其高 word 进入 table padding |
| `31c2e0` / `31c2fc` | global 临时 clone 释放后清空其 word，影响下一 table padding |

上述值由独立 caller 地址、fixture 内容和当前 AST 输入推导，未喂入 native
frame snapshot。其余 saved registers、整个 stack/TLS/OS、真实 allocator
及异常/abort 仍未恢复。四类 import 的 24 种顺序、连续 1..6 条、独立
output/cache 扩容与 spare capacity、名称 23/24/31/32/63/64/127 边界、
table/memory limits 与 memory64、全部可接受 global type/mutable、type
caller 变化、generic custom/start/data-count、截断/重复/逆序/非法 envelope
和固定种子生成组合均通过。72 项 guard 含 13 项实际中途写入失败。

共观察 **9426 次 allocation、896 次 owned destructor、
1138 次 deleting destructor、6442 次 free**。自然 return/SP、
未屏蔽 guest 前 `0xa000`、有序 effects/每次 owner bytes、parser exit、
callback cleanup、image globals、全部 arguments/cursor/limit 一致。另独立
核对名称、克隆节点、默认 maximum、counts、table padding、descriptor 尾部、
第九参数和 cache 清理。两个 image base 和两种额外 entry SP 均有对照。

旧默认 module、heap function import、inline function import 三组 **842 项
对照、190 项回滚**通过，三个历史 JSON 逐字节一致。AST 范围检查只移除
精确新 opt-in、caller stores、verified slots 后，确认旧分支与 `8b8240f`
一致。短名称其他 import、definitions/expressions/code、parse/root、完整
reader/factory/bootstrap、独立 signer 和线上验收仍未完成。
见 [本轮 import 证据](evidence/vm9_alternative_ast_module_other_imports_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_other_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-other-imports-evidence.json>
```

## 6.35 短名称其他 import 与 caller 栈传递（2026-10-11 Asia/Shanghai）

`run_reader_ast_module(..., enable_table_memory_global_imports=True,
enable_inline_table_memory_global_imports=True)` 现在贯通 table/memory/global
import 的空名称、短名称、长短混用和连续组合。**612 项原生/Python 对照、
41 项回滚检查**通过，含 12 项 entry SP 移位和 436 项独立完整 inline
padding 检查。验证于 10 月 10 日开始，跨日完成于 10 月 11 日；证据和
verifier 的文件日期沿用开始日期。修改前绑定 `08f9b02` 的 14 项实际入口
RED 均为原生自然成功、旧 Python 拒绝并全页面回滚。

新开关默认 `False`，需要 `enable_table_memory_global_imports=True`。
短名称其他 import 无需 function 开关；混合 function import 仍需
`enable_function_imports=True`，其短名称还需
`enable_inline_function_imports=True`。原有三个开关的默认行为保持一致。
零条目 type section 后的其他 import 仍依赖未建模的入口 `X22`，继续
回滚；一个或多个 type 节点的空参数/空结果向量已经支持。

短字符串仅覆盖长度、内容和终止字节，剩余 header padding 继承真实
caller 的保存、复制和清理写入。下面的来源按当前 state/image/AST
字段、type 数量与 parser 事件推导，**没有把原生 frame snapshot 喂入
Python**。原有 `[state-210, state)` 保留和 alias/allocation 限制继续适用。

| 原生来源 | 本轮恢复的字节 |
| --- | --- |
| `32a1f4`，来自 `31e888` 的最后非空向量复制 | state-`1e0` 的 FP/LR；空向量保留前次值 |
| `31ed20` / `31eea4` | function cache 增长/剩余容量路径保存的 FP/LR、type index、旧 cache end、source type 和 callback pointer |
| `31b8b8` / `31ba74` | function 的 field input pointer 和临时 clone 清零 |
| `31bd0c` / `31bd28` | table 第二个临时 clone 释放后清零，进入后续 function 名称 padding |
| `32a9d4` / `31f140` / `31c058` | memory 保存 callback pointer 并清零临时 clone，进入后续 table 名称 padding |
| `32a9d4` / `31f2d0` / `31f2d4` | global 保存第二 field header、旧 output end 和 callback pointer，进入后续 table/memory 名称 padding |

沿用已经恢复的三处 type-helper 保存、type 参数数量/index、descriptor
尾字节和第九 ABI 参数来源。四类 import 全部 24 种顺序、0/1/7/8/15/
16/21/22/23/24 名称边界、四种 type 向量形状、1..6 条连续增长、长短
互换、type lineage、custom/start/data-count、默认 maximum、memory64、
global type/mutable、截断、非法类型/flags、重复/逆序/envelope、后续
function section 的部分输出及固定种子 `31f2d4` 生成组合均通过。
非零 function type index 的 caller 传递另经私有合成对照核对。

共观察 **12736 次 allocation、1506 次 owned destructor、
2004 次 deleting destructor、8268 次 free**。自然 return/SP、
未屏蔽 guest 前 `0xa000`、有序 effects/每次 owner bytes、parser exit、
callback cleanup、image globals、全部 arguments/cursor/limit 一致。独立
核对名称、克隆节点、默认 maximum、counts、descriptor 尾字节和第九参数；
全部 inline 的组合还独立推导整个 24 字节 header 和 table padding。
41 项 guard 含 12 项模型中途写入故障，均回滚全部页面。

旧默认 module、heap function、inline function、长名称其他 import 四组
**1,248 项对照、262 项回滚**通过，四份历史 JSON 逐字节一致。AST 范围
检查仅移除新 opt-in 和六组 caller-store 分支后，确认旧可执行分支与
`08f9b02` 一致。整个 stack、其他 saved GPR、TLS/OS、真实 allocator/
异常、definitions/expressions/code 的 attached 组合、parse/root、完整
reader/factory/bootstrap、独立 signer 和线上验收仍未完成。
见 [短名称其他 import 证据](evidence/vm9_alternative_ast_module_inline_other_imports_fresh_20261010.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_inline_other_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-inline-other-imports-evidence.json>
```

## 6.36 Table/memory definitions 的 attached AST 组合（2026-10-11 Asia/Shanghai）

`run_reader_ast_module(..., enable_table_memory_definitions=True)` 现在贯通
section 4/5、真实 table/memory AST reserve/entry 和 callback cache 清理。
**470 项原生/Python 对照、32 项回滚检查**通过；含 12 项 SP 移位、
12 项整个 guest 搬到高位地址的对照，以及 1142 个独立完整 record 检查。
本阶段 fixture 均为合成输入，没有实际 ELF definitions payload 对照。
修改前绑定 `43ed463` 的 10 项实际 module 入口 RED：原生自然返回 0，
旧 Python 拒绝 definitions 并回滚全部页面。

新开关默认 `False`，不依赖 import 开关。需要 imports 的组合仍分别开启
已有 import/inline 选项。definition index 加上已有同类 import 数量，
definitions 不增加 import counts。零条目 type section 后的 definitions
已验证；此前零条目 type 后其他 import 的寄存器限制继续适用。

table callback entry SP 与 descriptor 均为 `state-0xc0`，memory 均为
`state-0xe0`；两者 callback frame 均为 `0xb0` 字节。新开关保留映射、
独立的 `[state-0x210,state)`。table padding 取自 `state-0x13c`；table
复制 descriptor 的 19 字节，memory 复制全部 24 字节，尾五字节保留 caller
的真实保存。下面的值来自独立 caller/AST 输入，未使用原生 frame snapshot。

| 原生来源 | 恢复的来源与用途 |
| --- | --- |
| `322704/32270c`、`32298c/322994`、`322cfc/322d04` | generic custom/type/import 保存 dispatcher FP 和输入 limit，进入 descriptor 尾字节 |
| `31b7b8` | type 的 moved parameter clone 清零，进入 table padding |
| `31b87c/31bb54/31be48/31c150` | import 的 X26 为 descriptor pointer；memory 的 flag bit 1 已拒绝，保存零 |
| `31c7c0/31c7c8/31f798` | function definition 保存 dispatcher X24=1/local index，清空 moved local vector |
| `31c9fc` | table reserve 保存 section count，进入后续 memory 尾字节 |

空/多条目、reserve/cache 增长与剩余容量、三个 table 类型、四种 flags、
u32/u64 边界、memory64 与默认 maximum、type 向量形状、四类 imports、
function definitions、generic custom 插入、start/data-count、warm rank、
部分输出、截断、非法 flags、重复/逆序/envelope 和固定种子 `3231e4`
生成组合均核对。高位 guest 对照覆盖 descriptor pointer、FP 的高字节，
以及 custom/function 后的 caller 传递。

全部未屏蔽 guest `0xa000`、ordered effects/每次 owner bytes、parser exit、
callback cleanup、image globals、arguments/cursor/limit、自然 return/SP
均匹配。独立推导 descriptor、尾字节、table padding、完整 owned record、
默认 maximum 和 import index；没有把原生观察数据作为模型输入。
观察 3854 次 allocation、2066 次 owned destructor、
224 次 deleting destructor、2432 次 free。
32 项 guard 含 7 项模型中途写入故障，均回滚全部页面。

五组旧 module/import 回归及 standalone section/table AST/memory AST 共
**2,582 项对照、463 项回滚**通过，八份历史 JSON 逐字节一致。
唯一生产 owner 仍为 `vm9_alternative_startup.py`，修改限于 attached allowlist、
私有 definition frame binding 与 module opt-in；其他运行函数 AST 不变。
整个 stack、其他 saved GPR、TLS/OS、真实 allocator/异常、global expression/
code 的 attached 组合、parse/root、完整 reader/factory/bootstrap、独立 signer
和线上验收仍未完成。见 [definitions 证据](evidence/vm9_alternative_ast_module_definitions_fresh_20261011.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_definitions_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-definitions-evidence.json>
```

## 6.37 Global definitions 与初始化表达式的 attached AST 组合（2026-10-11 Asia/Shanghai）

`run_reader_ast_module(..., enable_global_definitions=True)` 现在贯通 section 6、
global reserve/entry、expression begin/end，以及 end/i32/i64/f32/f64 的实际
AST 回调与清理。**398 项原生/Python 对照、37 项回滚检查**通过，含 12 项
SP 移位、12 项整个 guest 移至高位地址的对照及 780 个独立完整 global
record 检查。包含 394 项合成输入和 4 项实际 ELF global payload 对照；
实际 section 6 为 133 字节、22 个 globals，由私有样本运行时读取，未发布 payload。

修改前绑定 `829e458` 的 18 项实际 module 入口 RED：原生自然返回 0，
旧 Python 拒绝 section 6 并回滚全部页面。新开关默认 `False`，独立使用；
组合 imports 或 table/memory definitions 时仍分别启用已有开关。
定义索引加已有 global import 数量，definitions 不增加 import counts。
`max_initializer_ops` 默认 4096，按每个表达式计数，包含 end。

| 实际原生来源 | 恢复行为 |
| --- | --- |
| `323464` global handler 的 `0x40` frame | callback entry SP 与 caller result 均为 `state-0xb0` |
| `32365c` initializer 的 `0x60` frame，`3236f0/32376c/3237b8` | 指令 callback entry SP 为 `state-0x110`；整数读取 scratch 为 `state-0x108` |
| `323510/323524` 与 `3235e0` | type 只改 caller word 的低 4 字节；expression end 传完整 64 位结果 |
| `3237ac/3237f8/3236a8` | 成功常量替换全部 8 字节；i32/f32 为零扩展，f32/f64 保留原始 bits |
| `3241cc/3241d0` 与 `3232e4` | memory handler 将 dispatcher X25=`image_base+0x1210f8` 保存到 caller result；后续 end-only global 保留其高 32 位 |
| 既有 custom/type/import/function caller stores | 继续提供 end-only global 的高位来源，不注入原生 snapshot |

新开关保留映射且与输入、输出、scratch、reservations、allocation 分离的
`[state-0x2a0,state)`，覆盖 global entry callback 的 `0x1f0` frame。
私有 section bridge 使用真实 caller/result 和 initializer read 地址；
前置 descriptor 与 global result 的复用仅在已验证 attached 组合中开放。
standalone section parser 的显式 16 字节 scratch/status-service 合同保持有效。

检查覆盖七种 global types、mutable 0/1、u32/u64 与浮点原始位边界、空和
多条目、缓存增长与剩余容量、四类 imports 的短/长名称、type 向量、
function/table/memory definitions、generic custom、start/data-count、warm rank、
多常量与 end-only 高位继承，以及截断 count/type/constant、非法 mutable/
opcode/prefix、重复、逆序和 envelope。固定生成种子为 `32365c`。

完整未屏蔽 guest `0xa000`、ordered effects/owner bytes、parser exit、callback
cleanup、image globals、callback arguments/cursor/limit、自然 return/SP 均匹配。
独立推导完整 176-byte global record、type result vector、raw 常量串、
global index、caller high word 和最终 full-u64 result。观察到
6122 次 allocation、1538 次 owned destructor、
192 次 deleting destructor、4120 次 free。
37 项 guard 含 7 项中途写入故障，均回滚全部页面。

五组受影响旧回归（module、table/memory definitions、global AST、global
expression AST、standalone globals）共 **1,614 项对照、315 项回滚**
通过，五份历史 JSON 逐字节一致。唯一生产 owner 仍为
`vm9_alternative_startup.py`，修改限于三个现有函数。

整个 stack、其他 saved GPR、TLS/OS、真实 allocator/异常、code/其他剩余
attached handlers、parse/root、完整 reader/factory/bootstrap、独立 signer 和
线上验收仍未完成。见 [global module 证据](evidence/vm9_alternative_ast_module_globals_fresh_20261011.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_globals_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-globals-evidence.json>
```

## 6.38 Code definitions 的 attached AST 组合（2026-10-11 Asia/Shanghai）

`run_reader_ast_module(..., enable_code_definitions=True)` 贯通 section 10 的
metadata、local groups、raw words、function begin/end 与实际 AST 清理。
**256 项原生/Python 对照、42 项回滚检查**通过，包含 12 项 SP 移位、
12 项整个 guest 移至高位地址的对照、362 个独立完整 function records
和 340 个独立完整 child records。原始指令字只保存，不执行。

修改前绑定 `052c54b` 的 10 项真实 RED：实际 module 自然返回 0，旧 Python
拒绝 section 10 并回滚全部页面。新开关默认 `False`，可独立启用；混合
imports、table/memory definitions、globals 时仍需各自开关。code count
必须等于 function definition count，body index 加已有 function imports。

| 实际原生来源 | 恢复行为 |
| --- | --- |
| `323ca8` 的 `0x70` handler frame | dispatcher SP 为 `state-0x70`，五个 code callback 均在 `state-0xe0` 进入 |
| `31d7d8` 的 `0x70` frame | slot `+a8` 选择 function、写 metadata/raw offset，建立 56-byte child |
| `31d97c` | slot `+b0` 保存 group count，同时清零 cumulative locals |
| `31d984` 的 `0x60` frame | slot `+b8` 追加完整 type/count/cumulative local record |
| `31dbc0/31dbc4` | slot `+f8` 清空 active function 指针，保存 body remaining length |
| `31e5e4` 调用 `32136c` | slot `+168` 将 u32 原始指令字追加到 raw vector |

保留映射且独立的 `[state-0x210,state)`；启用 globals 时沿用较大的
`[state-0x2a0,state)`。`max_code_words` 默认 65536，允许 1 至 1048576，
预算跨整个 code section 的所有 bodies。输入只剩 0 至 3 字节而 body
尚未结束时，原生反复产生零且游标不前进。另有 **8 项原生观察**在第 4 次
word callback 入口主动截停，确认零值、游标和剩余字节数；这些观察没有
自然返回或清理验证，未计入上述 256 项对照。Python 达到预算时全部页面回滚。

248 项合成对照覆盖七种 locals types、u32 metadata/count 边界、空 bodies、
向量增长、累计溢出、四类 imports 与长短名称、table/memory/global/custom
组合、warm rank、重复与逆序 section、截断/非法 metadata/groups/type、
body 长度错位和部分 AST 保留。固定生成种子为 `323ca8`。
8 项实际输入对照从私有 ELF 的 218682-byte / 121-body code section 中
选择三个完整小 body：各自独立运行，并组成带合成 global 前缀的组合。
声明和前缀为合成输入；未运行完整实际 code section 的 attached AST，
未发布实际 payload、metadata 或 raw word 值。

完整未屏蔽 guest `0xa000`、ordered effects/owner bytes、parser exit、callback
cleanup、image globals、callback arguments/cursor/limit、自然 return/SP 均匹配。
独立构造完整 144-byte function record、56-byte child、type vectors、locals、
metadata、code offset、body length 与 raw bytes。观察到 6458 次
allocation、780 次 owned destructor、104 次 deleting
destructor 和 3560 次 free。42 项回滚含 7 项中途写入故障，
覆盖 local group/reset、cumulative locals、frame/raw publication、end/cleanup。

四组旧回归（module、attached globals、standalone code、code-begin AST）共
**1,124 项对照、235 项回滚**通过，四份历史 JSON 逐字节一致。
旧 module verifier 的 unsupported attached slot guard 从 `+b0` 改为仍关闭的
`+100`，因为本阶段已验证并开放 `+b0`；guard 标签和回滚断言不变。
唯一生产 owner 仍为 `vm9_alternative_startup.py`，修改限于两个现有函数。

其余 attached handlers、parse/root、完整 reader/factory/bootstrap、整个
stack/TLS/OS、真实 allocator/异常、独立 signer 和线上验收仍未完成。
见 [code module 证据](evidence/vm9_alternative_ast_module_code_fresh_20261011.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_code_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-code-evidence.json>
```

## 6.39 长名称 export 的 attached AST 组合（2026-10-11 Asia/Shanghai）

`run_reader_ast_module(..., enable_exports=True)` 现在贯通 section 7 的
`+98 → +31d500` export AST、克隆、扩容及 module/parser/callback 清理。
本阶段支持 **名称长度至少 23 字节**、kind 0/1/2/3 的 function/table/memory/
global export；每个 index 必须位于已有逻辑 cache。新开关默认 `False`，
不隐式启用 import、definition、global 或 code。kind 4 保持原生解析失败。

**294 项原生/Python 对照、46 项回滚检查**通过，含 12 项 SP 移位、
12 项整个 guest 移至高位地址的对照、618 个独立完整 export records
及 618 个完整克隆节点检查。修改前绑定 `928ba4d` 的 16 项真实 RED：
实际 module 自然返回 0，旧 Python 拒绝 export callback，全部页面回滚。

| 实际原生来源 | 恢复行为 |
| --- | --- |
| `3238b0` 的 `0x60` handler frame；`3239e0/3239e4` | dispatcher SP=`state-0x70`，export callback 在 `state-0xd0` 进入 |
| `31d500` 的 `0x90` frame | 直接 frame 起点与名称临时 header 均为 `state-0x160` |
| `31d5b4` 的长度 23 分支 | 23 字节起使用 heap string；短名称只覆盖长度标记、正文和终止零，未覆盖的 header 尾部保留 |
| `31d5ec/31d5f0` | heap 路径完整覆盖 24-byte header，无需把原生栈 snapshot 作为输入 |
| `31d644` 与既有虚表 clone | 输出拥有独立 node/type vectors，cache 仍由 callback 拥有 |

export 开关保留映射且独立的 `[state-0x210,state)`，与 globals 组合时保留
较大的 `[state-0x2a0,state)`。名称、output record、克隆节点和 type vectors
均验证独立所有权。输出 vector 按 40 字节记录增长；已生成输出在普通解析
错误后保留，guard 或中途写入故障则回滚全部页面。

全部对照为合成输入，覆盖四类 imports 和 definitions、混合长短 import
名称、23/24/31/32/33/63/64/127/128/255 字节 export 名称、内嵌零字节、
spare/growth、type vectors、table/global types、memory64/default maximum、
global initializer 与 code、warm rank、generic custom、截断/非法 kind/index
编码、重复/逆序/envelope、partial AST 和 function count mismatch。
生成种子为 `3238b0`。未将无效逻辑 index 送入不安全的原生 cache 路径。

完整未屏蔽 guest `0xa000`、ordered effects/owner bytes、parser exit、callback
cleanup、image globals、arguments/cursor/limit、自然 return/SP 均匹配。
独立构造整个 40-byte export record、名称容量/内容/index，核对完整 cloned
node 与 borrowed cache，并从输入独立推导 type vectors、types/mutable 和
limits。观察到 10816 次 allocation、730 次 owned
destructor、1658 次 deleting destructor 和 7042 次 free。
46 项回滚包含 6 项中途写入故障，以及开关、短名称、逻辑 index、虚表、
frame/mapping、allocation alias 和预算检查。

**短名称 export 尚未恢复。** 前置 import/definition/global 会把不同的 caller
字节留在 `[state-0x160,state-0x148)`；目前不能用统一零值或固定 padding
代替。运行时从私有 ELF 读取的 121 个实际 export 名称全部不超过 22 字节；
一个实际短名称进入合成边界用例，确认拒绝并完整回滚。实际 ELF 非空 export
原生/Python 对照数仍为 **0**，未公开名称或 payload。

三组旧回归（module、attached code、standalone export AST）共 **832 项
对照、372 项回滚**通过，三份历史 JSON 逐字节一致。生产修改仍限于
`vm9_alternative_startup.py` 的两个现有函数，section parser 未修改。
下一步恢复短名称 caller 来源，再推进其余 attached handlers、parse/root、
完整 reader/factory/bootstrap、整个 stack/TLS/OS、真实 allocator/异常、独立 signer 与线上验收。
见 [export module 证据](evidence/vm9_alternative_ast_module_exports_fresh_20261011.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_exports_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-exports-evidence.json>
```

## 6.40 短名称 export 的 attached AST 组合（2026-10-11 Asia/Shanghai）

`run_reader_ast_module(..., enable_exports=True, enable_inline_exports=True,
entry_x28=...)` 恢复 section 7 的 0..22 字节名称。`enable_inline_exports`
默认 `False`，要求显式传入原生入口 X28；其余开关保持独立。
四类 export 继续验证逻辑 cache index，输出克隆和 cleanup 自然执行。

绑定修改前 `9e8ac9f` 的 **16 项真实 RED**：原生自然返回 0，旧 Python
拒绝短名称并回滚所有页面。冻结代码后 **386 项原生/Python 对照、25 项
回滚检查**通过，含 12 项 SP 移位、6 项高位 guest、884 个完整
40-byte export records 和 884 个完整 cloned nodes。

| 原生写入来源 | 恢复的 header 字节 |
| --- | --- |
| `31b6f4/31b724/31b72c/31b84c/31b7ac` | type 临时参数 vector 的 begin/capacity 与 vtable |
| `31b874/31bb4c/31be40/31c148` | import FP/LR；前三类保存 X28，global 保存 X27 |
| `322f40/3230bc` | memory import 用 flags 改写 X28；X27 恢复为 image+1210ef |
| `31f778/31f794` | function 移动后清空 type vector |
| `31cb44/31cb10` | table descriptor[4:19] 与 vtable；byte 15 保留 |
| `31cdec/31ce0c/31ce3c` | memory kind、min/max 与默认上限 |
| `31d0b8/31d0c0/31d0c4` | global 嵌套 function 初始字段 |
| `32140c/321494/3214b4/2db2c4` | initializer FP、raw opcode 与 32-bit 参数保存 |
| `31d5c8/31d5ec/31d5f0/31d60c` | export 名称及终止零；后续名称继承未覆盖尾部 |

名称 header 仍为 `[state-0x160,state-0x148)`。模型只根据输入、显式入口
寄存器及上述原生 stores 恢复内容；每次 callback 前把模型 header 与原生
header 作完整断言，原生快照从未作为模型输入。inline record 尾部再与
原生 entry header 对照；名称、index、capacity、type vectors 与 limits
独立从输入检查。完整未屏蔽 guest、ordered effects/owner bytes、parser
exit、callback cleanup、image globals、arguments/cursor/limit 和自然返回/SP
一致。观察到 allocation 9092、destroy 2016、
delete 1990、free 5350。

**实际 ELF 的完整 121 条 export payload** 在两个基址通过；名称和 index
保持原样，声明与 code 为合成输入。测试器为此增加独立 1 MiB guest heap，
全区域逐字节比较。首次试验发现原有 oracle 仅返回前 `0xa000` 字节，已用
`observed_memory` 显式读回扩展 heap；生产代码无需为该测试器问题修改。
这不代表实际完整 module/code 已恢复。实际名称与 payload 未进入公开 Git。

合成对照覆盖每种 kind 的全部 0..22 名称长度、内嵌零、非零/全一 X28、
memory 后不同 import、连续长短名称、type/function/table/memory/global、
generic custom、空 section、部分输出后的解析失败与生成场景。25 项
回滚覆盖 opt-in、入口寄存器类型/范围、逻辑 index、frame alias、预算和
6 项中途写入失败。两组旧回归（heap export module、standalone export AST）
共 **656/293**，历史 JSON 逐字节一致。生产修改仅两个现有函数；
section parser 未改。

接下来推进 element/data/special-custom attached 组合、零条目 type 的
incoming X22、parse/root、完整 reader/factory/bootstrap、独立 signer 和线上验收。
整个 native stack/TLS/OS、真实 allocator/异常仍不在本轮验证范围。
见 [短名称 export 证据](evidence/vm9_alternative_ast_module_inline_exports_fresh_20261011.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_inline_exports_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-inline-exports-evidence.json>
```

## 6.41 完整实际 module 的 reader AST（2026-10-11 Asia/Shanghai）

`run_reader_ast_module` 新增默认关闭的 `enable_element_section`、
`enable_data_section`、`enable_special_custom_sections`。段表达式和 custom
分别要求显式八字节对齐且互不重叠的 scratch，并受 `max_expression_ops`
和 `max_custom_records` 限制；scratch 纳入 retained regions 和全页事务。
复用已有 parser、实际 AST callbacks 和清理，非空 element 列表仍在原生
abort 边界明确拒绝。

修改前 `12c0c09` 绑定的 **26 项真实 RED**：两个基址各 8 个段表达式和
5 类特殊 custom，原生自然返回 0，旧 Python 拒绝并全页回滚。冻结后
**406 项原生/Python 对照、36 项回滚检查**通过，含 12 项 SP 移位、
6 项高位 guest、12 项实际 custom payload 前置组合和两个完整实际 module。

完整输入直接从新鲜 ELF 的 `+387d20` 读取并独立 XOR，长度 **229328**，
section IDs 为 `[1,2,3,6,7,12,10,11,0,0,0]`。两个 image base 均自然
返回 0；每次 **55369 个实际 AST callbacks、121 个 code bodies、54533
个 raw words**，data payload 长度为 3632、352、0。完整 input、未屏蔽
guest `0xa000`、额外 1 MiB heap、ordered effects/owner bytes、parser exit、
callback cleanup、image globals、全部回调参数/cursor/limit 均逐字节一致。
模型没有使用原生快照作为输入，实际名称与 payload 未公开。

| 新恢复的原生来源 | 消费它的后续行为 |
| --- | --- |
| `322130/322134` | linking 的 0x90-byte frame，saved caller FP 进入 export header+16 |
| `32215c/3221b0/3221c8/322230` | version、tag、size、count 写入 header+8/+4/+12/+0 |
| `322338/3223ac/322494` | linking tags 6/7 的 count 在成功后保留 `0xffffffff` |
| `322264/3223bc/322590/3225f8/322680` | name length/条目字段在 header+12 清零后读取 |
| `321f10/322064` | dylink/target_features 保存 state，后续 global import 只覆盖低字节 |
| `321b3c/322148/3219a0` | 其余三类 helper 保存 custom name length 到相同 ABI word |
| `322138 → 31cb34` | linking 保存 X28 到 state-0x140，其高四字节被后续 table node 当作 padding 读取 |

custom 的栈写入由现有 parser 在解析时生成，无重复 parser。验证覆盖五类
custom 在四种 import 前后、linking 全部 tags/symbol 分支、空 count、连续
inline exports 和实际 custom。另有五类 custom 与 table/memory/global
definitions 的 15 个组合，以及关闭 inline exports 的 linking→table；
两个基址合计 32 项。custom 与 table/memory definitions 同时开启时，
必须显式提供 `entry_x28`，包括关闭 inline exports 的情形。
新测试器补齐旧 export harness 未记录的
data/element/global record 析构事件，内存与事件均完整对照。

完整 code 的性能测量暴露了逐字重新遍历整个 AST 的成本：原实现的有界
预览在 60 秒只完成 1050 个 raw words，未声称完整通过。现在每个连续
`+168` run 的首字执行完整 ownership 校验，后续字复用同一 append 实现，
逐字验证 vtable binding、vector、映射、预算及纯分配计划。其它 callback
会重置该状态；分配地址不得复用。完整实际模块已在两个基址完成，无跳过
raw words、回调、内存或清理。代码存储完成不等于指令执行完成。

回滚覆盖独立 opt-in、缺失/未对齐/未映射/别名 scratch、预算、原生非空
element abort 边界、错误 vtable，以及 custom 保存、element publication
和连续第二个 raw word 的中途写入失败。观察到 allocation 9364、
destroy 1510、delete 1318、free 5466。
三组必要旧回归（attached code、inline exports、standalone custom）共
**1502/99**，在最终 X28 padding 修复前的 owner
`3cb2cd6e461d059d84c4bcd27b73206581280d3474eefed16876410795a5022f` 上执行，历史 JSON 逐字节一致。
最终 owner 为 `7b53c24ad6bbdaa06301ff00fc8012f2a887f90a8229f6fe32f656c7b1ca9719`。三组回归分别关闭 attached
custom binding 或 special custom；按这些实际条件投影后，两版完整代码
AST 相同。该范围等价检查通过，不表示旧套件已在最终版全部重跑。

下一步恢复零条目 type 的 incoming X22，再推进 `+2cd5a4` 解析、
`+2cafd0` root/descriptor、factory/bootstrap、独立 signer 与线上验收。
整个 native stack/TLS/OS、真实 allocator/异常仍不在本次验证范围。
见 [完整模块 reader AST 证据](evidence/vm9_alternative_ast_module_segments_custom_fresh_20261011.json)。复现：

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_segments_custom_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-segments-custom-evidence.json>
```

## 6.42 零条目 type 与 incoming X22（2026-10-11 Asia/Shanghai）

`run_reader_ast_module` 新增 `entry_x22=None`。零条目 type section 后的
table/memory/global imports 需要显式 uint64 X22；非整数、bool、负数与
溢出均拒绝。默认值保留原来的拒绝边界，各类 import 仍要求已有开关。

修改前 `0859d42` 绑定的 **18 项真实 RED** 覆盖两基址、三类 import、
X22 为零、非零与全一：原生自然成功，旧 Python 拒绝并全页回滚。
修复来自 `+31b6b0` 的 type-count callback 与 `+31e75c` reserve helper：
`+31e760` 保存 incoming X22 到 `state-0x100`，`+31e764` 保存 X19=state
到 `state-0xe8`。count 为零时没有 type-entry callback 覆盖它们，后续
import 使用保存字和 descriptor 尾部。生产实现只恢复这些已消费的存储，
未使用原生快照作为输入。

**198 项原生/Python 对照、9 项回滚检查**通过。90 个合成输入覆盖三类
import、名称长度 0/1/21/22/23/31、三种 frame padding、六种 import
顺序、五类 custom 位于空 type 前后、后续 table/memory/global definitions、
关闭 inline exports 和 generic custom；另含 12 项 SP 移位、6 项高位 guest。
每项核对实际 helper 保存、自然返回/SP、全部 callback 参数/cursor/limit、
完整 input、未屏蔽 guest 与额外 1 MiB heap、ordered effects、parser exit、
callback cleanup 与 image globals。两处保存的中途写入失败均全页回滚。

同一最终 owner 另通过 **36 项关联回归、77 项旧回滚**：34 项选定的
旧短名称 import 对照，以及两个完整实际 ELF module；每项证据与历史
对应行一致，两组旧 guards 全部一致。完整实际输入每次仍为 229328 字节、
121 code bodies、54533 raw words、55369 callbacks。这是明确选定的回归
范围，不表示重跑了全部历史套件。

接下来恢复 `+2cd5a4` parse 转换、`+2cafd0` root/descriptor 与
factory/bootstrap，再完成独立 signer、新鲜签名输出和线上验收。
非空 element 的原生 abort、完整 native stack/TLS/OS 与实际 allocator/
异常仍不在本次证明范围。见 [零条目 type 证据](evidence/vm9_alternative_ast_module_zero_type_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_zero_type_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-zero-type-evidence.json>
```

## 6.43 parse 指令格式转换（2026-10-11 Asia/Shanghai）

`convert_parser_instruction_word` 恢复 `+2db778`：比较格式、旋转 uint32
指令字、按 triples 重排位段。两个 24 字节 record 的 count 实际只读取
低 32 位；byte +2 的 XOR key 与其余 padding 不参与比较。相同格式直接
返回原字，不同格式按 source byte +1 旋转，再使用目标字段的 shift。
SIMD 消费完整的八字段组，余数字段使用 AArch64 标量模 32 位移；零宽度、
超界 shift 等字节在两条路径中可能不同，Python 保留原生差异。

修改前干净 `0f5ed54` 的 **12 项真实原生 RED** 确认 helper 自然返回，
Python 缺少此 API。最终公开 verifier 新鲜通过 **434 项原生/Python 对照、
10 项拒绝检查**，覆盖 0/1/2/6/7/8/9/15/16/17/23/24/31/32/33/64
字段、格式相同、字段索引反序、不同 count、任意字段字节、旋转符号与
模 32 边界、极值指令；包含 **198 项实际构造器格式对照**，分别为三组
实际输入/builtin 格式的零字及 32 个基向量、两基址。实际格式从 fresh
ELF 指令和常量构造，核对 51 个 constructor stores，未输入原生快照。
另含 **16 项 SP 移位、12 项高位 guest**。全部检查自然返回、SP、完整
guest 与全部 Python pages 不变；原生栈保存不是本纯读 API 的输出。

唯一生产 owner 只新增这个函数。去掉新函数后，整个 Python AST 与
修改前完全一致；未把历史 reader/AST 套件标记为本次重跑。显式资源
边界、非 uint32 字、无效/未映射 record、字段预算均拒绝且页面不变。
该入口尚不负责 builtin catalog 初始化、完整函数/模块转换、root、
factory/bootstrap、独立 signer、新鲜输出或线上验收。
见 [parse codec 证据](evidence/vm9_alternative_parse_codec_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_parse_codec_20261011.py --library "$env:TOMATO_LIBMETASEC" --output <parse-codec-evidence.json>
```

## 6.44 parse 模块转换与 builtin catalog（2026-10-11 Asia/Shanghai）

`run_parser_conversion` 恢复 `+2cd5a4` 的 AST 到 128 字节 converted
module 转换：imports、functions、exports、global uint32 values 和拼接
data，包含原生分配/释放顺序、部分失败对象、错误字符串、冷/热 builtin
catalog、显式 serial thread ID 和 finalizer registrations。所有输入由
Python reader 和 fresh ELF 独立构造；原生输出只用于断言。

修改前干净 `8ca8c37` 绑定 **12 项真实原生 RED**。最终验证通过
**170 项原生/Python 对照、25 项回滚检查**：59 组合成输入/基址，
共两基址；另有 42 项 padding/SP/thread 变化、4 项完整实际 ELF
模块和 6 项高位 guest。完整实际模块每次有 **128 次分配、139 个函数
（18 imports + 121 definitions）、54533 个 decoded words**，分别
以初始栈 0/A5 在两基址运行。对照完整 guest、额外 2 MiB heap、全部
样本 image pages、每次分配/释放时的 converted owner bytes 及 finalizers。
实际模块同时包含 40 imports、22 globals、121 exports、3984 data bytes。

global definitions 数量须等于 global imports 数量。global 数量不符、
越界 function export、最后一个 raw word 不完整时返回原生失败 0，
保留相应部分对象；raw reader 会读取 end/capacity 之外的已映射 padding，
模型保留有界完整四字节输入。直接导出 imported function 的原生路径会
访问非法位置，模型拒绝。guard、资源边界、别名、未映射输入或写入故障
均全页回滚。输出和 error 必须分别是全零 128/24 字节新对象。

entry SP 显式输入；仅表示 C++ temporary records 和 builtin source
frame，未声称比较完整原生栈、TLS 或 OS。allocator 是纯地址计划；调用方
消费逻辑 effects。旧 owner（含 codec）去掉新增两类与 API 后 AST
完全一致；未将历史独立套件描述为本轮重跑。converted cleanup、root、
descriptor builders、factory/bootstrap、独立 signer、新鲜输出与线上验收
仍待完成。见 [parse conversion 证据](evidence/vm9_alternative_parse_conversion_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_parse_conversion_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <parse-conversion-evidence.json>
```

## 6.45 converted module 清理（2026-10-11 Asia/Shanghai）

`cleanup_parser_conversion` 恢复 `+2cb968`：依次释放 data、globals、
exports、imports、functions；记录按逆序销毁。function 先释放 decoded
vector 再释放名称；import 先 field name 再 module name。每个 vector
在释放前将 end 重置为 begin，保留原生 dangling begin/capacity、string
headers 和 scalar function count。output 对象、error string 和 builtin
catalog 仍由调用方拥有，逻辑 frees 只消费一次。

修改前干净 `bafac90` 绑定 **16 项真实原生 RED**。最终通过
**146 项原生/Python 对照、21 项回滚检查**：118 项独立 Python parse
生成的合成模块（包括部分失败对象），16 项非空零容量指针、空预留
vector、短内容的 long string 表示，2 项完整实际 ELF、4 项 SP 移位、
6 项高位 guest。完整实际输入每基址从 fresh ELF 经 Python reader/parse
独立生成；检查所有 guest、额外 heap、image pages、释放顺序/大小和
每次释放时的 128 字节 owner。无原生快照输入。

共享或重叠的 ownership、未映射/image/reserved 指针、非法 string/vector、
预算耗尽、早期及末期写入失败均拒绝并全页回滚。原生完整栈/TLS/OS、
真实 allocator 不属于此接口输出。去掉新增函数后，整个已有 owner AST
（含 parse/codec）保持一致；未宣称旧独立套件重跑。当前继续 root/
descriptor builders、factory/bootstrap、独立 signer、新鲜输出和线上验收。
见 [converted cleanup 证据](evidence/vm9_alternative_converted_cleanup_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_converted_cleanup_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <converted-cleanup-evidence.json>
```

## 6.46 instruction builder catalog（2026-10-11 Asia/Shanghai）

`initialize_instruction_builder_catalog` 恢复 `+2cc038` 的 serial guard、
`+2f67b4/+2f1488/+2ecd8c` 分配与构造：主表 `0x8a18` 字节，包含
529 个 typed nodes 和 99 张分发表；副表 `0x3840` 字节，包含 600 个
连续节点与指针表。节点的 4 字节 padding 保留 allocator 初始内容。
ready guard 返回已有表，不分配或写页；冷 pointer/guard 必须全零。
显式 thread ID 决定完成 guard，finalizer registration 作为逻辑 effect。

布局来自 fresh ELF 构造代码的 **5059 次静态 stores**，再整理为 typed
nodes、分发表和副表循环；未用原生快照初始化 Python。私有独立静态
求值与 typed layout 在两基址、0/A5 填充共 4 项对照一致，静态求值的
完整两块内存也分别与实际原生构造器一致。公开 verifier 直接执行
原生 `+2cc038` 验证生产接口，不依赖私有静态求值脚本。

修改前干净 `95c36f9` 绑定 **8 项真实原生 RED**。最终通过
**40 项原生/Python 对照、22 项回滚检查**：20 cold/20 warm，覆盖
0/39/A5/FF 填充、两 image bases、8 项 heap 地址变化（含高位地址）、
8 项 SP 移位、8 项 thread ID 变化。检查自然返回和 SP、完整 guest/
两块 heap/所有 image pages、有序分配和每次分配时的 global pointer、
finalizers；Python 不改初始 stack。未比较整个原生栈/TLS/OS。

忙 guard、冷残留指针、无效 warm ownership、分配缺失/别名/重叠/
未映射/image/reserved 地址、资源边界与初始/副表/发布/guard 写入故障
均拒绝并全页回滚。已有 owner AST 去掉本次两张 metadata 表、result
类型和 API 后完全一致。当前仅初始化 builder catalog；opcode builders
执行、root/descriptor、factory/bootstrap、独立 signer、新鲜输出和线上
验收仍待完成。见 [builder catalog 证据](evidence/vm9_alternative_builder_catalog_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_builder_catalog_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <builder-catalog-evidence.json>
```

## 6.47 decoded instruction 运行时构造（2026-10-11 Asia/Shanghai）

`build_parser_runtime_instruction` 从 12 字节 decoded record 经实际 builder
分发表构造 49 字节 optional variant：187 个线性叶子方法使用 fields、
low16 immediate、signed target 三种 operand 形式，另有嵌套分发、零字
特例、fallback 和 root-pointer 初始化。uint64 variant tag 位于 +40，
validity byte 位于 +48；不写的 padding 保持调用方初值。未命中 nested
entry 仅清零 +0/+48，返回 status 0；成功返回 status 1。原生 void X0
不是本接口状态。已有值的销毁和向 48 字节 vector 的 move 不在此入口。

修改前干净 `5fba7eb` 绑定 **12 项真实原生 RED**。最终公开 verifier
在 **22 个 native driver batches** 内通过 **116422 次原生/Python
指令构造对照、24 项回滚检查**。其中 **109066 次**来自两基址各自
fresh ELF → 独立 Python reader/parse 生成的完整实际模块（各 54533
条）；其余 7356 次覆盖两基址的 422 条 graph paths、全部 187 个线性
方法各六种 bit/field 输入、48 次 nested misses、6 个 padding batch、
4 个 SP 移位 batch。线性方法测试通过显式调整 primary slot 指向现有
typed node，仍执行原生虚函数体。driver 只负责循环和调用，不替换方法。

每项比较 64 字节存储（49 字节 optional 和相邻未写字节）、validity，
并检查完整 guest/heap/image pages、自然返回/SP；Python stack 不变。
无原生快照输入，实际名称与 payload 不导出。完整实际模块使用 62 种
规则、分发深度最高 4；没有触发 `+2ecce0` 的原生 diagnostic trap。
该 trap、非法节点/vtable/getter/selector、cycle/深度、别名、未映射/
reserved storage、operand/tag/validity 写入失败均拒绝并全页回滚。

去掉新增 rule table 和 API 后，已有 owner AST 完全一致。尚需恢复
向 runtime vector 的 move、特殊指令第二次转换和 root linking、完整
descriptor/root、factory/bootstrap、独立 signer、新鲜输出及线上验收。
未比较完整原生 stack/TLS/OS。见 [runtime builder 证据](evidence/vm9_alternative_runtime_builder_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_runtime_builder_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <runtime-builder-evidence.json>
```

## 6.48 runtime descriptor 二次转换与 root linking（2026-10-11 Asia/Shanghai）

`link_parser_runtime_descriptor` 恢复实际 +2dbe20/+2f67e4：遍历 descriptor
的 48 字节 runtime vector，为 tag 102 写入 root+72，为 tag 137/188
写入 root；tag 790 按 selector 选择 600 个副表 builder，将 tag 改为
selector+190，并倒序写入后续 2..5 条记录的地址。其他字节保留。
副表需要已初始化的 builder catalog；校验 ownership、node/vtable/
method 和 operand 位于所属函数的 used vector 内。此阶段不分配内存。

修改前干净 `9ffeeac` 绑定 **16 项真实原生 RED**。最终 verifier 通过
**3918 个原生/Python descriptor 对照、18 个 native driver batches、
27 项回滚检查**，比较 **138454 条记录、23490 次副表重写、1246 次
root 指针写入**。两基址各自 fresh ELF → 独立 Python reader/parse/
builder 构造完整实际模块输入，共 242 个函数、109066 条记录、19818
次副表重写和 1224 次 root 指针写入。所有 600 种副表规则另有三种
padding 的完整覆盖，并含四组 SP 移位、空 vector 和混合 tag。

完整 guest/heap/image pages、自然返回/SP 一致，Python stack 保持
不变；不使用原生快照输入。非法 selector、catalog/指针/容量/别名、
越界 operand、预算和写入失败均拒绝且全页回滚。这些 malformed 输入
是 Python 防护检查，不声称比较原生崩溃路径。去掉新增 arity 表和 API
后，旧 owner AST 完全一致。原生 vector move、完整 descriptor/root、
factory/bootstrap、独立 signer、新鲜输出和线上验收仍待完成；未比较
完整原生 stack/TLS/OS。见 [runtime linking 证据](evidence/vm9_alternative_runtime_link_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_runtime_link_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <runtime-link-evidence.json>
```

## 6.49 defined descriptor 构造与失败清理（2026-10-11 Asia/Shanghai）

`construct_parser_defined_descriptor` 恢复实际 +2dbf00 的空 name-filter
路径：从 converted function 的 decoded records 构造 48 字节 runtime
vector，复制 scalar/name，发布 kind=2 的 64 字节 descriptor。先分配
vector，首条指令才按需初始化 catalog。普通 variant move 复制四字节，
tag 102/137/188 复制十六字节；padding 保留实际临时栈来源。短名保留
完整 string24，长名另行分配，heap 短名表示按原生规则转换为 inline。

缺失 primary/nested builder 时，输出空指针，逆序将已构造记录 tag 改为
-1 并释放 vector。输入 function/name/decoded storage 保留；分配器是
纯地址计划，释放和 finalizer 注册作为逻辑效果返回。非空 name filter
涉及的注册表路径仍拒绝；实际 factory 的 names count 为零。

修改前干净 `473fea1` 绑定 **16 项真实原生 RED**。正式 verifier 通过
**288 个原生/Python descriptor 对照、48 个 native batches、113762 条
运行时指令构造、35 项全页回滚检查**。两基址各从 fresh ELF 经独立
Python reader/parse 生成完整实际模块：共 **242 个函数、109066 条指令、
488 次分配**。其余用例覆盖 422 条分发 graph paths、187 个 leaf move、
空函数、冷/热 catalog、短/长名称、heap 短名、缺失 builder、padding、
SP 和 thread ID 变化。

全部 guest/heap/image pages、64 字节 descriptor、已用/未用 vector
字节、96 字节已建模临时栈、自然返回/SP、分配/释放顺序、owner 发布
状态及 finalizers 均一致；无原生快照输入。异常输入、预算、别名、
move/destructor table 和写入失败拒绝并全页回滚。移除新增结果类型和
API 后旧 owner AST 完全一致。未比较完整原生 stack/TLS/OS；完整 root、
imported descriptor、factory/bootstrap、独立 signer、新鲜输出及线上验收
仍待完成。见 [defined descriptor 证据](evidence/vm9_alternative_defined_descriptor_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_defined_descriptor_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <defined-descriptor-evidence.json>
```

## 6.50 builtin function catalog 与名称哈希（2026-10-11 Asia/Shanghai）

`initialize_builtin_function_catalog` 恢复实际 +2cc0f8/+2e8c68：
构造 73 个 owned string/function 节点和 128 个哈希桶，保留 libc++
bucket predecessor 链。名称从 61 处受 guard 保护的 ELF XOR 源和
12 组 literal instruction 引用生成；代码和证据不包含解码名称。
`hash_descriptor_name` 支持 0..32 字节，实际最长名称为 29 字节；
0..8 字节委托现有短名哈希。

冷启动按序分配 98 次、释放 12 次长名称临时存储，返回一个 finalizer。
ready 路径检查节点、hash、function target 和桶链后保持全部页面不变。
已建模的 32 字节临时存储保留 caller padding、SP 派生指针和 matching
libc mutex 写入的半字/返回地址；这些字节会进入 inline string padding。
分配器为纯地址计划，释放和 finalizer 注册作为逻辑效果返回。

修改前干净 `a206f53` 绑定 **20 项真实原生 RED**。正式验证通过
**32 项原生/Python catalog 对照、198 项哈希对照、34 项回滚/类型检查**。
两基址覆盖冷/热 catalog、已解码 guard、四种 padding、SP、thread ID
和 heap 地址变化；hash 覆盖每个 0..32 长度的三种字节模式。
完整 guest/heap/image pages、名称、自然返回/SP、分配/释放顺序、
每次效果的 owner 发布字节、finalizers 和已用临时存储均一致。
静态独立 lowering 从原始 ELF 复核全部 73 项名称来源和函数引用。
移除四个新增定义后旧 owner AST 完全一致。

无原生快照输入；异常图、预算、别名、源指令和写入失败拒绝并全页
回滚。未比较完整原生 stack/TLS/OS。imported descriptor、完整 root、
factory/bootstrap、独立 signer、新鲜输出及线上验收仍待完成。
见 [builtin catalog 证据](evidence/vm9_alternative_builtin_functions_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_builtin_functions_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <builtin-catalog-evidence.json>
```

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
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_code_begin_20261009.py --library <private-metasec.so> --output <reader-ast-code-begin-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_table_20261009.py --library <private-metasec.so> --output <reader-ast-table-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_memory_20261009.py --library <private-metasec.so> --output <reader-ast-memory-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_global_20261009.py --library <private-metasec.so> --output <reader-ast-global-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_global_expression_20261010.py --library <private-metasec.so> --output <reader-ast-global-expression-evidence.json>
```

A observation ranges 跳过 VM dispatcher 热点，只保留服务、启动/caller/callback 边界。
VM 指令仍原生执行，没有替换结果。各验证器恢复 monkeypatch，同一进程要求串行；
输出仅合成 guest 状态、偏移、计数和比较结果，不导出 native 内存或 selector 正文。

这些证据证明导入/内存依赖、JNI→默认任务→cleanup/exit 控制流、once 发布顺序，以及
B 实际 descriptor 生成/发布与短 selector 布局。它们不能证明 fresh Medusa 输出、
服务器认可、全部 OS 析构或独立 Python/Rust signer。

下一步恢复短名称 export 与其余 attached handlers；零条目 type 的 caller 寄存器仍需独立输入证明，随后解析/root 生成，再把原始 JNI /
worker / cleanup 接入独立 Python 启动与真实 allocator/arena/OS 输入。B VM、fresh
签名和线上矩阵仍待通过。无 JVM Rust 下载链路、非空搜索/分页、抖音/起点闭环及
最终 Pages/Actions 搜索下载产品仍未完成。
