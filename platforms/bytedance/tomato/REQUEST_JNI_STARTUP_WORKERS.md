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

## 6.51 imported descriptor 解析与构造（2026-10-11 Asia/Shanghai）

`construct_parser_imported_descriptor` 恢复实际 +2dc3e4 的空 registry /
name-filter 路径：初始化全局注册表，查询 borrowed-name 外部函数 map，
找不到绑定时按需构造 builtin catalog。找到函数后复制名称，发布
kind=0 的 descriptor64；+32..55 保留 allocator padding。未找到名称
则发布空指针。注册表和 catalog 的 finalizer 按实际顺序返回。

外部 map 支持 power-of-two 和 prime 桶、碰撞链及 predecessor 校验。
短名复制完整 string24，长名按容量分配；heap 短名按原生规则转换为
inline。名称副本使用 SP-0x600 的 47 字节临时存储；builtin getter
incoming SP 在 cold registry 路径额外下降 16 字节。未声称重建全部
flattened control cells、原生 stack/TLS/OS 或非空注册表/过滤器路径。

干净 `aee6ad6` 绑定 **16 项修改前真实原生 RED**。正式验证通过
**106 个原生/Python descriptor 对照、72 个 batch、36 项回滚检查**。
两基址各从 fresh ELF 经独立 Python reader/parse 得到完整实际模块，
连续构造全部 18 项函数导入：16 项外部绑定、2 项 builtin。16 个外部
回调地址和名称来源直接从原始构造器 ADRP/ADD/STR 指令恢复；没有
以原生输出或快照作为输入。每组实际导入 **117 次分配、12 次释放、
2 个 finalizer** 一致。

合成用例覆盖 0..32 字节边界、heap 短名、四种 padding、冷/热 registry
和 builtin、桶碰撞、绑定优先级、空回调、缺失名称、SP 和 thread ID。
完整 guest/heap/image pages、输出、已用名称临时存储、分配/释放顺序、
每次 owner 发布字节及 finalizers 均一致；异常输入、预算、别名和
写入失败均全页回滚。移除新增结果类型和 API 后旧 owner AST 不变。
完整 root、factory/bootstrap、独立 signer、新鲜输出及线上验收仍待完成。
见 [imported descriptor 证据](evidence/vm9_alternative_imported_descriptor_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_imported_descriptor_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <imported-descriptor-evidence.json>
```

## 6.52 root 构造、全局数据搬移与运行时链接（2026-10-11 Asia/Shanghai）

`construct_parser_root` 恢复实际 +2cafd0 的空 names / registration-filter
路径。构造 borrowed-name 函数和全局绑定 map，搬移 converted data
vector，写入全局地址，依次构造 imported / defined descriptor，建立
owned name/index map，再发布 root96 并链接运行时指令。发布后按原生
顺序释放临时绑定 map。重复绑定和导出名称保留第一个值。

root96 包含 descriptor vector24、import count8、owned name map40
和 data vector24；搬移时修正首桶 predecessor。global count 不匹配
时在分配前发布空指针。其他异常图、缺失绑定/builder、索引、别名、
预算和写入失败全页回滚；未恢复的原生 trap 路径保持拒绝。

干净 `81099d3` 绑定 **9 项修改前真实原生 RED**。正式验证通过
**62 个原生/Python root 对照、34 项回滚检查**。两基址均从 fresh ELF
经独立 Python reader/parse 生成完整实际模块，使用原始构造器指令
提取的 16 项函数绑定和 22 项全局绑定：合计 **278 个描述符、109066
条运行时指令**。每个实际 root 的 **544 次分配、52 次释放、3 个
finalizer** 完全一致。

完整 guest/heap/image pages、212 字节 root 临时存储、全局数据搬移、
运行时链接、每次分配/释放的 owner 发布字节和 finalizers 均匹配。
额外恢复桶分配、imported frame alias 和名称复制 helper 留下的
FP/LR/index 字节，支持 heap 短名转换、连续构造和重复导入后的复用。
合成控制覆盖空模块、指令函数、外部/builtin/空回调、重复绑定/导出、
全局数据、短/长及 heap 短名、padding、SP 和 thread ID 变化。
移除新增结果类型和 API 后旧 owner AST 完全一致。

不使用原生快照输入，不发布名称或 payload。未比较整个原生
stack/TLS/OS；非空名称过滤器和 registration flag 路径仍拒绝。
factory/bootstrap、独立 signer、新鲜输出和线上验收仍待完成。
见 [root 构造证据](evidence/vm9_alternative_root_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_root_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <root-evidence.json>
```

## 6.53 factory 独立组合与两层清理（2026-10-11 Asia/Shanghai）

`run_module_factory` 恢复 +2cbdc8 的正常构造路径：原位 XOR、实际
reader/AST、parse 转换、root 构造及运行时链接，随后按原生顺序清理
converted module 和 AST。外部绑定、codec 表、输入帧和三个模型
scratch 区均为独立输入，跨阶段共用不复用地址的纯分配计划。

修复 reader 对完整位于 ELF 内的合法输入的重叠误判：整个 image
继续受保护，仅省去重复的输入子区间。部分重叠及其他输出、帧、
scratch 和分配别名仍拒绝。除了这一边界和新增 API，旧 owner AST
一致。每个逻辑 allocation/free 均记录当时的 factory 输出槽字节。

干净 `3b377ee` 绑定 **7 项修改前真实原生 RED**；其中两项同时证明
旧 reader 错误拒绝 ELF 内输入。正式验证通过 **26 个原生/Python
factory 对照、38 项回滚检查**。两份 fresh 完整实际 ELF 模块各自
构造 **139 个描述符、54533 条运行时指令**，各有 **2330 次分配、
1836 次释放、4 个 finalizer**，合计 4166 个有序分配/释放效果。

完整 guest/heap/image pages、输出发布顺序和 finalizers 一致；实际
factory 从原始 ELF 与构造器指令独立生成所有输入，没有原生快照。
合成控制覆盖 ELF 内/外输入、两种 XOR key、空模块、导入、连续定义、
分配/栈 padding、SP 和 thread ID 变化。异常参数、别名、短输入、
reader 失败及中途写入/清理失败均保留原页面。

本 API 支持 reader/parse 成功路径和 root 的自然 global-count
不匹配返回；原生 TLS 错误报告及异常路径仍拒绝。未比较整个原生
stack/TLS/OS，未执行真实分配器。constructor 的 121 项 publication、
完整 bootstrap、独立 signer、新鲜输出与线上验收仍待完成。
不发布名称或 payload。见 [factory 组合证据](evidence/vm9_alternative_factory_composition_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_factory_composition_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <factory-composition-evidence.json>
```

## 6.54 构造器输入生成与描述符发布（2026-10-11 Asia/Shanghai）

`run_module_constructor` 恢复实际 +29ecac 和 +2a95e0 参数包装：从
原始 ELF 的静态指令生成 16 个函数绑定、22 个全局绑定及 3 条 codec
记录，调用独立 Python factory，发布 root，再执行全部 **121 次**
短名称查找与 descriptor 全局槽写入。每次构造均从 fresh ELF 起步。

静态解码只接受已验证的构造器 setup/publication 指令形态，保留
167 次 caller 输入 store 和 121 次 publication；没有通用 ARM64
执行器，也没有原生快照、名称或 payload 常量作为输入。输出 root、
生成的 descriptor 和两层临时清理均来自已有唯一 owner 的组合。

干净 `f28381c` 绑定 **4 项修改前真实原生 RED**。正式验证通过
**2 个完整原生/Python 构造器对照、22 项回滚检查**。覆盖两基址、
重定位 SP、不同分配/栈 padding 和 thread ID。合计 **242 个发布槽、
278 个描述符、109066 条运行时指令**；每次 **2330 次分配、1836 次
释放、4 个 finalizer** 与原始构造器一致。

全部 guest/heap/image pages、自然返回 SP、root、121 项发布值和
factory 输出槽的有序效果匹配。新增 API 和结果类型以外旧 owner
AST 完全一致。非法参数、静态指令、caller/scratch/allocator 别名
及写入失败全页回滚；最后一个发布槽的故障检查在完成实际模块构造
之后注入，验证整段调用仍回滚。

未比较完整 stack/TLS/OS，未运行 Android loader 或 B VM。该结果是
独立构造器完成，完整 JNI/bootstrap、独立 signer、新鲜输出及线上
验收仍待完成。见 [构造器证据](evidence/vm9_alternative_constructor_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_constructor_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <constructor-evidence.json>
```

## 6.55 B 运行状态与有界描述符执行（2026-10-11 Asia/Shanghai）

`initialize_runtime_context` 恢复 +2a9754：清零 status32、active-frame64
和80个寄存器槽，设置软件栈指针，保留原始数据区与 padding。
`execute_runtime_descriptor` 恢复 +2a9718 的 kind0/kind2 分发，以及
B 初始化程序使用的执行路径。基础 tag 为55/66/102/134/169/188/189；
合并 tag 为250/397/401/451/624，保留中间 PC store、逆序 operand
pointer、嵌套调用 frame 和导入调用 link 的原生语义。

干净 `b3cde47` 绑定 **7 项修改前真实原生 RED**。正式验证通过
**48 项运行时原生/Python 对照、6 项 context 初始化对照、27 项回滚
检查**。两基址均从 fresh ELF 经独立 Python 构造器生成实际初始化
描述符；每次执行34条记录中的 **19 次分发、2 次导入回调**。

完整 guest/heap/image pages、自然返回 SP/status、导入回调的完整
context、active frame16 和传入 SP 均匹配。合成控制包含正负和非对齐
内存偏移、uint64 寄存器、五类合并操作、嵌套调用、回调寄存器改写
及重定位 SP。非法类型/索引、资源耗尽、别名、回调失败和中途写失败
全页回滚。新增定义以外旧 owner AST 完全一致。

导入回调使用显式纯 provider；本批次未执行原始导入函数体、线程和
队列工作。实际输入、生成描述符和执行过程均没有原生快照。其他
runtime tag、kind1、完整 stack/TLS/OS 和控制存储写入保持拒绝。
接下来连接真实 startup 回调，继续 JNI/bootstrap、worker、独立 signer、
新鲜输出与线上验收。见 [有界运行时证据](evidence/vm9_alternative_runtime_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_runtime_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_LIBC" --output <runtime-evidence.json>
```

## 6.56 B callable 的共享移动与清理（2026-10-11 Asia/Shanghai）

真实 B 启动回调 +29e908 调用共享 enqueue；+29eaf4 随后销毁源
callable。其虚表为 +35fc28，原有共享 `vm9_startup.move_callable`
和 `destroy_callable` 只支持 A 与 queue 的两张虚表，因而拒绝该输入。
本节在既有共享 owner 中扩展这两个入口，复用原队列算法与服务契约。

B inline clone +29e040 仅复制虚表，虚表来自 image+387cb0 的 GOT
指针加16；inline destructor +29e054 返回，heap deleting destructor
+29e058 释放 pointee。新增分支验证 clone/GOT 和所用析构槽的原始
重定位目标，不改变 inline 源的所有权；plain destroy 保留+20，reset
先清空+20。其他共享 owner 定义的 AST 完全一致。

干净 `a7b684c` 绑定 **12 项修改前真实原生 RED**。正式验证通过
**84 项原生/Python callable 对照、12 项回滚检查**：其中32项 B
callable，52项原有 A/queue 回归。两基址覆盖 inline、heap、empty、
move、destroy、reset、assign、自赋值、替换已有目标及不同 padding。
完整 guest payload、image pages、自然返回 SP 和有序 free 均匹配。
错误 clone/GOT/析构指针及中途写失败均回滚页面。

这一步恢复共享 callable 生命周期。完整 B startup 回调组合、线程
执行、JNI/bootstrap、独立 signer、新鲜输出和线上验收仍待完成。
不使用原生快照输入，不发布名称或 payload。
见 [B callable 证据](evidence/vm9_startup_b_callable_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_startup_b_callable_20261011.py --library "$env:TOMATO_LIBMETASEC" --output <b-callable-evidence.json>
```

## 6.57 B 主线程 startup 与真实导入回调（2026-10-11 Asia/Shanghai）

`vm9_alternative_startup.initialize_startup_caller` 恢复实际 +2a0028：
在 incoming SP-6310 初始化 context，保存并核对 TLS canary，执行
constructor 发布在 image+3e1eb8 的初始化 descriptor。其两个真实导入
由 `run_startup_imported_callback` 处理：+29e908 从 VM register8 取源
callable 并提交到默认队列；+29eaf4 销毁该源。复用既有 `vm9_startup`
的移动、队列、线程请求及析构逻辑，既有 owner 定义 AST 保持一致。

干净 `0233b11` 绑定 **6 项修改前真实原生 RED**。正式验证通过
**28 项原生/Python 对照、41 项回滚检查**：24 项导入回调覆盖两基址、
两种 padding 与 enqueue/destroy 的 inline/heap/empty 状态；另外4项
startup 使用两份从 ELF 独立构造的完整模块，并改变 incoming SP 和 tid。
每次 startup 自然返回，执行19次分发、2次真实导入，形成3个线程创建
请求与22项有序服务效果。完整 context、guest/heap/image/libc 页面、
TLS、最终队列和保存的 canary 均匹配。纯 provider 接收 staged pages；
外部动作需等整次结果接受后消费，线程体在本验证中尚未执行。

回滚检查覆盖服务缺失、无效指针、source/context/scratch/分配别名、
clone 和源析构重定位、递归 guard、线程及 signal 错误、后期 step
耗尽和两类 canary 破坏；后期失败仍撤回完整页面。完整原生寄存器保存
栈、线程输出临时地址和未指定 X0 不属于本次对照。测试夹具从 ELF
恢复 matching libc 的内部符号重定位，没有注入原生运行快照。

这一步完成有界 B 主线程 startup。B worker 的六个初始化程序、完整
JNI/bootstrap、独立 signer、新鲜输出和线上验收仍待完成。见
[B startup 证据](evidence/vm9_alternative_startup_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_startup_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <b-startup-evidence.json>
```

## 6.58 B worker 的分支与组合指令（2026-10-11 Asia/Shanghai）

在既有 `execute_runtime_descriptor` 扩展 tag62（有符号16位立即数）、
tag95（64位寄存器相等时的相对分支）和六类实际组合指令：
194=(188,62,95)、273=(102,134,169)、361=(169,169,188)、
402=(55,55,169,169)、651=(102,134,134)、726=(134,55,134,55)。
组合194在回调返回的 PC 上继续计算后续分支；361保留调用后的+2。
402的首个 store、273的第二个 load、726的第三个 load 都先操作内存
再写 PC。特意令 load 读取 context PC 的控制覆盖该执行顺序。
其他 owner 定义 AST 未改变。

干净 `74120bc` 绑定 **16 项修改前真实原生 RED**。正式验证通过
**112 项 runtime 原生/Python 对照、4 项实际 startup 回归、40 项回滚
检查**。112项包含40项新增指令控制、48项旧 runtime 回归，以及两基址
六个实际 worker descriptor 的冷/热分支共24项。包含正负极值立即数、
前向/后向分支、64位高字差异、回调修改返回 PC、读取 PC 的组合操作、
重定位 SP 和实际初始 descriptor。完整 guest/heap/image 页面、context、
有序导入参数、active frame 与原生自然返回一致。

worker descriptor 对照仍使用显式纯 imported provider，没有执行其
atomic/once/memset 回调体或嵌套初始化程序。四项 startup 回归则继续
执行已恢复的实际 enqueue/destroy，每次19次分发、3个延后线程请求、
22项有序效果匹配。完整 B worker、JNI/bootstrap、独立 signer、新鲜
输出和线上验收仍待完成。见 [worker runtime 证据](evidence/vm9_alternative_worker_runtime_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_worker_runtime_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <b-worker-runtime-evidence.json>
```

## 6.59 B worker 完整算术与内存内置函数（2026-10-11 Asia/Shanghai）

既有 B 执行器增加19个基础 tag 和36个组合 tag，现覆盖28个基础 tag、
47个已举证组合 tag。新增32/64位算术、位运算、移位/旋转、无符号
取余、字节访问和不等分支；32位结果按原生符号扩展。移位量按原生
寄存器宽度取模，除数为零的无符号取余保留分子。字节 load 在写 PC
前读取内存，组合指令也保留这一顺序。

`run_runtime_imported_builtin` 恢复实际 +2eae70 CAS64 与 +2ea98c memset。
register8 提供目标，register9/10 提供 expected/new 或 fill/count，
register6 与返回值接收原值或目标地址。该接口使用串行 guest 内存；
不创建主机原子操作或线程。context header 与 retained 区受保护，
别名参数先读取后写入，失败时回滚完整页面。

干净 `cf6401b` 绑定 **52 项修改前真实原生 RED**。正式验证通过
**310 项 runtime 对照、30 项真实 builtin 对照、4 项实际 startup
回归、69 项回滚检查**。runtime 包含152项新增基础指令、112项新增
组合指令、22项旧组合回归和24项实际嵌套 worker descriptor。
覆盖符号边界、移位回绕、别名、零除数、双向分支、直接读取 PC、
CAS 成败与返回值别名、memset 零长度/跨页/参数别名。两基址的实际
程序由 ELF 独立构造，嵌套程序执行真实 native memset callback，Python
使用已恢复 builtin；完整页面、context、导入参数/frame/SP 均匹配。

此处验证 descriptor 执行与两类内存 builtin。完整 once/caller/worker
组合、JNI/bootstrap、独立 signer、新鲜输出和线上验收仍待完成。
没有原生快照输入，没有发布私有名称或 payload。见
[worker arithmetic 证据](evidence/vm9_alternative_worker_arithmetic_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_worker_arithmetic_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <b-worker-arithmetic-evidence.json>
```

## 6.60 B 复用共享 once 状态机（2026-10-11 Asia/Shanghai）

既有 `vm9_startup.call_once_arena_boot` 增加可选 `control_address`，接受
B 的六个控制字。缺省参数保留 A 的 `table_index` 契约；显式 B 控制字
要求 `table_index=0`，避免两个选择来源冲突。两条路径复用同一份锁、
状态发布、完整初始化 provider、广播和回滚实现。状态1等待仍拒绝。

干净 `4c7a0ff` 上 **12 项修改前真实原生 RED** 后实施变更。新鲜验证
通过 **60 项原生/Python 对照、22 项回滚检查**：36项B控制覆盖两基址、
六个控制字及cold/done/其他非零状态，24项A回归覆盖六个原表。
原始 +32a0a0 与 matching libc 的真实 broadcast 自然返回，完整 guest、
image、libc、TLS页面和初始化/广播/唤醒顺序一致。初始化体在此为显式
纯 provider 边界，尚未用本批证据宣称完整 B worker 已组合。

非法控制字、含糊参数、busy/locked状态、缺失或失败服务、部分初始化、
最后状态发布故障均拒绝且全页回滚。其他共享 owner 定义的 AST 未变。
继续完整B任务/队列worker、JNI/bootstrap、独立signer、新鲜输出及线上
验收。没有原生快照输入或私有名称/payload发布。见
[共享 once 证据](evidence/vm9_alternative_shared_once_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_shared_once_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <b-shared-once-evidence.json>
```

## 6.61 B 完整 worker callable 与嵌套初始化（2026-10-11 Asia/Shanghai）

`initialize_worker_arena` 恢复 B 的六种实际初始化体：分配并清零0x4000，
发布八个0x800块指针，执行一次首程序及七次链式程序。输入SP独立推导
context和canary位置，每次调用重新读取原生发布指针及descriptor。
`run_worker_initialization_task` 组合实际 +29e05c 的六个外层程序，复用
共享once状态机，执行真实CAS64/memset语义，保存并检查两个TLS canary。
统一指令预算覆盖外层与嵌套分发，后期失败回滚之前已完成的整组页面。

干净 `6050d75` 上 **4 项修改前真实原生 RED** 后实施变更。正式验证
由两份 fresh ELF 独立构造输入，通过 **18 项完整原生/Python 对照、
36 项回滚检查**。12项逐个覆盖两基址的六种初始化体；六项完整任务覆盖
cold、warm、交错三组cold状态及不同SP。每次完整cold任务 **120847次
VM分发、54次descriptor调用、18次导入、6次0x4000分配与6次广播唤醒**。
原始CAS、memset、once和matching libc broadcast函数体真实执行。
全部非原生栈页面、完整context、canary、descriptor输入SP、导入context/
active-frame/SP与有序分配/唤醒均匹配；没有native快照输入。函数体执行
断言针对每条路径实际到达的导入；cold完整任务覆盖全部四类。嵌套canary
在初始化体RET时对照，返回后该槽位可被外层原生调用者复用。

非法参数/指针/descriptor、未恢复导入、重复分配、服务失败、canary破坏、
第六组末尾发布故障、第六次广播失败及总预算耗尽均全页回滚。既有owner
定义AST未变。本批完成callable任务体；队列worker及TLS清理组合、完整
JNI/bootstrap、独立signer、新鲜输出及线上验收继续。私有名称/payload
未发布。见 [完整 B callable 证据](evidence/vm9_alternative_worker_task_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_worker_task_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <b-worker-task-evidence.json>
```

## 6.62 B 同次 startup 的队列 worker 与清理（2026-10-11 Asia/Shanghai）

`run_queue_worker` 把实际 B callable 接入既有共享队列worker。worker入口
SP推导任务对象和callable入口，复用TLS key申请/所有权转移、队列移动、
调用、有限等待、任务析构和线程参数释放。正常返回时support仍属pthread
TLS，后续由既有共享key清理及guest pthread_exit owner完成释放。

干净 `0c62411` 上 **2 项修改前真实原生 RED** 后实施变更。两份 fresh
ELF独立构造输入，通过 **12 项原生/Python 对照、24 项回滚检查**：
两基址、不同worker SP、cold/warm support key、正常worker返回、key清理、
完整joinable guest pthread_exit。原生端在同一个CPU运行startup、选择其
实际发布的worker参数、执行队列任务及清理；没有native输入快照。

每次实际B任务执行6个外层及48个嵌套程序，匹配120847次分发。三个延后
线程描述符、一次等待、参数释放、TLS所有权、完整guest/heap/image/libc
及两份TLS页面、有序服务效果全部一致。cold key三种路径分别38/40/42项
效果；warm key省去一次key创建。main context完整匹配；两个任务context
在 +326620 返回点对照，之后的等待与退出可复用已失效的原生栈空间。

24项回滚检查覆盖入口/服务参数、错误队列或任务、key/TLS服务失败、
任务预算、最后等待/参数释放失败及等待次数耗尽；整次worker全页回滚。
既有owner定义AST未变。分配、线程调度、有限futex和OS exit是显式服务，
没有创建或终止主机线程。完整JNI/bootstrap、独立signer、新鲜输出及线上
验收继续。私有名称/payload未发布。见
[B 队列与清理证据](evidence/vm9_alternative_queue_worker_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_queue_worker_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <b-queue-worker-evidence.json>
```

## 6.63 另外四个 ELF module constructors（2026-10-11 Asia/Shanghai）

`run_module_constructor` 通过 `constructor_entry` 接受实际 `.init_array` 中
`+299B30/+29C518/+2A1AC0/+2A2D40` 四个入口，缺省仍为 `+29ECAC`。
五个入口复用同一静态指令 decoder、reader/AST、转换、root factory 和清理。
各自从 fresh ELF 生成绑定与 codec，再发布 root 和短名称 descriptor；
没有复制 parser 或从 native snapshot 初始化 Python。

干净 `0d37a27` 的 **8 项修改前真实原生 RED** 证明四个入口在两基址均
自然返回且全部 descriptor 已发布，原 Python 缺少入口选择。实现后
**8 项原生/Python 对照、2 项既有 B constructor 回归、77 项回滚检查**
通过，覆盖不同 SP、thread id、填充值和基址。root、所有 descriptor
publication、全部 guest/heap/image 页面及有序分配/free/finalizer 效果一致。
物理原生栈不是最终输出；逻辑 effect 的 caller owner 地址和当时字节独立对照。

四个新增入口每基址分别发布 2/3/8/8 个 descriptor，共 42 项发布。
回滚覆盖入口白名单、frame/scratch/allocator 别名、预算、setup/publication
指令损坏及 input/wrapper/root/最后 publication 写失败；整次调用全页回滚。
其余生产 owner 定义 AST 未变。分配与 finalizer 注册保留显式服务契约。
私有名称/payload 未发布。

这一阶段恢复 `.init_array` 的五个 module constructor；其余 loader
constructor、完整 JNI/bootstrap、独立 signer、新鲜输出及线上验收继续。
见 [module constructor 证据](evidence/vm9_bootstrap_module_constructors_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_bootstrap_module_constructors_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <module-constructor-evidence.json>
```

## 6.64 六个 ELF support constructors（2026-10-11 Asia/Shanghai）

`vm9_elf_bootstrap.run_support_constructor` 恢复实际 `.init_array` 中六个
支持入口；对象初始化与 JNI cache mutex 继续使用既有 owner。

| 入口 | 恢复行为 |
| --- | --- |
| +17319C | GOT时钟发布，cold singleton table保存incoming return地址 |
| +180D28 | 两个vector清零、normal mutex、三次exit注册 |
| +1834E4 | ELF sized string、NULL malloc分支、GOT-selected destructor注册 |
| +271940 | 复用JNI cache mutex构造，不清零已有class/method cache |
| +28300C | realtime毫秒发布，包括wrapped signed算术 |
| +343A84 | auxv bit8、property状态、实际strncmp控制结果 |

干净 `38a180a` 的 **12 项修改前真实原生 RED** 后实施，**48 项fresh
原生/Python对照、51项回滚检查**通过。两个基址与不同SP、填充值、
return地址、GOT重定向、cold/warm table/cache、负秒数及signed wrap、
NULL malloc、非零注册状态、auxv/property分支均有对照。全部存活
guest/heap/image/libc页面、有序服务、publication、finalizer状态一致。
原生端实际执行matching-libc mutex与strncmp；输入由fresh ELF独立生成。

失败检查覆盖入口、地址、scratch、保留区、分配别名、缺少服务、clock
错误及无效timespec、最后publication写失败和exit服务拒绝，整次调用
全页回滚。时钟、auxv、property、分配和注册是显式guest服务；外部副作用
须延后到接受完整结果时。对象与JNI生产代码未改，没有native快照或
公开私有字符串/payload。原生物理栈与析构执行不是这一阶段输出。

五个module与六个support入口共覆盖11个init_array成员；`+15DB50`、
`+2679F0`及完整顺序loader/JNI组合仍待恢复。独立signer、新鲜输出及线上
验收继续。见 [ELF support constructor证据](evidence/vm9_elf_support_constructors_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_elf_support_constructors_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <support-constructor-evidence.json>
```

## 6.65 ELF guarded string constructor（2026-10-11 Asia/Shanghai）

`run_support_constructor` 增加实际 `+15DB50`，复用empty string与normal
mutex owner。Cold C++ guard保存显式thread id，构造全局string，经GOT读取
真实destructor并注册，再发布guard完成状态；warm路径跳过所有分配/注册。
递归、等待和原生错误诊断路径仍拒绝并回滚。

干净 `32e9440` 上 **8项修改前真实原生RED** 后实施，**18项fresh原生
对照、25项回滚检查**通过。两基址/不同SP、cold/warm guard、byte0非零
但bit0清零、byte1完成状态、NULL malloc、thread id、guard/object padding、
GOT destructor重定向与非零注册状态均有对照。完整guest/heap/image/libc
存活页面、有序分配/注册、guard状态和thread id一致。原生端执行实际
C++ guard和matching-libc mutex；分配、thread id、注册是显式guest服务。

六个既有支持constructor再通过 **12项fresh原生回归**，全部存活页面和
有序效果匹配。原有分支AST保持一致；旧verifier的未支持入口负例移至
相邻非法入口。25项失败覆盖guard递归/等待、thread/service参数、分配
别名与映射、reserved区域、注册拒绝/状态越界及最终guard写失败；全页
回滚。物理原生栈、真实线程并发和destructor执行不是这一阶段输出。

现已恢复12/13个init_array成员。`+2679F0`、完整顺序loader/JNI/bootstrap、
独立signer、新鲜输出及线上验收继续。私有名称/payload未发布。见
[guarded string证据](evidence/vm9_elf_guarded_string_constructor_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_elf_guarded_string_constructor_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <guarded-string-evidence.json>
```

## 6.66 ELF configuration constructor（2026-10-11 Asia/Shanghai）

`run_configuration_constructor` 恢复实际 `+2679F0`：从新鲜 ELF 解码五组
guarded globals，调用显式 signed strtol 服务并验证实际分派目标，再通过
既有 registry/singleton/TLS owner 构造配置。四个 registry 入口新增可选
`diagnostic_scope`，完整组合实际末尾 enter/leave；默认行为沿用既有边界。
六次实际复制及 publication 从 ELF table、MOVZ/MOVK 指令生成，不使用原生
快照或私有 payload 常量。第四组复制的后半段读取已解码 global 数据；
相关 global selector 布局、非零 copy-hook bounds、未知分派均明确拒绝。

干净 `648405a` 上 **2 项真实原生 RED** 后实施。**16 项 fresh 原生/Python
对照、72 项拒绝/回滚检查**通过：两基址/不同 SP、cold 后连续两次 warm、
非零 decode guards、相同目标的 decimal 变体、静态模板重定位、marker
变化、分配地址/thread id/clock 变化。Cold 原生执行两组真实 diagnostic
scopes，matching-libc strtol、normal/recursive mutex 与 condition broadcast；
分配、独立 TLS keys、注册和无等待者 futex 保持显式 guest 服务。每个
cold 对照匹配 **190 项有序服务效果**，同次 warm 只新增各一次 strtol。
完整存活 guest/heap/image/libc 页面、TLS/分配状态、每次返回边界和 scope
地址一致；物理原生栈与线程并发不属于此次输出。

72 项负例覆盖参数/资源上限、缺少服务、分配别名、未知指令/table layout、
非零 copy bounds、递归 guard、reserved globals/heap/frame、诊断契约错误
及后期写入失败，全部页面回滚。原有 registry 验证 **38 项对照、14 项
负例**逐字节一致；support owner 既有函数 AST 保持一致。

现在 13/13 个 init_array 成员已有独立实现。完整顺序 loader、同次
JNI/bootstrap、独立 signer、fresh 输出和线上验收仍继续，不能将单入口
覆盖视为完整加载。见 [配置构造器证据](evidence/vm9_elf_configuration_constructor_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_elf_configuration_constructor_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <configuration-constructor-evidence.json>
```

## 6.67 ELF init_array 完整顺序组合（2026-10-11 Asia/Shanghai）

`run_elf_constructors` 从 relocated ELF 读取并验证真实 init_array，按顺序
调用全部13个构造器，跨五个module和support/configuration共享一个纯分配
计划、全局catalog、TLS和诊断状态，全部页面一次提交。Module frees保留
既有有序逻辑effects；module finalizers在其staged构造完成后调用注册服务。

干净 `35470b0` 上 **2项完整真实原生RED** 后实施。**4项fresh完整顺序
对照、40项拒绝/回滚检查**通过，覆盖两基址、不同SP、heap/stack padding、
分配偏移、thread id、clock、注册状态和实际property/strncmp分支。每项
连续执行全部13个原生成员，cold匹配11549项服务效果（property变体11550），
其中6272次分配、5156次free、11次注册、两组真实diagnostic scopes；五个
module共发布142个descriptor。全部存活guest/heap/image/libc页面一致，
分配/free、注册、OS/TLS/clock各自的有序序列以及最终TLS/分配状态一致。
Module注册与分配的交错时序、物理原生栈和真实线程并发没有比较。

完整顺序暴露了单入口对照中没有消费的retired stack cells：前一个imported
descriptor的控制值与root export copy保存的地址进入后续reader内联名称。
组合owner从真实ADRP/ADD、MOVZ/MOVK/STR和保存SP推导这些活跃字节；未知
指令布局拒绝，不使用原生快照或硬编码控制payload。40项负例包含入口顺序、
参数/预算、服务、别名/reserved、控制指令和最后auxv服务失败；全页回滚。
此前support/configuration函数AST保持一致。

本节验证完整init_array构造序列。ELF二进制映射/完整symbol linking、完整
同次JNI/bootstrap、独立signer、fresh输出与线上验收仍未完成。见
[完整构造序列证据](evidence/vm9_elf_constructor_sequence_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_elf_constructor_sequence_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <constructor-sequence-evidence.json>
```

## 6.68 ELF 映射与完整符号链接（2026-10-11 Asia/Shanghai）

`vm9_elf_image.load_elf_image` 从调用方提供的二进制解析 ELF64/AArch64
program headers 和 dynamic table，映射全部 PT_LOAD、清零 BSS、执行
ABS64/GLOB_DAT/JUMP_SLOT/RELATIVE，并返回映射页、权限、GNU_RELRO、
init/fini arrays、依赖与导出。外部地址由显式 symbol provider 提供；保留
符号版本和依赖名，缓存每个唯一请求，未解析强符号拒绝，缺失弱符号为零。
无 section headers 也可加载；有 SysV/GNU hash 两种符号计数路径。

干净 `bc5611d` 上 **2项真实原生RED** 后实施。**10项独立映射对照、
2项完整链接后原生/Python构造序列、42项拒绝检查**通过。每组映射对照
匹配全部990页和18481项重定位，包括18267项relative、210处外部符号
及4处库内符号；140个唯一符号请求的版本/绑定、13项init array、2项
fini array、导出和权限一致。两基址覆盖无section headers、仅GNU hash、
弱符号存在和provider地址变化。GOT `+375010` 从ELF绑定实际JNI_OnLoad。

原生构造输入由独立的section-based ELF oracle加载；Python独立使用新
program-header/dynamic owner。两基址连续执行13个原生成员，匹配所有
存活guest/heap/image/libc页面、11549项服务和各自有序效果。42项负例
拒绝错误头、截断、地址/预算、版本链、重定位/array格式及无效provider；
输入bytes不变，不返回部分image。Provider应暂存外部效果；本owner不
回滚provider已经执行的外部操作。所有此前生产owner保持不变。

本节完成当前样本的PT_LOAD映射与完整eager symbol linking。依赖加载与
初始化、真实host OS loader、TLS/IFUNC/REL/RELR/Android packed relocations
不在该有界契约内。完整同次JNI/bootstrap、startup/worker/cleanup、独立
signer、fresh输出与线上验收仍未完成。见
[ELF加载证据](evidence/vm9_elf_image_loader_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_elf_image_loader_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <elf-image-evidence.json>
```

## 6.69 完整 JNI 与两条主线程 startup 组合（2026-10-11 Asia/Shanghai）

`vm9_jni_bootstrap.run_jni_onload` 组合实际JNI_OnLoad `+27B41C` 到返回：
解码ELF常量、验证已链接的defined GOT与self-code、显式JavaVM GetEnv、
发布JavaVM、JNI注册、冷long switch、条件startup、finalizer排队与elapsed
clock。`long_word & 0x200` 选择 `+2A0028`，否则 `+28040C`，每次只执行
一个入口。既有JNI、registry、A/B startup和queue owners执行组件行为。

干净 `43d9f8c` 上 **2项完整真实原生RED** 后实施。**4项fresh完整组合、
38项拒绝/回滚检查**通过。每个原生控制在同次执行中运行全部13个ELF
constructor和实际JNI/startup，自然返回JNI_VERSION_1_6 `0x10006` 并恢复
入口SP。Python使用独立新ELF加载和构造输入，匹配所有存活guest/heap/
image/libc页面、19项JNI调用、4项JavaVM调用、3项deferred worker请求、
TLS/分配状态与各自有序服务组。两基址覆盖A/B、移动SP、分配偏移、thread
id及heap/stack padding。每个基址的fresh Python构造状态供两分支分别复制；
每个原生控制均重新执行所有成员，不使用原生快照输入。

完整JNI在startup后还执行 `+27BED8 -> +27BF1C -> +204098`，创建并向
第二queue提交 `+34F010` inline finalizer callable。`vm9_startup` 扩展其
clone/destructor和显式queue_index，两队列各保留一个48-byte callable。
另有 **32项finalizer callable原生对照、9项回滚**，覆盖move/heap/free/
reset/assignment和padding；旧A/B/queue callable **84项对照、12项回滚**
fresh结果与已发布证据逐字节一致。38项主组合负例包含错误输入/服务、
linked GOT、selector/self-code、finalizer方法及晚期thread/signal/clock失败；
全页回滚。其他生产owner不变，shared startup仅改动这三个已有函数。

对照比较全部存活页面与各自的allocation/free、registration、OS/JNI/VM/
thread有序组；module注册与分配的交错时序、physical native stack/thread
output scratch及真实JVM/并发不在契约中。Provider必须暂存外部操作，页面
事务不撤回已执行的外部效果。当前要求成功GetEnv、零singleton copy bounds、
当前样本dispatch/self-code及有界serialized服务；其他分支拒绝。

本节完成fresh ELF映射/链接/构造到JNI和条件主线程startup的完整组合。
三条worker及其TLS/线程清理尚未在本节同次组合验证；第二队列finalizer
callable的实际callback body、独立signer、fresh输出和线上验收仍未完成。
见 [完整JNI证据](evidence/vm9_jni_complete_bootstrap_fresh_20261011.json) 和
[finalizer callable证据](evidence/vm9_jni_finalizer_callable_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_complete_bootstrap_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <jni-bootstrap-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_jni_finalizer_callable_20261011.py --library "$env:TOMATO_LIBMETASEC" --output <finalizer-callable-evidence.json>
```

## 6.70 完整 JNI 后的两条 worker 与 guest 退出清理（2026-10-11 Asia/Shanghai）

`vm9_jni_workers.run_requested_worker` 消费JNI/startup实际发布的thread
entry与argument，复用既有executor、A/B queue、TLS与pthread_exit owners。
显式选择当前线程的独立TLS/pthread存储；线程共用进程级key generation
table，分别转移support所有权、运行实际初始化任务、自然返回，再完成
matching-libc joinable guest pthread_exit body。A/B来自JNI结果的startup
entry。未知任务、非fresh joinable存储与detached回收分支拒绝。

干净 `4bb15a2` 的 **2项真实完整原生RED** 后实施。**4项原生/Python
对照、28项回滚检查**通过：两基址×两条startup分支，每个native控制在
同一CPU运行全部13项constructor→JNI→executor worker→实际A/B queue
worker→两次guest退出。所有存活guest/heap/image/libc页面、各自有序
allocation/free、registration、OS/JNI/JavaVM/thread服务组与线程独立TLS
匹配；每组11464项allocation/free效果，两次finite wait，两条thread
support已清空，joinable状态变为1。每次仍仅执行一个A/B入口。

每个基址的Python独立ELF构造结果供两个分支分别复制；每个native控制
重新运行全部成员，不使用native snapshot。高基址覆盖SP偏移、thread id、
allocation delta及heap/stack padding。Clock provider承担实际libc首次
clock_gettime的lazy cache；finite futex provider在解锁后停止idle worker。
OS exit是显式guest事件。Provider需暂存外部效果，guest页面事务不能撤回
已完成的外部调用。B的max_steps/max_depth约束其descriptor运行；A复用
既有VM owner的内部预算。Physical stack/thread输出scratch、module注册与
分配的交错、真实OS线程/JVM/并发、真实allocator boot不在本节契约中。

JNI一共请求三条worker；本节完整组合其中executor和第一条初始化queue。
第二queue仍保留JNI finalizer callable，实际callback与其延时后续任务
尚未在Python组合。独立signer、fresh输出及线上验收仍未完成。
见 [完整worker证据](evidence/vm9_jni_requested_workers_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_requested_workers_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <jni-workers-evidence.json>
```

## 6.71 JNI finalizer 的首条延时任务提交（2026-10-11 Asia/Shanghai）

`vm9_timed_tasks.submit_timed_callable` 恢复 `+325454` 的非零 W32 delay
分支、`+326C00` deadline 和首次 `+326D04` deque 插入。复用共享 callable
移动/析构，新增 `+34F058` 后续任务的实际 clone/destructor；task 拥有
80-byte wrapper，保留分配 padding，构造 64-byte task、首个 map/segment，
按原生顺序释放 controller mutex、发送 condition signal，再解锁 executor。
Clock、分配与 signal 是显式 provider，外部效果须由调用方暂存。

干净 `85b80c7` 上 A/B 各一次完整原生 ELF/13 constructors/JNI/三条 worker
及 guest exit 自然返回后实施。**8项原生/Python提交对照、24项 callable
对照、25项回滚检查**通过；两基址、两 queue index、正/负非零 delay、
不同 heap padding 和地址偏移覆盖全部存活 guest/image 页面、有序 provider
效果、完整 wrapper/task/deque。旧 finalizer callable **32/9** 与旧共享
callable **84/12** 回归 JSON 逐字节一致。

本节接受已初始化 controller 的首个空 deque 和 inline 后续 callable。
Immediate/cold singleton、已有任务的排序/扩容、cancelled executor、真实
并发及定时 callback 执行均在本节边界之外。第三条 finalizer 的完整
Python worker、独立 signer、新鲜签名输出和线上验收仍未完成。
见 [延时提交证据](evidence/vm9_timed_task_submission_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_timed_task_submission_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <timed-task-evidence.json>
```

## 6.72 JNI finalizer 完整 worker 与 guest 退出（2026-10-11 Asia/Shanghai）

`vm9_jni_finalizer.run_finalizer_worker` 恢复第三条 startup queue 的实际
`+204348` body，依次复用 singleton、JNI environment、image VM、timed task
和 guest exit owners。覆盖两次 absent-file open、rejected sigaction、
trylock 后的临时代码探针、实际 GetEnv/GetStaticMethodID/ExceptionCheck、
ELF PT_LOAD 范围与 metadata 写入，再提交 `+34F058` delay 60000 的首条
后续任务。结束 queue cleanup 后执行完整 joinable guest pthread_exit，
包括此 worker 的 JavaVM/TLS destructor；所有 OS/clock 服务均为显式 provider。

原生侧从 fresh ELF 映射开始，在同一 CPU 执行全部13constructors、JNI、
三条 worker 和三次 guest exit，实际复制并执行原有临时代码后自然返回。
Python侧独立映射自己的ELF；临时复制代码经完整hash与指令guard限定，
恢复自修改counter语义，返回 **1**；image VM 经 **6435 steps** 和实际
pagesize callbacks 到达原有exit。私有代码、路径与解码字符串不进入公开仓库。

干净 `88a8801` 上 A/B 两条完整原生 RED 后实施。
**4项完整原生/Python对照、4项copied probe对照、47项回滚检查**通过。
完整对照覆盖两基址×两分支，包括不同heap/stack padding与地址偏移；
copied probe另覆盖page-size cache冷/热状态。所有存活guest/heap/image/libc
页面、分配/释放、JavaVM/JNI和有序服务组一致。五个既有共享owner保持
原有hash；本节完整组合同时覆盖已接受的两条worker与延时提交。

物理stack保存区、线程输出scratch以及module registration与allocation
之间的交错不属于页面/服务组契约。文件存在、成功signal安装、探针系统
服务失败、contended mutex、非空timed deque、detached exit均不在本节
支持路径内。Guest页面回滚不能撤销外部provider效果，调用方需自行暂存。
后续 `+203948` callback、完整独立signer、fresh签名和线上验收继续。
见 [finalizer证据](evidence/vm9_jni_finalizer_worker_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_finalizer_worker_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <finalizer-worker-evidence.json>
```

## 6.73 实际延时 JNI callable 与两段 image VM（2026-10-11 Asia/Shanghai）

`vm9_jni_followup.run_delayed_followup_callable` 恢复已入队的 inline callable
`+2043BC → singleton136 → +203948`。它从 guest ELF 执行两段实际 bytecode：
checksum VM **8,606,106 steps** 到达 `+89640`，lookup VM **301 steps** 到达
`+89D18`。第二段的 **15 次实际 callbacks** 包含 masked decode、真实
`+21CBEC/+2191D4` Java lookup、diagnostic scope、字符串比较、guest ELF
CRC 表读取、配置写入，以及 owning string/reference 的有序释放。
恢复 helper 保存输出 reference 的栈写入，供后续 TLS 节点复制 padding；
CRC 表地址由真实 ARM64 指令确定为 guest ELF `+96144`。
结束后继续 registry320 getter、最终配置写入和临时字符串销毁。

本节串行路径中的默认 Java 对象尚未发布。执行真实 unavailable logger，
构造并持有错误字符串，共新增 **2 次 GetEnv、0 次 JNI 方法调用**。
原生与 Python 的有限服务响应全部消耗；错误分支没有用空返回代替。
成功的 live Java 字符串转换、NULL environment 和其他未恢复分支明确拒绝。

干净 `dd2dc01` 的 A/B 两条完整原生 RED 后实施。
**4 项 fresh 完整原生/Python 对照、22 项页面回滚检查**通过，覆盖两基址
×两分支及不同 heap/stack padding。原生从 fresh ELF 在同一 CPU 执行
全部13constructors、JNI、三workers、三次完整 guest exit，再显式驱动
实际入队的 callable 自然返回。Python 独立映射自己的 ELF，全部存活
guest/heap/image/libc 页面、分配/释放、JavaVM/JNI 和有序服务组一致。
六个既有共享 owner 保持原始 hash；不使用 native snapshot 作为模型输入。

这批对照使用 **显式 callable body driver**，尚未证明完整 timed executor
dispatch/queue 周期。物理 stack、线程输出 scratch、module registration
与 allocation 的交错继续沿用既有排除契约；provider 外部效果需调用方暂存，
guest 页面回滚不能撤销它们。完整独立 signer、fresh 签名和线上矩阵继续。
系统服务按有效 ABI 参数比较；`close` 未使用的尾部寄存器不属于参数契约。
私有 ELF、bytecode、常量文本和诊断快照不进入公开仓库。
见 [延时回调证据](evidence/vm9_jni_followup_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_followup_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <followup-evidence.json>
```

## 6.74 实际 timed poll、转交与 queue 清理（2026-10-11 Asia/Shanghai）

`vm9_timed_tasks.dispatch_timed_callable` 恢复实际 `+325950` wrapper 转交，
克隆 inline JNI follow-up 到 ABI 临时区，再移入已清空 queue 保留的 48 字节
槽位并 signal。`vm9_startup.destroy_callable` 恢复 `+3725B8` heap wrapper
拥有的 inline follow-up 析构和外层 free。既有 poll 与 queue owner 完成
`+326DFC → +325950 → +326578 → +2043BC/+203948` 组合，任务与 wrapper
各释放一次，queue 最终为空。

原生转交中的 matching-libc mutex lock 会保存临时 callable 地址。
这次 ABI 栈写入随后进入 image VM 保留的寄存器 backing，并被最后的
scoped writer 高七字节复制到 TLS node padding。恢复该写入后，存活
页面中的 padding 也逐字节一致；没有通过排除 heap 字节消除差异。

干净 `9066915` 的 A/B 两条完整原生 RED、两基址旧 owner 拒绝后实施。
**4 项 fresh 完整原生/Python 对照、20 项页面回滚检查**通过，覆盖两基址
×A/B 及不同 heap/stack padding。每组匹配 **11,502 项 allocation/free**，
checksum VM **8,606,106 steps**、lookup VM **301 steps / 15 callbacks**，
新增 **2 次 GetEnv、0 次 JNI**。全部存活 guest/heap/image/libc 页面、
JavaVM/JNI 和有序服务组一致。共享 callable 的旧 B、queue、finalizer
回归也通过。follow-up owner 保持原始 hash；Python 独立映射和构造自己的
ELF 状态，native snapshot 仅为私有诊断输出，不作为正式测试输入。

本节使用 **显式 poll/queue driver**，尚未验证完整 executor worker 等待
周期。仅支持保留一个空槽位的串行队列；vector growth、非空队列、未知
ownership 和 contention 明确拒绝。物理 stack、线程输出 scratch、module
registration 与 allocation 的交错沿用既有比较排除契约。provider 外部
效果需调用方暂存，页面回滚不能撤销它们。完整独立 signer、live Java
字符串转换、fresh 签名和线上矩阵继续。私有 ELF、解码文本和诊断快照
不进入公开仓库。见 [timed cycle 证据](evidence/vm9_jni_timed_cycle_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_timed_cycle_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <timed-cycle-evidence.json>
```

## 6.75 三条 worker 协作等待、转交与完整退出（2026-10-11 Asia/Shanghai）

`vm9_worker_scheduler.run_requested_worker_schedule` 接收实际 JNI 产生的三条
worker descriptor，以显式有限选择与 futex provider 交替推进。原始
executor 在初次等待暂停，initializer 退出后 finalizer 提交 timed task 并
暂停，executor 到期转交真实 follow-up，queue 执行两段 image VM 和清理，
三条 worker 按 **1、2、0** 自然返回并完成 joinable guest thread exit。
总计 **6 次等待（3、1、2）、9 次选择**；没有创建 host worker threads。

`vm9_startup` 统一拥有 condition 暂停/恢复、queue extraction、controller
等待和 executor 循环；同步入口通过显式 provider 完成同一套 generator。
等待之间使用单一外层页面事务，避免各 worker 保留过期页面副本。
默认 queue 的 ABI 准备也由同一 helper 负责。finalizer 的本地线程析构
注册恢复 emutls getter 保留的返回地址，后续 VM backing/TLS padding 一致。
同步 wait provider 的耗尽异常也原样传递并回滚（4 项边界检查）。provider 外部 effects 需调用方
暂存；guest 页面回滚不能撤销它们。

干净 `881e06d` 的两条完整原生 A/B RED 与旧 executor 实际到期任务拒绝
建立因果证据。**两基址×A/B 四项 fresh 完整原生/Python 对照、23 项页面
回滚检查**通过。每组 allocation/free、JavaVM/JNI、有序服务和全部存活
guest/heap/image/libc 页面一致，15 callbacks、checksum VM **8,606,106**
steps、lookup VM **301** steps，新增 **GetEnv 2 / JNI 0**。task/wrapper
清理、空队列、退出顺序匹配。旧 executor **62/6**、queue **94/5** 回归与
已发布结果逐字节一致。condition 暂停/恢复的 **44 项 matching-libc 对照、
19 项回滚**仅比较其 guest/TLS、mutex、futex、返回值与 errno 边界。

原生和 Python 分别从独立 ELF、13 constructors 和 JNI 输入开始。物理
stack、线程输出 scratch 和 module registration/allocation 交错沿用既有
比较排除契约；native snapshot 仅作私有诊断输出。vector growth、未知
callable ownership、重复 timed task 和 contention 尚未恢复。
**live Java 字符串转换、完整独立 signer、fresh 签名和线上矩阵仍未完成。**
私有 ELF、解码文本和快照不进入仓库。见 [协作等待证据](evidence/vm9_jni_worker_schedule_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_worker_schedule_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <worker-schedule-evidence.json>
```

## 6.76 Java byte array 转引用与实际诊断锁（2026-10-11 Asia/Shanghai）

`vm9_jni_environment.construct_java_byte_array_reference` 恢复原始
`+2700A8`：通过 `0x558 GetArrayLength` 和 `0x640 GetByteArrayRegion`
读取 Java byte array，调用 `calloc(1,n)`、实际 sized string owner
`+2481FC`，释放临时 buffer，再组合 `+1625A4` 的诊断 scope 与 reference。
NULL environment/array、非正 signed W32 长度及 calloc NULL 均生成 NULL
string/count1；字符串 buffer 的 malloc NULL 保留空 string object。
内嵌 NUL、所有字节值和跨页 payload 按显式长度保留。region 为 void
调用，其返回字不参与判断；此 helper 沿用原生行为，不额外检查 Java exception。

两基址×冷暖诊断锁共 **52 项原生/Python 对照、19 项页面回滚检查**通过。
原始 helper、reference constructor、matching-libc mutex 自然执行；guest
payload、所有 image 页面、完整 24-byte scope 和 JNI/allocation/free/lock
服务顺序一致。实际 `+248208` 保存的输出 reference 字用于后续 scope
padding，已按 ABI 恢复。测试还覆盖 JNI table 重读、分配失败和 provider
异常后的页面回滚；provider 外部 effects 由调用方暂存。

实现前两项原生 RED 和旧 owner 的真实入口 API 缺失建立基线；原有
environment 定义的执行 AST 完全一致。原生和 Python 从独立 ELF 与
synthetic 服务输入开始，native snapshot 不作输入。完整物理 stack、
C++ unwind 和真实 Android JVM 尚未验收。**实际 live lookup `+21CBEC`、
完整独立 signer、fresh 签名与线上矩阵仍未完成。**
见 [byte array 证据](evidence/vm9_jni_byte_array_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_byte_array_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <byte-array-evidence.json>
```

## 6.77 JNI 引用字段、无参数方法与引用清理（2026-10-11 Asia/Shanghai）

`vm9_jni_environment` 增加 `read_java_reference_field`（`+26FA00`）、
`invoke_no_argument_java_reference_method`（`+26F650/+26F6E0`）和
`release_java_reference`（`+26F1D0`）。它们复用同一 JNI table 调用 owner。
字段 API 只恢复 object/array，方法 API 只恢复无参数的 object/array 返回；
primitive 和带参数的方法明确拒绝。方法 wrapper 的两份 va_list 和
CallObjectMethodV 消费的 32-byte copy 按实际 ABI 写入。

两基址共 **74 项原生/Python 对照、18 项页面回滚**通过；returned
reference、status low byte、guest payload、所有 image 页面和有序 JNI
服务一致。覆盖 PushLocalFrame 失败、初次/class/末次 exception、NULL
对象与 member、high status word，以及 local/global/weak/unknown reference
类型。按原生保留最终 exception 前已返回的 reference，class exception
的早退路径不额外删除 class local，末次检查按低字节 clear/status。
方法 helper 在 environment 检查前读取 signature，NULL signature 明确
拒绝。NULL environment/reference 的清理跳过 JNI。

新增真实入口在旧 owner 上缺失；原有 environment 定义（含 6.76 byte array）
的执行 AST 完全一致。两基址×SDK27/30 的四项实际 `+21CBEC` 原生 RED
也已自然生成 binary byte array 的 MD5 hex/count1，旧 Python live 分支
拒绝且页面未变。这些原生结果是后续 live lookup 的基线。
本节仅完成上述 JNI component；**Python live lookup、完整独立 signer、
fresh 签名、真实 Android JVM 和线上矩阵仍未完成。** native snapshot
不作 Python 输入，JNI/provider 外部 effects 不能由页面回滚撤销。
见 [JNI 引用 member 证据](evidence/vm9_jni_reference_members_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_reference_members_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --output <jni-reference-members-evidence.json>
```

## 6.78 实际 reference 作用域与 MD5 生命周期（2026-10-11 Asia/Shanghai）

`vm9_reference_scopes` 恢复 `+1625A4` 的构造、`+1651C0/+15F580`
的复制和 `+15E1A8` 的释放。三个操作使用实际 entry SP 定位 scope，
复用诊断锁、reference/count 与 deleting string cleanup 的既有 owner。
复制按原生先清空 destination，再在 scope 内重读 source，保留别名行为。
释放即使 count 为 NULL 也进入 scope；有符号计数边界及 free 前字节一致。

两基址×冷/暖诊断锁，共 **64 项原生/Python 对照、12 项回滚**通过。
另有 **16 项实际 MD5 对照、4 项回滚**通过，覆盖内嵌 NUL、全部字节值、
跨页输入、NULL source 和单/双 padding block。MD5 算法和 ELF alphabet
继续由 `vm9_objects.construct_digest_reference` 独占；可选 lifecycle
在实际构造、发布和释放边界操作临时 reference，不按分配序号插入 scope。
原生 MD5 padding block 与保存的 X20 会成为后续 scope 的 padding，按
因果写入恢复；scope 在每次退出边界比较，后续物理 frame spills 不作
scope 最终状态。所有 guest payload/image 页面、有序分配/free/锁和
临时 reference 一致。六项旧 unscoped helper 的真实原生 RED 已记录。

原有摘要回归 **142 项对照、5 项拒绝**的
JSON 与已接受结果逐字节内容一致。**实际 Python live lookup、完整独立
signer、fresh 签名、真实 Android JVM 和线上矩阵仍未完成。** ELF、解码
文本和 native snapshot 不发布；native memory 只用于执行后比较。
页面回滚不撤销外部 provider effects。见 [scope 与 MD5 证据](evidence/vm9_reference_scopes_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_reference_scopes_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <reference-scope-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_scoped_digest_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <scoped-md5-evidence.json>
```

## 6.79 已初始化对象的实际 live Java lookup（2026-10-11 Asia/Shanghai）

`vm9_jni_followup.recover_absent_java_string` 保留既有 absent 分支，并恢复
`+21CBEC` 的已初始化 Java 对象路径。SDK≤27 读取 field；SDK>27 读取
中间 object 后调用无参数 method。两者继续读取 object array 的 element0、
调用 byte-array method、构造 binary string、计算 MD5 hex，并按原生顺序
复制和销毁 owning reference、删除 byte array/element/array locals。

两基址×SDK27/30，共 **48 项原生/Python 对照、11 项页面回滚**通过。
覆盖内嵌 NUL、全部字节值、NULL field/element/method、空数组/byte array、
length/element/method exception、calloc NULL 和 string-buffer malloc NULL。
全部 guest payload/image 页面、JNI/JavaVM/分配/free/锁顺序、free 前字节、
每次 scope 退出的24字节一致；成功输出 MD5 hex、count1。沿用四项实际
原生 RED，旧 owner 明确拒绝 live 分支且所有页面未变。

SDK getter 使用 `+1CFAF8` 的 encoded table/cache，独立于既有 plain
getter 的 cache；本节仅接受 warm cache。所有 member name、signature、
error source 和 alphabet 都来自 guest ELF，不发布 literal。MD5 算法
复用原 owner，同时恢复其 raw scratch，以及 field return address、
canary 和 reference slot 进入后续 scope padding 的实际重叠。
新增11项 guards 另行运行，未重复已接受的48项 native controls。

**cold live initializer、cold encoded SDK conversion、delayed VM 的 live
provider 接线、完整独立 signer、fresh 签名、真实 Android JVM 和线上矩阵
仍未完成。** 本节使用 synthetic JNI，不把 native snapshot 用作 Python
输入。页面回滚无法撤销外部 provider effects。见 [live lookup 证据](evidence/vm9_jni_live_lookup_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_live_lookup_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <live-lookup-evidence.json>
```

## 6.80 cold encoded SDK getter 与实际 live lookup（2026-10-11 Asia/Shanghai）

`vm9_configuration_init.get_encoded_sdk` 恢复 `+1CFAF8` 的属性查找、
属性读取及冷缓存转换。encoded cache `+3DF140` 与 plain cache
`+3DF148` 独立；两者共用既有 `+2771BC` 十进制转换 owner。
冷 encoded getter 清零 entrySP−0x160 的256字节 buffer，显式调用
find/read provider，忽略 read 的返回字并读取其写入的 guest buffer。
转换仍要求已初始化 singleton136，并明确拒绝 active instrumentation。

SDK getter 通过 **52项原生/Python对照、9项页面回滚**：两基址各13种
encoded 与13种 plain 情况，包括已有有符号缓存、属性缺失、空值、
SDK27/30、空白与后缀、负值、无效值、有符号边界及 read status 忽略。
原生返回、全部 guest payload/image 页面、property buffer、缓存字与
有序属性服务一致。plain getter 的旧行为同时回归通过。

`recover_absent_java_string` 继续使用实际 initialized live lookup，
并接收可选 `find_sdk_property` / `read_sdk_property`，通过
**10项完整原生/Python对照、4项页面回滚**。两基址分别覆盖 cold
SDK27/30、属性缺失→SDK0，以及 warm SDK27/30。全部 guest payload/
image 页面、JNI/JavaVM/分配/free/锁顺序、free前字节和24字节 scope
退出内容一致；binary MD5 hex 与 count1 一致。新增服务参数未改变
历史 absent 分支执行语义。

合计 **62项对照、13项回滚**，分组证据保留52/9与10/4的各自范围。
两组各有4项改动前 native RED；已接受原生测试未重复执行。所有名称
从 guest ELF 解码；native snapshot 不作 Python 输入。页面回滚无法
撤销外部 provider effects。

**实际 cold live initializer `+2191D4`、delayed VM/worker live provider
接线、完整独立 signer、fresh签名、真实Android JVM与线上矩阵仍未完成。**
见 [SDK与lookup分组证据](evidence/vm9_encoded_sdk_live_lookup_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_encoded_sdk_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <sdk-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cold_sdk_lookup_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <cold-lookup-evidence.json>
```

## 6.81 带整型引用参数的 JNI 方法与静态字段（2026-10-11 Asia/Shanghai）

`vm9_jni_environment` 在同一 member owner 内恢复实例 `+26F650`、静态
`+26F2A4` 方法，以及 `+2715B8` 静态字段。方法接受按 signature 匹配
的 raw uint64 参数：前三个进入 X5–X7 save slots，后续写入 guest entry
stack。JNI读取并消耗独立 va_list copy。支持 object/array、Z/B/C/S/I/J
返回，以及 void；字段支持相同的非浮点值。返回按原生字宽写入预先
清零的8字节临时结果。生产名称/signature仍来自 guest ELF。

两基址共 **140项原生/Python对照、11项页面回滚**通过。覆盖所有上述
返回字宽、0/1/2/3/4/5/7个参数、NULL环境/status/target/name/class/member、
PushLocalFrame失败及push/class/final exception。全部guest payload/image
页面、逻辑scratch、JNI顺序、已消耗的参数和va_list一致；原生返回及
status byte一致。旧reference field与无参数reference method各在两
基址回归通过；没有重复既有完整批次。四项改动前原生RED证明旧
无参数owner拒绝带参数整数返回，且所有Python页面不变。

测试member/signature是明确的synthetic control，不声明真实JavaVM。
未知/浮点signature、参数数量/字范围、未映射stack与provider失败
明确拒绝，页面保持不变；页面回滚无法撤销外部JNI effects。
**完整physical register spills、浮点参数/返回、C++ unwind、实际
cold initializer与class resolver组合、VM/worker接线、完整独立signer、
fresh签名和线上矩阵仍未完成。** 见 [JNI member证据](evidence/vm9_integer_jni_members_fresh_20261011.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_integer_jni_members_fresh_20261011.py --library "$env:TOMATO_LIBMETASEC" --output <integer-jni-evidence.json>
```

## 6.82 实际 UTF 构造与 Java service 查找（2026-10-12 Asia/Shanghai）

`construct_java_utf_string` 恢复 `+270204`：复用既有 C++ string owner，
以 short/heap tagged layout 保存输入，在 `+270168` 内调用实际
NewStringUTF slot，并在调用前后按原生顺序 check/clear exception。
清除新异常时仍保留返回引用；JNI之后释放临时heap string。

`lookup_java_service` 恢复 `+218660` 的八组ELF lazy字符串、default
对象读取及environment获取。两次静态调用取得中间引用，再把输入
service name转换为Java string，调用实例方法并按原生顺序清理
string、manager、binder locals。所有生产name/signature来自guest ELF。
该entry是取得service引用的调用，供实际initializer使用。

两基址共 **42项原生/Python对照、9项页面回滚**。其中UTF20项覆盖
empty、short、22/23/64字节、NULL环境/source/reference及调用前后异常；
service22项覆盖正常lookup、NULL name、中间/最终NULL引用、各方法
异常、UTF异常及其外层异常。返回引用、全部guest payload/image页面、
逻辑UTF对象/exception scope、所有服务顺序和free前字节一致。
四项改动前native RED自然返回，旧API缺失。服务路径要求live default
Java对象和现有environment acquisition；缺失default/VM明确拒绝，
与其余参数/provider失败一道保持页面不变。页面回滚无法撤销外部effects。

**完整physical register spills、真实Android JVM、实际cold initializer
的公开组合、VM/worker provider接线、完整独立signer、fresh签名和线上
矩阵仍未完成。** 见 [UTF与service查找证据](evidence/vm9_java_service_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_java_service_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <java-service-evidence.json>
```

## 6.83 实际 live initializer 与 cold lookup（2026-10-12 Asia/Shanghai）

`initialize_absent_object` 保留历史调用名称并恢复实际 `+2191D4` 的
live default 对象分支。31组lazy字符串由ELF解码；once flag与mutex、
service查找、FindClass/IsInstanceOf、Parcel静态调用、UTF转换、default
对象方法、SDK分支静态字段、整数/void方法及global引用发布沿用实际
原生顺序。成功路径recycle两个Parcel，临时local引用反序清理。
`recover_absent_java_string` 在cold初始化发布引用后继续完整binary lookup。

两基址共 **92项原生/Python对照、6项页面回滚**。88项initializer覆盖
SDK22/23/27/28/34/35、already initialized、类型不符、class NULL/异常、
空Parcel、负UID、global NULL/异常/既有global类型、各member NULL/异常
及cold SDK27/30。另4项从cold initializer与cold SDK执行完整lookup，
比较scope退出字节及binary MD5输出。全部guest payload/image页面、
JNI/JavaVM/分配/free顺序、free前字节、once flag与发布引用一致。
六项参数/provider拒绝保持页面不变；页面回滚无法撤销外部effects。
已有四项改动前native RED在旧owner拒绝时自然完成原生初始化；旧RED
与本批基线的历史initializer/lookup/default拒绝行为经AST检查衔接。

**完整physical register spills、真实Android JVM、VM/worker provider接线、
完整独立signer、fresh签名和线上矩阵仍未完成。** 见
[initializer证据](evidence/vm9_live_initializer_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_live_initializer_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <initializer-evidence.json>
```

## 6.84 delayed VM/callable/worker 的 live provider 接线（2026-10-12 Asia/Shanghai）

`_run_vm`、`run_delayed_followup_callable` 与 worker scheduler 转发既有
JNI、calloc/reallocate、diagnostic observer、encoded SDK property 服务及
payload上界，沿实际 `+2043F4 → +21CBEC` 回调执行cold initializer与lookup。
验证还发现并恢复 `+21CD60` 在live路径保存owning output reference的
写入；后续registry setter的TLS节点保留其上七字节padding，释放前
字节因此与原生一致。

两基址 **4项原生/Python evaluator对照、2项完整callable对照、2项
worker入口检查、16项回滚**。evaluator覆盖SDK27/30：实际301步bytecode、
15对callback、全部guest payload/image页面、JNI/JavaVM/SDK/allocator
顺序、free前字节及配置写入匹配。callable从 `+2043BC` 执行两个VM与
最终配置发布及清理；本批synthetic输入的checksum范围为空，第一VM
自然执行30步，lookup执行301步。既有完整checksum的8606106步验收
保持为历史独立证据，本批没有重复6.72–6.75完整批次。

worker从真实scheduler入口取得queue task并执行完整live callable，
在随后的queue wait检查global引用与配置值7，然后按显式一步调度
上界停止；这两项入口检查及两项missing calloc拒绝都回滚全部页面。
此边界检查没有执行完整三worker退出，也没有原生/Python整轮调度
对照。其余12项检查在evaluator/callable入口分别拒绝missing JNI、
calloc、SDK find/read、过小payload上界及JNI provider异常。
外部provider ledgers不属于页面回滚范围。

**完整live三worker调度对照、真实Android JVM、完整独立signer、fresh
签名和线上矩阵仍未完成。** 见 [live provider接线证据](evidence/vm9_live_delayed_providers_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_live_delayed_providers_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <live-provider-evidence.json>
```

## 6.85 实际 request stack evaluator 与请求 VM 接线（2026-10-12 Asia/Shanghai）

`vm9_request_leaf_prefixes.execute_stack_evaluator_prefix` 恢复实际 `+28B05C`
的 FindClass、method ID、static/instance object calls、array iteration、UTF
借用/释放、local reference 清理和最终 exception clear。九组名称仍由 guest
ELF 解码；JavaVM/JNI 与 singleton getter 是显式输入服务。

两基址 **78项原生/Python对照、1项请求VM入口检查、20项页面回滚**。
76项对照执行原始 acquisition；2项 NULL environment 对照使用显式 NULL
acquisition 边界，验证其后实际 evaluator 的自然零返回。singleton 为独立
构造的 warm 输入，原始 getter/比较 helpers 正常执行，没有使用原生页面
作为 Python 输入。全部 guest payload/ELF 页、environment pair、服务与
getter SP 顺序、两份 logical va_list 匹配；physical register spills 未验。

对照覆盖 JNI NULL/exception 清理、UTF 单边 NULL、descriptor cursor、
array/descriptor signed overflow、空字符串和前缀比较。原始代码虽然取得
两条 UTF 字符串，却使用第一条指针做两次比较；保持此行为及第二条 UTF
的释放顺序。比较耗尽长度时跳过 singleton；非零 checked environment
分支仍明确拒绝。显式 frame/string 上界及缺失服务/异常均回滚页面，
外部服务 ledger 不在页面回滚范围。

请求 VM 入口转发 `invoke_jni/get_singleton`。fresh Python outer 的拥有者
分配 JavaVM/JNI fixture，经实际请求 callback 执行原始语义的 acquisition
和 evaluator；使用 NULL FindClass 输入，965步后停在尚未恢复的
`+28C09C` scope cleanup。该1项入口检查不是完整请求返回或整链原生对照。
请求入口 missing JNI/provider exception 的2项检查也保持所有页面不变。

**scope cleanup、cold singleton/request 整链组合、真实 Android JVM、
完整独立 signer、fresh 签名和线上矩阵仍未完成。** 见
[evaluator 证据](evidence/vm9_request_stack_evaluator_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_stack_evaluator_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <stack-evaluator-evidence.json>
```

## 6.86 实际 boolean scope 清理与 elapsed event（2026-10-12 Asia/Shanghai）

`leave_boolean_scope` 恢复 `+28C09C`：非零 scope flag 才读取 elapsed
microseconds，再对 `+3E1620` 执行 uint64 fetch-add，并以旧计数进入
`+28E1FC/+28E204`。`+343D60` 的原始指令是 LDADDAL 或 LDAXR/STLXR，
不是 decoder；此实现记录串行语义，未验证 host 并发原子性。

`execute_elapsed_event` 恢复两组 guest ELF lazy 名称、C++ string 克隆、
计数采样、mode formatter、两项 uint64 借用参数、warm logger emission
和临时清理。两项参数 formatter 使用既有 token/renderer/转换拥有者，
新入口对应 `+1B4054/+1B41D8`；参数和格式均来自 guest 输入。

两基址 **46项原生/Python对照、1项请求VM入口检查、28项页面回滚**。
全部 guest payload/ELF 页、时钟顺序、allocator/free 顺序、存活堆和
logger vector/锁状态匹配，没有 padding mask 或 native snapshot 输入。
覆盖 flag0/2、负 elapsed 的 uint64 表示、微秒截断、计数回绕、零除数
采样、clock 后载入计数、warm names、vector append/grow/drop、两次
event emission、signed mode 和不采样路径。

26项 leaf 拒绝检查覆盖缺失服务、clock error、NULL start unmapped input、
cold/contended/alternate logger、格式、栈和 allocation failure；2项请求
入口 missing JNI/provider exception 保持全部页面不变。外部服务 effects
不属于页面回滚范围。fresh owning outer 的实际请求VM完成 evaluator 与
scope cleanup，从965步继续到993步，下一处明确拒绝 `+28C0EC` 发布
callback。该1项检查不是完整请求返回或整链原生差分。

**发布 callback、真实 URL/header/JNI 转换、完整独立 signer、fresh
签名和线上矩阵仍未完成。** 见 [scope 证据](evidence/vm9_request_boolean_scope_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_boolean_scope_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <boolean-scope-evidence.json>
```

## 6.87 实际 JNI 发布器与请求 byte gate（2026-10-12 Asia/Shanghai）

`publish_request_handle` 恢复实际 `+28C268`：先获取 environment，
再经 `+28C308/+26E70C` 分别派发 `(0x2000001,0,root,0,0)` 与
`(0x2000002,0,root,0,0)`，两次调用结束后使用首次 environment
清理两个引用。返回值只检查首次 dispatch 的引用是否非零。
复用既有 JNI acquisition、dispatcher、exception 和 reference cleanup 拥有者。

**纠正上一检查点的 callback 归属：** `+28C0EC` 的实际编码表
`+383858` 指向 `+28BB54`，原始指令为 `MOV W0,0; RET`。
`execute_request_byte_gate` 解码 guest ELF 名称、调用该零返回叶函数并写入
输入对象的状态字节；原生执行没有 JNI effects。该请求分支与上述
`+28C268` 发布器分别验证，旧文档中的 publisher 归属以本节为准。

两基址 **44项原生/Python对照、1项请求VM入口检查、20项页面回滚**。
44项含40项 publisher 与4项 cold/warm byte gate；全部 guest payload/ELF 页、
JNI/JavaVM/清理顺序和逻辑 va_list 匹配。覆盖 local/global/weak/未知引用
类型、混合类型、NULL 返回、单次/双次 exception、NULL exception 引用、
缺失 class/method、NULL/full uint64 root，以及三次 acquisition 的 NULL 组合。
实际 acquisition 和原始 dispatcher/cleanup 执行；NULL acquisition profiles
使用明确的服务边界。没有 native snapshot Python 输入。

18项 leaf 拒绝检查覆盖缺失 acquisition/JNI/table、服务异常、栈/root 范围
和改写的 gate 编码表/target/code；2项请求入口拒绝检查保留 missing JNI
和 provider exception。全部页面回滚通过，外部服务 effects 不回滚。
公开请求入口完成 byte gate，从993步推进到1019步，在
`+285AA0 -> +25CDD4` 对象构造明确停止并回滚。**完整请求返回、
整链原生差分、真实 Android JVM、完整独立 signer、fresh 签名和线上矩阵
仍未完成。** 见 [发布器与byte gate证据](evidence/vm9_request_publication_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_publication_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-publication-evidence.json>
```

## 6.88 实际请求对象构造与临时引用生命周期（2026-10-12 Asia/Shanghai）

`construct_request_object_with_null_reference` 恢复 `+25CDD4`：在实际
栈位置创建临时 NULL reference，调用 `+25CE68` 后清理临时引用。
`construct_request_object` 写入 vtable、kind，复用 `+2483E0` 字符串克隆
和既有带诊断锁的 reference copy，再写 realtime 毫秒、清零状态字节、
mode 与低8位 flag。对象 padding 保持输入值；临时计数复制到2后释放
为1，由新对象继续持有。直接构造入口的第六参数经显式 X5 输入。

`read_realtime_milliseconds` 对应 `+26CC60/+291958/+329404`：读取
clock0，先计算有uint64回绕的微秒，再按signed SDIV1000向零截断。
时钟失败拒绝，未将原始 abort 路径替换成时间值。原始 reference
constructor/copy/release、诊断锁和 matching libc 锁体执行。

两基址 **60项原生/Python对照、1项请求入口检查、34项页面回滚**。
44项NULL-reference生命周期与16项直接构造包含2种实际 tail wrapper
输入。全部 guest payload/ELF 页、临时reference、clock/allocator/free/
diagnostic顺序、存活堆和free前字节匹配；没有 native snapshot 输入。
覆盖cold/warm诊断锁、跨页对象、字符串0/1/31/32/33长度、内嵌NUL、
signed长度、NULL字符串allocation、kind/mode的uint32边界、flag截断、
正负/sub-ms时间、秒数回绕、NULL/0/1/2/wrap计数与借用opaque引用。
直接constructor的realtime返回值也匹配；wrapper的附带X0未作ABI承诺。

32项leaf拒绝检查覆盖服务缺失、时钟异常/非法timespec、NULL count
allocation、栈、未映射源、payload限额、uint32溢出与guard等待；
2项请求入口missing JNI/provider exception仍拒绝。全部页面回滚通过，
外部服务effects不回滚。真实fresh owning请求完成对象构造，VM从
1019步继续到1419步，在 `+285ABC -> +256AB0` 回调明确停止。
**完整请求返回、整链原生差分、真实Android JVM、完整独立signer、
fresh签名和线上矩阵仍未完成。** 见 [请求对象证据](evidence/vm9_request_object_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_object_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-object-evidence.json>
```

## 6.89 实际 registry 计数回调与拥有者 TLS 接线（2026-10-12 Asia/Shanghai）

`increment_configuration_counter` 恢复 `+256AB0`：先取得registry writer
scope，再使用既有树lookup。已有值返回旧u32，仅在signed旧值不大于
`0x7FFFFFFD` 时递增；`0xFFFFFFFF` 返回旧值并回绕为0，而
`0x7FFFFFFE/0x7FFFFFFF` 保持不变。缺失键时分配并克隆StringObject，
分配u32值1，复用既有red-black树插入后返回0，最终释放scope。
TLS registry、mutex、条件唤醒、树查找与插入没有新增替代实现。

两基址 **40项原生/Python对照、1项请求入口检查、36项页面回滚**。
包含4项实际 `+285ABC` wrapper；原始scope/lookup/clone/insertion与
matching libc mutex/condition执行。完整guest payload/ELF/TLS页、
TLS/allocator/free/wake顺序、存活堆和free前字节匹配。覆盖缺失键的
左右/平衡树插入、空键、NUL前缀比较、既有平衡树lookup、10种u32
计数、饱和与有符号回绕；没有native snapshot作为Python输入。

32项leaf拒绝检查覆盖五类服务缺失、TLS异常、多TLS键、活跃reader、
mutex争用、scope/key/value allocation NULL、栈、未映射键、payload/
tree限额。请求入口保留missing JNI/provider exception，另加missing TLS/
TLS provider exception，共4项。页面全部回滚；外部服务effects不回滚。

公开请求入口显式接收并传递拥有者get_tls、initialize_registry与broadcast，
完成实际计数调用并按wrapper ABI只写回4字节旧值，保留高4字节。
fresh owning请求从1419步到1444步，在 `+285ADC -> +25BF14`
树构造回调明确停止。**完整请求返回、整链原生差分、真实Android JVM、
完整独立signer、fresh签名与线上矩阵仍未完成。**
见 [registry计数证据](evidence/vm9_request_counter_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_counter_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-counter-evidence.json>
```

## 6.90 实际请求树构造与 iterator ABI（2026-10-12 Asia/Shanghai）

请求 `+285ADC -> +25BF14` 接入既有树constructor，直接使用packed
container与descriptor输入。`configuration_tree_iterator` 恢复
`+25C180/+25C188`：返回实际guest iterator table与begin/end node两字；
`+285AEC` wrapper把两字存入packed+0x10。begin读取sentinel左端节点，
end返回sentinel。`configuration_tree_iterators_equal` 恢复 `+24C600`，
先比较node，只有node相同才读取并比较table；`+285B08`写回4字节结果。

两基址 **24项原生/Python对照、1项请求入口检查、13项页面回滚**。
12项constructor/iterator与12项comparison均执行实际wrapper；完整packed
ABI、guest payload/ELF页、allocator顺序与堆匹配。覆盖跨页构造、空/非空
begin/end、不同node/table、NULL/full uint64两字，以及node不同时不读取
未映射table字的短路行为。native输出不作为Python输入。

入口发现旧fixture的header reference为NULL，在1452步触发非法读取。
现用既有树constructor与reference owner独立生成有效空header输入；
同时保留NULL-header拒绝检查。8项leaf guards覆盖descriptor、allocation、
controller与iterator位置，5项入口guards覆盖JNI/TLS服务缺失/异常与
NULL header。页面全部回滚，外部服务effects不回滚。

实际fresh owning请求完成树与iterator比较，从1444步到1539步，随后
`+285B7C` 拒绝NULL function target。原始ELF relocation确认该target来自
`+382CD8` 的 `R_AARCH64_ABS64 __cxa_atexit`；当前请求import resolver
只绑定memset/memcpy，因此仍需要进程析构导入与注册服务。**完整请求
返回、整链原生差分、真实Android JVM、完整独立signer、fresh签名与
线上矩阵仍未完成。** 见 [请求树与iterator证据](evidence/vm9_request_tree_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_tree_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-tree-evidence.json>
```

## 6.91 实际进程析构导入与注册（2026-10-12 Asia/Shanghai）

请求ELF resolver从实际 `.rela.plt` 推导 `__cxa_atexit` PLT，再绑定
`+382CD8` 的ABS64 relocation；目标确认为 `+347EA0`。保留既有resolver
名称与memset/memcpy绑定。`register_process_destructor` 恢复
`+285B7C` wrapper：转发packed中的destructor/object/dso三字，显式
进程注册服务返回的W0写入packed+0x20。请求使用owning session的
`register_destructor`，线程析构注册仍由其独立owner处理。

两基址 **16项原生/Python对照、1项请求入口检查、17项页面回滚**。
实际wrapper覆盖0、1、负数、signed边界与unsigned u32状态，以及NULL
和full uint64参数；完整payload、packed写宽与注册调用顺序匹配。
10项leaf guards覆盖缺失服务、provider异常、非法/越界状态与越界参数；
7项入口guards保留JNI/TLS/NULL header，并加入exit服务缺失/异常。
所有失败页面回滚；外部注册effects不回滚。native输出不作为Python输入。

fresh owning请求从1539到1558步，完成实际导入与注册，下一边界为
`+285B9C -> +248274` 填充字符串构造。对照仅验证显式注册服务和实际
wrapper，**未执行真实libc atexit table、进程退出或已注册析构函数**。
完整请求返回、整链原生差分、真实Android JVM、完整独立signer、fresh
签名与线上矩阵仍未完成。见 [进程注册证据](evidence/vm9_request_exit_registration_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_exit_registration_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-exit-evidence.json>
```

## 6.92 实际填充字符串构造与 wrapper 字节参数（2026-10-12 Asia/Shanghai）

`construct_filled_string_object` 恢复 `+248274`，复用既有sized-string
布局owner并生成填充payload。低8位fill写入全部length字节，再追加NUL；
非负W2分配length+1，负W2或malloc NULL清零两个长度字段。返回buffer
字段，不把原始函数的偶然X0作为承诺。`+285B9C` consumer按实际指令
读取packed+0x10的BYTE fill与packed+0x14的u32 length。

两基址 **40项原生/Python对照、1项请求入口检查、20项页面回滚**。
20项direct与20项actual wrapper覆盖empty/one/fifteen、zero/full-byte
fill、跨页对象和payload、两种负长度、空/非空malloc NULL。完整guest
payload、packed、ELF页、allocator顺序与堆匹配；native输出不作为输入。
12项leaf guards覆盖参数、payload bound、对象/缓冲区未映射与provider
异常；8项入口guards保留已有JNI/TLS/header/exit检查，并注入仅在实际
进程注册之后发生的填充allocation异常。失败页面全回滚；外部effects
不回滚。既有copy-sized owner及internal布局函数AST保持不变。

fresh owning请求从1558到1567步，下一处为 `+285BB0 -> +25C168`
树查询wrapper，其业务owner已存在。**完整请求返回、整链原生差分、
真实Android JVM、完整独立signer、fresh签名与线上矩阵仍未完成。**
见 [填充字符串证据](evidence/vm9_request_fill_string_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_fill_string_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-fill-evidence.json>
```

## 6.93 实际树查询与 C 字符串长度 wrapper（2026-10-12 Asia/Shanghai）

请求 `+285BB0 -> +25C168` 复用 `lookup_configuration_value`，实际packed
container/key顺序与返回X0写入packed+0x18的8字节ABI得到验证。
`+285C00 -> +27617C` 复用既有NULL安全的guest C-string读取owner，
把长度写入packed+0x10的8字节字段。两个业务owner保持不变。

两基址 **28项原生/Python对照、1项请求入口检查、20项页面回滚**。
16项lookup wrapper覆盖空树、NULL query、found/左右missing、NUL等价、
NULL/full uint64值。12项length wrapper覆盖NULL、empty、ASCII、内嵌NUL、
binary与跨页读取；完整guest payload、packed写宽和ELF页匹配。
12项leaf拒绝检查与8项入口回滚通过。新consumer每次从实际请求参数
求值，native输出不作为输入；已接受的原生批次未重复。

fresh owning请求从1567到1812步，实际读取两次C-string长度并完成tree
lookup。下一处 `+285C1C -> +2765C4` 使用实际ELF字节折叠表，并在比较前
调用两次singleton getter，仍待恢复。**完整请求返回、整链原生差分、
真实Android JVM、完整独立signer、fresh签名与线上矩阵仍未完成。**
见 [collection wrapper证据](evidence/vm9_request_collection_callbacks_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_collection_callbacks_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-collection-evidence.json>
```

## 6.94 实际 guest table 折叠比较与 singleton 接线（2026-10-12 Asia/Shanghai）

`compare_folded_cstrings` 恢复 `+2765C4`。非零长度先调用两次实际
singleton getter：第一次payload+0x10在第二次调用前读取并保留；只有
该字段非零才读取第二次payload+0x18。两个字段同时非零的环境检查
仍显式拒绝。之后读取guest ELF `+A5BB7` 中的字节映射，比较映射后的
unsigned bytes；差值或原始first-byte NUL结束，length零跳过getter
和指针读取。实际table有27项变化，不能用主机lowercase替代。

`+285C1C` consumer转发packed三参数，并只写packed+0x20的W0四字节。
helper entry SP来自既有实际请求wrapper frame；getter使用helperSP-0x40。
两基址 **48项原生/Python对照、1项请求入口检查、26项页面回滚**。
24项direct与24项actual wrapper均执行两个实际warm getter，验证
getter顺序/SP与scratch、完整guest payload、packed写宽及ELF页。
覆盖ASCII fold、有符号差值、内嵌NUL、binary、长度截断、跨页、单个
环境字段、修改guest table，以及full uint64 length的early NUL。
zero length使用未映射指针且不调用getter，原生/Python均返回零。

16项leaf回滚覆盖缺失/第一或第二getter异常、两个环境字段、第二次
getter修改first字段时仍保留初值、未映射输入、byte bound与stack；
10项入口回滚包含新的singleton服务缺失/异常。所有失败页面回滚；
外部provider effects不回滚。native输出不作为输入。

fresh owning请求从1812到1995步，完成折叠比较并使用owning singleton。
下一处为 `+285F44 -> +25C150` 树计数读取。warm原生组件对照不代表cold
整链、真实Android JVM或完整请求原生差分。**完整请求返回、完整独立
signer、fresh签名与线上矩阵仍未完成。**
见 [折叠比较证据](evidence/vm9_request_folded_compare_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_folded_compare_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-fold-evidence.json>
```

## 6.95 请求树计数与 value 清理和 iterator 遍历（2026-10-12 Asia/Shanghai）

`configuration_tree_size` 恢复 `+25C150/+24B958/+24BDD0`：从container+0x20
读取controller，再读取controller+8的完整u64 count。`+285F44`将结果
写入packed+0x10。请求接入后在2001步触发旧2000预算，页面全部回滚；
据实际边界把有限预算调整到4000，继续到后续真实callback。

实际请求树value是字符串对象。`insert_configuration_pair` 支持
`+182D6C` value清理：先释放incoming key，再重新加载value清理callback，
销毁旧字符串payload/object，最后替换value pointer。保留既有raw free
路径；原始指令确认callback在key销毁后重新加载，provider修改它的
原生/Python顺序与结果一致。NULL旧value不调用字符串析构。

`configuration_tree_iterator_pair` 恢复 `+24C59C`，只读取iterator+8的
node及node+0x20的pair pointer；不消费table和pair payload。
`+285B28`写入8字节结果。`+285B44 -> +2483E0` 复用既有string clone
owner。`advance_configuration_tree_iterator` 恢复 `+24C5B8/+24C62C`：
右子树取最左节点，或沿parent回溯；按实际顺序更新iterator，并返回
table/node两字，`+285B54`写入packed+0x10的16字节pair。

两基址 **128项原生/Python对照、1项请求入口检查、40项页面回滚**：
24项size、28项string-value replacement、24项iterator pair、16项clone
wrapper、36项iterator advance。覆盖full u64、跨页、NULL/未映射pair
返回值、未读取的table word、空/二进制/内嵌NUL字符串、value别名、
清理callback reload、左右子树/parent回溯/最后节点及完整返回两字。
完整guest payload、对应packed ABI、清理allocator/heap/free前字节匹配。
30项leaf拒绝与10项入口回滚通过；外部effects不回滚，native输出不作输入。
各已接受原生分组在增加独立功能时未重复。

fresh owning请求从1995到2321步，完成树计数、重复value替换、iterator
pair、clone与遍历，下一处为 `+285B70 -> +25C01C` 局部树析构。
**完整请求返回、整链原生差分、真实Android JVM、完整独立signer、fresh
签名与线上矩阵仍未完成。** 见 [请求树遍历证据](evidence/vm9_request_tree_size_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_tree_size_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-tree-operations-evidence.json>
```

## 6.96 请求局部树析构（2026-10-12 Asia/Shanghai）

`destroy_configuration_tree` 恢复 `+25C01C/+25C04C`，接入实际 `+285B70`
wrapper。先写回container vtable，复用begin/end、pair和advance owner；
按iterator顺序清理key，再重新加载value callback，清理value并释放pair。
支持实际string delete和NULL safe raw free。节点释放顺序为右子树、当前
节点、左子树；左指针在右子树返回后读取，当前节点free前保存。

clear按原始顺序重置count与sentinel，再清理controller并释放sentinel和
controller。container+0x20保留原始悬空指针。逻辑begin/end iterator scratch
分别为析构入口SP-0x88/-0x78；物理寄存器spill不作完整恢复声明。
页面事务覆盖整个析构，free provider外部effects不随页面回滚。

两基址 **32项原生/Python对照、1项请求入口检查、27项页面回滚** 通过。
直接入口和实际wrapper均覆盖空树、单节点、平衡与降序树、二进制key，
以及raw/string value。完整guest payload、ELF页面、逻辑iterator scratch、
free顺序、heap和释放前字节一致，所有owned blocks释放。16项leaf拒绝与
11项入口拒绝通过，新增入口free异常实际发生在第2321步的树析构中。
两个有效native RED在owner恢复前取得；已接受native分组没有重复运行。

fresh owning请求从2321推进到2329步，局部树析构完成，下一边界为
`+285F9C -> +25CF98` 请求对象析构。**完整请求返回、整链原生差分、真实
Android JVM、完整独立signer、fresh签名与线上矩阵仍未完成。**
见 [局部树析构证据](evidence/vm9_request_tree_destroy_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_tree_destroy_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-tree-destroy-evidence.json>
```

## 6.97 请求对象与树删除清理和 VM 返回（2026-10-12 Asia/Shanghai）

`destroy_request_object` 恢复 `+25CF98` 的清理分支，接入 `+285F9C`。
先读取object+0x48，写回vtable；flag为零或object+0x40非零时清理引用和
字符串。实际 `+162714` 的scope/release指令与既有 `+15E1A8` 相同，
复用引用owner；NULL、retained和支持的string deleting target得到验证。
其他虚析构target仍拒绝。引用清理入口SP为析构SP-0x20，逻辑scope为
析构SP-0x60。`+25CFE4` 事件发送分支仍明确拒绝，未宣称恢复。

`+285910 -> +32A264` 直接转交owning free provider，包括NULL，packed
无返回槽写入。`delete_configuration_tree` 恢复 `+25C12C`：在SP-0x20
调用既有树析构，之后释放container，外层页面事务覆盖全部清理。

两基址 **78项原生/Python对照、1项请求入口检查、36项页面回滚** 通过。
56项request object析构覆盖冷/热锁、跨页、空/二进制string、NULL/count
边界、被引用string删除、已发送状态与非boolean状态字节；6项实际free
wrapper覆盖NULL、普通payload与packed别名；16项tree delete覆盖空与
平衡树、raw/string value、直接入口和实际wrapper。完整guest payload、
ELF页面、逻辑scope/iterator、清理顺序、heap和释放前字节匹配。
22项leaf与14项入口拒绝通过；新入口异常分别在2329、2405、2416步。
六个native RED在新增分支恢复前取得，入口旧边界为2329/2405/2416。
已接受native分组未重复运行。

fresh owning请求在 **2475步、105次回调** 完成VM返回，PC为 `+FFB78`，
选中的slot31与调用者return sentinel一致；请求事务提交到传入页面。
该输入使用空header和NULL FindClass JNI服务，事件未发送。成功路径会
提交页面，因此每个入口case从独立页面事务开始；外部provider effects
仍不回滚。被释放controller可能被后续allocator复用，不读取其终态
count来推断先前清理；native清理对照和实际callback完成是该项证据。

**这还不是完整signer：物理native caller epilogue/X0 ABI、整链原生差分、
真实Android JVM、fresh签名与线上矩阵未完成。**
见 [请求清理与VM返回证据](evidence/vm9_request_cleanup_return_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_object_destroy_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-cleanup-return-evidence.json>
```

## 6.98 请求 scoped tree reference 构造（2026-10-12 Asia/Shanghai）

`construct_scoped_configuration_tree_reference` 恢复 `+25C324` 实际调用的
`+163DDC` scoped reference constructor，接入 `+2858BC`。先分配40字节
container，再写descriptor并构造tree；diagnostic范围进入后才分配count。
`+163DDC` 的有效指令与既有 `+1625A4` 相同，复用scoped reference owner。
原raw constructor保留，既有原生分组未重复。

实际wrapper压栈0x10；consumer传入caller frame SP-0x190作为helper入口。
descriptor位于helper SP-0x50，logical scope位于SP-0xA0。allocator provider
观察到的descriptor/output、完整guest payload和ELF页面、heap、逻辑scope
字段与diagnostic/allocator顺序均与原生一致。之前native allocator栈帧在
scope+12的四字节padding留下物理寄存器残留，该padding不属于本批对照。

两基址 **24项原生/Python对照、1项请求入口、31项回滚** 通过：cold/warm、
direct/实际wrapper、跨页output和跨页stack；16项leaf、15项entry拒绝。
两个有效native RED在新增owner前取得；descriptor过早写入也有独立RED。
请求仍在 **2475步、105回调** 返回，新增allocator异常在599步拒绝并回滚
全部页面。外部provider ledger不随页面回滚。

私有整链探针观察到88次分配、输出引用和32个VM寄存器一致；另有一个
全局字节差异，已定位到native compare-and-store handler `+171474`。
该探针尚未覆盖完整heap和服务参数，不作为整链等价证据；physical caller
epilogue/X0 ABI、真实Android JVM、完整signer、fresh签名和线上矩阵未完成。
见 [scoped tree证据](evidence/vm9_request_scoped_tree_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_scoped_tree_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <request-scoped-tree-evidence.json>
```

## 6.99 VM load 与串行 compare/store（2026-10-12 Asia/Shanghai）

修正 `vm_full` 的opcode36与opcode57：`+16F63C` 读取完整64位word到目标
寄存器及hidden slot34；`+1713C0` 比较目标word与slot34，相等时写入source
并将source/status置1、slot34清零；不相等时source/status置0，slot34改为
当前目标值。native比较器不保存原始load地址，因此不同目标word相等时
也可成功。guest backing被提供时，其slot34为比较值owner；抽象runner
要求先执行opcode36。有效地址需八字节对齐，未对齐时明确拒绝。

原MOVZ/no-op解释基于零目标与无寄存器delta的旧trace，遗漏了内存效果。
两个独立native RED证明非零load及实际store与旧模型不同。两基址
**114项原生/Python对照、1项实际请求入口、21项拒绝/回滚** 通过。
108项主对照覆盖zero/nonzero/full-width、目标值干预后的失败、signed
displacement边界、高编号register、不同目标、重复store与寄存器别名；
抽象及guest backing均验证。6项backing-only store验证slot34输入；
4项native alignment fault、2项缺少抽象比较值拒绝及15项入口回滚通过。
对照包括32个寄存器、目标bytes、slot34及干预；这不提供host并发原子性。
主对照之后只添加alignment拒绝和case标签，新增分支单独验证；已接受
native分组未重复。其他旧VM指令保持原AST。

请求仍在2475步、105回调返回。私有原生整链探针中的 `+3E0D48` 差异
已消失：main ELF页面、输出引用、32 VM寄存器、回调路径和88次分配顺序
一致。有效回调参数、完整heap/服务与物理caller ABI尚未全部对照，故不
将该探针标为整链等价或完整signer；真实JVM、fresh签名与线上矩阵继续。
见 [VM load/store证据](evidence/vm9_llsc_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_llsc_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <vm-load-store-evidence.json>
```

## 6.100 Request caller 物理返回（2026-10-12 Asia/Shanghai）

新增 `vm9_request_caller.finish_request_caller`，恢复 `+283134` 的 canary
检查、saved X19/X28/X29/X30、SP 和返回 PC。原生 `+1683F0` 从 descriptor
加载 physical X0，callback trampoline `+16AA30/+16AA58` 保存并恢复它；
`+172440` 保留该值。因此此请求入口的 native X0 为 `image+28587C`。
Python 使用明确 callback sentinel，不把虚拟 R0 当作 native X0。
owner 只读完整 saved frame 与 TLS，拒绝未映射、错 sentinel、未对齐栈、
canary mismatch 和 PAC-tagged return。consumer 在 VM exit 验证后、页面
commit 前调用它；失败保留 `RequestContinuationBoundary` 与未提交页面。

两基址 **16项原生/Python对照、1项实际请求入口、26项拒绝检查** 通过。
原生 caller/interpreter 未改；合成 bytecode 是明确 guest 输入。覆盖两个
SP、zero/pattern saved registers、无回调及回调主动改写 X0。native 返回
PC/SP/X0/X19/X28/X29/X30 全部一致。两个 native RED 记录旧模型缺少物理
epilogue；两基址 canary 失败确实跳转 `+347EB0`。已接受的原生分组未重复；
之后仅收拢 frame 读取并明确转换未映射输入异常，入口与 guards 验证该改动。

其中 **25项确认全部页面不变**。新增 canary 入口负例在2475步、`+FFB78`
拒绝，全部原有页面字节不变，但最后 malloc 经 allocator provider 新增的
64页 OS 映射保留。这些映射位于 owning OS transaction；当前 request
页面事务不回滚 provider 的 mapping/cursor 或外部服务效果。该项独立
记录为 mapping boundary，不能算作全部页面回滚。

完整请求原生等价尚未验收；有效 packed 参数、服务、heap/allocator
metadata 与 padding 区分仍需继续。真实 Android JVM、URL/header 输入
转换、完整 signer、fresh 签名与线上矩阵未完成。
见 [caller返回证据](evidence/vm9_request_caller_return_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_caller_return_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <request-caller-return-evidence.json>
```

## 6.101 NULL raw cleanup 与整链有效字段（2026-10-12 Asia/Shanghai）

`insert_configuration_pair` duplicate 路径的 raw cleanup `+165334` 现在
只对非 NULL 的旧值调用 free。两基址原生 RED 证明旧 Python 模型多一次
`free(0)` provider 效果，虽然内存结果相同。**16项新增原生/Python对照、
6项回滚**通过：direct 与实际 `+2859B8` wrapper，NULL旧值、旧/新均NULL、
key释放后改为raw cleanup，以及包含高字节和嵌入NUL的key。全guest/ELF
bytes、释放顺序、allocator状态、释放前payload一致。provider key释放失败
或释放后出现未知callback时，全部页面回滚；外部释放效果不回滚。
其他registry函数与非NULL raw cleanup保持既有实现。已接受分组未重复。

私有 fresh 整链探针仍使用明确构造的 ABI、空header tree与NULL FindClass，
原caller和interpreter未改。2475步/105回调返回，其PC/SP/X0/X19/X28/X29/
X30一致。按原wrapper的load宽度提取 **105次有效packed输入**，包括第五
word、uint32与byte字段，零差异；callback26不同word2未被wrapper读取。
**10次clock/GetEnv/JNI/atexit服务**参数与结果一致。main ELF页面、32个VM
registers、输出引用、88次malloc与55次free的顺序/地址/size，以及34个
retained request blocks和OS mapping/cursor geometry一致。

logger vector的 **12个C++ string** tags、声明payload和NUL全部一致。
15个释放前token buffer的差异只在 `+4..7`、`+45..47` 与tag2 literal的
`+44`。guest RAM范围 `0x12000000..0x50000000` 中6页/167个不同字节，
全部定位到最后释放的token padding或retained short string声明payload+
NUL之后的尾部；释放lifetime、pointer/size及最后释放前bytes逐项核对。
没有屏蔽初始化字段。这是有效字段证据，不宣称未初始化物理bytes相等。

physical stack、libc ELF/global metadata与全部syscall参数仍需对照，
request allocator映射回滚亦未完成。真实URL/header/JNI转换、Android
JVM、完整signer、fresh签名及线上矩阵继续。完整请求等价标志保留False。
见 [NULL raw cleanup证据](evidence/vm9_request_raw_cleanup_fresh_20261012.json) 与
[整链有效字段证据](evidence/vm9_request_effective_abi_fresh_20261012.json)。私有探针与payload保留在仓库外。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_raw_cleanup_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <raw-cleanup-evidence.json>
```

## 6.102 ASCII case 与 request byte flag（2026-10-12 Asia/Shanghai）

新增 `vm9_objects.transform_string_fields_ascii_case`，恢复 `+246FC0` 与
`+247028` 的ASCII upper/lower转换。`+248F4C/+248F54` 将object+8传给
fields helper；实际 `+28591C` callback接入同一owner。按signed capacity/
length判定有效输入：NULLfields/payload、capacity<1、capacity<length或
negative length返回uint32 -1。只转换声明长度内ASCII字母，包含embedded
NUL之后的bytes；高字节不变，不追加terminator。每次读取重新加载pointer，
保留原生field-alias读取顺序。实际访问受显式bound约束，失败不提交页面。

新增 `read_signer_request_flag` 对照 `+282A68`，只读receiver+0x52的完整
byte，不读object header；`+285C3C` wrapper把最低位写到packed+16的
一个byte，其他packed padding保留。consumer依照这一区分处理返回值。

两基址 **92项新增原生/Python对照、8项回滚**通过。72项ASCII对照涵盖
全部256种byte、embedded NUL、空string、capacity==length、跨页payload、
six invalid profiles，以及fields/object/actual callback三种入口。20项
receiver对照涵盖0/1/2/255及只有目标field映射的receiver，direct/wrapper
均一致。4项native RED记录这两个缺失回调。72项native全部已PASS后，
一个guard fixture把“未映射”地址误放入已映射page而失败；纠正fixture，
单独验证8项guards，未重复已接受native分组。新flag分组单独验证。

私有probe从合成URL与一项user-agent header bytes独立分配StringObject/
reference/tree，并按 `+27E478` 的native callsite放入四个arguments。
该构造prefix从1556步推进至1933，再到2174步的 `+FB1F8`；下一处为
`+285C5C -> +248C1C` byte search。probe保留原有page bytes的回滚检查。
它不是实际JNI转换，亦未验证这个非空prefix的完整native差分。
原JNIcaller的flattened跳转仍需恢复；局部callsite能说明argument角色，
不能据此声明完整frontend。真实JVM、完整signer、fresh/live继续。
见 [ASCII/receiver flag证据](evidence/vm9_request_ascii_case_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_ascii_case_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-ascii-case-evidence.json>
```

## 6.103 Request byte search（2026-10-12 Asia/Shanghai）

新增 `vm9_objects.find_string_object_byte`，恢复 `+248C1C` 的declared-length
byte search，并接入实际 `+285C5C` wrapper。W2起点为负时直接返回uint32
-1，不读取receiver；其余路径按原生顺序读取object+12的signed length与
object+16的payload pointer各一次。比较target最低byte，包含embedded
NUL之后的bytes，命中返回index，否则返回uint32 -1。wrapper读取packed+16
的一个byte与packed+20的uint32，只写packed+24的四个bytes。

显式bound限制实际检查的bytes，允许很大declared length下的早期命中。
不按总length预先拒绝。两基址 **80项新增原生/Python对照、12项回滚、
8项精确扫描上限检查**通过，2项native RED确认缺失owner/callback。
20种profiles分别经过direct和actual wrapper，覆盖NUL target/其后命中、
high-byte target、正负起点边界、negative length、无payload读取路径、
只映射length/pointer fields、跨页、receiver field alias、packed result
alias，以及全部256 bytes中的末尾命中。所有guest bytes与packed padding
一致，无allocator/service effects。guards覆盖部分unmapped payload、
unmapped receiver、bound和非法word输入；失败保持页面不变。

同一合成URL与一项header的请求入口从2174步推进到 **2224步** 的
`+FB6A4`，下一callback为 `+285C80 -> +2481FC` sized string constructor。
它仍是独立构造ABI，未完成actual JNI转换或非空prefix native差分。
完整signer、fresh/live与真实JVM继续。见 [byte search证据](evidence/vm9_request_byte_search_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_byte_search_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-byte-search-evidence.json>
```

## 6.104 Request sized string dispatch（2026-10-12 Asia/Shanghai）

实际 `+285C80 -> +2481FC` tail-wrapper接入已有
`vm9_objects.construct_sized_string_object`。按原生读取packed+8的object、
packed+16的source和packed+24的W2 length；调用同一owner，无packed
result store。buffer field由owner发布；不将它等同于原生incidental X0。

两基址 **18项新增actual wrapper对照、10项回滚**通过，2项native RED
确认已有owner正确但request dispatch缺失。9种profiles覆盖empty、embedded
NUL/binary、长payload、跨页object/source/buffer、signed negative W2、
malloc NULL与source alias。全部guest/ELF bytes、ordered allocation、heap
和packed padding一致。未重复已接受的定长字符串direct分组。guards覆盖
source/object/buffer unmapped、显式bound及provider异常；页面保持不变，
不声称外部allocator effects回滚。

同一构造URL与一项header的请求入口从2224推进到 **2243步** 的
`+FB6F0`，下一处 `+285C94 -> +2487E8` binary string equality。
该入口拒绝时原有page bytes保持不变，**64个新增allocator OS pages保留**，
因此不是全部页面或mapping回滚。私有记录已改为original-page-bytes并
记录新增page count。实际JNI转换、非空prefix native差分、完整signer、
fresh/live与真实JVM仍未完成。见 [sized dispatch证据](evidence/vm9_request_sized_dispatch_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_sized_dispatch_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-sized-dispatch-evidence.json>
```

## 6.105 Request binary equality（2026-10-12 Asia/Shanghai）

修正已有 `vm9_configuration_init.strings_equal` 的原生短路读取顺序，
接入实际 `+285C94 -> +2487E8 -> +2472F8` callback。先读取first payload，
NULL时跳过second；second payload NULL时跳过lengths；first length负数
时跳过second length。长度不同返回false；同一payload pointer或两项
length==0直接true，先于payload读取与显式bound。其余按完整declared
bytes比较，包括embedded NUL后的bytes。此处是binary equality；原生
helper的signed positive结果经adapter转换为boolean。wrapper只写packed+24
的一个byte，保留另外七个bytes。NULL对象或uint64 fields溢出由request
consumer拒绝；原helper的nullable object接口保持既有角色。

两基址 **48项新增原生/Python对照、8项回滚**通过，4项native RED证明
短路读取及同指针大length的旧owner拒绝，亦记录request dispatch缺失。
12种profiles经direct与actual wrapper，涵盖NUL后差异、长度不等、
NULL payload/negative length的unmapped后续fields、空串unmapped
payload、同一pointer大length、全部256 bytes及仅映射对象fields。
正常payload的16项对照执行 **matching libc真实memcmp**，没有替换body。
叶级guest byte比较范围是oracle的 `0x70000000..+0xA000` data区域，
不包含physical stack；matching libc global pages亦未全部比较。
guards覆盖必需fields/payload缺页与comparison bound，页面保持不变。
RED记录首次漏捕缺页ValueError；原生assertions已通过的第一项保留，
修正异常捕获后只运行剩余原生项，未重复已接受的native controls。

同一构造URL与一项header的入口从2243推进到 **2395步** 的 `+FBCF0`，
下一callback `+285CB8 -> +248D3C` 为substring构造，经X8输出object。
拒绝时原有page bytes保持不变，但64个新增allocator OS pages保留。
实际JNI转换、非空prefix native差分、完整signer、fresh/live与真实JVM
仍未完成。见 [binary equality证据](evidence/vm9_request_binary_equality_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_binary_equality_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <request-binary-equality-evidence.json>
```

## 6.106 Constructed nonempty request effective ABI（2026-10-12 Asia/Shanghai）

新增一组构造URL与一项header的原生prefix输入对照。双方从同一份独立
构造的fresh ABI/ELF状态开始；原native caller/interpreter指令保持原样，
真实matching libc allocation执行，JNI/clock/OS服务使用显式边界。Python
入口推进到2395步；native在 `+285CB8 -> +248D3C` substring callback
入口受控停止，尚未执行该body。

**98次callback路径、packed addresses与有效packed输入全部一致，0差异**。
输入范围由original wrapper load宽度提取，包括byte/W/u64/pair与第五word；
其中97项callback body已经执行，第98项比较的是下一个body的入口输入。
这里未逐一比较指向payload的全部内容、heap bytes、physical stack、
libc globals或全部syscall参数，不能升级为完整非空request native等价。
native wrapper入口SP实测为request caller entry-0x18C0，即caller local
stack-0x180；substring wrapper保存LR后进入body的SP为local-0x190。
Python拒绝保留原有page bytes，但64个新增allocator OS pages仍保留。

初次受控停止已到达正确wrapper，但沿用whole-return断言而被误报为
did-not-return；只调整私有oracle的终止判定，使其接受所请求的wrapper
停止点，未修改ELF caller/interpreter。后续原生prefix与98项输入对照通过；
未重复此前已接受的native分组。正常库memcmp/callback实现保持原native
指令；最后一处未执行的substring也没有替换成猜测结果。

实际JNI输入转换、substring body、完整signer、fresh/live与真实JVM继续。
见 [非空effective ABI证据](evidence/vm9_request_nonempty_effective_abi_fresh_20261012.json)。

## 6.107 Field clone 与 substring（2026-10-12 Asia/Shanghai）

新增 `construct_string_object_from_fields` 恢复 `+248448`。先读取declared
W length，再初始化destination；negative length或NULL source payload
不分配，X0返回wrapped capacity W0。malloc NULL保留capacity/length，
payload为NULL。malloc后重新读取source pointer，复制完整declared bytes，
追加NUL。该行为与sized `+2481FC` 的NULL allocation清空字段有所区别。

新增 `construct_substring_string_object` 恢复 `+248D3C`，并接入
`+285CB8` 的X8 output ABI。按32位signed/wrapping算术计算offset与长度：
offset=max(start,0)，length=min(start负数部分+count,declared-offset)。
positive length生成capacity=-1的borrowed fields，再调用同一field clone
owner；非positive通过guest image的empty CString构造。负start会减少
requested count；declared length负数与offset相减溢出时也按native W
结果处理。wrapper不写packed return。恢复descriptor与TLS canary slots；
完整physical register spills未恢复，相关receiver/output/payload alias
显式拒绝。只允许建模窗口内的descriptor/canary payload alias，并在
allocator可能改pointer后复核。页面失败回滚，外部provider effects不回滚。

两基址 **74项新增原生/Python对照、20项回滚**通过，4项native RED。
18项field clone包括binary/empty/negative/NULL source/malloc NULL、
source pointer分配后重载、self alias及跨页；56项substring为14 profiles
的direct/actual wrapper对照，含negative start/count、wrapped算术、
negative declared length溢出、same object、allocation failure、跨页、
scratch descriptor与canary payload alias。guest data区域+0xA000、packed
bytes、allocation顺序与heap匹配；field clone X0一致，substring的
incidental X0未作整体声明。原生malloc/memcpy保持显式边界；没有用
native输出初始化Python，也未重复已接受native分组。

构造非空请求从2395推进到 **2510步** 的 `+FBEBC`，下一callback
`+285CD8 -> +248F5C`。该函数先以CString构造temporary StringObject，
调用 `+248780` 后析构temporary，并检查canary；组合body仍需核实。
当前构造入口并非actual JNI转换；新suffix native整链差分、完整signer、
fresh/live与真实JVM未完成。拒绝仍保留64个新增allocator OS pages。
见 [field clone/substring证据](evidence/vm9_request_substring_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_substring_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-substring-evidence.json>
```

## 6.108 CString/StringObject 拼接（2026-10-12 Asia/Shanghai）

新增 `construct_cstring_string_object` 恢复 `+248F5C`，接入
`+285CD8`：packed+8 为X8 output，+16 为CString，+24 为StringObject。
先在body SP-0x50构造temporary，再执行 `+248780` 的clone/declared
append组合，最后复用现有析构并检查TLS canary。NULL CString仍执行
8字节allocation；第二项的embedded NUL之后字节按declared length追加。
复用现有construct/clone/append/destroy owner；wrapper不写packed result。
内部append status与原native一致，outer incidental X0未声明恢复。

两基址 **84项新增原生/Python对照、28项回滚**通过，4项native RED。
21 profiles分别通过direct body和actual wrapper：binary tail、empty与
NULL输入、negative second length、output/second alias、first/output
alias、second/temporary与output/temporary alias、跨页、constructor
allocation failure、reserve malloc/realloc failure、inplace realloc、
allocator改写second pointer后重载，以及temporary/canary payload alias。
guest data区域+0xA000及packed bytes、全部main image pages、分配/追加/
释放顺序、剩余heap与pre-free bytes匹配。原ELF body和wrapper未修改，
malloc/realloc/free与memory PLT保持显式服务边界。没有使用native输出
初始化Python，也未重复已接受的原生分组。

只恢复temporary object和canary slots；physical register spills alias
显式拒绝。首项CString在其allocation期间被provider改写也显式拒绝，
以保留现有CString owner的边界。unsupported操作回滚guest pages；
外部provider allocation/free ledgers不回滚。native allocation NULL的
部分效果和temporary析构仍保留。

构造非空请求从2510推进到 **2520步**，组合callback执行一次；下一处为
`+285CF4 -> +2487B4`。该body已静态核实为clone StringObject，然后
tail-call CString append，仍待新增原生对照。原有页面字节回滚，64个
新增allocator OS pages仍保留。构造入口并非实际JNI转换；新suffix
native整链差分、完整signer、fresh/live及真实JVM未完成。
见 [组合与清理证据](evidence/vm9_request_concat_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_concat_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-concat-evidence.json>
```

## 6.109 StringObject/CString 构造（2026-10-12 Asia/Shanghai）

新增 `construct_string_object_cstring` 恢复 `+2487B4`，接入
`+285CF4`：packed+8为X8 output，+16为StringObject，+24为CString。
先复用 `clone_string_object`，按declared length完整复制首项binary
bytes，再tail-call现有 `append_cstring_object`。第二项在clone以后
读取；保留live overlapping输入、部分prefix写入、reserve失败和分配时
改写输入的效果。body恢复0x20 frame后tail-call append；不包含新的
temporary/canary，physical spill aliases显式拒绝。X0返回output object，
wrapper不写packed result。clone malloc NULL后的guest NULL写入不建模，
遇到该失败以页面回滚拒绝。

两基址 **68项新增原生/Python对照、24项回滚**通过，4项native RED。
14 profiles的56项direct/actual wrapper覆盖binary/empty/long tail、
same object、tail指向首项payload/output fields/新payload、cross page、
malloc/realloc failure与inplace realloc，以及allocation时首项pointer
重载和tail变化。真实请求首次触发matching-libc realloc后，另加3个
long-first profiles的12项新对照，包含direct realloc、NULL和inplace。
没有重跑已接受分组。guest data区域+0xA000、packed bytes、全部main
image pages、分配释放顺序、pre-free bytes、剩余heap及native X0一致。
原body和wrapper未改；malloc/realloc/free/memory PLT为显式边界，未用
native输出初始化Python。unsupported回滚pages，外部provider ledger
不回滚；已建模的reserve NULL仍保留原native部分写入。

非空构造入口仍为 **2520步**，已进入新回调，停止原因变为
`matching-libc realloc is unrecovered`。本检查点没有声称入口步数增加
或matching-libc realloc恢复。原有页面字节回滚，64个新增allocator OS
pages仍保留。下一任务恢复当前真实allocator状态上的realloc分支，
并进行新原生对照；actual JNI转换、suffix整链原生差分、完整signer、
fresh/live及真实JVM未完成。见 [对象与CString构造证据](evidence/vm9_request_object_cstring_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_object_cstring_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-object-cstring-evidence.json>
```

## 6.110 Matching-libc 同类别 realloc（2026-10-12 Asia/Shanghai）

新增 `vm9_libc_tcache.reallocate_same_small_bin`，接入共享
`ActualAllocatorSession.reallocate`。针对current initialized TSD/cache、
有效small slab slot、positive request<=4096且新旧size class相同的分支，
恢复原libc `+1BB88 -> +90420 -> +7BB80/+7B2C8`。原指针与usable
buffer保留，不执行malloc/free，也不增加cache event；TSD allocated及
deallocated byte counters都按usable size增加，保留uint64 wrapping。
NULL/zero、cross-bin、profiling、缺失或noncurrent TSD/cache与无效输入
仍显式拒绝。本检查点未恢复完整realloc。

两基址 **18项新增原生/Python对照、28项回滚**通过，2项原生RED。
新输入来自已验证的Python allocator bootstrap，不使用native输出或
捕获进程页。loader relocation是输入，原libc export及realloc/helper
指令实际执行；该分支没有替代malloc/free或syscall。核对除physical
stack页以外的全部初始页面、pointer、payload、allocator metadata和
TSD counters。覆盖多个small classes、identity、同类别变更及统计溢出；
拒绝NULL/zero/cross-bin/oversized/profiling/missing TSD/cache、interior、
wrong tag、never-issued slot、已回cache对象与unmapped payload，页回滚。
已接受的早期native组未重跑。

首次私有original realloc trace已观察到实际请求中的8->8原地分支。
初次探针缺少native loader relocation导致fetch failure；补齐ELF
relocation后原body返回，但外层探针记录列表混用令最终检查失败。
随后独立验证器的2 RED与18 GREEN/28 guards全部通过；本节证据以
独立验证器为准。期间一个合成profile的新旧类别不同，在进入native
之前被fixture检查拒绝；更换为新profile，未重复已通过原生对照。

非空构造入口从2520推进到 **2538步**，StringObject/CString回调完成
一次并执行后续析构；下一处为 `+285D10 -> +248C54`，static wrapper
输入为两个StringObject与W start，W result写packed+28。该body委托
`+2476B0`，搜索语义仍待原生恢复。原有页面字节回滚，64个新增allocator
OS pages仍保留。whole request/suffix原生差分、actual JNI转换、完整
signer、fresh/live与真实JVM未完成。见 [同类别realloc证据](evidence/vm9_libc_realloc_same_bin_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_realloc_same_bin_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <same-bin-realloc-evidence.json>
```

## 6.111 StringObject ASCII casefold 搜索（2026-10-12 Asia/Shanghai）

新增 `find_string_object_ascii_case_insensitive` 恢复
`+248C54 -> +2476B0`，接入 `+285D10`：packed+8为receiver，+16为
pattern StringObject，+24为W start，W0 result写packed+28。按declared
length搜索，包括NUL之后的binary bytes；仅将ASCII A-Z折为a-z。
保留原native read order：receiver pointer、receiver signed length、
pattern pointer/length、start边界，再逐项比较pattern byte与receiver
byte。negative/NULL与empty pattern的short circuits、same-pointer
fast path和signed start均保留。capacity/vtable不参与搜索。

两基址 **72项新增原生/Python对照、20项回滚**通过，2项native RED。
18 profiles的direct body与actual wrapper覆盖binary/mixed ASCII、
last match、empty pattern/at end、negative start/length、past end、
NULL payload、longer pattern、non-ASCII、miss、same pointer跳过unmapped
payload、overlap、cross-page、large declared length早期匹配，以及标点
不能以ASCII大小写折叠。native W0与packed+28的4字节写入一致，guest
data区域+0xA000一致；Python搜索本身不改变任何页面，无allocator或
service调用。native output未用于Python输入，旧原生分组未重跑。

比较上限按实际byte pairs计数，允许大声明长度下早期match；非法
start/bound/stack、unmapped访问、scan超限及physical spill alias显式
拒绝且pages不变。body/wrapper的physical register spills未恢复。

非空构造入口从2538推进到 **2590步**，新搜索callback完成两次；下一处
为 `+285D34 -> +248B24`。其packed layout同样包括W start与+28 W结果，
第二输入是CString；static body先检查NULL source、receiver W length
与start，再读取source首byte，完整搜索body仍需核实。原有页面字节
回滚，64个新增allocator OS pages保留。actual JNI、suffix整链原生差分、
完整signer、fresh/live及真实JVM未完成。见 [casefold搜索证据](evidence/vm9_request_casefold_search_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_casefold_search_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-casefold-search-evidence.json>
```

## 6.112 CString pattern 搜索（2026-10-12 Asia/Shanghai）

新增 `find_string_object_cstring` 恢复 `+248B24`，接入 `+285D34`：
packed+8为receiver StringObject，+16为CString，+24为W start，+28写
4字节W0 result。先检查NULL pattern，再按unsigned W length/start比较，
读取pattern首byte；empty pattern返回start，包含high-bit start；nonempty
且start==length返回FFFFFFFF。一字节pattern复用已验证byte-find owner。
多字节pattern恢复原生paired scan、first hit和matched count；NUL时检查
所有命中是否连续，不连续时按W wrapping状态重试。receiver offset使用
原sxtw语义，pattern逐byte读取，不预先转换为独立Python字符串。

两基址 **76项新增原生/Python对照、24项回滚**通过，2项native RED。
19 profiles的direct/actual wrapper覆盖gap后contiguous match、first/last
match、empty/at end/high-bit start、negative/past end、NULL pattern不读
receiver、zero length、one byte、binary NUL tail、case-sensitive、miss、
overlap、cross page、high-bit signed offset与large length早期match。
W0、packed结果和guest data区域+0xA000一致，Python搜索无页变化，
无allocator/service调用。原body/wrapper未改，native输出未用于Python
输入；旧原生分组未重跑。实际receiver byte comparison超过上限、非法
参数、unmapped访问及physical wrapper spills alias显式拒绝，pages不变。

非空构造入口从2590推进到 **2761步**，CString搜索callback完成一次，
并继续通过已有CString构造、集合写入及析构。当前边界为VM指令
**op17 sub53**，bytecode PC为image+FC708；没有下一缺失callback的
声明。该算术指令仍需恢复。原有页面字节回滚，64个新增allocator OS
pages仍保留。actual JNI、suffix整链原生差分、完整signer、fresh/live及
真实JVM未完成。见 [CString搜索证据](evidence/vm9_request_cstring_search_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_cstring_search_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <request-cstring-search-evidence.json>
```

## 6.113 VM signed product 与 low copy（2026-10-12 Asia/Shanghai）

恢复 `vm_full` 的op17/sub53与sub39。原生 `+16B1B0` 从fB、fC读取
signed64操作数，实际MUL/SMULH产生128位乘积，低64位写hidden slot32、
高64位写slot33；不修改普通寄存器，fA/fD字段不参与计算。两个半部均
保留完整64位，不做W截断或额外sign-extension。已有sub52可消费高半部。
原生 `+16AE04` 的sub39从slot32读取完整word到fA；提供guest backing时
其slot32为读取owner，同时写回目标slot。slot33和slot34保持不变。

两基址 **238项新增原生/Python对照**通过，对应220次原始interpreter
执行；四项native RED确认旧指令缺失。200项signed multiply覆盖零、正负
组合、signed min/max、128位溢出边界、W边界、同source、高编号source、
ignored字段、abstract/backing及sub52消费。38项low-copy覆盖R0/R4/R15/
R16/R29/R30/R31目标、完整high bits、外部backing修改后的读取，以及
sub53接sub39。R31目标使用独立R30退出，原探针不完整的sub30退出编码
已修正；退出错误不再归因于sub53。所有32普通寄存器和3隐藏槽对照
一致，backing模式比较完整35-slot array，Python仅改变声明的slots。
两组验证后的源码增量只含sub39新增分支，已接受旧分组未重跑。

构造URL与header的非空入口从2761步，经sub53后的2762步sub39边界，
推进至 **2850步**。当前边界：`unknown request callback +0x285d74 -> +0x26bdfc`。
原有页面bytes回滚，64个新增allocator OS pages
仍保留。该入口使用Python构造的ABI，actual JNI frontend、suffix整链
原生差分、完整physical stack、alternate opaque分支、真实JVM、完整
signer、fresh签名和线上矩阵尚未完成。
见 [signed product证据](evidence/vm9_signed_product_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_signed_multiply_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <signed-multiply-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_product_low_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <product-low-evidence.json>
```

## 6.114 State numeric member 读取（2026-10-12 Asia/Shanghai）

新增 `vm9_state.find_state_member` 与 `read_state_integer_member`，恢复
`+24A0A0`、`+269BF4/+269C80` 的状态linked-node查找与数值转换。root+10
指向首node，node+0为next，node+38为CString key；按ASCII A..Z折叠
逐byte比较。NULL root/key直接miss，NULL node key跳过；key pointer相同
直接命中。StringObject+10提供CString，声明长度不改变NUL终止语义。
node+18的type byte精确等于8才从node+30读取double，否则使用-1.0。

原生整数getter的外层与double getter的内层各获取shared reader，再
依次释放；复用已验证的uncontended normal mutex与reader owner。
receiver+20指向mutex object，primitive在object+8，reader count在+90；
两次获取将+94置1，释放后+94仍为1。已有reader计数恢复到输入值。
`FCVTZS W0` 向零截断，超界饱和为signed32 min/max，NaN转0；输出
为zero-extended W0 bit pattern，供后续调用者按原生语义sign-extend。

两基址 **60项新增原生/Python对照、18项回滚检查**通过，2项native RED。
原body与nested reader bodies完整执行，每次实际matching-libc锁/解锁
各4次，无allocator。覆盖fraction、signed边界、溢出、NaN/infinity、
missing/nonnumeric/combined kind、大小写、empty、NULL、链尾、重复键、
identical key pointer、high bytes、binary NUL和已有readers。W0及完整
guest data一致，image/pages保持不变；cycle、node/comparison bounds、
unmapped key/node/mutex、writer、reader saturation与非法bound明确拒绝，
全部页字节回滚。旧state VM/caller AST保持一致，旧分组未重跑。

这是 `+26BDFC` 的数值读取依赖；实际request callback及其lazy state
service尚未接入。非空入口仍停在2850步的 `+285D74 -> +26BDFC`。
下一步恢复 `+26A3AC` lazy reference及 `+26BDFC` 构造/清理，并对照
actual callback。actual JNI、suffix整链差分、physical stack、真实JVM、
完整signer、fresh/live仍未完成。
见 [state numeric证据](evidence/vm9_state_numeric_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_state_numeric_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <state-numeric-evidence.json>
```

## 6.115 Lazy state service（2026-10-12 Asia/Shanghai）

新增 `vm9_state.get_state_service_reference` 恢复 `+26A3AC`：首先按flag
解码key，再检查guard/slot；warm直接返回wrapper，包括NULL slot，cold
按16-byte wrapper、48-byte state owner、temporary CString、完整state
VM/caller、4-byte counter顺序执行。清理temporary后发布wrapper并释放
guard。key与guard由fresh ELF提供，无decoded names或native output输入。

两基址 **8项新增原生/Python对照、7项回滚检查**通过；2项cold native
RED证明旧owner缺失。cold与decoded-key路径各42次分配、22次释放、
2次注册、3次no-waiter唤醒；warm与warm-NULL无分配。返回、完整guest
data、所有ELF页、TLS0xB00 bytes及allocation/free/register/wake顺序一致。
原guard、state VM、matching-libc once/key/formatter与mutex实际执行；
properties absent、file/socket不可用、mkdir EEXIST与futex结果为明确
虚拟环境服务。原诊断scope效果不在该对照范围，完整physical stack未
比较。旧state owner/VM AST保持一致，旧接受分组未重跑。

独立全冷探针发现102次分配，Python最初仅42次；首分叉在原
`+25DDEC` 文件检查调用的singleton136冷初始化，多出60次分配。
当前request外层已构造singleton136，故恢复helper明确要求这一前置
条件，并用两侧独立构造的warm reference验证。未初始化singleton136、
guard wait、缺少tid、非法stack及NULL operator-new明确拒绝，页字节
回滚；provider外部effects仍不回滚。首次原生fetch失败来自Python libc
pages覆盖原生loader relocations，验证器已由各自loader提供libc输入。

request的 `+285D74 -> +26BDFC` 构造callback尚未接入，非空入口仍2850
步；下一步组合state service、numeric lookup、scoped writer及reference
清理，执行actual callback对照。actual JNI、suffix整链差分、完整signer、
fresh/live与真实JVM继续未完成。
见 [state service证据](evidence/vm9_state_service_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_state_service_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <state-service-evidence.json>
```

## 6.116 Request state 构造与清理（2026-10-12 Asia/Shanghai）

新增 `construct_request_clock_state` 恢复 `+26BDFC` 并接入实际leaf
wrapper `+285D74`，packed+0为target、+8为object。按原生顺序memset
object前0x98字节、构造mutex、zero+98、获取lazy state reference、复制
临时引用、解码key、构造StringObject、读取numeric member、销毁key、
scoped writer acquire、写object+98、release writer、释放临时引用。
getter的W0=FFFFFFFF映射为zero，其他值sign-extend W0到64位写+98。
temporary reference在global ownership仍正时释放，不支持删除state
service；unsupported分支回滚page bytes，provider effects保持外部。

两基址 **16项新增actual wrapper对照、7项回滚检查**通过，2项native
RED。覆盖missing、positive/negative fraction、minus-one、NaN、positive/
negative infinity saturation与nonnumeric。输出state word、完整guest data、
ELF与TLS页、allocation/free/register/wake顺序及global count一致。
lazy依赖由Python从fresh ELF独立生成，native输出不作为输入。原
callback实际执行matching-libc mutex/TLS；诊断scope与完整physical stack
未对照。reader helper的 `+269C34` Wstatus spill会成为TLS节点padding：
恢复四字节zero，保留高四字节输入；native writer observer确认了该效果。
warm依赖的libc once/key generation输入页显式提供，避免loader重置后
TLS tree失配；undefined-symbol relocations仍由native loader负责。

非空URL/header构造入口从2850推进至 **2911步**。下一边界
`+285D80 -> +26BF90`，bytecode image+FCB34；state构造callback已完成。
原有页面字节回滚，64个新增allocator OS pages仍
保留。接入增加显式state-service provider，沿用外层已初始化singleton136
和同一allocator/TLS会话。旧原生接受分组未重跑；旧state helper/caller
AST未修改。actual JNI、suffix整链原生差分、完整signer、fresh/live和
真实JVM继续未完成。见 [request state证据](evidence/vm9_request_state_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_state_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <request-state-evidence.json>
```

## 6.117 Request elapsed seconds（2026-10-12 Asia/Shanghai）

`vm9_state.read_request_elapsed_seconds` 恢复 `+26BF90/+26BF18`，接入
actual packed wrapper `+285D80`。shared reader获取后将flag94置1，先读
object+98，再调用现有realtime milliseconds provider（clock id0）。
now-start按64位回绕；signed delta>0选delta，否则选now；释放reader后
将选中64位word按unsigned除1000，写packed+10的完整8字节结果。
reader count恢复，flag94保留1。未知clock/mutex状态拒绝并回滚page
bytes，provider外部effects不回滚。现有clock/reader owner直接复用。

两基址 **36项新增原生/Python对照、12项回滚检查**通过，2项native
RED。覆盖零/未来start、subsecond、负时间、microseconds与subtraction
回绕、signed delta极值、已有reader、shared mutex bit、clock修改start。
原生wrapper/body与matching-libc mutex实际执行；完整guest data、ELF、
TLS和packed uint64匹配。clock在reader scope内部，修改start控制证明
读取发生在clock之前。完整physical stack及Android clock仍未验证。

非空URL/header构造入口从2911推进至 **3167步**，时间getter实际接入，
next `+285E14 -> +2633A4`，bytecode image+FD2B4。原有页字节回滚，
64个新增allocator OS pages保留。未重复已接受的原生
分组；旧state与request callback AST保持一致。actual JNI、suffix整链
差分、完整signer、fresh/live及真实JVM仍未完成。
见 [elapsed证据](evidence/vm9_request_elapsed_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_elapsed_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <request-elapsed-evidence.json>
```

## 6.118 Request contained reference copy（2026-10-12 Asia/Shanghai）

接入actual wrapper `+285E14 -> +2633A4`：packed+8为hidden X8输出，
packed+10为source object；target将source+18交给已有 `+15F580`
scoped reference copy。复用 `vm9_reference_scopes`，保留先清零输出、
读取pointer、诊断锁scope、重新读取pair、uint32计数回绕及scope退出。
wrapper push10，因此helper entrySP为callback entrySP-10。

两基址、cold/warm诊断锁共 **32项新增actual wrapper对照**通过，
2项native RED。覆盖NULL/zero/wrapped count、retained、NULL object、
self与双向重叠。完整guest、ELF、24字节scope及allocator/free/lock
顺序一致。主体owner与旧回归AST保持一致。非空请求3167->3245步；
下一hash64回调。见 [reference证据](evidence/vm9_request_contained_reference_fresh_20261012.json)。

## 6.119 Request StringObject table hash64（2026-10-12 Asia/Shanghai）

新增 `vm9_objects.hash_string_object64` 恢复 `+258BE0/+24B2D4`，接入
actual wrapper `+285E38`。先读payload pointer、再读signed W length；
非正长度返回zero且不读取payload/table。正长度逐字节处理，embedded
NUL包含在内。accumulator初值0，每步table[(hash XOR byte)&FF]
XOR(hash>>8)，表来自loaded ELF +96548，不硬编码CRC变体。wrapper
将完整64位结果写packed+10，保留后8字节。

两基址 **52项新增原生/Python对照、6项回滚检查**通过，2项native
RED。覆盖0..1024字节边界、全256字节、embedded NUL、负signed长度、
仅fields映射、跨页、receiver/payload与packed output alias、修改guest
table。uint64返回、packed/fullguest与table页一致，无allocator/service
effects。未知receiver/payload/table及扫描超限拒绝，全部页字节不变。
max_bytes=0下三种非正长度成功返回0。

非空URL/header构造入口推进 **3257步**，next `+285E54 -> +2850A8`，
bytecode image+FD5E8；原有页字节回滚，64个新增allocator OS pages
保留。已接受旧原生分组未重复，完整physical stack、actual JNI、suffix
整链原生差分、完整signer、fresh/live与真实Android JVM仍未验证。
见 [hash64证据](evidence/vm9_request_hash64_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_contained_reference_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <contained-reference-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_request_hash64_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --group all --output <hash64-evidence.json>
```

## 6.120 Request TLS uint32 读写（2026-10-12 Asia/Shanghai）

接入actual wrapper `+285E54 -> +2850A8` getter和 `+285E70 -> +27ED70`
setter。两者忽略receiver，调用已有TLS owner解析loaded ELF control
image+382920（size4/alignment4/index0/template NULL）。getter读取TLS
变量的uint32，仅写packed+10四字节，高四字节与后八字节保留。setter
从packed+10读取W1，将低32位写TLS变量，packed保持原样。两条薄分支
使用outer session的同一显式get_tls，不重复实现pthread或emutls。

两基址共 **34项新增actual wrapper对照**通过：getter14项，setter20项，
4项native RED。覆盖cold once/key/slot、warm zero/small/high-u32、warm
empty slot，以及cold/warm下0/17/7FFFFFFF/80000000/FFFFFFFF写入。
未映射receiver证明该输入被忽略；packed padding、完整guest、ELF与
TLS页、allocation/wake顺序一致。原生TLS主体与matching-libc once/
key/get/set真实执行。warm依赖由Python独立构造，libc once/generation
输入页显式保留，loader继续拥有其他import relocation。

非空请求3257->3273-> **3307步**，next `+285E80 -> +2869F0`，bytecode
image+FD6B0。原有页字节回滚，64个新增allocator OS pages保留。旧TLS
owner及旧request callback AST不改，已接受原生分组未重跑。完整physical
stack、actual JNI、suffix整链差分、完整signer、fresh/live与真实JVM仍
未验证。见 [TLS getter证据](evidence/vm9_request_TLS_word_fresh_20261012.json) 与
[TLS setter证据](evidence/vm9_request_TLS_store_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_TLS_word_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <TLS-getter-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_request_TLS_store_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <TLS-setter-evidence.json>
```

## 6.121 Request binary transform（2026-10-12 Asia/Shanghai）

新增 `vm9_request_transform.construct_transformed_reference` 恢复实际
`+286084`，限于已初始化singleton136首次读取payload+10为zero的分支。
按原生顺序allocate StringObject、构造scoped reference、resize到
source signed length+6、两次获取SDK reference、构造8字节key、两轮
S-box生成、复制source、逐字节变换及forward混合。key包含allocated
payload地址低两字节与W1 seed低16位；栈内key暂存字节在使用前均被
原生写入覆盖。S-box写入将同一值同时写两处，末字节混合会读取已变换
的首字节，保留这些行为。source与allocator/SDK服务由caller显式提供。

两基址 **24项新增原生/Python对照、10项回滚检查**通过，2项native
RED。覆盖0/1/2/7/8/20/31/64字节以及0/1/FFFF/12345678/FFFFFFFF
seed；完整guest、ELF、reference scope构造返回时的24字节和allocator/
diagnostic lock顺序一致。scope所在physical stack随后由fill/transform
复用，因此最终该栈区域不作比较；完整physical stack未验证。原生主体
与matching-libc recursive mutex真实执行，不使用native输出初始化模型。
nonzero SDK首次field、负长度、未知stack/provider及allocation failure
明确拒绝并回滚guest pages，外部provider effects不回滚。

这是外层 `+2869F0` 的一个组件，尚未接入该完整caller。非空request
仍停3307步的 `+285E80 -> +2869F0`。私有原生诊断证明当前Python
构造输入上外层自然返回并执行MD5、字符串拼接和引用清理；它不计入
formal native/Python controls。外层参数组装、hex publication与cleanup、
actual JNI、整链差分、完整signer和fresh/live仍未完成。
见 [transform证据](evidence/vm9_request_transform_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_transform_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <transform-evidence.json>
```

## 6.122 Request hexadecimal reference（2026-10-12 Asia/Shanghai）

在既有reference scope owner新增 `construct_hexadecimal_string_reference`
恢复 `+192494/+19364C`。在allocation之前保留source pointer与signed
length，allocate24、empty StringObject、scoped reference/count、reserve
2*length+1，再逐字节读取高/低半字节对应guest alphabet。每半字节重新
读取源byte、image+37A068 alphabet pointer与output reference；复用
原有reserve、append与diagnostic owner。最后仅在length过长时截短。
负length与显式bounds拒绝；未知页/provider回滚page bytes。

两基址 **20项新增原生/Python对照、8项回滚检查**通过，2项native
RED。覆盖0/1/2/7/8/20/31/64/128字节与custom guest alphabet。完整
guest、ELF、reference constructor返回时scope24，以及allocator/free/
diagnostic lock顺序匹配。alphabet由caller输入，不假定固定hex编码。
原生主体和matching-libc recursive mutex实际执行；完整physical stack
未比较。旧reference/digest helper AST保持一致，旧原生接受组未重跑。

这是 `+2869F0` 的另一个组件；外层参数组装、publication与cleanup尚待
恢复。非空入口仍停3307步。actual JNI、suffix整链原生差分、完整signer、
fresh/live与真实JVM仍未完成。见 [hex reference证据](evidence/vm9_request_hex_reference_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_hex_reference_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <hex-reference-evidence.json>
```

## 6.123 Request raw MD5 and reference assignment（2026-10-12 Asia/Shanghai）

扩展既有 `construct_scoped_digest_reference`，由flag低位选择raw或hex；
默认hex保持原语义。raw通过已有digest owner计算MD5并构造16字节
StringObject，复用新增scoped owned assignment `+162944` 发布引用与
count1。恢复MD5 scratch SP-48；最终padding block的+36 word经实际
`+243250/+24325C` 存到context+7C，与随后scope的SP-C4重叠。
此处是block word，不是bit count。hex lifecycle原方法及hex分支AST
保持一致；不重复旧原生接受分组。

新增 `assign_scoped_string_reference` 恢复 `+162620`：先比较object
pointer，相等则不触碰count/锁；不同则按需scope旧引用cleanup，再
重新读source pointer并在新scope复制live pair及uint32计数。新增
owned assignment `+162944` 总是构造新count，旧引用按同一cleanup
owner处理。source/destination部分重叠沿用原生读写顺序。

两基址 **54项新增原生/Python对照、12项回滚检查**通过，2项native
RED。18项raw覆盖0/1/45/60/64/4097字节、NULL source、flag2及dirty
scope；28项assignment覆盖删除/保留/zero/signed-min旧count、NULL
object/count、count回绕、同object不同count、self与双向重叠；8项
owned assignment覆盖空输出、删除、保留与NULL新object。全部guest/
ELF、digest scratch、scope24及每次scope退出边界、allocator/free/
matching-libc diagnostic锁顺序与free前bytes一致。allocator是显式
合成服务，原始helper与matching libc锁实际执行。guards拒绝非法栈、
unmapped scope、missing allocator、未知析构及source bound；页面
保持不变，外部provider ledger不声称回滚。

这是 `+2869F0` 外层所需的raw digest与assignment依赖；外层组装、
`+172AF4` getter、C-string格式化及清理仍需恢复。非空入口仍3307步，
actual JNI、suffix整链原生差分、完整signer、fresh/live和真实JVM均
未完成。见 [raw MD5与assignment证据](evidence/vm9_request_raw_digest_fresh_20261012.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_raw_digest_fresh_20261012.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <raw-digest-evidence.json>
```

## 6.124 Request version word（2026-10-13 Asia/Shanghai）

在既有configuration owner新增 `initialize_request_version_word` 与
`get_request_version_word`，恢复 `+172F2C/+172AF4`。从guest encoded
table读取version pointer，按原生strdup allocation/copy顺序构造副本，
在+3/+6写NUL，再调用显式atoi服务读取+1/+4/+7，取各结果最低byte。
free副本后复用已有environment service reference、constant与identifier
getter；constant首byte==e决定bit5，identifier的i/l/w选择低位1/2/3，
其余为0。三个数字占bits24/16/8。字符串至少7字节；越界delimiter
store、unknown pages或provider行为拒绝并回滚page bytes。

外层getter复用已有serialized guard acquire/release，保留guard bit0
与whole byte0判定区别。initializer返回status1写到encoded table+8
指向的槽；实际packed word从table+16指向的另一个槽读取。所有相关
table在原生重读边界重新读取；分配期间更改status slot仍正确。先前
静态假设status覆盖packed word被新鲜原生RED否定，未进入实现或证据。

两基址 **40项新增原生/Python对照、10项回滚检查**通过，2项native
RED。20项initializer覆盖signed/whitespace/non-numeric/large低byte
component、环境和三种platform标志及cold service；6项cold getter
覆盖原路径、cold service与status slot变更；14项cached controls覆盖
zero/small/signed边界/allbits与两种completed guard状态。完整guest/
ELF、uint32 return、allocator/atoi顺序与free前副本bytes匹配。原始
helper、matching libc atoi与guard mutex实际执行；malloc和strdup为
显式合成服务。所有旧configuration函数AST保持一致，无旧原生组重跑。

这是 `+2869F0` 外层另一个依赖。两遍C-string格式化、外层组装及cleanup
继续恢复，非空入口仍3307步。actual JNI、整链差分、完整signer、fresh/
live和真实JVM仍未完成。见 [version证据](evidence/vm9_request_version_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_version_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <version-evidence.json>
```

## 6.125 Request allocated printf（2026-10-13 Asia/Shanghai）

在既有configuration formatter owner新增 `allocate_printf_cstring`，恢复
`+278314` 的两遍 `%d/%s/%%` C-string格式化。第一遍读取live format/
arguments计算长度，malloc(length+1)，先把pointer写入output slot；NULL
分配返回uint32 -1。第二遍重新读取format和string，按第一遍容量截短，
写NUL并返回第二遍完整长度。复用已有guest printf renderer，未增加
并列渲染器。unsupported转换或未知页拒绝并回滚page bytes。

两基址 **36项新增原生/Python对照、9项回滚检查**通过，2项native
RED。覆盖0/1/7/32/128 bytes、empty/literal/percent/two strings、signed
%d边界、embedded NUL、第二遍变长/变短/format改变、NULL malloc、
output/source alias与跨页slot。全部guest/ELF bytes、uint32 return、
allocator与publication效果一致；原始custom printf主体实际执行，
malloc为显式合成服务。已有configuration函数AST保持一致，无旧原生
接受组重跑。guards验证unmapped format/argument/output/buffer、未知
conversion、扫描上限和provider错误；不声称外部provider ledger回滚。

这是 `+2869F0` 外层格式化依赖。raw MD5/scoped assignment、version
getter、binary transform、hex reference及allocated printf均已分别
恢复；外层组装和cleanup、非空入口replay及整段原生差分仍待恢复。
非空入口仍3307步；actual JNI、完整signer、fresh/live与真实JVM未完成。
见 [allocated printf证据](evidence/vm9_request_alloc_format_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_alloc_format_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <allocated-printf-evidence.json>
```

## 6.126 Request outer suffix and raw free（2026-10-13 Asia/Shanghai）

在request transform owner新增 `construct_request_suffix`，恢复 `+2869F0`
完整semantic组合。读取guest encoded table三组lazy constants；按实际
mode选择clone constant或raw MD5/scoped assignment。先四字节substring
三次，再四字节version和REV W timestamp，依次append/destroy，组合
长度最多20字节。LDRH读取seed，调用已恢复binary transform、hex引用，
clone结果并生成两个allocated printf C strings；随后按原生次序清理
hexclone、transform reference、combined string、sized16 reference、
MD5 reference、constant string。所有ownership和string行为复用已有
owner，outer helper SP为入口SP-260；physical callee spills/unwind仍
未完整恢复，不把void X0当成签名或业务状态。

两基址 **26项新增原生/Python suffix对照、9项回滚**通过；原始外层
自然返回。覆盖0/1/2/7/32-byte source、mode1及短constant、mode allbits、
warm constants、seed和timestamp边界、相同output slot。完整semantic
guest/ELF bytes、两个output C strings、allocator/diagnostic lock/free
顺序及free前bytes一致。matching-libc锁实际执行；allocator和initialized
zero-first SDK为显式独立输入。其他SDK分支仍拒绝。旧transform AST
保持一致，无旧接受原生组重跑。

actual `+285E80` callback接入同一suffix；另把 `+285910 -> +347FA0`
接入既有free service。新增 **6项actual raw-free wrapper对照、2项
provider回滚**，实际source callback body在隔离dispatch中执行，验证
NULL、buffer及packed/free alias；无另写Python callback。总计本节
**32项新增对照、11项回滚**，4项native RED。

同一owning allocator、合成URL及一个header的非空入口从3307推进到
**3405步 / bytecode+FD838**，suffix执行一次，随后两个raw C strings
释放并继续VM；下一未知callback为 `+285E8C -> +287168`。原有page
bytes回滚，64个新增allocator OS pages保留，不声称mapping回滚。这是
独立构造ABI，actual URL/header/JNI转换与整个prefix原生差分尚未验证。
完整signer、fresh/live、真实JVM与full physical ABI均未完成。
见 [suffix证据](evidence/vm9_request_suffix_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_suffix_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <suffix-evidence.json>
```

## 6.127 Request metadata formatting（2026-10-13 Asia/Shanghai）

恢复 `+287168` 的metadata组合：从encoded ELF table解码三组lazy
constants，先读取input低32位与两个output slots，再调用已有allocated
printf生成两个C strings。第二个格式原生为 `%u`；已用两基址失败对照
确认旧renderer拒绝后，在同一renderer补齐低32位unsigned decimal。
保留原有 `%d/%s/%%` 分支语义，不重复实现两遍formatting或allocator。
整个guest transaction共同提交；allocator外部effects不声称回滚。

两基址 **32项metadata、8项unsigned printf、6项actual source callback**
新增原生/Python对照通过，合计 **46项对照、12项回滚检查**。覆盖
0/1/高位/全位、cold和warm constants、相同output slots、input/packed
alias、跨页slot、第一次malloc期间修改scalar与第二slot、第二format
字节或table指针变化、constant变长、first/second/both NULL allocations。
返回W0、完整semantic guest/ELF bytes、publication与allocation顺序一致。
actual `+285E8C` wrapper对照执行现有consumer callback的源码AST。
6项native RED包含缺失组合、旧unsigned拒绝与旧consumer缺失。

非空owning allocator入口从3405推进至 **3520步 / bytecode+FDA04**；
suffix与metadata各执行一次，下一未知callback为 `+285C94 -> +258D6C`。
原有page bytes回滚，64个新增OS pages仍保留，不声称provider mapping
回滚。actual JNI转换、whole-request native差分、full physical ABI、完整
signer、fresh/live及真实JVM仍未完成。见 [metadata证据](evidence/vm9_request_metadata_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_metadata_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <metadata-evidence.json>
```

## 6.128 Request Base64 encoder（2026-10-13 Asia/Shanghai）

在既有StringObject owner补齐 `encode_configuration_base64(+2456AC)` 与
`encode_string_object_base64(+258D6C)`。原始helper的跳转小函数只调整LR，
没有diagnostic lock；通过当前独立输入原生trace确认后按实际语义组合。
raw encoder读取guest ELF alphabet；query容量含NUL，成功length不含NUL，
empty只写length=0；overflow query写uint64全位并返回-42。按实际byte
顺序保留forward source/target、alphabet与length/output alias；尤其tail
第三alphabet读取发生在前两个输出store之后。

StringObject组合先query，非空则fill目标再reload source pointer/length，
第二遍encode。目标声明length保留第一次query容量（含NUL），忽略fill
和第二encode status，返回第一次query是否非空。空input不修改目标。
复用既有fill/reserve/allocator；比较真实length scratch与TLS canary，
完整physical callee spills与C++ unwind未恢复。

两基址 **36项primitive、26项组合、6项actual source callback** 新增
原生/Python对照通过，合计 **68项对照、10项回滚检查**。覆盖0/1/2/3/
4/7/32/128-byte input、query/短容量/大长度/overflow、修改alphabet、
source/target与alphabet/length aliases、预分配、自身StringObject、
malloc期间source变长/变短/换pointer与NULL malloc。完整semantic
guest/ELF bytes、scratch/canary、返回值、allocation/free顺序和free前
bytes一致。实际 `+285C94` callback只写packed+18的一个bool byte，
其余padding保留，source callback AST对照通过。6项native RED。

非空owning入口3520→ **3538步 / bytecode+FDA4C**，suffix、metadata、
Base64各一次；下一未知 `+285E98 -> +2482EC`。原有page bytes回滚，
64个新增OS pages保留，provider mapping回滚仍未验证。actual JNI、
whole-request差分、完整signer、fresh/live与真实JVM未完成。
见 [Base64 encoder证据](evidence/vm9_request_base64_encode_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_base64_encode_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <base64-encode-evidence.json>
```

## 6.129 Request character string（2026-10-13 Asia/Shanghai）

恢复StringObject owner `construct_character_string_object(+2482EC)` 与actual
`+285E98` consumer。先从guest ELF+6E170复制八字节capacity/length字段，
再写vtable，malloc两字节并发布pointer；成功写W1低byte与NUL，NULL则
清除两个length字段。保留malloc期间字段变化、ELF字段在读取后变化和
buffer/object alias；返回实际allocation pointer，即使payload store
改变了object中的pointer字段。不能用普通filled ctor替代其读取/写入顺序。

两基址 **24项constructor、6项actual source callback** 新增原生/Python
对照通过，合计 **30项对照、7项回滚检查**。覆盖0/1/7bit/8bit/allbyte/
宽W1、NULL malloc、修改ELF字段、跨页object、malloc改字段和buffer自身
alias。返回pointer、完整semantic guest/ELF bytes、allocation顺序与
packed输入padding一致；wrapper读取一个byte，consumer执行实际源码AST。
4项native RED，旧StringObject与request方法AST保持一致。

非空owning入口3538→ **3550步 / bytecode+FDA7C**，character构造一次；
下一未知 `+285B44 -> +248EF8`。原有page bytes回滚，64个新增OS pages
保留。actual JNI、whole-request差分、full physical ABI、完整signer、
fresh/live与真实JVM仍未完成。见 [character证据](evidence/vm9_request_character_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_character_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <character-evidence.json>
```

## 6.130 Request right character-set trim（2026-10-13 Asia/Shanghai）

在StringObject owner恢复 `find_string_fields_last_not_in_set(+24795C)` 与
`trim_string_object_right_set(+248EF8)`。原始helper用guest stack构造32-byte
bitmap，再逐byte取反；从给定位置反向查找第一个不属于集合的byte。
保留逐次reload set pointer/length、bitmap/input alias、position等于length
时退一步，以及invalid receiver/position/set提前返回-1的顺序。外层将
length设为index+1，即使返回-1也写0；signed capacity大于新length才写NUL。

两基址 **34项search、24项trim、6项actual source callback** 新增原生
对照通过，合计 **64项对照、9项回滚检查**。覆盖trailing/all/no-set、
empty、重复/高byte/embedded NUL、position边界、NULL fields/payload/set、
bitmap与pattern alias、自身集合、capacity等于/零/负值。返回index、完整
semantic guest/ELF bytes、32-byte bitmap/TLS canary与length/NUL一致；
无allocator effects。actual `+285B44` consumer保持packed bytes，执行现有
source callback AST。6项native RED，旧objects/request方法AST保持一致。

非空owning入口3550→ **3559步 / bytecode+FDAA0**，right trim一次；下一
未知为同wrapper的 `+248EB4`。原有page bytes回滚，64个新增OS pages保留。
actual JNI、whole-request差分、full physical ABI、完整signer、fresh/live
与真实JVM仍未完成。见 [right-set证据](evidence/vm9_request_trim_set_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_trim_set_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <trim-set-evidence.json>
```

## 6.131 Request left character-set trim（2026-10-13 Asia/Shanghai）

恢复 `find_string_fields_first_not_in_set(+247894)`、`erase_string_fields
(+247250)`、`trim_string_object_left_set(+248EB4)` 和actual `+285B44`
consumer。正向查找复用原有right-search的live bitmap构造及逐byte取反；
通过展开共享helper后的完整AST一致性证明旧reverse语义未变，不重跑
已接受的reverse原生组。position须严格小于length；bitmap后reload
receiver pointer/length。erase处理负start裁剪、W count调整、无操作边界，
按memmove语义移动，再reload fields写length/NUL。left trim查到-1时
使用live receiver length删除整个prefix，返回erase status。

两基址 **34项forward search、30项erase、24项left trim、6项actual
source callback**通过，合计 **94项新增对照、11项回滚检查**。覆盖
leading/all/no-set、NUL/highbyte/重复集合、NULL及position边界、bitmap
alias、negative start/count、capacity拒绝、payload/fields alias、prefix/
middle/suffix删除。完整semantic guest/ELF bytes、适用bitmap/canary、
status、length/NUL与memmove一致，无allocator effects。8项native RED。

非空owning入口3559→ **3767步 / bytecode+FDDE0**，left/right trim、
Base64和character各两次；下一未知 `+285EA8 -> +287500`。原有page bytes
回滚，64个新增OS pages保留。旧私有探针固定TLS读取一次的假设被后续
第二次读取否定；本次收据记录实际次数，页面差异为空。actual JNI、
whole-request差分、full physical ABI、完整signer、fresh/live与真实JVM
仍未完成。见 [left-set证据](evidence/vm9_request_left_trim_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_left_trim_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <left-trim-evidence.json>
```

## 6.132 Request token VM caller and prefix（2026-10-13 Asia/Shanghai）

恢复 `prepare_request_token_vm_caller(+287500)` 的0x680字节caller frame、
`+168324` 已定义prelude slots与 `+118570` 嵌套VM前缀。descriptor top
为localSP+650，backing为top−118；packed包含object、2884AC sentinel、
top与未带PAC的LR。未写入的32槽保留独立caller字节。TLS canary在保存
寄存器后读取，覆盖TLS与spill重叠。原有caller函数AST逐个一致。

两基址 **14项caller/prelude、6项嵌套prefix** 对照和 **8项回滚检查**
通过。覆盖NULL/cross-page object、wide spills、stack迁移、TLS alias、
patterned stack；caller完整frame、32 backing words、5个VM入参、physical
SP/X28/X19一致。嵌套 **179步 / bytecode+118838** 的两个decode callbacks、
decoded bytes、32虚拟寄存器和下一packed descriptor一致。prefix不发布
pages，未知回调为显式边界。2项native RED已证明此前owner缺失。

下一 `+288B08 -> +26CC8C` 为random getter。外层仍3767步，尚未接入
该嵌套callback。完整generic VM physical spills、actual JNI、整链差分、
allocator mapping回滚、完整signer、fresh/live及真实JVM未完成。
见 [token VM证据](evidence/vm9_request_token_vm_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_vm_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <token-vm-evidence.json>
```

## 6.133 Request random state and getter（2026-10-13 Asia/Shanghai）

恢复matching bionic `+487A8` random state、`+4884C` seed初始化、
`random(+48CE8)` / `srandom(+48934)` normal mutex包装，以及actual
request getter `+26CC8C`、time helper `+2728F4` 和consumer `+288B08`。
native rand/srand实际执行matching libc，Python独立维护相同guest state；
syscall169 gettimeofday为明确的virtual service。

非零type执行W加法、右移和cursor advance/wrap；type0使用LCG。seed
使用signed W Park-Miller递推，<=0加7fffffff，不把zero seed替换为1。
degree及state pointer按native缓存，warmup每次reload live字段。getter
guard的实际偏移 **3DEDB0**：ADRP3DE000+DB0，修正旧私有摘要的误读。
warm guard跳过time/seed；cold acquire读取seconds lowW作为seed。时间
helper独立验证timeval、canary、errno与negative result；返回后其scratch
被libc physical spills复用，getter终态不宣称保留该child scratch。

**58项新增state/seed/serialized-wrapper对照、40项新增time/getter/actual
consumer对照、15项回滚检查**通过，4项native RED。覆盖两libc基址、
wrap、cursor/data/field alias、cross-page state、zero/highbit/wide seeds、
degree0/-1/1/7/15/31/63、shared mutex、warm/cold及completed guard、errno
与非errno负syscall、packed W store和padding。guest、适用ELF/libc/TLS/
canary、结果和time calls一致，未复制native state或random输出。

嵌套random callback尚未接入，外层仍3767步，内层仍179步边界。
完整generic physical ABI、actual JNI、整链差分、allocator mapping回滚、
完整signer、fresh/live及真实JVM未完成。见 [random证据](evidence/vm9_request_random_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_random_fresh_20261013.py --libc <matching-libc> --group all --output <random-state-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_request_random_getter_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <random-getter-evidence.json>
```

## 6.134 Request nested random continuation（2026-10-13 Asia/Shanghai）

嵌套 `+287500` 接入已验证 `+288B08 -> +26CC8C` random owner，使用明确
libc/syscall/errno/thread服务；未提供服务时保留旧179步边界。actual外层
`+285EA8` consumer源码生成内层caller参数，包括callback SP、saved FP、
X28/X19和trampoline LR `+16AA4C`。下一个未恢复callback为显式边界，
既不宣称callee完成，也不发布partial guest pages。

两基址 **6项nested、6项actual outer source consumer对照**及 **5项回滚**
通过。fresh ELF fixture的内层179→ **191步 / +118868**，下一
`+288B24 -> +32A444`。cold/warm、wide wall seconds覆盖32 virtual registers、
下一descriptor、guest/ELF/libc state、time调用与supplied-page rollback。
2项native RED；去除新增服务参数和新增回调后，旧default prefix和全部旧
outer callback AST一致，既有原生组不重跑。

独立构造非空URL/header的owning入口实际进入内层 **158步 / +118868**，
外层仍3767步/+FDDE0，停在同一shared-reader边界。该入口未作whole-prefix
native差分。原有page bytes差异为空，64个新增OS pages保留。完整nested
return、generic physical ABI、actual JNI、整链差分、mapping回滚、完整
signer、fresh/live及真实JVM仍未完成。见 [nested random证据](evidence/vm9_request_token_random_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_random_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <nested-random-evidence.json>
```

## 6.135 Request nested shared readers（2026-10-13 Asia/Shanghai）

新增 `apply_token_shared_reader_callback`，恢复actual `+288B24` consumer
的 `+32A444` acquire / `+32A4FC` release。复用已接受的uncontended
reader owner，不重跑旧helper原生组。acquire保留定义的local pointer、
byte flag及TLS canary；正常native X0为最终mutex unlock的 **0**，与
semantic helper返回的新reader count分别处理。等待、signal及canary
变化拒绝，guest pages回滚；physical spills/PAC仍未宣称恢复。

**16项actual consumer、6项nested prefix、6项actual outer source对照，
7项回滚检查**通过。覆盖acquire/release计数、边界、shared mutex和packed
与count alias；guest/ELF、applicable acquire scratch、32 virtual registers、
下一descriptor、libc random state和time调用一致。2项native RED。
新增continue开关默认关闭；剥离新增开关/分支后的旧prefix及outer callback
AST一致，既有分组未重跑。

fresh fixture191→ **211步 / +1188B8**；独立非空URL/header-owning入口
158→ **178个内层步骤**，外层仍3767/+FDDE0。下一
`+288B30 -> +26C858` diagnostic scope。新fixture按bytecode构造service+8
StringObject依赖；不导入native对象字节。owning原页差异为空，64个新增
OS pages保留。完整nested return、actual JNI、整链差分、physical ABI、
mapping回滚、完整signer、fresh/live与真实JVM仍未完成。
见 [nested readers证据](evidence/vm9_request_token_readers_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_readers_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <nested-readers-evidence.json>
```

## 6.136 Request nested diagnostic scopes（2026-10-13 Asia/Shanghai）

新增 `apply_token_diagnostic_callback`，恢复actual `+288B30 -> +26C858`
enter与 `+288B40 -> +26C9D0` leave，复用已接受的scope owner。allocator、
thread id和observer是显式服务；关闭新服务时保留旧边界。作用域之后
重用已验证的 `+288B24 -> +32A4FC` release consumer。剥离新增服务和
分支后，旧default/source AST一致，既有helper原生组未重跑。

两基址 **16项actual consumer对照、5项回滚检查**通过。cold zero/high
word、warm recursive nested/saturated锁覆盖enter/leave、packed padding、
guest/ELF、allocator顺序与mutex/gettid events；原生执行matching libc
recursive mutex。2项native RED。此处结果经guest对象传递，不宣称scope
constructor的physical X0 ABI；native stack/PAC仍是独立待办。

独立构造非空URL/header-owning入口178→ **231个内层步骤 / +1189A8**，
外层仍3767/+FDDE0，下一 `+288B4C -> +2483E0` StringObject clone。
原有page bytes差异为空，64个新增OS pages保留。本检查点没有对照整段
nested prefix或whole-request。完整nested return、actual JNI、整链差分、
physical ABI、mapping回滚、完整signer、fresh/live及真实JVM仍未完成。
见 [nested scopes证据](evidence/vm9_request_token_scopes_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_scopes_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <nested-scopes-evidence.json>
```

## 6.137 Request nested string lifecycle（2026-10-13 Asia/Shanghai）

新增 `apply_token_string_lifecycle_callback`，恢复actual `+288B4C -> +2483E0`
clone、`+288B5C -> +32A264` free，以及 `+288B68` 的default `+2481AC`、
destroy `+2484B8`、delete `+2484FC`。复用已接受的object owner和显式
allocate/free服务；关闭string服务时保留231步clone边界。旧default/source
AST保留证明通过，既有helper原生组未重跑。

两基址 **36项actual consumer对照、8项回滚检查**通过；binary/empty/
signed-negative/wrap长度、self/field/cross-page alias、NULL allocation与
allocator修改live source pointer均覆盖。guest/ELF/packed padding与
allocator/free顺序一致。clone/default比较native X0；cleanup结果经guest
对象传递，不宣称physical cleanup X0、native spills或PAC。2项native RED。

独立非空URL/header-owning入口 **231→287个内层步骤 / +118AC8**，外层
3767/+FDDE0，下一 `+288B74 -> +248908` 格式化。原有page bytes差异为空，
64个新增OS pages保留。没有整段nested prefix或whole-request对照；完整
nested return、actual JNI、physical ABI、mapping回滚、完整signer、fresh/live
及真实JVM仍未完成。见 [nested lifecycle证据](evidence/vm9_request_token_lifecycle_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_lifecycle_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <nested-lifecycle-evidence.json>
```

## 6.138 Request nested string transforms（2026-10-13 Asia/Shanghai）

新增 `apply_token_string_transform_callback`，恢复actual `+288B74 -> +248908`
format、`+288B8C -> +2481FC` sized constructor和 `+288BA0 -> +248780`
StringObject pair。format/sized复用已接受owner，pair按actual hidden-X8参数
布局组合既有clone/append。W2读取low32；allocator/realloc/free与locale
prepare为显式服务。旧default AST保留；string/format/outer源码逐字节不变。

两基址 **46项actual consumer对照、10项回滚检查**通过：16 format、14 sized、
16 pair。原生format执行matching-libc vsnprintf；signed/high-word、third
argument、长字符串、重试/failure、binary/empty/negative长度及first/second
output alias均覆盖。guest/ELF/TLS/packed padding、allocator/realloc/free和
locale wake顺序一致。format及signed-negative sized的incidental X0不作ABI
承诺；pair W0与positive/NULL sized X0对照。未建模physical spill alias
拒绝，包括allocator在child transaction中修改source pointer的边界。2项RED。

独立非空URL/header-owning入口 **287→321个内层步骤 / +118B50**，外层
3767/+FDDE0，下一 `+288BBC -> +25874C` MD5 reference。原有page bytes差异
为空，64个新增OS pages保留。没有整段nested prefix/whole-request对照；
完整nested return、actual JNI、physical ABI、mapping回滚、完整signer、
fresh/live及真实JVM仍未完成。见 [nested strings证据](evidence/vm9_request_token_strings_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_strings_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <nested-strings-evidence.json>
```

## 6.139 Request nested scoped MD5（2026-10-13 Asia/Shanghai）

新增 `apply_token_digest_callback`，恢复actual `+288BBC -> +25874C`。
hidden X8来自packed+8、source X0来自+16、flag只读取+24的byte；wrapper
保存LR后child entrySP=wrapperSP-16。复用已接受的scoped MD5 owner，实际
reference constructor/assignment/release和diagnostic scopes接线。原有digest/
reference/scope/outer源码按LF归一逐字节不变，旧default AST保留证明通过。

两基址 **32项actual consumer对照、8项回滚检查**通过。raw/hex、empty/
binary、NULL source、45/60字节padding、high flag word、warm scopes与
cross-page packed/output覆盖；原生执行matching-libc recursive mutex。
guest/ELF/packed/defined digest scratch、scope exit bytes、allocator/free/
mutex/gettid顺序及pre-free bytes一致。wrapper没有存physical X0，此处
不宣称physical X0/spills/PAC。2项native RED，旧helper原生组未重跑。

独立非空URL/header-owning入口 **321→422个内层步骤 / +118CE4**，外层
3767/+FDDE0，下一 `+288BDC -> +287580` obfuscated string helper。原有
page bytes差异为空，64个新增OS pages保留。没有整段nested prefix或
whole-request对照；完整nested return、actual JNI、physical ABI、mapping
回滚、完整signer、fresh/live及真实JVM仍未完成。
见 [nested MD5证据](evidence/vm9_request_token_digest_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_digest_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <nested-digest-evidence.json>
```

## 6.140 Request round schedule and block helpers（2026-10-13 Asia/Shanghai）

新增 `vm9_request_token_cipher.py`，恢复 `+287EDC` 四个little-endian seed
words的34轮展开和 `+2881CC` block helper。实际 `+383548/+383550` 编码
helper slots在两个基址均解析为这两处；变更slot拒绝。block复用既有Helios
VM owner，先核对guest `+118F50` 的23条bytecode，再读取caller的34轮密钥
和16字节input。round context写入35个words，剩余context bytes保留。

两基址 **32项新helper对照、8项回滚检查**通过：14 schedule、18 block。
zero/walk/pattern、key/context/scratch alias、cross-page、block原地/前后
overlap及key/input/output alias覆盖。scratch先清零再复制seed，符合actual
source/scratch alias；guest/ELF/defined scratch/canaries逐字节一致，没有
allocator或service effects。4项native RED。physical X0/spills/PAC仍未对照，
旧accepted helper组未重跑。

此检查点只恢复standalone helpers，`+287580/+287A78` caller及 `+288BDC`
consumer尚未接入。没有重放已接受入口，当前owning边界仍422/+118CE4。
下一恢复caller的StringObject/填充/allocator/cleanup顺序，再验证consumer。
整段nested return、actual JNI、whole-request、physical ABI、mapping回滚、
完整signer、fresh/live及真实JVM仍未完成。
见 [round/block证据](evidence/vm9_request_token_cipher_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_cipher_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <token-cipher-evidence.json>
```

## 6.141 Request allocated and string cipher callers（2026-10-13 Asia/Shanghai）

恢复 `+287A78` allocated/padded block caller、`+287580` StringObject caller
和actual `+288BDC` consumer。复用已接受round schedule/block/string owner，
保持四个temporary StringObject的构造、填充、分组、output malloc、writeback
及cipher/pad/input/key清理顺序。短key补零至32；input按16字节分组填充，
输出malloc NULL发布NULL/zero length并清理。物理X0/spills/PAC仍无对照承诺。

两基址 **48项新caller对照、10项回滚检查**通过：20 allocated caller、
8 direct StringObject caller、20 actual wrapper。0/1/15/16/17/31/32/47/64
input、0/1/16/31/32/40 key、NULL receiver/output malloc和existing destination
覆盖。guest/ELF/defined parent locals、malloc/realloc/free顺序及allocator
blocks一致。4项native RED；旧helper原生组未重跑，旧core/default AST保留。

独立owning入口执行新consumer后，仍在 **inner422/+118CE4、outer3767/+FDDE0**
停止于owning allocator的 **32→64字节cross-bin realloc**（class2→4）。
不是next append边界：此前same-bin realloc owner明确拒绝该路径。原有
page bytes差异为空，64个新增OS pages保留，mapping rollback未证明。
下一先恢复matching-libc cross-bin realloc并验证真实入口，再接append/
reference/printf。完整nested return、actual JNI、whole-request、physical ABI、
完整signer、fresh/live及真实JVM仍未完成。
见 [cipher caller证据](evidence/vm9_request_token_cipher_callers_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_cipher_callers_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <token-cipher-callers-evidence.json>
```

## 6.142 Matching libc cross-bin small realloc（2026-10-13 Asia/Shanghai）

新增 `reallocate_small_bins` 并接入 `ActualAllocatorSession.reallocate`。
same class继续原owner；cross class通过disposable transaction调用既有
same-bin校验live slab input，再实际allocate/copy/free。校验transaction
的counter变化不发布。新块复制min(old usable size,request size)，NULL新
分配保持旧块；NULL/zero/large realloc和profiling继续明确拒绝。

两基址 **18项actual export/allocator对照、9项回滚检查**通过。8/16/32/
48/64/128/256字节growth/shrink与uint64 counter overflow覆盖，原生执行
matching-libc realloc export及actual allocator指令，未替换allocation/free。
new pointer、所有非physical-stack pages、payload、allocator metadata/cache
和TSD counters一致。2项native RED。旧same-bin实现AST不变，既有原生
分组未重跑；缺少owner staging chain的fixture已改为session.pages。

独立非空URL/header-owning入口越过32→64 realloc， **422→430内层步骤 /
+118D04**，外层3767/+FDDE0，下一 `+288BF0 -> +248684` append。原有page
bytes差异为空，64个新增OS pages保留。provider mapping rollback未证明；
整段nested return、actual JNI、whole-request、physical ABI、完整signer、
fresh/live及真实JVM仍未完成。见 [cross-bin证据](evidence/vm9_libc_realloc_cross_bin_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_libc_realloc_cross_bin_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <cross-bin-realloc-evidence.json>
```

## 6.143 Request nested append and Base64 reference（2026-10-13 Asia/Shanghai）

恢复actual `+288BF0 -> +248684` append与 `+288C10 -> +258C14` Base64
reference。append将X0写回packed+24；reference从packed+8读hidden X8、
+16读source，childSP=wrapperSP-16。`construct_base64_string_reference`
组合既有query/encode/sized/reference owner，query后malloc、重读source/
encode、allocate24 object、sized copy、free temporary、scoped reference。
empty query构造NULL reference。physical X0/spills/PAC仍未对照。

两基址 **34项新consumer对照、8项回滚检查**通过：14 append、20 Base64
reference。binary/empty/self/output alias/cross-page/allocator failure、0/1/2/
3/32 source、warm scopes和malloc后live source变短/数据变更均覆盖。guest/
ELF/packed/defined length-canary、scope exit bytes、allocator/free/realloc/
mutex/gettid及pre-free bytes一致；原生执行matching-libc recursive mutex。
4项native RED，旧helper原生组未重跑，旧default AST保留证明通过。

独立非空URL/header-owning入口 **430→505内层步骤 / +118E30**，外层
3767/+FDDE0，下一 `+288C28 -> +278314` allocated printf。原有page bytes
差异为空，64个新增OS pages保留。mapping rollback、完整nested return、
actual JNI、whole-request、physical ABI、完整signer、fresh/live及真实JVM
仍未完成。见 [append/Base64证据](evidence/vm9_request_token_tail_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_tail_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc> --group all --output <token-tail-evidence.json>
```

## 6.144 Request nested allocated printf（2026-10-13 Asia/Shanghai）

恢复actual `+288C28 -> +278314` wrapper：packed+8 output-pointer address、
+16 format、+24 argument，调用既有 `allocate_printf_cstring`，仅将W0的
四字节写回packed+32，保留后续padding。恢复childSP=wrapperSP-16的
defined canary。原生执行wrapper与guest formatter，两次format读取跨malloc
保持live语义；accepted standalone helper组未重跑。

两基址 **36项新增原生对照、10项回滚检查**通过：0/1/32/128长度、empty/
literal/percent、signed minimum/unsigned maximum、embedded NUL、malloc后
source变长/变短/format变化、NULL malloc、source/output/packed-result alias、
packed/output跨页。W0、guest/ELF/packed/padding/canary及allocator effects一致。
2项native RED，保留旧default AST、tail consumers与formatter owner证明通过。

独立owning入口 **505→574内层步骤 / +118F44**，40 callbacks；printf后既有
cleanup全部返回，当前拒绝 `0x07C00791` nested return。outer3767/+FDDE0。
原有page bytes差异为空，64新增OS pages保留。完整nested return、mapping
rollback、whole-prefix原生差分、actual JNI、physical ABI、完整signer、fresh/
live矩阵与真实JVM仍未完成。见 [nested printf证据](evidence/vm9_request_token_printf_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_printf_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <token-printf-evidence.json>
```

## 6.145 Request nested caller return（2026-10-13 Asia/Shanghai）

恢复 `+118F44` 的 `0x07C00791` return验证：generic handler `+16A974`
读取selected slot31并与caller sentinel比较，选择 `+172440` epilogue。
`finish_request_token_vm_caller`恢复 `+28755C` canary检查、saved PC/SP/
X19/X28/X29/X30和physical X0=`image+2884AC`。callback trampoline保存并
恢复physical X0，未使用virtual R0代替。返回owner不写page。

**32项新增原生对照、10项回滚检查**通过：两基址、两栈位置、zero/pattern
saved registers、callback改写X0、direct caller/actual `+285EA8` outer
wrapper。短synthetic bytecode是独立明确输入，original caller/interpreter/
trampoline/epilogue执行。canary失败到stack_chk_fail的原生路径已观察。
2项native RED；新增5项Python真实入口检查覆盖enabled、default disabled、
invalid option、wrong exit word、budget。失败页字节不发布，vm_module.B恢复。

`continue_caller_return`显式启用validated return；outer random services的
`continue_token_return`接入同一owner，旧default和callback AST保留。
独立owning nested **574/+118F44、40 callbacks返回**，outer **3767→3879/
+FE27C**，下一 `+285F14 -> +2828D4`。原页差异为空，64新增OS pages保留。
此入口不是whole nested/request原生差分；full physical spills/PAC、mapping
rollback、actual JNI、完整signer、fresh/live与真实JVM仍未完成。
见 [nested return证据](evidence/vm9_request_token_return_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_token_return_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <token-return-evidence.json>
```

## 6.146 Request URL condition（2026-10-13 Asia/Shanghai）

恢复actual `+285F14 -> +2828D4` URL条件。三个lazy flags是32-bit，全部
按序decode后读handler+53 byte；disabled直接true且不读URL。enabled按序
调用既有 `find_string_object_cstring`，任一signed-W nonnegative result为
true，全未找到为false。wrapper仅写packed+24的一字节，后续padding保留。

两基址、cold/warm flags共 **40项新增原生对照、7项回滚检查**通过：disabled/
unmapped-disabled URL、first/second/third match、missing/empty、embedded
NUL后的pattern、handler byte255、packed跨页。guest/ELF/lazy flags/packed
结果与padding一致，无allocator/service effects。2项native RED，既有decode/
search原生组未重跑；保留旧transform/default outer AST与所有nested owner。

独立owning outer **3879→3900/+FE2D0**，URL condition=true；nested574已返回。
下一 `+285F38 -> +287474`。原页差异为空，64新增OS pages保留；mapping
rollback、whole-request原生差分、actual JNI、full physical ABI/PAC、完整
signer、fresh/live与真实JVM仍未完成。见 [URL条件证据](evidence/vm9_request_url_condition_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_url_condition_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <URL-condition-evidence.json>
```

## 6.147 Request second VM caller and prefix（2026-10-13 Asia/Shanghai）

恢复actual `+287474` caller/prelude：SP=entrySP-1A00，bytecode `+102BB0`，
tables `+35EDF0/+35F3D0`，callback sentinel `+2884AC`，packed=SP+8，
descriptor=SP+10，top=SP+19D0。saved FP/LR/X28/X19与live TLS canary、
generic `+168324` prelude的全部32 backing words独立生成。

**20项新增原生对照、8项回滚检查**通过：14 caller frames（两基址、NULL/
跨页object、wide saved words、relocated stack、TLS/spill alias、patterned
stack），6 cold prefixes。前三次 `+2884B8 -> +167E54` decode复用既有owner；
prefix到 `+2884CC -> +2481AC`，native/Python全部32虚拟寄存器、callback
ledger/descriptor及三个decoded ranges一致。native output未作为输入。
2项native RED，旧caller/default outer AST与所有first nested/URL owners保留。

独立owning outer3900/+FE2D0，second VM **617/+1035D4** 到default StringObject
构造；cold standalone fixtures为650步。bounded prefix不发布页。原页差异
为空，64新增OS pages保留。second VM完整return、whole-request原生差分、
physical spills/PAC、mapping rollback、actual JNI、完整signer/fresh/live及
真实JVM仍未完成。见 [第二VM证据](evidence/vm9_request_287474_vm_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_287474_vm_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <second-VM-evidence.json>
```

## 6.148 Request second VM consumers（2026-10-13 Asia/Shanghai）

恢复第二VM的实际consumer：`+2884CC -> +2481AC/+2484B8` default/destroy
StringObject、`+288578 -> +248274` filled StringObject、`+2884D8 -> +347F60`
imported memcpy，以及 `+28858C -> +2A9280` local ARM64 copy。对象操作复用
既有owner。filled读取packed+16一个byte、+20一个W；tail wrappers不写packed
结果。local copy按实际scalar/vector读写、alignment及forward/backward loops
处理重叠；返回destination写packed+32的Q。imported memcpy的重叠仍拒绝。

**153项新增原生对照、12项回滚检查，另5项Python入口拒绝检查**通过。
152 component controls覆盖两基址、NULL allocation/payload、zero/negative-W
length、跨页、packed别名；local copy覆盖0～511 bytes、全部length阈值、
非对齐和前后重叠。malloc/free/memcpy/memset在component oracle中是明确的
import/provider边界；local copy执行原始ARM64指令。6项native RED通过。
错误target、缺页、late allocation/free、size bound及result store失败均不
发布页；入口拒绝还验证vm_module.B恢复。旧native分组未重跑，旧default/
decoder/outer AST以及已有caller/object/first VM/URL/allocator源码保留。

独立owning第二VM **617→8184/+1069D4**，下一 **+2885AC -> +28048C**。
真实入口设10000步上限；旧4000步default保持。1项owning bounded第二VM
原生差分执行614220 instructions，32虚拟寄存器、完整callback ledger及
declared decoded/object/payload/copy ranges一致，未使用native输出作输入。
outer仍3900/+FE2D0；原页差异为空，64新增OS pages保留。bounded页不发布。

这项证明止于第二VM的下一child入口；完整第二VM/whole outer request、
physical spills/PAC、mapping rollback、actual JNI、完整signer、fresh/live与
真实JVM仍未完成。未知nested helper的NULL callable尚待定位，不能归类为
JNI或补假返回。见 [second VM consumer证据](evidence/vm9_request_287474_consumers_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_287474_consumers_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <second-consumer-evidence.json>
```

## 6.149 Request child VM caller and prefix（2026-10-13 Asia/Shanghai）

恢复实际 `+2885AC -> +28048C` hidden-X8包装与child caller：wrapper保存LR、
按顺序读取packed X0/X8/W1/X2，child SP=wrapperSP-16；caller local=entrySP-F20。
packed=local，descriptor=local+20，top=local+EF0；bytecode `+A71D0`，tables
`+35D6B0/+35D970`，callback sentinel `+281414`。W1仅写低32位，保留padding；
TLS在saved FP/LR/X28/X19 spills之后读取，未定义backing words保留输入。

**26项新增原生对照、10项回滚检查**通过：20 caller frames（14 direct、6
actual wrappers），6 first-decode prefixes。两基址、wide W/saved words、NULL
hidden output、换栈、TLS/spill别名及patterned stack覆盖。全部caller frame/
32 backing words/五个VM参数，以及prefix全部32虚拟寄存器、callback ledger/
packed/decoded范围一致。2项native RED通过；wrapper错误target/缺页/带tag
返回地址，caller输入/TLS/frame/bytecode缺页等拒绝不发布页。

第二VM接入child bounded prefix；旧second VM default/decoder/consumer与所有
旧caller AST保留。新result子类携带child状态；parent与child页均未发布。
owning outer3900、second8184、child **290/+A7654**，下一 **+281434 -> +248274**
filled StringObject。原页差异为空，64新增OS pages保留。owning child完整原生
前缀、child return、whole-request/full physical ABI/PAC、mapping rollback、
actual JNI、完整signer及fresh/live/真实JVM仍未完成。
见 [child VM证据](evidence/vm9_request_28048c_vm_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_28048c_vm_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <child-VM-evidence.json>
```

## 6.150 Request child VM consumers（2026-10-13 Asia/Shanghai）

恢复child四个实际包装：`+281434 -> +248274` filled StringObject读取BYTE fill/
W length；`+281448 -> +347F20` memset读取BYTE fill/Q size；`+28145C -> +347F60`
memcpy；`+281470 -> +2A9280` local copy返回destination写packed+32 Q。
前三个tail wrappers不写packed result；填充构造复用既有对象owner，local copy
复用已验证的有序scalar/vector和对齐forward/backward loops。

**83项新增原生对照、13项回滚检查、5项Python入口拒绝检查**通过：82项实际
wrapper覆盖两基址、零长/负W/分配NULL、对象与packed别名、跨页、重叠方向、
自身复制及长copy；新增1项owning child有界原生差分。全部32虚拟寄存器、
完整11项已执行callback ledger、16声明内存范围及下一wrapper参数一致。
原生执行2039760条指令；Python child **19295/+ECE20**，下一
**+2814C8 -> +204E50**。8项native RED通过。

Owning parent传入实际allocate/free services与显式20000步child预算；standalone
4000默认及旧child decoder/default、second consumers和共享copy AST保留。
outer3900、second8184；原页差异为空，64新增OS pages保留。有界child差分
止于nested helper入口；完整child/second/request return、full physical ABI/PAC、
provider mapping rollback、actual JNI、完整signer及fresh/live/真实JVM仍未完成。
见 [child consumer证据](evidence/vm9_request_28048c_consumers_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_28048c_consumers_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <child-consumers-evidence.json>
```

## 6.151 Request environment helper VM callers and prefixes（2026-10-14 Asia/Shanghai）

恢复 `+204E50/+204ED4` 的实际caller、`+2814C8` 包装入口和已知decoder。
wrapper保存LR/X19、从packed读取target，传入helper时X19=packed；caller
仅保留local+8的W结果与padding，descriptor=local+10，callback `+2050E4`。
204E50：local=entrySP-500、top=local+4D0、bytecode `+8A040`、tables
`+34F170/+34F210`；204ED4：local=entrySP-3D0、top=local+3A0、bytecode
`+8A4F0`、tables `+34F250/+34F290`。TLS在saved-register spills后读取。

**33项新增原生对照、11项回滚检查**通过：24 caller frames（16 direct、
8 actual wrappers）、8 decoder prefixes、1 owning helper有界原生差分。
两基址、换栈、TLS/spill别名与patterned stack覆盖；全部caller frame/
32 backing words/五个VM参数及prefix全部32虚拟寄存器、完整callback ledger/
packed/decoded范围一致。2项native RED通过；输入/TLS/frame/bytecode/包装
target缺失时拒绝且不发布页。

Owning outer3900、second8184、child19295；helper **134/+8A254**，下一
**+205058 -> +26EDC4** 环境获取。204ED4独立前缀 **70/+8A604**，下一
`+205104` 导入getenv。新增owning helper原生差分2049560指令、5声明范围一致。
旧child decoder/default/consumer、caller及共享copy/object/JNI owners保留。
bounded helper/child/parent均不发布页；原页差异为空，64新增OS pages保留。
完整helper/child/second/request return、full physical ABI/PAC、mapping rollback、
actual JNI转换、完整signer及fresh/live/真实JVM仍未完成。
见 [environment helper证据](evidence/vm9_request_environment_vm_fresh_20261013.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_environment_vm_fresh_20261013.py --library "$env:TOMATO_LIBMETASEC" --group all --output <environment-helper-evidence.json>
```

## 6.152 Request environment acquisition callback（2026-10-14 Asia/Shanghai）

恢复实际 `+205058 -> +26EDC4` tail callback：packed+0 Q target、packed+8 Q
output pair，SP保持不变且不写packed result。复用既有环境获取owner、实际TLS、
显式GetEnv/AttachCurrentThread/DetachCurrentThread服务；没有合成JNI环境值。
outer请求的acquire_environment经second/child传入helper，保留默认decoder边界。

**17项新增原生对照、6项回滚检查、3项Python入口拒绝检查**通过：16项实际
wrapper覆盖两基址、warm/cold owner、cold TLS slots/destructor key、temporary
GetEnv、attach/detach、跨页pair与packed/pair别名；全部声明guest/image字节、
allocation/TLS/JavaVM顺序一致。2项native RED通过。新增1项owning helper
有界原生差分从actual2814C8开始，15707指令与Python **214/+8A394** 一致：
全部32虚拟寄存器、完整callback ledger、9声明范围、下一包装参数一致，
实际环境获取body执行且复用现有GetEnv provider，调用1次。

下一 **+205064 -> +248344** 字符串对象构造；outer3900、second8184、child19295。
旧helper/default/decoder、caller/shared copy及TLS/JNI owner AST保留。
helper/child/parent页未发布；原页差异为空，64新增OS pages保留。
provider外部效果和mapping rollback、完整helper/child/request return、full
physical ABI/PAC、actual URL/header JNI转换、完整signer及fresh/live/真实JVM
仍未完成。见 [environment acquisition证据](evidence/vm9_request_environment_acquisition_fresh_20261014.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_environment_acquisition_fresh_20261014.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <environment-acquisition-evidence.json>
```

## 6.153 Request environment StringObject callbacks（2026-10-14 Asia/Shanghai）

恢复实际 `+205064 -> +248344` 字符串构造与 `+205094 -> +2484B8` 析构
tail callbacks：target位于packed+0、object位于packed+8；构造再读packed+16
source。两者不写packed result，复用既有StringObject owner与显式allocate/free。
child把原有consumer_services传入helper，保留默认decoder/acquisition边界。

**39项新增原生对照、9项回滚、3项Python入口拒绝检查**通过。38项实际
wrapper覆盖两基址、NULL/empty/embedded-NUL、跨页object/source、packed/object/
source别名、allocation failure、自定义空描述符与free期间修改object；4项native
RED通过。新增1项owning helper有界差分从actual2814C8及独立构造的child页开始，
原生16746指令与Python **226/+8A3C4** 一致：全部32虚拟寄存器、完整callback
ledger、11声明范围与下一包装参数相同。原生tail transfer `205070 -> 248344`
及实际constructor入口已观察；复用原有GetEnv provider，调用1次。

下一 **+205074 -> +26E9E0** logger；owning路径尚未执行清理callback，析构仅有
独立实际wrapper对照。outer3900、second8184、child19295；原页差异为空，64新增
OS pages保留。旧默认/helper/decoder/acquisition AST与对象/TLS/JNI/logger/copy
owner保持。provider外部效果和mapping rollback、完整return/request、full physical
ABI/PAC、actual URL/header JNI转换、完整signer及fresh/live/真实JVM仍未完成。
见 [environment StringObject证据](evidence/vm9_request_environment_strings_fresh_20261014.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_environment_strings_fresh_20261014.py --library "$env:TOMATO_LIBMETASEC" --group all --output <environment-strings-evidence.json>
```

## 6.154 Request environment logger and cleanup（2026-10-14 Asia/Shanghai）

恢复实际 `+205074 -> +26E9E0` logger callback：target/object/format位于
packed+0/8/16 Q，callee SP=wrapper SP-16，返回值仅写packed+24 W，保留高位
padding。复用既有literal logger与显式property/syscall/errno服务。当前owning
helper的32字节format无转换、file sink已初始化且不可用，属于已支持分支。

**13项新增原生对照、9项回滚、3项Python入口拒绝检查**通过；2项native RED。
12项实际wrapper在两基址覆盖literal/empty/embedded-NUL、跨页format/packed与
packed-object别名，原始logger/formatter/sink实际执行，声明guest/global/output/
sink字段和packed W/padding一致。新增1项owning helper有界差分执行logger与
`+205094` 清理后到VM退出边界：Python **262/+8A4E8**、原生20798指令。
全部32虚拟寄存器、完整8 callback ledger、14声明范围与slot31指向2814D8一致；
原生停在16A974，尚未恢复helper调用者canary/寄存器恢复和实际返回。

outer3900、second8184、child19295；实际GetEnv provider调用1次，原页差异为空，
64新增OS pages保留。默认helper与acquisition/strings AST及logger/object/JNI/
copy owner保留。conversion/live sink、provider外部效果/mapping rollback、完整
helper/child/request return、actual URL/header JNI转换、full physical ABI/PAC、
完整signer与fresh/live/真实JVM仍未完成。见 [logger证据](evidence/vm9_request_environment_logger_fresh_20261014.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_environment_logger_fresh_20261014.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --group all --output <environment-logger-evidence.json>
```

## 6.155 Request environment helper return（2026-10-15 Asia/Shanghai）

恢复helper `+204EAC/+204F30` canary/restore与实际`+2814D8` wrapper返回：先读
helper packed W，再查TLS canary和恢复helper寄存器；随后wrapper通过恢复的X19
写packed+8 W，最后读取wrapper保存的LR/X19。结果与saved LR/X19/X28/FP发生
别名时仍保持此顺序。`+204E50` VM exit验证8A4E8/07C00791/slot31=2814D8；
显式continue选项提交helper页到child，默认helper边界保持。

**53项新增原生对照、8项回滚、4项Python入口拒绝检查**通过；4项native RED。
52项独立实际epilogue对照覆盖两helper/两基址、W宽度/padding、变更stack、
跨页result、保存槽与TLS别名；七个物理返回值及完整声明guest/stack范围一致。
新增1项owning helper实际返回原生20833指令，Python262步：32虚拟寄存器、
完整8 callback ledger/14 body范围一致；真实helper与wrapper尾部执行后，七个
物理返回值及完整wrapper packed范围一致，W0=0。不能仅以16AA4C作为停止点：
它也用于每次generic callback返回；新探针要求先观察2814E0 RET再到16AA4C。

child推进到 **19302/+ECE3C**，下一 **2814C8→204B80 JNI helper**；outer3900、
second8184。helper页仅提交到child，原页差异为空，64新增OS pages保留。既有
caller/helper/default/logger AST及对象/JNI/copy owner保持。仅owning204E50分支
完成返回；204ED4 body、完整child/second/request、full physical/PAC、实际URL/
header JNI转换、provider mapping rollback、完整signer及fresh/live/真实JVM仍
未完成。见 [helper return证据](evidence/vm9_request_environment_return_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_environment_return_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --group all --output <environment-return-evidence.json>
```

## 6.156 JNI static method availability（2026-10-15 Asia/Shanghai）

恢复实际 `+204B80` 的共享JNI语义：先按各自32位guard解码，再读原始缓存byte；
非零缓存直接返回，包含2与255。冷路径复用原环境获取，之后读取`+3DEEB8`
cached class，调用GetStaticMethodID；忽略method ID，仅按ExceptionCheck低byte
决定缓存0或1，异常时实际ExceptionClear。每次调用都重新读取JNI table。

**32项新增原生对照、10项回滚检查**通过；4项native RED。两基址覆盖raw cache、
冷/暖decode和TLS、临时GetEnv/attach/detach、NULL env/class/method、获取期间
class变化、异常1/255/256及调用间table变化。原生执行实际204B80、26EDC4及
26E190，完整guest payload/image、适用output pair和全部JavaVM/JNI效果一致。
NULL env由有限Detach服务清空TLS环境后真实获取得出。缓存命中时不宣称未初始化
physical scratch属于output pair。

finalizer内联逻辑提取到同一owner；保留NULL env拒绝及完整注册closure，包含
pair−C0 retained stack word。旧原生分组未重跑，旧owner与提取外AST保持。
child仍停19302/+ECE3C，2814C8→204B80 wrapper待接入。全物理栈/PAC、204ED4
body、完整child/second/request、URL/header JNI、mapping rollback、完整signer及
fresh/live/真实JVM未完成。见 [availability证据](evidence/vm9_jni_availability_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_availability_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <jni-availability-evidence.json>
```

## 6.157 JNI availability wrapper（2026-10-15 Asia/Shanghai）

恢复实际`2814C8→204B80` wrapper prologue、canary及epilogue。先保存wrapper
LR/X19再读target；保存helper寄存器后读TLS canary。返回时先恢复helper的
X20/X19、X22/X21、FP/LR，再写packed+8 W，最后读取wrapper LR/X19。

**26项新增原生对照、9项回滚检查**通过；4项native RED。两基址覆盖raw cache、
异常低byte、真实acquisition得出的NULL环境、冷TLS、JNI table变化、packed跨页
和结果别名到saved X20/X21/X22/FP。十个物理返回值、完整声明guest/image/frame/
packed bytes及JavaVM/JNI effects一致。未声明完整obfuscation/deeper stack。

私有request fixture已复用dispatch initialization owner与既有有限JNI合约，实际
执行注册并保留class；availability provider检查其global引用及原name/signature。
此项仅为Python初始化组合。child19302/+ECE3C仍待callback接入；完整child/second/
request、full physical/PAC、URL/header JNI、mapping、完整signer及fresh/live/JVM
未完成。见 [wrapper证据](evidence/vm9_request_jni_availability_wrapper_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_jni_availability_wrapper_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <availability-wrapper-evidence.json>
```

## 6.158 Child JNI availability callback（2026-10-15 Asia/Shanghai）

显式JNI service现由实际request入口经second传到child；`2814C8→204B80`
使用已验收wrapper，并记录完成的availability callback。默认不启用该项时，
既有request/child/helper/consumer AST保持。

**1项新增owning callback原生对照、6项request/child入口拒绝检查**通过；
1项接线前RED。原生实际执行375指令，从独立构造的callback前child页面开始，
使用已建立的dispatch初始化合约。十个物理返回值、996个声明范围、完整JNI
effects一致，复用1次显式GetEnv，W结果1。此项未证明整个child的原生执行或
完整physical caller ABI。

Python child从19302推进到 **19470/+ED084**，下一实际边界 **2814E4→26EDC4**
environment acquisition。outer3900/second8184不变。6项真实入口拒绝保留所有
页面与VM基址，未调用外部服务。callback只提交child事务；原页差异为空，64
新增OS pages保留。204ED4 body、完整child/second/request、full physical/PAC、
URL/header JNI、mapping、完整signer及fresh/live/JVM未完成。见
[child callback证据](evidence/vm9_request_jni_availability_child_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_jni_availability_child_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <child-availability-entry-evidence.json>
```

## 6.159 Child environment acquisition（2026-10-15 Asia/Shanghai）

`2814E4→26EDC4`复用既有environment acquisition owner；与205058的12字节
tail wrapper完全相同，无PC-relative指令。callback使用原SP，不额外减16，
不写packed return，不合成环境。helper返回与availability记录保持。

**17项新增原生/Python对照通过**：16项新地址、两个基址的冷/热TLS、临时
GetEnv/attach/detach、跨页及packed-pair别名；1项owning callback从独立构造
child页面执行160条原生指令，993声明范围、output pair/TLS owner及一次GetEnv
effects一致。旧205058分组未重跑；既有child与旧verifier默认语义由AST证明保留。

初次owning探针用了oracle默认线程指针，导致另一TLS owner和两次GetEnv；
传入实际child线程指针后对齐。此为fixture修正，生产逻辑未加补偿。
child从19470推进到 **19533/+ED358**，下一 **28155C→248344** 字符串构造。
原caller页面差异为空；64新增OS页和外部服务效果仍不回滚。完整child/second/
request、physical/PAC、204ED4 body、URL/header JNI、mapping、signer和fresh/live/
真实JVM尚未完成。见 [child environment证据](evidence/vm9_request_child_environment_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_child_environment_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <child-environment-evidence.json>
```

## 6.160 Child StringObject construction（2026-10-15 Asia/Shanghai）

`28155C→248344`的16字节tail wrapper与205064一致，无PC-relative指令。
既有StringObject callback只扩展该精确wrapper/target配对，复用原constructor，
不写packed return；旧helper构造/析构和verifier默认行为由AST证明保留。

**23项新增原生/Python对照、8项回滚检查通过**。22项新地址控制覆盖两个基址、
NULL/空/内嵌NUL、跨页、packed/object/source别名、分配失败及empty descriptor。
1项owning callback执行155条原生指令，包含实际匹配libc malloc且关闭分配stub；
1186个声明image/heap/packed/object/payload范围、返回payload指针及一次分配请求/
结果一致，使用实际child callback SP/线程指针。此项未证明完整physical ABI。

child从19533推进到 **19541/+ED378**，下一 **28156C→256A18** 配置值读取。
helper返回、availability和acquisition记录保持。原caller页面差异为空，64新增
OS页与外部effects仍不回滚。完整child/second/request、204ED4 body、physical/
PAC、URL/header JNI、mapping、signer及fresh/live/JVM尚未完成。见
[child strings证据](evidence/vm9_request_child_strings_fresh_20261015.json)。旧原生分组未重跑。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_child_strings_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <child-strings-evidence.json>
```

## 6.161 Child configuration u32 read（2026-10-15 Asia/Shanghai）

`28156C→256A18`恢复共享读锁中的配置u32读取，复用既有reader transition和
tree lookup。保留helper SP−50的24字节guard及padding，wrapper以SP−16调用，
只写packed+24的低W。缺失键/NULL value返回A985F；reader count恢复，shared
flag保留为1。writer/wait/concurrent及完整physical/PAC尚未覆盖。

**41项新增原生/Python对照、12项回滚检查通过**；另有2项原生RED和1项接线RED。
40项新控制涵盖两个基址、空树/NULL/缺失/零/高位/最大值、内嵌NUL、跨页及
packed结果/guard padding/status/reader count/shared flag别名，完整声明guest/
image/scope bytes和四次真实mutex操作一致。1项owning callback从独立构造的
child页面执行524条原生指令，1186范围、W结果、四次mutex操作一致，无allocator/
JNI服务。旧registry/child AST和共享owner保持，旧原生分组未重跑。

child从19541推进到 **19549/+ED398**，下一 **28158C→2484B8** 字符串析构。
已有helper/availability/acquisition/string记录保持。原caller页差异为空，64新增
OS页及外部effects不回滚。完整child/second/request、204ED4 body、physical/PAC、
URL/header JNI、mapping、signer及fresh/live/JVM尚未完成。见
[child registry read证据](evidence/vm9_request_child_registry_read_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_child_registry_read_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <child-registry-read-evidence.json>
```

## 6.162 Child StringObject cleanup and VM exit（2026-10-15 Asia/Shanghai）

`28158C→2484B8`复用既有StringObject析构owner。该tail wrapper的12字节与
205094完全一致，无PC-relative指令，也不创建额外stack frame。

**17项新增原生/Python对照、7项回滚检查通过**；另有1项接线RED。16项新控制
覆盖两个基址、NULL payload、跨页对象、object/packed/payload别名、free副作用和
自定义empty descriptor。1项owning callback执行152条原始指令，真实匹配libc
free调用一次，1186声明范围及free pointer一致。void析构的incidental X0不比较。
旧environment/child AST及StringObject/registry/JNI/allocator/oracle owner保持；
旧原生分组未重跑。

child从19549推进到 **19566/+ED3DC**，观察到VM exit指令07C00791，R31匹配
`image+2885C8`。新增记录只保存退出状态，**物理child caller/wrapper返回尚未恢复**，
second仍在8184步的child边界。已有helper/availability/acquisition/string/registry
记录保持。原caller页差异为空，64新增OS页及外部effects保留。完整child/second/
request、204ED4 body、physical/PAC、URL/header JNI、mapping、signer及fresh/live/
JVM尚未完成。见 [child cleanup证据](evidence/vm9_request_child_cleanup_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_child_cleanup_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <child-cleanup-evidence.json>
```

## 6.163 Child physical caller and wrapper return（2026-10-15 Asia/Shanghai）

恢复`2804F0`的live TLS canary检查、FP/LR/X28/X19恢复及`2885C8`的wrapper
LR/SP恢复。physical X0保持descriptor callback `image+281414`。child退出必须
匹配`ED3DC/07C00791/R31=image+2885C8`，明确继续返回时才向second事务提交页面。

**23项新增原生/Python对照、16项回滚检查通过**；另有2项原生RED和1项接线RED。
22项新控制执行实际16A974 selected-slot dispatch、172440 generic restore及child/
wrapper epilogue，覆盖两个基址、宽值/NULL保存字、栈重定位/模式及六种TLS与保存区
别名，七个物理返回值及声明范围一致。generic handler的四个W scratch outputs未
包含在声明范围。1项owning对照在构造的child页上执行10条返回指令，1184范围和
七个物理返回值一致，无allocator/JNI服务。旧caller/child/second AST和共享owner
保留；旧原生分组未重跑。完整physical ABI/PAC及whole-child native对照尚未完成。

child在19566步恢复父callback返回；second从8184推进到 **8251/+106AE0**，
下一 **2885D0→248344** 字符串构造。outer仍在3900步second边界，原caller页
差异为空，64新增OS页和外部effects保留。完整second/request、204ED4 body、
URL/header JNI、mapping、signer及fresh/live/JVM未完成。见
[child return证据](evidence/vm9_request_child_return_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_child_return_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <child-return-evidence.json>
```

## 6.164 Second VM StringObject construction（2026-10-15 Asia/Shanghai）

`2885D0→248344`的16字节tail wrapper与205064完全相同。复用既有StringObject
callback owner，second记录实际构造结果并保留child caller return。

**23项新增原生/Python对照、8项回滚检查通过**；另有1项接线RED。22项新地址
控制覆盖两个基址、NULL/空/内嵌NUL source、跨页、object/packed/source别名、
分配失败与自定义empty descriptor。1项owning callback执行155条原始指令，真实
匹配libc malloc调用一次，1186声明范围、payload pointer与分配请求/结果一致，
使用实际second callback SP/线程指针。旧environment/second AST和child return/
共享owner保留；旧原生分组未重跑。

second从8251推进到 **8261/+106B08**，下一 **2885E0→32A444** shared-reader
acquisition。child保持19566步和已恢复的物理返回；outer仍在3900步的second边界。
原caller页差异为空，64新增OS页与外部effects保留。完整second/request、204ED4
body、physical/PAC、URL/header JNI、mapping、signer及fresh/live/JVM未完成。见
[second strings证据](evidence/vm9_request_second_strings_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_strings_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <second-strings-evidence.json>
```

## 6.165 Second VM shared-reader acquisition（2026-10-15 Asia/Shanghai）

`2885E0→32A444`复用既有shared-reader及normal mutex owner，在锁内将
receiver+88的u32加一。返回count仅供内部记录，未伪造physical X0或packed结果。

**19项新增原生/Python对照、11项回滚检查通过**；另有2项原生RED和1项接线RED。
18项新控制覆盖两个基址、0/1/7/7FFFFFFD/7FFFFFFE reader count、process-shared
mutex、跨页及packed padding/receiver pointer别名；实际wrapper/helper与两次真实
匹配libc mutex操作在94指令内返回，全部声明guest bytes一致。1项owning对照
执行94指令、1185声明范围及两次mutex操作一致，使用实际callback SP/TP，无
allocator/JNI服务。旧second AST和reader/mutex/StringObject/child return等共享
owner保持，旧原生分组未重跑。physical guard/canary/PAC、并发/writer/wait未覆盖。

second推进到 **8279/+106B50**，下一 **288530→26C858** diagnostic scope entry。
child返回和second字符串保持；outer仍在3900步second边界，原caller页差异为空，
64新增OS页和外部effects保留。完整second/request、URL/header JNI、mapping、
signer及fresh/live/JVM未完成。见 [second reader证据](evidence/vm9_request_second_reader_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_reader_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <second-reader-evidence.json>
```

## 6.166 Second VM diagnostic scope entry（2026-10-15 Asia/Shanghai）

`288530→26C858`的16字节tail wrapper与288B30一致，复用既有token packed
adapter及diagnostic/recursive mutex owner。传递实际TP、allocator与可选tid/
observer；cold对照显式提供tid，实际构造的outer诊断全局已warm。

**13项新增原生/Python对照、7项回滚检查通过**；另有2项原生RED和1项接线RED。
12项新控制覆盖两个基址、cold zero/high-bit/cross-page、recursive nesting/
saturation及packed-object别名；声明guest/image/heap/packed bytes与有序分配/
mutex/gettid事件全部一致。1项owning对照执行110条原始指令，1185声明范围和
真实递归锁事件一致。warm table/entry无需分配；关闭malloc stub不代表本项执行
了malloc。非callable的direct allocator按既有TypeError拒绝且页面保持。旧second
AST及共享owner保持，旧原生分组未重跑。完整physical ABI/PAC/stack未覆盖。

second推进到 **8298/+106B9C**，下一 **288540→26C9D0** diagnostic scope
cleanup。child返回、second字符串/reader记录保持；原caller页差异为空，64新增
OS页及外部effects保留。完整second/request、URL/header JNI、mapping、signer及
fresh/live/JVM未完成。见 [second diagnostic证据](evidence/vm9_request_second_diagnostic_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_diagnostic_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <second-diagnostic-evidence.json>
```

## 6.167 Second VM diagnostic scope cleanup（2026-10-15 Asia/Shanghai）

`288540→26C9D0`的12字节tail wrapper与288B40一致，精确接入既有token packed
adapter和diagnostic leave/recursive unlock owner。scope进入和清理分别记录，
实际TP、allocator及可选observer保持。共享owner和旧second AST保持不变。

**21项新增原生/Python对照、9项回滚检查通过**；另有2项原生RED和1项接线RED。
20项新控制覆盖两个基址、普通/递归unlock、high-bit/cross-page scope、饱和/
非零saved result跳过、NULL entry、packed-object/tail别名及wrong-owner EPERM。
声明guest/image/heap/packed bytes和有序unlock事件全部一致。1项owning执行53条
原始指令，1185声明范围和真实递归锁事件一致，无分配。原生物理X0、完整stack/
canary/PAC不在本项合同内。旧原生分组未重跑。

second推进到 **8309/+106BC8**，下一 **2885E0→32A4FC** shared-reader release。
child返回、string/reader/diagnostic entry记录保持，独立记录1次scope leave。
原caller页差异为空，64新增OS页及外部effects保留。完整second/request、URL/header
JNI、mapping、signer及fresh/live/JVM未完成。见 [second diagnostic cleanup证据](evidence/vm9_request_second_diagnostic_cleanup_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_diagnostic_cleanup_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <second-diagnostic-cleanup-evidence.json>
```

## 6.168 Second VM shared-reader release（2026-10-15 Asia/Shanghai）

精确接入`2885E0→32A4FC`，复用既有shared-reader release/mutex owner。
reader acquisition、diagnostic entry/leave与child返回保持；release独立记录，
reader计数是内部metadata，不代表原生physical X0。

**19项新增原生/Python对照、12项回滚检查通过**；另有2项原生RED和1项接线RED。
18项新控制覆盖两个基址、1/3/7/near-limit/last-accepted reader、shared mutex、
cross-page与packed count/pointer别名；声明guest bytes及两次真实libc mutex一致。
12项拒绝检查包括zero/saturated/writer count与不支持的mutex状态，所有页面保持。
1项owning执行83条原始指令，1185声明范围及两次实际mutex一致，无分配/JNI。
完整stack/canary/PAC和physical ABI、writer/signal/wait/并发仍未覆盖。旧原生分组
未重跑，旧AST和共享owner保持。

second推进到 **8355/+106CA4**，下一 **2885EC→24880C** string/C-string比较。
释放后实际又执行一组scope进入/清理，最终各2次；初次探针错误假定各1次，修正
断言后通过，生产代码无需调整。child/string/acquisition/leave记录保持。原caller
页差异为空，64新增OS页和外部effects保留。完整second/request、URL/header JNI、
mapping、signer及fresh/live/JVM未完成。见 [second reader release证据](evidence/vm9_request_second_reader_release_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_reader_release_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <second-reader-release-evidence.json>
```

## 6.169 Second VM string equality（2026-10-15 Asia/Shanghai）

`2885EC→24880C`的36字节wrapper与2858EC一致，复用既有StringObject/C-string
比较owner。比较结束后仅写packed+24的boolean byte，保留+25起padding与内存
别名的读写顺序。原second行为、scope/reader/child与共享比较owner保持不变。

**27项新增原生/Python对照、9项回滚检查通过**；另有2项原生RED和1项接线RED。
26项新控制覆盖两个基址、空/相等/不等/短/长/embedded-NUL、负长度、NULL
source/payload、跨页payload/source以及result-source/packed-object别名。声明
guest bytes和返回byte/padding全部一致。原生NULL receiver会读未映射内存，
新适配器明确拒绝，纳入回滚检查；共享owner不变。初次新对照暴露该边界，最终
通过的组各计一次。1项owning执行32条原始指令，1185声明范围一致，无分配或
外部service。完整physical ABI/stack/canary/PAC仍未覆盖，旧原生分组未重跑。

second推进到 **8405/+106DBC**，下一 **28861C→2485A4** StringObject assignment。
实际scope entry/leave各3次，comparison/release各1次，既有记录保持。原caller页
差异为空，64新增OS页及外部effects保留。完整second/request、URL/header JNI、
mapping、signer及fresh/live/JVM未完成。见 [second equality证据](evidence/vm9_request_second_equality_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_equality_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <second-equality-evidence.json>
```

## 6.170 Second VM string assignment（2026-10-15 Asia/Shanghai）

恢复`28861C→2485A4` StringObject赋值。新语义owner复用既有reserve；原outer
entry仅透传已有reallocator。保留signed容量判断、分配后重读source length、NULL
destination payload清零capacity/length，以及memcpy后重读终止位置。native忽略
reserve失败返回，模型保持该效果；partial-overlap memcpy和负copy长度明确拒绝。
wrapper仅在packed+24写8字节destination pointer。旧AST/所有既有StringObject与
reserve owner保持，无替代allocator。

**37项新增原生/Python对照、13项回滚检查通过**；另有2项原生RED和1项接线RED。
36项新控制覆盖两个基址、empty/binary/shrink/same-object/payload/cross-page、
malloc与moving/in-place realloc、失败与rounded→exact fallback、全部reserve
失败、NULL payload、allocator/memcpy改变字段后的重读和packed-result别名。
初始capacity8/length7会选择malloc；修正length8后验证direct realloc，并显式检查
事件种类。最终新组各计一次。字节、有序allocator调用及其状态全部一致。
1项owning执行347原始指令，1185声明范围及实际libc malloc/free一致，allocator
stub关闭；不声称本项执行realloc。完整physical ABI/stack/canary/PAC仍未覆盖。

second推进到 **8416/+106DE8**，下一 **28863C→26CC8C** random getter。assignment/
comparison/release各1次，scope entry/leave各3次，child/string/acquisition保持。
原caller页差异为空，64新增OS页及外部effects保留。完整second/request、URL/header
JNI、mapping、signer及fresh/live/JVM未完成。见 [second assignment证据](evidence/vm9_request_second_assignment_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_assignment_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --output <second-assignment-evidence.json>
```

## 6.171 Second VM random callback（2026-10-15 Asia/Shanghai）

恢复`28863C→26CC8C` random回调，复用未修改的request random owner。28字节
wrapper与已恢复的token wrapper逐字节相同，W0写packed+8，保留padding。outer
entry仅透传已有random services；旧second AST、StringObject/reserve和random
owners保持。

**17项新增原生/Python对照、11项回滚检查通过**；另有2项原生RED、1项接线RED。
16项组件控制覆盖两个基址、cold/warm、type-zero、wide seconds、syscall失败/
errno、guard第二字节和跨页packed结果，所有声明字节及时间调用一致。
1项owning执行126原始指令，1191范围及实际libc随机状态一致；直接观察两次mutex
export调用。owning为warm路径，没有时间syscall，也没有allocation/JNI服务。
首次探针重做重定位误覆盖四个实时random指针；保留独立构造输入后差异消失。
libc内部mutex调用不进入导入事件表，改为观察实际符号入口；未用原生输出修补输入。

second推进到 **8532/+106FFC**，下一 **288658→257804**。reader acquire/release
各3次，scope entry/leave各5次，string/comparison/assignment/random各1次，child
return保持。原caller页无差异，64新增OS页及外部effects保留。完整physical ABI/
stack/PAC、second/request、URL/header JNI、mapping、signer及fresh/live/JVM
仍未完成。见 [second random证据](evidence/vm9_request_second_random_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_random_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <second-random-evidence.json>
```

## 6.172 Second VM reference getter（2026-10-15 Asia/Shanghai）

恢复`288658→257804`隐藏X8输出的引用getter。新registry helper复用已有shared
reader和`copy_scoped_string_reference`，保留`15F580`的诊断锁、清零后重读及引用
计数递增。mutex来自receiver+100，reference来自receiver+D8。wrapper先读取
target/X8/X0，不写packed result。旧second/registry AST、所有共享owners和outer
entry保持。

**33项新增原生/Python对照、13项回滚检查通过**；另有2项原生RED、1项接线RED。
32项组件控制覆盖两个基址、cold/warm、zero/wrap/NULL计数、NULL pointer、既有
reader、shared mutex、跨页、same/partial pair overlap以及packed/counter/mutex
pointer输出别名。所有声明字节、有序allocation和诊断锁effects一致。
outer release会物理复用已结束的copy frame，因此在`257850`比较诊断有效字段，
最终另比outer scope；dead register slots及诊断+12物理padding未比较。初始跨页
fixture误占TLS，最终使用独立输出范围；owning探针函数重名已修正。

1项owning执行 **429原始指令/1186声明范围**，实际shared mutex四次transition和
诊断effects一致，allocator stub关闭但本项没有分配，不声称执行allocator。
second到 **8539/+107018**，下一 **288670→257880**；reference getter1次，其余
child/string/reader/scope/equality/assignment/random记录保持。原caller页无差异，
64新增OS页保留。完整physical ABI/stack/PAC、second/request、URL/header JNI、
mapping、signer及fresh/live/JVM未完成。见 [second reference getter证据](evidence/vm9_request_second_reference_getter_fresh_20261015.json)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_second_reference_getter_fresh_20261015.py --library "$env:TOMATO_LIBMETASEC" --libc <matching-libc.so> --output <second-reference-getter-evidence.json>
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
