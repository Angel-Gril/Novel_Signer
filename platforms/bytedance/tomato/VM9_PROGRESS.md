# Current VM9 progress checkpoint

## 2026-10-09 Asia/Shanghai：data expression frame、u32 修补与树节点删除

同一 owner 恢复 slots `+148/+150 → +31e4a4/+31e4f4`：**148 个原生/Python
对照、36 个保护/回滚**，两个基址各 74 项，全部合成。三个修改前 RED 分别为
两个回调不支持，以及合法 u32 tree payload 在原生可清理、模型却按八字节拒绝。
相同最小对照随后 GREEN；共享树 payload 检查宽度改为四字节，原 ownership
规则保留。146 项执行实际 vtable callback，2 项直接执行 cleanup。

Begin 忽略 index，指向最后记录的内嵌 type，保存原始指令 buffer 的 u32 字节
长度到 record+88 低字，清空当前 frame 数量并追加 16 字节 image 常量/sentinel。
End 忽略 index，按 frame_count-1 查找树 key；逐个 u32 byte offset 写入每次修补
前的 raw 字节长度，必要时清零扩容。随后更新 begin/count，以原生 libc++ 布局
删除并平衡树，free payload/node，最后弹出 frame。未找到 key 时只弹出。

核对 guest 前 0xa000 字节（含 padding 和删除节点遗留链接）、自然返回/SP、
分配/析构/free 顺序及每个效果时的 owner 内容；另有独立 frame/raw 修补断言。
左右旋转、红 sibling、近/远子节点、双子节点 successor、逐个删除至空、未对齐/
重复 patch、连续扩容、create/word/cleanup 组合均通过。非法 frames、树元数据/
键/颜色/黑高、u32 offset 越界、分配缺页/别名和晚期重复分配全部回滚。
旧 AST **308/54**、data reserve/析构 **176/30**、data create **148/105** 和
payload **104 AST / 34 ABI / 30 回滚** 重新通过，四份 JSON 与旧公开证据
逐字节一致；parser owner 行为未改。

Detached callback、纯地址计划、逻辑 free 仍为边界。其余 expression/AST callbacks、
attached parser/wrapper、parse/root、完整 reader/factory/bootstrap、独立 signer
与线上矩阵尚未完成。见
[expression 证据](evidence/vm9_alternative_ast_data_expression_fresh_20261009.json)与
[第 6.16 节报告](REQUEST_JNI_STARTUP_WORKERS.md#616-data-expression-frameu32-修补与树节点删除2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：data payload 写入与 parser length 参数修复

同一 owner 恢复 slot `+158 → +31e53c` 并补齐 section 11 的 length 参数：
**104 个 AST 原生/Python 对照、34 个 parser 参数对照、30 个保护/回滚**。
两个基址各 52/17 项；含 6 项实际 ELF payload、2 项实际 section 输入，均由
独立 Python XOR/envelope/LEB 提取，不使用 native 输入快照。修改前分别取得
原生参数与模型不一致、Python 不支持 payload callback 的两个 RED，随后 GREEN。

Index 忽略，length 使用完整 u64；零长度保留已有 payload，不读 source，也不要求
活动 data record，但仍执行 callback/ownership 预检。非零写入最后一条 176 字节
记录，扩容至 max(length,capacity*2)，清零新增长度区、复制旧内容、发布 header、
free 旧块，再复制 payload。Source 必须映射、有界、与 owned storage 分离，
并保留至分配完成；非法参数、长度/预算、缺页、别名与分配计划全部回滚。
实际 payload lengths 3632/352/0；guest 内容、自然返回/SP、效果顺序与每个效果
时的 owner 内容一致，另有独立 payload 内容/长度断言。

旧 AST **308/54**、data reserve/析构 **176/30**、data create **148/105**、
segments **450/33** 与 **16** 个 abort 边界重新通过，四份 JSON 逐字节一致。
两个基址的全部实际 section custom 组合记录亦与旧证据一致。旧证据未捕获 +158
第三项；新原生 oracle 明确核对 index/pointer/length 和已推进 cursor。
共享 ownership 方法未改；parser 行为仅补 length，不代表接入实际 AST callbacks。

本批结束时 detached callback、纯地址分配和逻辑 free 仍为边界；+148/+150 expression/tree、
其它 AST callbacks、attached parser/wrapper、parse/root、完整 reader/factory/
bootstrap、独立 signer 与线上验收仍未完成。见
[payload 证据](evidence/vm9_alternative_ast_data_payload_fresh_20261009.json)与
[第 6.15 节报告](REQUEST_JNI_STARTUP_WORKERS.md#615-data-payload-写入与-parser-length-参数修复2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：data record 创建与追加

同一 AST owner 恢复 slot `+140 → +31e1d4`：**148 个原生/Python 对照、
105 个保护/回滚**，两个基址各 74 项，全部合成。实际 vtable、构造、复制、
扩容和析构自然执行；guest 前 0xa000 字节（含 padding）、效果顺序和每个效果
时的根 owner 内容一致。独立字段断言核对新记录布局。空容器创建在 owner 修改前
原生正常返回而 Python 拒绝，RED 后实现，三种基础场景 GREEN。

Index 忽略；memory_index/flags 截断至 u32，分类为 flags 低两位等于 3 时的 2，
否则 flags&1。+18 高字保存 memory_index；内嵌 type index 为零、params 空，
results 为一个 owned u64 -1；+88 为 0x00000000ffffffff，其余标量与 vectors 清零。
结果依次复制到原始/临时 type/临时 data/最终 record 四块 8 字节存储；第一块在
临时 data 创建前释放，后两块在 append 完成后倒序释放，不额外生成临时 destroy。
满容量扩至 max(size+1,capacity*2)，搬移旧 ownership，发布后倒序析构并 free 旧块。

flags 0..7/u32 截断、spare/full、丰富/空/混合 ownership、连续创建、reserve 组合、
最终析构与保留 data 的 callback cleanup 均通过。所有分配边界的别名/缺页/重复地址
检查包括晚期失败，全页不变。旧 AST **308/54**、data **176/30** 重新通过，
两份 JSON 与既有证据逐字节一致；共享 ownership 方法和 parser owner 未改。

Detached callback、纯地址分配与逻辑 free 仍为边界。其它 AST callbacks、attached
parser/wrapper、parse/root、完整 reader/factory/bootstrap、独立 signer 和线上验收
未完成。本批当时发现 slot +158 的实际 ABI 有第三个 length 参数，旧 status parser
省略它；后续独立 RED 与修复见第 6.15 节，创建证据仅描述本批范围。见
[创建证据](evidence/vm9_alternative_ast_data_create_fresh_20261009.json)与
[第 6.14 节报告](REQUEST_JNI_STARTUP_WORKERS.md#614-data-record-创建与追加2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：data record 容量预留、搬移与析构

同一 AST owner 恢复 slot `+160 → +31e5b4 → +320fb0` 和 176 字节记录
`+2cc1ec` 非 deleting 析构：**176 个原生/Python 对照、30 个保护/回滚**，
两个基址各 88 项，全部合成。原生实际 vtable 与析构入口自然执行并恢复 SP；
guest 内容（含 padding）、分配/析构/free 顺序、每个副作用的 owner 状态均一致。
两个原生成功/Python 缺失的行为在 owner 修改前 RED，修改后 GREEN。

`output+f0` 仅预留容量，不增加 size。扩容反向转移记录的 00/30/48/70/98
五组 vector，清零源端指针，复制标量并保留目标 padding；发布 header 后倒序
析构旧记录并释放旧块。实际析构倒序释放 +98 的 56 字节子记录 payload 与列表，
随后 +70 locals、内嵌 type 的 results/params、+00 byte payload；不释放记录自身。
Data storage 加入共享 ownership graph，子记录 +10 为 owned u64 vector，其余
字段按实际复制路径视为标量；节点/字节界限、共享指针、重叠、缺页与错误绑定均回滚。
审查复现非空零容量指针未映射却生成 free 的 RED；共用 claim 现要求该地址映射。
修复后完整重跑 176/30，全部原生正向记录与首次完整运行一致。旧 AST 308/54、
type/vector 102/372 与 34 个回滚、section 202 与 12 个回滚通过；三份回归 JSON
与既有证据逐字节一致，未涉及的 owner 函数与旧 AST 方法保持一致。

Detached callback、纯地址分配计划和仅逻辑 free 的边界保持。Data record 创建、
其它 AST callback、attached parser/wrapper、parse/root、完整 reader/factory/B VM/
bootstrap、独立 signer 和线上矩阵仍未完成。见
[data 证据](evidence/vm9_alternative_ast_data_fresh_20261009.json)与
[第 6.13 节报告](REQUEST_JNI_STARTUP_WORKERS.md#613-data-record-容量预留搬移与析构2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：实际 AST callback 与临时清理

同一 owner 增加五个实际 callback 的独立有界入口和对应析构/清理：
**308 个原生/Python 对照、54 个保护/回滚**；276 项合成、32 项使用独立
Python XOR 后的真实 ELF 类型输入。两个基址各 154 项，实际 vtable 与函数
执行；全部 guest 对象/输入/分配内容（含 padding）、分配/析构/free 顺序，
以及每个副作用时的容器内存均一致。修改前四个状态服务 RED，修改后 GREEN；
非法 slot、attached parser 和未恢复输出容器三个保护也先复现后收紧。
最终审查另复现两个错误 callback slot 绑定，再补 relocation 拒绝；完整 308 项
重跑通过。旧 type/vector 102/372 个对照与 34 个回滚、section 202 个对照与
12 个回滚全部通过，两份新回归 JSON 与既有证据逐字节一致。

Slots +18/+20/+a0/+b0/+168 分别预留 type 容量、追加带两组 owned u64 vector
的 64 字节 type node、写入 u32 start、写入 local group 数量并清零 +7c、追加原始
u32 字。预留容量不增加 size；type entry 忽略 index，先复制到两个临时 vector，
再复制到 owned node，最后释放临时 results/params。扩容反向移动旧节点，发布
新 header 后析构旧节点并 free。`+321260` 先释放 results，再释放 params。
`+31b458` 按 e0/c8/b0/98/80 倒序析构五组节点，随后对 68/50 两棵树做
left/right/payload/node 后序释放，最后清理 +30 buffer。

这些入口要求 detached callback（+8 为零）和空的未恢复输出容器。分配为
显式纯计划，free 为逻辑效果，不 poison/unmap；节点/字节预算、未知 vtable、
缺页和存储重叠均拒绝并全页回滚。未接入 section parser，未比较整个 native
stack/TLS，未发布实际类型内容或原生快照。完整 AST/callback、wrapper
`+31b360`、parse/root、reader/factory/B VM/bootstrap、独立 signer 和线上矩阵
仍未完成。见 [AST 证据](evidence/vm9_alternative_ast_fresh_20261009.json)与
[第 6.12 节报告](REQUEST_JNI_STARTUP_WORKERS.md#612-实际-ast-callback-与临时清理2026-10-09-asiashanghai)。

## 2026-10-08 UTC：B section 0 特殊 custom 元数据

同一 reader owner 恢复 dylink/dylink.0/linking/target_features/reloc 前缀：
**860 个原生/Python 对照、32 个保护/回滚**；850 项合成、10 项含真实 ELF custom。
三个实际 custom payload 为 1758/3240/177 字节；两个基址的全部实际 section
组合均正常返回，匹配 55369 次 callback、4 次计划分配和 2 次逻辑 free。
Import counts 保持 18/0/0/22，121 个 body、54533 个原始指令字和三段 data 均一致。

默认关闭的 `enable_special_custom_sections` 要求独立八字节
`custom_scratch_address`；`max_custom_records=4096` 汇总每个 custom 的子段、
列表条目与内部数对。已知子段严格消费，未知 tag 跳过；解析失败恢复临时 limit
及原 custom flag。名称匹配按原生顺序先判断长度 6/8 的 dylink，再判断 reloc
前缀，最后处理长度 7/15 的 linking/target_features，避免额外懒解码写入。
保护现有/后续 type storage、其他 scratch、decoder 区、opcode 表指针和启用的
expression opcode 表。五类最小输入修改前 RED、修改后 GREEN；opcode 表及
GOT 指针重叠也先复现再修复。
94 项对照到达 linking 的符号 mask 再检查；本批未到达 abort，不宣称全局不可达。

旧 globals/code/segments/sections/import limits 回归全部通过，五份新 JSON 与
既有证据逐字节一致；语法、隐私、链接、CLI 与十文件范围检查通过。

Special custom 不发送 AST callback。实际 AST/callback/cleanup、指令执行、
parse/root、完整 reader/factory/B VM/bootstrap、独立 signer 与线上矩阵仍未完成。
见 [custom 证据](evidence/vm9_alternative_reader_custom_fresh_20261008.json)与
[第 6.11 节报告](REQUEST_JNI_STARTUP_WORKERS.md#611-section-0-特殊-custom-元数据2026-10-08-utc)。

## 2026-10-08 UTC：B section 9/11 与独立 expression helper

同一 owner 独立启用 section 9 空元素列表和 section 11 data：**450 个原生/Python
对照、33 个保护/回滚、16 个 abort 边界检查**；444 项合成、6 项含真实 ELF data。
实际 section 11 有 4001 字节、3 段，payload lengths 3632/352/0；11、12/11、
1/2/3/6/7/12/10/11 每基址 18/19/55369 次 callback。完整组合保持 4 次计划分配、
2 次逻辑 free 和 import counts 18/0/0/22。

`+0x3215f0` 独立于 global initializer：kind 0 发 +f0 后继续；常量只发送 callback，
不写结果字。两个 section 开关默认关闭，八字节 `expression_scratch_address` 与
input/state、其他 scratch、现有及后续 type storage 分离；每个 expression 有独立
预算。Section 9 非空列表到达 native abort，模型明确拒绝并回滚；样本无实际
section 9，相关真实输入对照为 0。本批旧 oracle 只捕获 +158 的 index/pointer，
遗漏实际第三项 length；修复和新增参数对照见第 6.15 节。

修改前最小失败对照、完整 callback 参数/状态/input 和回滚均验证；未使用 native
输入快照，未执行实际 AST callback 或指令。旧 globals/code/sections/import limits
回归全部通过，四份 JSON 与既有证据逐字节一致；语法/隐私/链接和 CLI 检查通过。
下一处为 special custom、实际 AST/callback/
cleanup 与 parse/root；完整 reader/factory/B VM/bootstrap、独立 signer、线上矩阵
仍未完成。见 [segment 证据](evidence/vm9_alternative_reader_segments_fresh_20261008.json)
与[第 6.10 节报告](REQUEST_JNI_STARTUP_WORKERS.md#610-section-911-与独立-expression-helper2026-10-08-utc)。

## 2026-10-08 UTC：B section 10 元数据、局部类型与指令字

同一 owner 通过独立 `enable_code_section=True` 恢复 section 10 `+0x323ca8`：
**228 个原生/Python 对照、15 个保护/回滚**；222 项合成，6 项包含独立 Python
XOR 后的真实 ELF code。实际 payload 218682 字节、121 个 body、54533 个原始
指令字；10、3/10、1/2/3/6/7/12/10 组合每基址 54896/55017/55351 次 callback。
完整选取组合有 4 次计划分配、2 次逻辑 free，import counts 为 18/0/0/22。

原始指令纠正了私有反编译把 section 10 并入 section 9 的错误。Body count
写入 state 并要求匹配 function count；group count、body metadata、local groups、
raw words、body end callbacks 和部分状态均对照。Remaining body bytes 是声明
长度减头部字节数，uint32 回绕，随后不再扣 local groups。第二个 u32 的业务含义
未知。样本 local groups 为零，非空 groups 用合成输入验证。

Raw read 受 section limit 限制，可能跨过 body end 后失败；不足四字节时 native
重复发送零、cursor 不推进。独立 `max_code_words` 对整个 section 的所有字回调
计数，含重试，超限回滚。完整 supplied input、guest/rank state、callback 参数、
计数/type cells/vector effects 均核对。只在含 section 6 的组合启用 global 合成
local 初值，不发布真实 code/metadata/names，不比较整个 stack/TLS。

旧 global、type/vector、section 和 import limits 回归重新通过，四份 JSON 与
旧证据逐字节一致。修改前先取得空 section/单字 body 的失败对照；无子代理。
Section 9/11、special custom、实际 AST/callback/cleanup、指令执行、parse/root、
完整 reader/factory/B VM/bootstrap、独立 signer 与线上矩阵仍未完成。见
[code 证据](evidence/vm9_alternative_reader_code_fresh_20261008.json)与
[第 6.9 节报告](REQUEST_JNI_STARTUP_WORKERS.md#69-section-10-元数据局部类型与指令字读取2026-10-08-utc)。

## 2026-10-08 UTC：B signed i64、section 6 与初始化表达式

同一 owner 恢复 `read_reader_varint64`（`+0x324f6c`）：**1480 个原生/Python
对照、10 个保护/回滚**。第十终止字节只接受 0/127，所有失败不访问/修改输出。
两种九字节前缀的全部 256 个第十字节在两个基址核对，冗余、别名和截断通过。

独立 `enable_global_section=True` 与 16 字节 `global_scratch_address` 恢复
section 6 `+0x323464` 和表达式 `+0x32365c`：**390 个对照、26 个保护/回滚**。
380 项纯合成，10 项含独立 Python XOR 后的真实 global section（133 字节、
22 项，均为 i64 常量）。单独与 2/6、2/3/6/7/12、1/2/3/6/7/12 组合分别
155/195/438/455 次 callback；加合成 section 4/5 后 459 次。完整选取组合有
4 次计划分配、2 次逻辑 free，import counts 保持 18/0/0/22。

操作码 kind 跟随 GOT 指针，重定位与条目覆写已对照；i32/f32 bits 零扩展，
end-only 保留 caller local 高四字节，支持连续常量并要求 end。原生 local 的
八字节初值是明确注入的合成 ABI 输入，不证明自然栈初始化，不比较整个 stack/TLS。
global/import/section 4/5 开关独立，scratch 与 input/state、已有及后续 type storage
分离。旧 section、两类 imports、section 4/5、vector/type 全部重新通过，五份
JSON 与旧证据逐字节一致。最小失败对照在生产修改前取得；无子代理。

剩余 instruction/data/special custom、实际 AST/callback/cleanup、parse/root、
完整 reader/factory/B VM/bootstrap、独立 signer 与线上矩阵仍未完成。见
[i64 证据](evidence/vm9_alternative_reader_varint64_fresh_20261008.json)、
[global 证据](evidence/vm9_alternative_reader_globals_fresh_20261008.json)与
[第 6.8 节报告](REQUEST_JNI_STARTUP_WORKERS.md#68-有符号-i64-与-section-6-初始化表达式2026-10-08-utc)。

## 2026-10-08 UTC：B section 4/5 table/memory 定义

同一 owner 通过独立 `enable_table_memory_sections=True` 与已有 32 字节
`import_scratch_address` 恢复 section 4 `+0x3231e4`、section 5 `+0x3232dc`。
私有交接曾错把已恢复的 section 3 `+0x323108` 当作 section 4，本轮从原生
dispatcher 修正。数量 slots `+0x58/+0x68`，条目 slots `+0x60/+0x70`；条目索引
加对应 import count 并按 uint32 回绕，定义本身不递增 import counts。空定义仍
发送数量回调。table/memory 复用同一 descriptor 解析，回调冻结 19 字节 limits。

两个基址通过 **266 个 native/Python 对照、18 个拒绝/回滚**。260 项纯合成，
6 项为 fresh ELF function/global 输入加合成定义；样本没有真实 section 4/5，
相关真实输入对照为 **0**。完整选取组合每基址 306 次回调、4 次计划分配、
2 次逻辑 free，import counts 保持 18/0/0/22。仅转换临时 descriptor 指针，
未比较整个 stack/TLS；callbacks、allocator/free 仍为显式服务。

启用定义与启用 import 独立，旧 API 默认拒绝仍经过检查。旧 section、
function/global import、table/memory import、vector/type 回归全部
通过，四份 JSON 与旧证据逐字节一致。下一处为 section 6
`+0x323464`，随后其余 instruction/data/custom 与实际 AST、parse/root。完整
reader/factory/B VM/bootstrap、独立 signer 与线上矩阵仍未完成。见
[定义证据](evidence/vm9_alternative_reader_table_memory_sections_fresh_20261008.json)与
[第 6.7 节报告](REQUEST_JNI_STARTUP_WORKERS.md#67-section-45-tablememory-定义2026-10-08-utc)。

## 2026-10-08 UTC：B u64 与 table/memory import

同一 owner 新增 `read_reader_varuint64`，恢复 `+0x3249b0`：**1438 个 native/Python
对照、10 个回滚**。两个基址各 719 项，第十字节全 256 值分别在 `80`/`ff` 前缀下
核对；终止字节大于 1 不访问输出，缺少终止字节则清零输出。冗余编码接受。

section 2 table/memory 又通过 **234 个对照、15 个拒绝/回滚**，涵盖四类混排、
计数回绕、回调失败和部分状态。需显式 `enable_table_memory_imports=True` 与
已映射、对齐、不重叠的 32 字节 `import_scratch_address`。回调时 19 字节 limits
内容、参数、名称、cursor/end、四类计数和 type cells 一致；只将原生临时 descriptor
指针转换为模型工作区指针，未比较整个原生 stack/TLS。`import_limits` 从暂存页
读取并提供不可变字段值，旧 API 默认和以前的回滚控制保持。

其中 228 项是合成输入，6 项是 fresh ELF function/global 输入加合成 table/memory；
实际 ELF table/memory import 输入为 0。完整选取的 1/2/3/7/12 组合每基址 302 次
回调、4 次计划分配、2 次逻辑 free。旧 section、function/global import、vector/type
均重新通过，JSON 逐字节一致。实际 AST、真实 allocator 和完整 reader 尚未恢复。
下一处为 section 4/5/6 等剩余 handler、special custom、实际 node/callback/cleanup，
随后 parse/root 构建；完整 signer 和线上矩阵仍未完成。
见 [u64 证据](evidence/vm9_alternative_reader_varuint64_fresh_20261008.json)、
[import limits 证据](evidence/vm9_alternative_reader_import_limits_fresh_20261008.json)与
[第 6.6 节报告](REQUEST_JNI_STARTUP_WORKERS.md#66-u64-与-tablememory-import2026-10-08-utc)。

## 2026-10-08 UTC：B section 2 函数与全局变量 import

`run_reader_sections` 通过显式 `enable_function_global_imports=True` 恢复 section 2
`+0x322cf8` 的 kind 0 function 与 kind 3 global。两个基址共 **254 个 native/Python
对照、14 个拒绝/回滚**，其中 248 项合成输入、6 项 fresh ELF 独立 Python XOR 输入。
真实 import payload 为 316 bytes、40 项：18 个函数、22 个全局变量。1/2/3/7/12
组合每基址 300 次回调一致，section 3 使用已更新的 imported function count。

回调参数、cursor/end、名称字节、四种 import count 与 type cells，以及 guest 输入/
输出区的 0xA000 字节和 rank globals 一致。计数只在对应 callback 成功后递增，
按 uint32 回绕；普通解析失败保留部分状态。全局变量回调第九参数在 native caller
栈上，`+0x323024` 仅写一个 bool 字节，填充字节不属于参数。未恢复分支/guard
全页回滚，旧 section 与 type/vector 批次均通过且 JSON 逐字节一致。

旧 API 默认仍拒绝 import，table/memory 两类仍未恢复；没有执行实际 AST callback。
下一处为 table helper `+0x321844`、memory 所需 u64 `+0x3249b0`，再恢复其余
handler、special custom、实际 AST/callback/cleanup 和 parse/root 构建。完整 reader/
factory/B VM/bootstrap、fresh 签名与线上矩阵仍未完成。
见 [import 证据](evidence/vm9_alternative_reader_imports_fresh_20261008.json)与
[第 6.5 节报告](REQUEST_JNI_STARTUP_WORKERS.md#65-section-2-函数与全局变量-import2026-10-08-utc)。

## 2026-10-08 UTC：B type vector 与 section 1

同一 owner 新增 `grow_reader_word_vector`，并通过显式 `vector_allocate` 将 section 1
接入 `run_reader_sections`。两个基址共 **102 个 vector 对照、372 个 type 对照、34 个
拒绝/回滚**。type 对照为 368 项合成输入和 4 项独立 Python XOR 后的实际 ELF 输入；
真实 type section 含 16 个定义，分别及与 3/7/12 组合时通过，组合每基址 260 次回调。
fixture imported-count 显式为 0，实际 AST callbacks 尚未执行。

扩容保留 native 的新增单元清零、容量加倍/满足新增长度、旧元素复制、指针先发布后
记录旧块 free 的顺序；收缩只修改 end，空 vector 的 callback 指针为 NULL。
type 值接受 -5..-1 和 -17..-16，存为符号扩展的 64-bit word；-21 前缀消费第二个
i32 后拒绝。所有回调参数、cursor/end、当时的 type cells、分配/free 效果与顺序、
guest 输入/输出区的 0xA000 字节和 rank globals 一致，不使用 native 快照。

分配地址和 free 是显式受控服务；没有执行真实 allocator boot、实际 AST callbacks
或完整 wrapper cleanup。普通解析失败保留部分状态，未恢复分支/guard 全页回滚。
下一处为 section 2 `+0x322cf8` import；其余 handler、special custom、AST/factory/B VM、
完整 bootstrap、Medusa/fresh 签名/线上矩阵与最终下载产品仍未完成。
见 [type/vector 证据](evidence/vm9_alternative_reader_types_fresh_20261008.json)与
[第 6.4 节报告](REQUEST_JNI_STARTUP_WORKERS.md#64-type-vector-与-section-12026-10-08-utc)。

## 2026-10-08 UTC：B reader 的有符号 i32 读取

`read_reader_varint32` 独立恢复 `+0x324e0c`，两个基址各 668 项、共 1336 个
native/Python 对照及 10 个拒绝/回滚通过。全部 256 种第五字节分别核对：第五
终止字节只接受 `0x00..0x07` 或 `0x78..0x7f`。冗余编码接受，截断、连续五个
continuation 或非法第五字节返回 0 且保留输出；30 个原生控制使用 NULL、未映射
或超出 word 边界的未使用输出地址。成功读取写入 int32，输入/输出重叠与跨页通过。
自然返回和 guest 输入/输出区的 0xA000 字节一致，输入为合成字节，不使用 native 快照。

这只是 type/import handler 的读取依赖。section 1 type vector、vector resize
`+0x324540`、section 2 import、实际 AST 和完整 reader/factory/bootstrap 仍未恢复。
下一步先恢复 vector resize 与 section 1，再恢复 section 2。
见 [i32 证据](evidence/vm9_alternative_reader_varint32_fresh_20261008.json)与
[第 6.3 节报告](REQUEST_JNI_STARTUP_WORKERS.md#63-有符号-i32-读取2026-10-08-utc)。

## 2026-10-08 UTC：B section 状态与部分 handler

`run_reader_sections` 恢复 core `+0x324188` 的 envelope/排序/重复/精确消费和失败状态，
以及通用 custom、function index、export、start index、data count。两个基址共
**202 个 native/Python 对照、12 个拒绝回滚**；194 项合成输入，8 项独立 Python XOR
后的实际 ELF section 输入。全 guest/global 写入和 callback 参数/时机一致，真实
section 3/7 分别包含 121 个索引/导出项；fixture imported-count 仍显式为 0。

section 0 可重复且不更新 previous；实际 rank 将 section 12 排在 section 10 前。
回调是显式纯状态服务，实际 AST 构造没有执行；type/import、特殊 custom 与完整
reader 尚未恢复。unsupported/guard 回滚全部页，普通解析失败保留 native 部分状态。
完整 Python bootstrap 仍 0，Medusa/fresh 签名/线上矩阵、Rust 与最终下载产品未完成。
下一处为 section 1 `+32298c` 的 type vector/有符号读取，随后 section 2 `+322cf8`
import 和实际节点/callback/cleanup。见
[section 证据](evidence/vm9_alternative_reader_sections_fresh_20261008.json)与
[第 6.2 节报告](REQUEST_JNI_STARTUP_WORKERS.md#62-section-状态与部分-handler2026-10-08-utc)。

## 2026-10-08 UTC：B reader 的独立 Python u32 读取

在既有 B startup owner 中恢复 `+0x324870`：允许 1..5 字节冗长编码，截断或第五
字节仍无终止时返回 0 并清零输出；第五字节已终止但大于 0x0f 时返回 0，保留输出
且不访问该指针。两个基址各 129 项，**258 个 native/Python 对照、7 个拒绝/回滚**
通过。对照核对自然返回值与整个 guest 区域；包含两个未映射但无需访问的输出指针。
Python 仅消费合成输入，不使用 native 输出快照。跨缺页写入失败后原页保持不变。

这是 core reader `+0x324188` 的一个原语；section 排序/边界、节点、回调、AST 和
cleanup 尚未实现，完整 Python bootstrap 对照仍 0。下一步使用该原语恢复 section
状态与实际 handler，再接独立 factory/root 构建。完整 Medusa/fresh 签名/线上矩阵、
Rust 下载链路及最终产品仍未完成。证据见
[reader u32 对照](evidence/vm9_alternative_reader_varuint32_fresh_20261008.json)，复现与
边界见[本轮报告](REQUEST_JNI_STARTUP_WORKERS.md#61-reader-u32-原语2026-10-08-utc)。

## 2026-10-07 UTC：原始 JNI 同次 worker TLS/exit 与 B 实际 factory

文件名沿用本机试验标签 `20261008`。原有两个基址的 A JNI_OnLoad 0x10006 自然返回、
同次六个默认 caller / 48 嵌套返回、task cleanup / wait / stop / argument free 已验证。
新增 **2 个同次 TLS cleanup 观察和 2 个 guest pthread_exit 观察**，清空实际 support
slot，恰好按 argument(64)→payload(48)→wrapper(8) 释放并核对 poison。guest joinable
状态由实际 libc body 0→1，到显式 syscall 93 exit；原 13 项启动控制回归通过。

exit 增加 worker normal-return→cleanup/exit driver；此前 ctor→JNI、JNI→虚拟 worker
driver 保留。libc TLS getter、空 cxa 线程链、deferred thread-create、受控 allocator /
arena、JNI/OS 和 warm TLS 输入仍显式。未证明真实 OS 线程终止、非空 cxa 链、detached
退出或 stack region 回收；完整 Python bootstrap 对照仍 **0**。

B 新增 **2 个原始 +29ecac constructor / +2cbdc8 factory 观察**，每次自然返回、121 个
非空 descriptor 发布、2330 次受控分配、4 次 exit 注册；actual root bucket count 163。
预算末端 +2dbf80 由 12 字节步长的有限 vector 推进解释，54533 次边界后自然返回。
发布地址按 ELF str 的立即数偏移解码；不把 #imm 漏算的 probe 错误归因于 lookup。
另 **242 个 Python lookup 对照消费 native 生成 root**，与此前 20+30 合成 root 控制和
6 个回滚控制单列；新 lookup evidence 的 native_input_snapshot_used=true。

B XOR 前导新增 **82 个 native/Python 控制、8 个回滚**：0/8/32/tail、零 key 和
count=0 时 row=size，以及两个实际 ELF blob 输入通过。Python/native 都从 fresh ELF /
合成 codec 输入开始，不用 native 快照；停在 +2cbf24 的 reader 调用前。下一处为
+31b360 reader、+2cd5a4 解析及 +2cafd0 构建，不等于完整 factory。

后续 **2 个 native reader 观察**使用 fresh ELF 的 Python XOR 结果，直接调用 +31b360；
每次 1658 次受控分配、status=0、自然返回和 SP 恢复通过。输出仅 vector 长度，Python
reader / AST 对照仍 0。下一处 +324444→+324188 状态/node/清理，再接 +2cd5a4 / +2cafd0。

B constructor 是直接调用，Python factory、原始 JNI B 组合和 B VM 未恢复。真实
allocator/arena/OS 输入、独立 Medusa、fresh 签名/线上矩阵、Rust 下载链路、非空搜索 /
分页、抖音/起点与最终下载产品仍未完成。下一步恢复 B factory blob 解析与独立输入，
把 JNI / worker / cleanup 接回 Python / actual allocator 组合。
见 [原始 JNI 与同次 worker 报告](REQUEST_JNI_STARTUP_WORKERS.md)。下列记录为此前证据。

## 2026-10-08 Python once/getter/mask 与启动导入边界（本机 Asia/Shanghai）

新增 34 组 native/Python 对照、9 项负控制：正常 once callback/完成/broadcast、
完整 64 位 mask、零 mask 仍初始化、cache fast path、共享条件和 u32 回绕通过。
caller pair 在实际消费时比较；原有 14/4/4 回归也通过。另 4 条同次原始入口前缀
到达 A 的 VM prelude 末端和 B 的构造器返回；4 条单变量 memcpy ABS64 导入观察
把 A 推进到 pthread_create +348000 前（部分 VM 已执行，完整 VM 返回未验证）。
B +3e1eb8 descriptor 仍 NULL；JNI table/线程存储已移出大栈区域。Python 完整
bootstrap 对照仍 0，外部服务/warm reference/TLS globals/OS keys 仍显式。
下一步接 A thread-create/startup worker，追 B descriptor publication；完整独立
Medusa、fresh 签名、线上矩阵及下载产品未完成。
见 [本轮 once/mask 与启动报告](REQUEST_JNI_COLD_MASK.md)。以下记录为此前检查点。

## 2026-10-08 cold getter组合与原生once完成（本机Asia/Shanghai）

新增14个fresh caller组合对照、4个负控制：同次构造/JNI初始化/TLS/dispatcher/Long/
word写入/object删除通过，包含不同outer/dispatch env。栈参数在JNI实际消费时比较，
旧临时区在后续调用后不再作为有效终态；缺方法写0与NULL对象保留旧word均验证。
另4条constructor→原始JNI_OnLoad观察（一个显式driver continuation）cold once自然
完成到FFFFFFFFFFFFFFFF，Long0/200分别停在+28040c/+2a0028前；真实libc broadcast及
无等待者futex服务贯通。完整Python bootstrap对照0，startup VM body未执行。
下一处为Python once/JNI_OnLoad控制及A分支+168324、B分支+2a02d4状态/VM输入；
warm reference/TLS全局/OS keys及外部服务仍显式，fresh签名、线上矩阵与下载产品未完成。
见 [cold once报告](REQUEST_JNI_COLD_ONCE.md)。下列once1停止点为此前历史证据。

## 2026-10-07 后续cache mutex构造来源已恢复

`.init_array +271940` 新增8个原生/Python对照、6个负控制：分配48、normal mutex
构造、发布+3df0a8、原地构造+3df118、__cxa_atexit参数/状态通过；不清除已有
class/method缓存。分配和exit服务仍显式，析构body及整个.init_array未执行。
本轮JNI累计96个组件对照、27个负控制，另2条原始入口观察；完整bootstrap对照0。
下一步把此构造与actual dispatcher/Long/object清理接回同次fresh启动，验证cold once。
下方两条入口探针未执行本构造，仍停+270854前且once1；不能拼接成完整bootstrap。
完整Medusa/fresh签名/线上矩阵及下载产品仍未完成，见
[JNI报告第7节](REQUEST_JNI_DISPATCH.md#7-后续init_array-0x271940-的-mutex-构造已恢复)。

## 2026-10-07 actual JNI dispatcher 与 Long 转换组件

- Dispatcher新增54个原生/Python对照、10个负控制：30 dispatcher、20异常helper、
  4 actual-TLS组合；旧+26e70c oracle stub关闭，GP frame/live JNI顺序和返回引用通过。
- Long转换+270854/+224ff8新增34个对照、11个负控制：三组lazy decode、cache/锁内
  复查、global retention、GetMethodID和64位返回通过；cache mutex为显式已构造输入。
  ()J只比较两份va_list及冗余object spill，不补造其余未消费GP/SIMD/physical ABI。
- 另两条原始JNI_OnLoad观察（Python完整bootstrap对照0）自然经过actual dispatcher，
  四次GetEnv、六次malloc，caller把env/opaque object传至+270854前。once仍1。
  正确+3df0a8/+3df0c0/+3df0c8处的mutex/class/method仍全0，未在此探针执行Long转换。
- 下一处是cache mutex构造/发布来源，再接回同次fresh启动、object清理和cold once。
  完整bootstrap、fresh签名/线上全头矩阵、Rust、搜索分页/其他平台及下载产品未完成。
  见 [JNI dispatcher与Long转换报告](REQUEST_JNI_DISPATCH.md)。下列旧停止点保留为历史证据。

## 2026-10-07 原始 cold switch startup 接过实际 TLS acquisition

两条额外原生入口观察（Python bootstrap对照数0）：原始JNI_OnLoad经
publisher/initializer/cold call_once和实际TLS获取，到达+26e70c前。
三次GetEnv，六个显式allocator请求；OS thread slot初始为空，subsystem globals/
OS keys及136/320reference仍为显式warm输入。once仍1，getter输入的前五个
words为0x1000000e,0,0,0,0；dispatcher body及旧stub都没有执行。

下一处为+26e70c/+26e944实际JNI调用、异常处理与+270854转换/缓存依赖。
完整Python bootstrap、真实全局OS/arena冷启动、fresh签名和下载产品仍未完成。
见 [JNI初始化报告第6节](REQUEST_JNI_INITIALIZATION.md#6-后续原始-cold-switch-initializer-已经经过-tls-获取)
及 [cold switch TLS证据](evidence/vm9_jni_cold_switch_tls_fresh_20261007.json)。

## 2026-10-07 JNI dispatch 初始化、类引用与 cold switch once

- 56个原生/Python对照、9个负控制；`+26e19c/+26f154` 原始body执行，
  fresh payload/image、JNI顺序和24字节方法表匹配。注册状态实际被忽略，
  最初FindClass类用于静态方法查找与引用保留，服务仍为显式fixture。
- 四个publication→初始化组合在同次原生执行中返回，中间continuation明确。
- 六个JNI_OnLoad原始探针单独计数；warm switch的四个停在+28040c/+2a0028；
  cold switch两个经matching-libc真实mutex进入+165648/+165658，停在+26edc4前。
  cold once仍1，initializer未完成、predicate未返回；136/320reference仍为warm输入。
- owning session保持957 synthetic返回/965缺VM拒绝；未注入probe VM/env。
  下一处是cold switch的TLS/JNI getter +26e70c/+270854，随后实际startup。
- 完整Medusa、fresh签名、线上矩阵、Rust与下载产品仍未完成。
  详见 [REQUEST_JNI_INITIALIZATION.md](REQUEST_JNI_INITIALIZATION.md)。

## 2026-10-07 此前JavaVM publication 与原始 JNI_OnLoad 探针

- 54个native/Python对照、11个负控制；publisher +27be88与adapter +271998
  实际执行并返回，caller FP/LR、保留frame、live X6 word及image/payload匹配。
- 六个同次原生publication→TLS acquisition组合通过；JavaVM与OS服务为显式
  组件输入，global从0经原始writer发布，未使用native输入快照。
- 四个原始JNI_OnLoad warm-dependency探针：GetEnv失败返回-1且VMglobal保持0；
  成功后publication执行，停在+27bca0。定义JNI_OnLoad GOT来自ELF symbol绑定。
- 完整cold/Python JNI_OnLoad仍未恢复，下一处+26e19c及之后的startup/JNI服务。
  当前owning session仍957返回/965缺少VM拒绝；fresh签名/线上矩阵/产品未完成。
- 详细范围见 [REQUEST_JNI_PUBLICATION.md](REQUEST_JNI_PUBLICATION.md)。

## 2026-10-07 TLS／JavaVM 环境获取与 FindClass 调用前对照

- 新增40个原始body对照、14个负控制；legacy env stub 显式关闭。
- 恢复 `+0x26edc4/+0x17caac/+0x26eeec/+0x26ef2c` 和attach成功分支；
  original TLS／本地析构注册及matching-libc normal mutex实际执行。
- 六个evaluator组合到达 `+0x28b71c` FindClass调用前，参数和相关内存匹配。
  JavaVM/pthread/allocator仍为显式组件服务，FindClass没有执行。
- 同次owning session：低基址957步返回；高基址965步，在 `+0x26ef7c` attach
  因JavaVM global `+0x3deed8` 为0而拒绝，TLS分配16/39字节，父事务未提交。
- 完整独立Medusa、fresh签名、线上矩阵、Rust、搜索分页及下载产品仍未完成。
  当前边界和复现见 [REQUEST_JNI_ENVIRONMENT.md](REQUEST_JNI_ENVIRONMENT.md)。

## 2026-10-07：事件/boolean callback 编排、C++ string 与 realloc 纠正

新增 **76 个组件控制/10 个负控制**：52个24-byte C++ string构造/复制/析构、
16个boolean gate、8个event wrapper。外围原生代码执行，evaluator、scope
cleanup和event formatter仍是显式测试服务；不等于这些叶函数body已恢复。

同次request现可生成两个callback内部前导，再严格停止。低基址仍 **945 /
+0xffb48**，进入`+0x28dc38`，下一缺口为`+0x28ddd0` formatter；高基址仍
**965 / +0xf8fd0**，进入`+0x28bb5c`，counter=0/receiver[1]=0时下一缺口为
`+0x28b05c` evaluator。observer读取暂存页，新增内部body事务没有提交；
whole-native request、真实URL/headers/JNI和fresh签名仍未验证。

已纠正旧formatter verifier：`+0x347fe0`是memcmp，realloc PLT为`+0x348320`。
旧truncation控制实际没有realloc，不能作为其证据。新增两个强制控制各调用1次
显式realloc；格式化由14到16、该组总计58，matching-libc realloc仍未实现。
完整ABI、输入、窗口和复现见 [REQUEST_EVENT_GATE.md](REQUEST_EVENT_GATE.md)。
下方保留较早阶段原值，不把旧组件数量或停止点当成当前结论。


## 2026-10-07：请求 monotonic clock、raw state、guard release 与 pointer getter

新增 **82 个 native 组件控制、18 个负控制**及 **4 个既有 outer constructor
回归**全部通过。`+0x3294b0` 使用显式 clock_gettime(1)；`+0x2914d0` 按
wrapped int64 SUB 后 signed divide 1000，输出 microseconds。raw `+0x32a330`
只清零 140 字节，和外层 `+0x17d7e0` 共享清零 helper，保留各自 vtable/flag
契约。`+0x32d4f8` 无 waiter release 的 byte0-before-lock 顺序和 padding
已有 matching-libc 对照；broadcast/contended 分支仍拒绝。另有 20 个 pointer getter 对照恢复
`+0x172ca4 → +0x1727e0` 的 shared acquire / read +0x90 / release，返回 word
不解引用，writer/saturated/contended 状态拒绝。

同次 owning clock/allocator 组合现在低基址到 **945 / +0xffb48**，下一
`+0x285fb4 → +0x28dc38`；高基址到 **965 / +0xf8fd0**，下一
`+0x285a80 → +0x28bb5c`。两条 request 仍为 synthetic，whole-native 分支
一致性未验证。低基址 elapsed=0 来自两次显式固定 clock 输入，不能当成 f13
时间戳冻结实测。六个外层 prefix 回归继续通过。

接口、单位/位宽、构造器区别、复现与证据用途见
[REQUEST_CLOCK_STATE.md](REQUEST_CLOCK_STATE.md)。真实 URL/headers/JNI、完整
request 返回、fresh Medusa、新线上矩阵及后续下载产品仍未完成。下方保留较早
阶段记录，不能混作当前 stop。


## 2026-10-07：请求相等性、signed 格式化和 ELF memset 输入接入

此前 `%d|%s` 格式化与高基址相等性停止点已恢复，新增 **56 个 native 对照 /
11 个负控制**：32 equality、14 signed format、10 serial guard。复用原有
字符串 constructor/destructor、配置树插入和 guard transition，未创建重复语义。
格式化执行 matching-libc `vsnprintf`；其分配/realloc/free 是明确的组件服务。
native 成功返回 cleanup status 0，Python helper 的对象返回是另一层契约。

同次 owning session 组合使用实际 receiver、原 allocator/free/locale 服务；本次
两路径都未触发仍未恢复的 matching-libc realloc。低基址从 816 推进到 **919 /
+0xffae0**，完成 length=11 的 `%d|%s`、getter 临时字符串清理和配置 pair 插入；
下一 callback `+0x285f60 → +0x2914d0`。高基址从 641 推进到 **793 / +0xf87bc**，
完成相等性、cold guard acquire 和 160 字节清零；下一 `+0x2859e0 → +0x32a330`。

高基址中途 NULL target 已定位为 `image+0x382c80` 对 memset 的 ABS64 外部重定位。
resolver 从 matching ELF 推导 memset/memcpy 的 PLT，绑定 35 个限定 symbol 槽，
没有用 native 输出填洞。六个 prefix 回归对照保持通过，仍验证 30 个 physical
callback frame；这不是整个 loader 或 whole-native request 的验证。

详细接口、位宽/NUL/guard 行为、观测窗口、证据用途和复现命令见
[REQUEST_STRING_CALLBACKS.md](REQUEST_STRING_CALLBACKS.md)。下方较早记录保留各自
当时边界；当前进度由本节与新证据为准。
**真实 URL/headers/JNI、完整 request 返回、fresh Medusa 与新线上矩阵仍未完成**；
Rust、当前搜索、其他平台和最终下载产品的完成状态没有改变。


## 2026-10-07：ORi、getter 返回链和同次请求接入

`+0x16e32c` 的正常 OR immediate 已恢复。fresh caller 经已有 prefix、MOVhi、ORi
进入 `+0x99058..+0x99150` 的 VM，完整执行三次 callback：

```text
+0x25705c -> +0x32a444 acquire
+0x257068 -> +0x2483e0 clone
+0x25705c -> +0x32a4fc release
```

新增 28 个原生对照（12 ORi / 12 getter / 4 request wrapper）和 7 个负控制通过。
比较 callback 参数与全部 32 slots、guest backing、stream、virtual saved stack、
0xA000 字节 payload 和分配序列。原生 caller 与 wrapper 确实返回，Python VM
退出；Python 完整 native epilogue/ABI 仍未建模。native mutex 使用 matching libc，
malloc 是显式服务，不把这组结果描述成 real allocator boot 的整体对照。
未知 target 负控制确认修改的是实际函数槽 `image+0x381c50`，而非 `+0x35b650`。
6 个 outer-prefix 回归另在 30 个实际 callback 入口验证 physical SP/x29/x28/x19；
此前 STORE64/sub-dispatch/MOVhi/caller 的 36 个对照和 5 个负控制也通过。

同次 Python outer/request 使用原 allocator/OS session 和 constructor 的 receiver，
未注入字符串/reader fixture。低基址 `0x122c0000` 从第 803 步推进到第 816 步、
bytecode `+0xf85b4`，getter 复制声明长度 8 的字符串，实际分配 9 字节，reader
count 恢复。新停止点 `+0x285990 → +0x248908` 的格式是 `%d|%s`，int32 为 -5。
高基址 `0x775c205000` 的外层控制在 641 / `+0xf812c` 提前停于
`+0x2858ec → +0x24880c`；没有达到 getter，外层分支尚无 whole-native 对照。

字段、调用、复现及证据用途见 [REQUEST_NESTED_VM.md](REQUEST_NESTED_VM.md)。
当前结论由本节及其新证据为准，下方前缀记录保留当时边界。
**整个 request、真实 URL/headers/JNI、fresh Medusa 和新线上矩阵未完成**；
Rust 下载链路、非空搜索/分页、其他平台和 Pages/Actions 产品也仍未完成。


## 2026-10-07：fresh caller 的 nested VM 前缀已推进到 `+0x16e32c`

本轮恢复了正常路径的 `+0x171138` STORE64 循环、`+0x16855c` sub-dispatch、
`+0x16a5a8` OR64 和 `+0x16e158` signed MOVhi，并把它们接到已验证的
`+0x16d7d0` dispatcher。Python 输入由 ELF/重定位、显式对象/x8 和 fresh 页生成，
没有读取 native 前导快照作为输入。组合链为：

```text
+0x256ed4 caller / defined prelude
  -> +0x16d7d0
  -> +0x171138 STORE64 × 10
  -> +0x16855c
  -> +0x16a5a8 OR64
  -> +0x16e158 MOVhi
  -> +0x16e32c（下一处尚未恢复）
```

新增 **48 组 fresh native/Python 对照全部通过**：OR64 12 组、STORE64 12 组、
sub-dispatch 6 组、MOVhi 12 组，以及使用原 ELF dispatch table 的 caller 组合 6 组。
另有 8 组拒绝/回滚控制通过，已有 dispatcher 的 6 组回归通过。
组合覆盖两 image base、三对象/保留 x8 profile 和三种 fresh page fill；每组核对
各组件输出寄存器、从 store loop 开始的 **61 次写入顺序**、25 个规定内存范围，
最终 stream 为 `image+0x99054`，PC 为 `image+0x16e32c`。

OR64 使用 `x21`，并按原生顺序处理槽位和 scratch 别名；STORE64 覆盖正负及
极值 signed displacement，以及覆盖下一条 word 的控制；MOVhi 覆盖正、负、
零立即数和 signed 32→64 扩展。验证器在 bounded 分支出口直接读取 emulator
内存，修正了异常停止时 normal-return 内存导出没有执行的问题。

证据与字段/调用说明见 [REQUEST_NESTED_VM.md](REQUEST_NESTED_VM.md)、
[OR64 对照](evidence/vm9_request_or64_fresh_20261007.json) 和
[nested 组合对照](evidence/vm9_request_nested_fresh_20261007.json)。
下方较早记录保留当时的边界；本节记录当前实现进度。

**这仍是合成 native request 输入下的 bounded 前缀。** 其他 generic VM frame spills、
repair paths、`+0x16e32c` 后续 body、真实 URL/headers/JNI 转换和 callback 返回链
尚未贯通；完整独立 Medusa、fresh 签名和线上全头矩阵仍未通过。Rust、当前搜索、
抖音/起点以及最终 Pages/Actions 下载产品继续保持未完成状态。

## 2026-10-07：请求 nested VM dispatcher `+0x16d7d0`

`+0x16d7d0` 已从“入口定位”推进为一个可独立复现的 bounded dispatcher transition。
`python/vm9_request_dispatcher.py` 从显式 fresh caller/frame 输入生成 nested VM 的
寄存器地址布局，不复制 native stack 或 page snapshot；`dispatch_request_word` 恢复
正常解码路径的字段重排、两个 backing-slot 访问、stream pointer 推进、`x22/x23/x30`
scratch 发布和 relocated dispatch-table 下一跳计算。当前 verified word 是
`image+0x99020 = 0xff7bdc0f`，解码得到 slot `29`、signed displacement `-144`、
next-word selector `0x1a`，下一跳为 image-relative `+0x171138`。

[6 组 fresh native differential](evidence/vm9_request_dispatcher_fresh_20261007.json)
覆盖两 image base × 三个对象/保留 x8 profile。每组均比较 dispatcher 入口寄存器、
`x19/x22/x23/x28/x29/x30` 相关写入和首个下一 handler 的 PC，全部通过。
这只完成 `+0x16d7d0` 的正常路径和状态恢复；repair path、`+0x171138` handler、
后续 nested VM、完整 Medusa 和签名仍未完成。

复现：

```powershell
python platforms/bytedance/tomato/python/verify_vm9_request_dispatcher_fresh_20261007.py --library C:\AI\6\libmetasec_ml_71332.so --output platforms/bytedance/tomato/evidence/vm9_request_dispatcher_fresh_20261007.json
```

## 2026-10-07：`+0x171138` handler loop 出口定位

沿着 dispatcher 的 `+0x171138` 下一跳继续做 native-only fresh probe。该入口会
在自身范围内重复处理 VM words；6 组同样的两基址 × 三个对象/保留 x8 profile
均在 **1001 条 native 指令**后第一次离开 loop，统一进入 `+0x16855c`。

[evidence/vm9_request_nested_handler_exit_fresh_20261007.json](evidence/vm9_request_nested_handler_exit_fresh_20261007.json)
只记录 handler entry/exit 边界和指令计数，尚未把 `+0x171138` loop 或
`+0x16855c` 转成 Python；因此不能把该边界当成 nested VM 已完成。

## 2026-10-07：请求配置树 x8 输出与同次 allocator 接入

当前请求诊断边界进一步推进到 **第 611 步、`+0xf80a8`**。
上一节的第 599 步／`+0x25c324` 为此前检查点；其输入布局仍由原生前段对照证明。

`construct_configuration_tree_reference` 复用已有 controller/sentinel/reference
模型，恢复 `+0x25c324`：分配 40 字节容器、40 字节 controller、40 字节 sentinel
和 4 字节 count，初值 1，将 owning reference 写入调用者的 **x8 输出槽**。
[8 组原生组件差分](evidence/vm9_request_tree_reference_fresh_20261007.json)
覆盖两基址与四输出位置，包括跨页和输出／新容器重叠控制；比较范围内的字节
与分配序列相同。重叠控制验证 native 写入顺序，不表示重叠后的容器图仍可使用。
缺页输出在分配前拒绝，guest pages 不变。该组件对照使用显式 allocator 服务，
不能单独证明 actual allocator 组合完成。

[4 组同次 Python allocator 组合](evidence/vm9_request_allocator_handoff_fresh_20261007.json)
则从 fresh outer 的 child A pair/handler 继续运行，按 **pages 对象身份**选择
持有这些页的现有 allocator session，保持 GuestOS staging chain。
请求中的四次分配均由匹配 libc 的 Python allocator 模型生成，没有返回地址替代；
x8 reference、count 和 owned OS mapping 的包含关系通过。
每组还验证：脱离 owner 的普通页拷贝会在分配前明确拒绝，页、mapping 和 cursor 不变。
先前诊断用复制页适合只读前段，不能交给 actual allocator 继续分配；不得用 ready
flag、预置指针或新的独立 allocator 绕过这个 owner 边界。

复现新增组件与组合：

```powershell
python platforms/bytedance/tomato/python/verify_vm9_request_tree_reference_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_request_tree_reference_fresh_20261007.json
python platforms/bytedance/tomato/python/verify_vm9_request_allocator_handoff_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_request_allocator_handoff_fresh_20261007.json
```

注册表既有回归另外通过 96 组原生差分／11 项拒绝控制；请求前段的 6 组
原生回归保持通过。142 个 Python 文件语法检查、公共材料扫描和 diff 检查通过。

**诊断 scope 已完成一个独立组件对照，并已接回请求组合。**
`+0x2858d0 → +0x26c858` 现在由 [diagnostic scope model](python/vm9_diagnostics.py)
恢复：对象 vtable/错误码字段、按 `(input >> 4) & 0xff` 的表项选择、全局普通锁、
0x800 字节表、0x30 字节 entry、递归锁和 `+0x26c9d0` 退出解锁都已实现。
[18 组 native 对照与 7 项回滚控制](evidence/vm9_diagnostic_scope_fresh_20261007.json)
覆盖两基址、cold/warm、跨页输入、嵌套递归和饱和错误码；matching libc 的
`pthread_mutex_*` 实体路径参与对照，未导入 native 页或签名快照。

请求组合进一步从诊断 scope 继续到：`+0x2858e0 → +0x26c9d0`、
`+0x285928 → +0x32a1f0` 的 24 字节分配、`+0x28591c → +0x2481ac` 的空字符串对象
和 8 字节 payload 分配。一次 fresh outer → owning allocator → request 组合到第
803 步、`+0xf8580`，记录的下一个未恢复 callback 是
`+0x285978 → +0x256ed4`；后者进入 `+0x168324` VM，尚未把该 VM 的输入对象图、
真实 URL/headers/JNI 转换和后续正文处理接通。[组合探针证据](evidence/vm9_request_diagnostic_continuation_20261007.json)
只证明 Python 组合和边界定位，不证明 whole native handoff 或 signer 输出。

复现新增边界：

```powershell
python platforms/bytedance/tomato/python/verify_vm9_diagnostic_scope_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_diagnostic_scope_fresh_20261007.json
python platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

`+0x285978 → +0x256ed4` 的 caller 也已完成 bounded fresh 对照：
[6 组 caller/prelude 差分](evidence/vm9_request_vm_caller_fresh_20261007.json)覆盖两基址、
三个对象位置和三个 incoming x8 值。Python 从显式 `entry_stack/x0/x8/TLS` 生成
0x3b0 字节 caller frame；`+0x168324` 通用前导的 descriptor、32 个 backing slot、
TLS canary 和到 `+0x1684f0` 的临时栈字节与 native 相同。特别确认 descriptor 的
第二个 word 是 `sp+0x380`（`ADD #0x28` 后又加 `#0x358`），不是简单的 `sp+0x28`。
对照在 `+0x1684f0` 停止，尚未执行该入口选择的 nested VM body。另用
[dispatch observation](evidence/vm9_request_dispatch_fresh_20261007.json) 做了 6 组
fresh 入口定位；两基址、三个对象/x8 profile 的首个 post-prelude handler 都是
`+0x16d7d0`，这只是下一处 native handler 的位置证据，不等于已恢复该 handler。

复现：

```powershell
python platforms/bytedance/tomato/python/verify_vm9_request_vm_caller_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_request_vm_caller_fresh_20261007.json
python platforms/bytedance/tomato/python/verify_vm9_request_dispatch_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_request_dispatch_fresh_20261007.json
```

当前仍未完成：独立 fresh-input Python Medusa、whole native outer→request→allocator
对照、`+0x168324` 之后的 nested VM、JSON 临时 buffer 正文、真实 URL/headers/JNI 输入、
fresh Medusa 输出、线上全头矩阵（含 Perseus）和时间戳冻结实测；无 JVM Rust、非空搜索/分页、
抖音/起点闭环以及最终 Pages/Actions 下载产品也仍未完成。

## 2026-10-07：构造器收尾与当前请求 caller／VM 前段

最新构造器状态见 [finalization evidence](evidence/vm9_outer_finalize_fresh_20261007.json)。
此前对象图报告中仍存在的构造器哈希、格式化全局差异以及 publication/JNI 对照缺口，
已被本次验证取代；旧证据保留为历史记录，不表示当前代码仍缺这些有界分支。

- **8 字节哈希输入来自 u32 零扩展。** `+0x27cdf4` 的 `LDR W11` 零扩展后，
  `+0x27ce00` 的 `STUR X11` 写完整 8 字节；高 4 字节为零，不是未知栈残留。
  `update_outer_constructor_hash` 从当前 `image+0x3D1994` 生成输入，以
  `0x201507` 为初值恢复 8 轮 W-register 运算，再写 `+0x3D1998`。
  10 组原始指令差分覆盖两基址、5 种 counter、A5 poison 和跨页 caller slot。
  零输入的 `0xA99E2E98` 仅是对照结果，没有写成输出常量。
- **8 个全局位置是 4 个解码常量和 4 个 guard。** `+0x28e9f8…+0x28eabc`
  的 source/mask 对从 fresh ELF 解码 `N/n/D/d`，并发布各 guard=1。
  前一节“8 个初始化标记”不应解释为 8 个 guard。
- **publication 接回真实顺序。** 在 `+0x27cd9c → +0x28c268`、最后一次
  registry `"59"` append 之前发布，入口计数为 293 次分配／99 次释放。
  两个 tag `0x2000001/0x2000002` 均传同一 outer、int=0、string/object=NULL；
  两次 invoke 完成后才查询并删除 global/weak-global 返回引用。
  root、children、callback pair、JNI ledger 和入口 allocator 计数两侧相同。
  使用的是显式虚拟 JNI 服务，没有实际 JVM；需要 publication 却未提供服务时明确拒绝。

两基址 × absent/SDK30/changed-counter 共 **6 组独立 Python/native 差分**通过。
20 个对象跨度、310 次分配／115 次释放及选定全局相同；195 个存活分配仍仅
allocation #308 的 short-string 未使用 padding 不同，已限制差异只位于 padding。
5 个拒绝控制通过，并验证 guest pages 不变。
JSON parser/formatter 临时 buffer 的正文仍只恢复 allocator ledger，完整 native
writable globals、物理栈 scratch 和并发线程没有整体对照。

当前请求的 [离线 bridge reference](evidence/current_request_entry_reference_20261007.json)
也已修正：12 条 ARRBUILD/ARRBUILD2 对应 6 次 `+0x27152c`、6 次 `+0x271548`，
它们是 **SetObjectArrayElement 调用后的返回点**，不是 signer entry。
`VM_ENTRY` 仅打印每种 bytecode 首次命中；本次有 15 种、footer 共 34 次命中，
不能用首次日志替代完整调用序列。签名轮次首次新出现的 VM 为 `+0xf7720`，
由 child A pair 的 caller `+0x2830c4` 在 `+0x283130` 调用，返回到 `+0x283134`。
bridge 对合成 example.invalid URL 生成 1072 字符／802 原始字节的 Medusa 参考，
只公开摘要、长度和偏移；这次使用 JVM，没有请求服务器，也未证明独立 Python 签名。

新增 [request caller](python/vm9_request_caller.py) 从显式 x0/x1/w2/x3/x8、TLS、
栈与 fresh ELF 生成 packed inputs、descriptor 和 VM 32 槽前导状态。
[20 组原生差分](evidence/vm9_request_caller_fresh_20261007.json)覆盖两基址、
两栈位置、5 种 x2；验证 STR W2 保留 slot 高 4 字节，以及 4 项拒绝／回滚。

[请求 VM 前段差分](evidence/vm9_request_prefix_fresh_20261007.json)进一步执行
`+0xf7720` 至第 599 步、`+0xf8078`：三次 `+0x285888 → +0x167e54`
解码 19/32/9 字节，`+0x28589c → +0x291440` 读取显式单调时钟，
`+0x2858a8 → memcpy` 复制 24 字节。
6 组原始 native VM 对照验证 callback 输入 ledger、解码字节、全部 32 个 VM 槽和
最终 descriptor 一致。另有两基址 × absent/SDK30 的 4 组 Python 同次组合，
直接使用 fresh outer 生成的 child A pair/handler 接入该前段，没有 native 内存补页。
组合中的请求对象仍是显式合成输入，prefix 状态停在诊断事务中；不是 whole-handoff
native 对照，也没有执行请求分配 callback。

复现（需要本地匹配样本和 libc；这些私有输入不在 Git 中）：

```powershell
python platforms/bytedance/tomato/python/verify_vm9_outer_finalize_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_outer_finalize_fresh_20261007.json
python platforms/bytedance/tomato/python/verify_vm9_request_caller_fresh_20261007.py --output platforms/bytedance/tomato/evidence/vm9_request_caller_fresh_20261007.json
python platforms/bytedance/tomato/python/verify_vm9_request_prefix_fresh_20261007.py --outer-libc C:\AI\6\_vlibc.so --output platforms/bytedance/tomato/evidence/vm9_request_prefix_fresh_20261007.json
```

**此前下一处：`+0x2858bc → +0x25c324` 的配置树 reference 构造；现已按上节继续恢复。**
该 wrapper 使用 descriptor 的第 2 个 word 作为 x8 输出；不能把它作为普通 x0
参数处理。随后还需恢复真实 URL/headers/JNI 输入构造与其余请求 callback，
把请求分配接回同次 actual allocator，再验证 fresh Medusa 输出与新的线上矩阵。
完整独立 Python Medusa、无 JVM Rust、非空搜索/分页、抖音/起点和最终
Pages/Actions 下载产品仍未完成；Rust current Medusa 仍保持 unavailable。

## 此前 2026-10-07：fresh outer 返回对象图与默认记录差分

当前状态以 [fresh object-graph evidence](evidence/vm9_outer_graph_fresh_20261007.json)
为准。此前 `vm9_outer_constructor_boundary_20261006.json` 的“当前停在
`+0x2584ac`”结论已被本次运行取代；保留旧文件作为历史证据，不再用于描述当前代码。

边界 verifier 以前未保存 `OuterConstructorResult`，却固定写入
`rejected_at_boundary=true`、logger/trampoline 已捕获。现在这些状态由本次实际返回、
异常和 callback 观察计算；独立 wrapper tests 的通过不会被自动标成当前路径已执行。

同输入差分的顺序固定为 **Python 先从 fresh ELF/TLS、matching-libc allocator 与显式
OS/clock/property/virtual-thread 服务运行，native 后独立运行**。native 终态仅作期望值，
不注入 Python。两基址 × absent/SDK 30 共 4 组均通过：

- root VM `+0x991c0` 在 716 步到 `+0x99f04`；每组短 wrapper `+0x2584b8`
  调用 2 次、长 wrapper `+0x2584ac` 0 次、logger VM callback 0 次。
- 每组 310 次分配、115 次释放的尺寸、指针和先后顺序相同。
- 20 个对象跨度与对应地址一致：singleton/count、40 字节 outer、264 字节 internal
  root/count/state、两 child/state/count/callback pair、两 handler、配置 count、
  publication recursive mutex 和 64 字节记录容器。
- outer 的 internal reference 位于 `+8/+0x10`，临时 factory reference 已减计数；
  `+0x27cf68` 按真实 scoped writer 路径清零 root `+0x68` 的低 u32，保留高 u32。
- native 指令显示 embedded handler 绑定 child B、service handler 绑定 child A；
  两 handler 的 child/configuration references 和计数已接回。
- singleton slot/guard、refresh lazy globals、sink global、publication once/chain 与
  logger-record singleton 的选定字段全部相同。
- `+0x28ff44` 的默认 96 字节记录由 fresh ELF 解码 title/格式，生成四个 libc++
  short strings。字符串长度、内容和终止符相同，64 字节容器的 begin/end/capacity
  相同；unused string padding 由 Python 置零，不复制 native 栈残留。

195 个存活分配中，唯一完整 byte-span 差异为 allocation #308 的记录填充字节。
这不代表整个 native 状态完成：额外检查仍发现 `image+0x3D1998` 构造器哈希与
`image+0x3E1AB0…+0x3E1ACC` 的 8 个格式化初始化标记未生成。构造耗时
`image+0x3E07C0` 在本次显式时钟控制中相同。JSON parser/formatter 临时 buffer
内容仍仅恢复 allocator ledger；Python 的 JNI publication/cleanup 尚未与 native 对照。
默认 record 模型明确拒绝 nonzero outer 值、long string、已有 record singleton 和
未恢复的 concurrent once 分支。4 个拒绝控制（nonzero outer、超长格式、已有 singleton、
busy once）均抛出 `RefillUnsupported`，且所有 guest pages 保持不变。

复现本次四组差分与拒绝控制：

```powershell
python platforms/bytedance/tomato/python/verify_vm9_outer_graph_fresh_20261007.py --library C:\AI\6\libmetasec_ml_71332.so --libc C:\AI\6\_vlibc.so --output platforms/bytedance/tomato/evidence/vm9_outer_graph_fresh_20261007.json
python scripts/check_python.py
python scripts/scan_public.py
```

匹配样本的 SHA-256 已写入证据并在 verifier 入口检查；二进制不随仓库发布。

下一步恢复 `+0x27cdd0 → +0x27ce44` 的 8 字节 caller 哈希输入及 u32 计算，再定位
JSON 初始化标记和 `+0x28c268` 的 Python publication/JNI 服务，之后才接 fresh 请求签名。
两组 native 基址控制在 hash 入口观察到当前 8 字节为零，但 Python 必须从自己的
fresh caller 状态准备这些字节，不能写入采样 hash 常量。

**完整独立 Medusa、fresh 请求签名与线上全头矩阵仍未通过。** Rust signer/download、
非空搜索与分页、抖音/起点闭环和最终 Pages/Actions 搜索下载产品仍待完成。
Rust 当前 Medusa 保持 unavailable。本轮仅公开 offsets/counts/hashes/equality；
私有 ELF、运行页、设备材料和原始探针未提交。


## 2026-10-06: Medusa f13 explicit clock differential

`medusa_f13.py` 现在支持 `wall_time`/`wall_nanoseconds` 和 `MEDUSA_F13_SNAPSHOT_DIR`，可在不复制私有快照的情况下注入测试输入。新增 [clock evidence](evidence/medusa_f13_clock_parameter_20261006.json)：同一 query 的 5 组时间控制输出全部为 `af82bde0311cf322dc9f36ececc60d61`，且每组 `svc_log` 都没有 syscall 113。

结论是当前 BIG VM 快照的这条 f13 路径没有读取时钟；这验证了参数入口和“未消费”事实，不能把冻结时间改写成线上时间戳已解决，也不能证明当前线上 Medusa。


## 2026-10-06: callback consumer APIs kept explicit

`vm9_callbacks.py` 现在提供 `dispatch_packed_callback_consumer` 和 `dispatch_callback_result_writer`。前者只读取并传递 `target/packed_x8/x0/x1` 四个显式字段；后者只执行 `target` 读取、callback `x0=object` 和 `object+0x08` 低 32 位写回。两者都拒绝空 target、未提供 callback 或越界输入。

这使 Python 使用方可以引用已经由 native differential 证明的 ABI，而不会把 packed x8 的未知上游组合或当前对象图隐藏在常量中。


## 2026-10-06: callback result writer fresh differential

补充 [result-writer evidence](evidence/vm9_callback_result_writer_native_fresh_20261006.json)：`+0x28863c` 的原始 native bytes 在 12 组 fresh object 控制中执行通过。它从 object `+0x00` 取目标、以 object 作为 callback `x0`，把 callback `w0` 写回 object `+0x08`，再恢复保存的 `x19/x30` 和 `sp`。

该结果补齐了同一 callback object 家族的“结果写回”边界，但没有恢复 object 的上游 writer、packed x8 组合、当前 VM9 owner-frame continuation 或 Medusa 输出。


## 2026-10-06: packed callback consumer ABI fresh differential

新增 [packed consumer evidence](evidence/vm9_packed_callback_consumer_native_fresh_20261006.json)。从私有 ELF 提取并执行 `+0x2887f0` 的 28 字节 consumer，12 组 fresh 32 字节 callback object 全部通过。

原生 consumer 被实测为：从 object `+0x00` 取 indirect target、从 `+0x08` 取 packed `x8`、从 `+0x10/+0x18` 取 `x0/x1`，调用目标后恢复 caller 的 `x30` 和 `sp`。每组都确认 callback 入口收到原始 packed x8、两个参数和正确返回 PC，返回值与栈恢复一致。

这只闭合了 packed callback 的消费 ABI。packed x8 上游组合、当前 VM9 callback object writer、owner-frame continuation、fresh Medusa 和线上校验仍未完成；合成 callback hook 不构成当前 native body 证据。


## 2026-10-06: native `+0x25863c → +0x25865c` return trampoline differential

新增 [return trampoline evidence](evidence/vm9_callback_return_trampoline_native_fresh_20261006.json)。从私有 ELF 提取并在 Unicorn 中执行原始 `+0x25863c` 入口和 `+0x25865c` continuation，8 组 fresh 控制均通过。

证据确认：入口把 `x9/x30` 压栈后把返回地址改到 continuation；continuation 恢复 `sp/x30`，把 `x19` 指向对象的 16 字节清零，写入并重载 selector 中间值，按 `w20 & 1` 在乘法路径与 `IMAGE+0x2586a0` 路径间选择，最终在 `br x8` 边界得到可复现目标。

这是一条与直接 `+0x2584b8` reader wrapper 和 `+0x2584ac` descriptor wrapper 分开的 callback-family 路径。它闭合了返回 trampoline 的栈和分支语义，但没有执行最终 target body，也没有恢复当前 VM9 owner-frame、packed callback x8、fresh Medusa 或线上矩阵。


## 2026-10-06: native `+0x2584ac` fresh wrapper differential

新增 [native wrapper evidence](evidence/vm9_descriptor_trampoline_native_fresh_20261006.json)。测试直接从私有 ELF 提取 `+0x2584ac` 的 24 字节原始指令，在 Unicorn 中执行 12 组 fresh descriptor 控制。每组由 synthetic pre-dispatch hook 在真实 `blr x8` 边界改写 descriptor，再让原始 wrapper 执行 `ldp x1,x8,[x0]; mov x0,x8; br x1`。

全部控制验证了：callback 入口 `x0` 保持 descriptor；`blr` 返回地址为 reload 点；栈中保存的原始 `x30` 未损坏；descriptor 的 target/object 改写被 reload 读取；最终 branch 入口收到改写后的 `x1` 和 `x0`；执行在最终 branch target 边界停止。该证据把之前的静态/事务模型推进到真实 native wrapper 指令差分。

这仍不等于当前 VM9 callback object graph：callback body 是 hook 提供的 synthetic side effect，最终 branch target 和 continuation 没有继续执行，packed callback x8、fresh Medusa 输出与线上矩阵仍未恢复。



同次四组 fresh root 控制记录到 8 次 `+0x2584b8`、0 次 `+0x2584ac`。这说明有界
root VM 当前走的是短 descriptor wrapper；较长 pre-dispatch trampoline 在这些
控制中没有进入，必须作为独立 native 路径继续追踪。



## 2026-10-06: direct +0x2584b8 branch handoff verified

fresh root callback 序列显示当前有界路径直接进入 `+0x2584b8`，其 16 字 descriptor
的 field0 是 active target、field8 是 reader object。新增 16 组 native fresh
差分，逐条执行 `ldp x1,x8,[x0]; mov x0,x8; br x1` 到
`+0x32a444/+0x32a4fc`，内存、descriptor 保持、mutex lock/unlock 和返回状态
均与 Python 模型一致。证据为
[evidence/vm9_descriptor_branch_handoff_fresh_20261006.json](evidence/vm9_descriptor_branch_handoff_fresh_20261006.json)。

这只闭合了直接 `+0x2584b8` wrapper 的 branch ABI；更长的
`+0x2584ac` pre-dispatch、packed callback x8、完整对象图和线上 Medusa 仍未闭合。



Python 侧已新增 `vm9_callbacks.dispatch_direct_descriptor_branch`，将直接
`+0x2584b8` descriptor pair、branch target 和 object callback 作为事务边界；
它只服务已验证的短 wrapper，不代替 `+0x2584ac` pre-dispatch。



## 2026-10-06: fresh writer object classified as shared-reader state

四组 fresh `+0x991c0` 控制现在保留了 active target pair 所用对象的局部字节：
初始化前为零；经过 `+0x32a40c` 后，`+0x00..+0x87` 仍为零，`+0x88` 的 u32
reader count 为 `1`，相邻 u32 也是 `1`。因此该指针是 shared-reader 状态对象，
不是两字 callback descriptor。后续必须把 writer/reader 生命周期和
`+0x2584ac` 的 `[x0]` target、`[x0+8]` object 链分开追踪，不能把二者直接拼接。



## 2026-10-06: active target relocation table lead

静态 ELF 还发现 active pair 的 10 个 `R_AARCH64_RELATIVE` relocation addend，分布在
5 个连续 dispatch/table 区域。每个局部上下文都重复
`+0x32a444 → +0x32a40c → +0x32a4fc`，其中 `+0x32a40c` 是已确认的 shared-reader
对象初始化入口；旧偏移没有 relocation。它为下一步追踪对象首字段和实际下一跳
提供了候选表面，但没有证明这 5 张表都属于当前请求路径。出现列表已写入
fresh target evidence。

## 2026-10-06: corrected descriptor targets direct fresh differential

对 active writer 生成的 `+0x32a444/+0x32a4fc` 已做独立 fresh native
差分：两种 image base、acquire/release 两方向、16 组 reader count 控制全部
匹配内存结果和正常 mutex lock/unlock；native 返回值为 0。旧的
`+0x31e444/+0x31e4fc` 未执行并保留为 superseded offsets。证据为
[evidence/vm9_descriptor_target_roles_fresh_20261006.json](evidence/vm9_descriptor_target_roles_fresh_20261006.json)。

这仍不是 `+0x2584ac` 的完整分支链。由于 shared-reader 函数的返回值是 mutex
状态，且 trampoline 会在 `br x1` 后重新读取当前 `x0` 对象，下一步仍需从同次
fresh descriptor/object graph 追踪实际下一跳和返回链接；不得把这 16 组函数
差分当成 callback object 或 fresh Medusa 已恢复。


## 2026-10-06: corrected literal logger sink state boundary
## 2026-10-06: descriptor trampoline semantics parameterized
## 2026-10-06: corrected active descriptor target roles

The active writer values resolve to image-relative `+0x32a444` and
`+0x32a4fc`, not `+0x31e444`/`+0x31e4fc`. At the current ELF those active
addresses are function entries for shared-reader acquire and release, with
real prologue instructions. The earlier one-page-lower audit was a wrong target
selection and is explicitly superseded in [corrected target-role evidence](evidence/vm9_descriptor_target_roles_20261006.json).

This closes the static target-role misclassification and connects the active
values to the existing bounded shared-reader components. It does not execute
the final `br x1` handoff or prove the callback object, full VM continuation, or
fresh Medusa output.


The generic `+0x2584ac` sequence is now represented as a transactional
component: read the initial target/object pair, invoke an explicit
pre-dispatch callback, reload the pair, then invoke an explicit branch
callback with the reloaded object. The verifier also checks the six-instruction
sequence against the current private ELF (`str/ldr/blr/ldp/mov/br`) and covers
target rewrite plus null/missing-callback rollback cases without executing a
guest function pointer. Evidence: [descriptor trampoline semantics](evidence/vm9_descriptor_trampoline_semantics_20261006.json).

This closes only the instruction-level continuation contract. The native
callback-object writer, packed x8 composition, active current VM9 branch body,
fresh Medusa output and online header matrix remain open.



The four fresh controls now pass the complete bounded sink verifier: two image
bases (`0x122c0000`, `0x775c205000`) crossed with absent and SDK 30 property
profiles. Native and Python agree on the `+0x26cdc4 → +0x26cf08 → +0x26e9e0
→ +0x271ec8 → +0x271ddc → +0x271f18` path, the owned 24-byte string
object prefix, `METASEC` payload, decoded fallback message, `level=6`, the
unavailable-sink global state before/after the call, and the return value.

The earlier 0x80-byte capture is a native stack window, not a claim that all
128 bytes are logger-object fields. The corrected model uses the 24-byte object
layout and derives the payload through the allocator event ledger. Evidence:
[corrected sink boundary](evidence/vm9_logger_sink_match_20261006.json).

This closes a literal logger/sink state boundary only. The sink callback body,
file/socket effects, descriptor publication, fresh Medusa output, and online
header matrix remain open.


## 2026-10-06: logger object and formatter payload boundary

The native fresh dispatch trace was extended through `+0x271ec8`,
`+0x2772a4` and `+0x271ddc`. At `+0x271ec8`, `x1` points to the
heap payload `"METASEC\0"`; `x2` is the decoded fallback format object and
`+0x271ddc` receives the formatted text `"Invalid JavaVM, fallback to test path."`
with `x0=6`. The native capture around `vm_stack-0xAE0` is a 0x80-byte stack window. The
owned logger string object within it is modeled as 24 bytes; the surrounding
bytes are caller/callee stack state and are not promoted to object fields.
The earlier [broad-window record](evidence/vm9_logger_model_match_20261006.json)
is retained as historical scope only. Use the corrected sink evidence above for
the object-size and global-state claims.

This closes only the literal logger object/formatter input boundary. The final
`+0x271ddc` sink callback, file/socket writes, native callback publication,
descriptor trampoline and fresh Medusa signature remain open.


## 2026-10-06: post-VM logger handoff boundary

The native root VM returns at `+0x99f04`, then the outer path enters
`+0x26cf08 → +0x26e9e0`. Four fresh controls now match the handoff
relations: the logger object is `VM stack - 0xAE0`, the source object is
`image + 0x3DEDB8`, the first logger argument is `image + 0x3DEDD0`, and
`x2=8`, `x3=3`. The Python provider generates those addresses from the
current stack and image base, then rejects at the handoff instead of invoking a
guessed logger. Evidence: [logger handoff boundary](evidence/vm9_logger_handoff_boundary_20261006.json).

The short-string object fields, payload contents, `+0x271ec8` formatting/sink
dispatch and callback side effects remain open. This is a post-VM argument
boundary result, not a fresh Medusa signature.


## 2026-10-06: fresh root caller spill aligned at the generic VM prelude

The native path `+0x257084 → +0x257308 → +0x168324 → +0x1684f0` was
traced at the point where the generic prelude has finished writing the VM
backing window. The Python outer path now derives that window from the current
root object, outer object, entry stack, ELF addresses and guest base; it never
reads a native memory snapshot. Across two image bases and absent/SDK 30
controls, all 32 backing words matched the same fresh native controls with no
mismatch indices. Evidence: [root prelude backing match](evidence/vm9_root_prelude_backing_match_20261006.json).

This closes only the caller-spill/prelude divergence. The Python control still
does not reach the native logger/callback handoff in this run, so logger
semantics, descriptor publication, fresh Medusa output and the online header
matrix remain open.


## 2026-10-06: logger/state write boundary from a fresh outer getter

A fresh native outer getter control at image base `0x122c0000` with the absent
property profile returned normally and decoded the five lazy globals with
lengths `3, 5, 241, 3, 3`. The trace directly observed the final stores at
`+0x27ce44` (`image+0x3d1998 = 0`) and `+0x27ce6c`
(`image+0x3e07c0 = 0`). Evidence: [state-write boundary](evidence/vm9_outer_constructor_state_write_boundary_20261006.json).

These stores establish a fresh-input state boundary only. They do not recover
the `+0x28ded0` formatter fields, locale/sink dispatch, callback publication,
or the native `+0x26cf08` handoff. The raw process-memory trace is omitted,
and the Python model still does not consume a native snapshot.

## 2026-10-06: outer constructor allocation/free ledger through wrapper publication

The fresh Python outer constructor now continues past the second registry
append. The two decoded globals are handled in native order:

`+0x27cd10` appends `+0x3e08d8` (`"51"`), releases its temporary payload,
constructs the second `+0x27d188` child-B reference, then
`+0x27cdbc` appends `+0x3e08e0` (`"59"`). The measured 16-byte reserve at
`+0x246988` is produced by the real string-growth model, rather than inserted
as an unexplained padding allocation. The NULL temporary reference is then
released, yielding the native 4-byte counter, 241-byte payload and 24-byte
object frees.

The subsequent `+0x28ded0` logger/state path currently models its explicit
allocator boundary: two 64/128/256/8/8 grow-and-release cycles followed by
40/64/96 state allocations, then the `+0x165968` singleton counter. Across
both image bases and absent/SDK 30 fresh ELF controls, Python has **310/310
allocation sizes and pointers and 115/115 ordered frees identical to the
native oracle**. Evidence: [outer constructor allocator match](evidence/vm9_outer_constructor_allocator_match_20261006.json).

This is an allocator/free-ledger result. Formatter text, locale and sink
dispatch, the native `+0x26cf08` handoff, descriptor writer, logger callback
semantics and fresh Medusa output remain open. The descriptor trampoline is
still an explicit rejection boundary; this result does not establish a
complete Python Medusa or an online signer.

## 2026-10-06: 外层 constructor 的 logger 与 descriptor trampoline 边界

新增 [outer constructor boundary verifier](python/verify_vm9_outer_constructor_boundary.py) 和 [边界证据](evidence/vm9_outer_constructor_boundary_20261006.json)。从 fresh ELF/TLS、同次 actual allocator 和虚拟启动服务开始，4 组（两种 image base × absent/SDK 30）都到达 `+0x26e9e0` logger callback，然后进入当前 active 的 `+0x2584ac` descriptor trampoline。每组都记录了 callback 参数块、descriptor 地址、field0 branch target 和 field8 传给后续分支的对象；不同基址只改变 relocated 地址，字段关系和停点一致。配套的 [native logger trace](python/verify_vm9_native_logger_trace.py) 又在同样两种基址与 absent/SDK 30 共 4 组记录了真实 `+0x26e9e0 → +0x271ec8 → +0x271ddc` 寄存器入口，并确认返回到 `+0x26cf0c`；这组 native 结果用于和 Python descriptor 参数做差分，不能直接当成 Python 实现。

该控制在 trampoline 处显式拒绝，未把它替换成 no-op，也未把静态猜测当作 callback 实现。当前已确认 descriptor 位于 native bridge argument+8，field0 是 logger branch target，field8 是后续 x0 object；`+0x2887f0` 仍未成为当前 active path。可选 logger provider 控制见 [provider evidence](evidence/vm9_outer_constructor_logger_provider_20261006.json)：absent 两组继续到达同一 `+0x2584ac`，SDK=30 两组在已有 singleton136 前置条件处拒绝，错误为 `SDK conversion requires an initialized singleton136`。

新的 native outer trace 说明这条 `+0x2584ac` 不是外层 constructor 的 native active path：4 组 native 控制都走 `+0x257084 → +0x257308 → +0x168324 → +0x26cf08 → +0x26e9e0 → +0x271ec8 → +0x271ddc`，没有进入 `+0x258488/+0x2584ac`。因此 Python 到达 trampoline 是 VM prelude/分支不一致的证据；logger/global 的实际状态写入、native `+0x26cf08` handoff、descriptor writer 的输入驱动对象图仍未恢复，这不是完整 outer constructor、fresh Medusa 或线上签名证据。

本轮继续把 native `+0x168324` 入口和 Python outer 的 `VM +0x991c0` 入口并排采样。两者的 fresh stack、root object、descriptor（callback `+0x258520`、return `+0x257250`）和 VM stack 地址已对齐；但 native `+0x1683f0` 处保留的 32 个 backing words 与 Python 当前生成的 backing 不一致。受控地把整组 native backing words 写入 Python 只会绕过 logger 停点，随后在未映射 guest page 停止，因此不能作为实现。该实验仅用于定位，未把 native 快照写入生产路径。下一处应恢复 `+0x257084/+0x257308` 产生这些 backing words 的 fresh caller spill，再重新执行 Python/native 差分。

## 2026-10-06: actual allocator 外层前段组合

`verify_vm9_outer_prefix_allocator.py` 已完成 fresh main startup → registry string caller → actual root → 两 child/handler → callback publication 的同次 guest 状态组合。4 组（两基址 × absent/SDK 30）通过，147/716 VM steps，root reference count=1，JNI publication 的 invoke/type/delete 顺序通过；缺页输入回滚。该证据仍是 Python-only composition，不是 native whole-prefix match，也没有产生 fresh Medusa 签名。

This file records the current state of the independent VM9 work. It is a
checkpoint, not a completion claim.

## Current registry-string caller and C-string append (2026-10-06)

[Live C-string append](python/vm9_objects.py) +0x2486b0 is restored with both
byte loops, partial prefix/length publication and reserve/memmove tail.
Moving/in-place realloc, poisoned alias reads and modeled NULL failure effects
match **28 native controls / 8 rollback checks**. Unsupported provider/memory
or resource-bound failures roll pages back; native NULL realloc preserves
partial writes and the wrapper's object return. Matching-libc realloc itself
is not restored. [Evidence](evidence/vm9_cstring_append_native_20261006.json).

[Registry owner](python/vm9_registry.py) now generates the independent
+0x256e50 caller and runs VM +0x98d50. It composes lazy decode, existing scoped
writer, C-string/object append and release. All32 caller slots are retained
for a later invocation at the same SP. The correct acquisition pair is VM
native SP-0x48; pre-free node padding is checked, not hidden by final poison.
**12 native / 6 rollback controls** pass at both bases: cold/three-call sequences,
growth before formatting, empty/binary values, relocated stack/canary and
allocator-time padding changes. Each return's all32 slots, guest/image/TLS,
pre-free bytes, allocator blocks and TLS/wake order match. Typical cold/warm
VM lengths are 147/119 steps, stop +0x99018. These are newly constructed
registry-layout inputs with **explicit warm TLS and synthetic allocation
effects**, not complete actual-allocator process startup.
[Caller evidence](evidence/vm9_registry_string_caller_native_20261006.json).

Large accumulated data reaches +0x256ff0 -> +0x248908 formatting; it remains
closed, with third-call rollback after two completed large appends. Preflight,
missing source, VM step budget and late free-provider errors also reject,
preserving guest pages and VM base. Affected old string and registry suites
terminate with **204 native / 22 rollback checks**.
[Regression evidence](evidence/vm9_registry_string_regression_20261006.json).

Next compose main startup, registry/reference and this string caller in one
actual allocator/TLS prefix, then execute actual root and outer publication.
Full independent Python outer construction, fresh Medusa output, online
headers/f13, no-JVM Rust, nonempty search/pagination, other platforms and final
Pages/Actions products remain incomplete. See [signer report](SIGNER_CONSTRUCTION.md).

## Previous recursive mutex and native outer-signer control (2026-10-06)

The actual-libc oracle now has an explicit private recursive-mutex opt-in.
It validates NULL or attr=1 initialization and serial TLS owner/depth branches
before executing the actual matching-libc exports. The ordinary default stays
closed to recursive/shared/error-checking/destroyed/wait states. Existing Python
stdio mutex semantics are reused: **48 native controls / 15 rejection checks**
pass across both bases, cross-page layouts, overflow/wrong-owner outcomes and
same-run construction/acquire/recursive-release/reacquire with two TLS tids.
[Mutex evidence](evidence/vm9_recursive_mutex_native_20261006.json).

The previous native-only outer frontier at 307 mallocs / 115 frees was the
oracle rejecting this mutex, not a constructor failure. The reproducible
[fresh outer control](python/verify_vm9_outer_signer_native.py) now naturally
returns from +0x1658e4 -> +0x27c930 for **10 controls**: two bases times four
SDK profiles plus altered stack/mapping/canary inputs. Each executes 310
actual malloc PLTs, 115 free PLTs, one small GC and three small flushes.
Same-run main startup, actual root, both children/handlers, root slot/guard,
count=1, callback pairs and ordered two-tag publication/JNI cleanup are
asserted. A second actual warm getter reuses the wrapper with no new
allocator/provider effects. The root caller SP is getter SP-0x210; no guessed
native backing formula or captured root input seeds a Python comparison.
[Outer evidence](evidence/vm9_outer_signer_native_20261006.json).

Virtual OS, clock/properties, three unexecuted pthread descriptors, diagnostic
scope exclusions and JNI services remain explicit. This is **native-only
outer completion under bounded providers**, not independent Python outer
construction, same-startup Python worker/root composition, real host threads,
fresh Medusa output, online full-header matrix or f13 freeze confirmation.
The bounded Python +0x256e50 caller is now verified above; same-startup actual
allocator/TLS prefix/root and outer assembly/publication remain to compose.
Affected regressions terminate with **106 native / 34 rejection or rollback
checks** (signer components, actual root and old recursive initialization).
[Regression summary](evidence/vm9_recursive_mutex_regression_20261006.json).
Rust, nonempty search/pagination, Douyin/Qidian and final Pages/Actions products
remain incomplete. See [signer report](SIGNER_CONSTRUCTION.md) for reproduction
and evidence limits.

## Previous small-GC and actual-root checkpoint (2026-10-06)

Small-cursor GC +0x9833c is restored by the shared matching-libc exit/cache
owner: **28 native controls / 8 rollback checks** pass. Positive low water
reuses the real shared flush, negative low water adapts fill, and W-register
variable shift, low/cursor/event updates match. Malloc, void free and large
allocation trigger the small GC correctly. Large-cursor GC stays closed;
legacy public entries without an explicit GC callback retain event=228
rejection. [GC evidence](evidence/vm9_libc_gc_native_20261006.json).

The [actual root bridge](python/vm9_root_allocator.py) now composes natural
cold malloc, actual small/large allocation, shared small flush/GC/extent
release and existing root/TLS/registry/state owners in one GuestOS transaction.
[Strict verifier](python/verify_vm9_root_allocator.py) terminates with
**10 native controls / 8 rollback checks**: two bases times four SDK profiles,
plus two controls changing stack, mapping cursor and TLS canary. Every run
naturally returns after 206 actual malloc PLTs, 93 free PLTs, three small
flushes and one GC. Root VM has 716 steps and stops at +0x99f04; count=1.
All32 slots, guest objects, all main-image pages, observed TLS/libc globals,
all retained mapping pages, ordered effects and OS records/protection/cursor
match. Observable malloc/TLS/cache-refill spills derive from explicit SP,
ELF offsets, TLS canary and live cache/refill state. No native snapshot or
substituted allocation seeds Python. [Root evidence](evidence/vm9_root_actual_allocator_native_20261006.json).

Preflight, mapping/observer and oversized-property failures preserve pages,
owned mappings/cursor and VM base. Late controls fail after GC, free #93 or
allocation #206; external provider effects are not rolled back. The former
170-allocation/54-free GC frontier below is historical. This proves a bounded
independent actual-root factory, not same-startup worker/root composition,
full physical-stack emulation, fresh request signing or an online pass.
Realloc/large GC/nondefault config/host threads remain outside this result.
Next compose root after the same fresh startup worker, then continue outer
signer/handle initialization and compare fresh Medusa outputs. Rust, nonempty
search/pagination, other platforms and final Pages/Actions remain incomplete.

Affected regressions terminate with **90 native / 55 rollback checks**
(old fresh root, small flush, cached free, default tcache boundaries).
[Regression evidence](evidence/vm9_root_actual_allocator_regression_20261006.json).

## Previous full-small-cache flush and root GC checkpoint (2026-10-06)

Matching libc free +0x91d18 -> +0x97f40 is now implemented by a single
_flush_small_bin owner in [vm9_libc_exit.py](python/vm9_libc_exit.py).
TSD destruction reuses remaining=0; ready-allocator C free retains the final
half of a full bin, groups returned slots by actual arena, updates shared
bitmap/tree/stats under the correct mutex, moves retained slots and updates
count/low-watermark before appending the incoming free. The new public entry
is release_small_with_flush; the old cached-free entry keeps its strict
full-bin boundary. Duplicate incoming free is checked before flushing.

[Fresh differential CLI](python/verify_vm9_libc_small_flush.py) terminates with
**14 native controls / 7 rollback checks** across both bases: 32/128/256-byte
classes, reuse after flush, three consecutive flushes, foreign-only and mixed
arena cache slots. Every defined malloc result and every malloc/void-free
return's full observed globals/TLS/retained-mapping bytes match. Final guest,
OS order, mappings/protection/cursor match. No native snapshot seeds Python.
Busy bin mutex, corrupt count, wrong class, full-cache duplicate, late duplicate,
late GC and third-slot provider failure reject atomically; late controls
perform three/four actual slab returns. Affected same-startup guest exit,
old key-phase and cached-free regressions terminate with **20 native / 24
rollback checks**. Evidence: [small flush](evidence/vm9_libc_small_flush_native_20261006.json),
[regressions](evidence/vm9_libc_small_flush_regression_20261006.json).

The subsequent independent Python root attempt passes the former class-2
8/8 full-cache boundary and reaches **170 allocations / 54 frees**, then
rejects free tcache event=228. GC cursor=0, signed low-watermark=-1, fill
divisor log2=1. Static instructions assign the branch +0x91cbc -> +0x9833c;
recover that GC owner before another full native/Python actual-root comparison.
[GC frontier](evidence/vm9_root_actual_allocator_gc_frontier_20261006.json)
explicitly marks root completion/native root comparison/fresh signer false.
No GC counter reset or bypass is used. Complete independent Medusa, online
header/f13 matrix, no-JVM Rust, nonempty search/pagination, other platforms
and final Pages/Actions products remain incomplete.

## Current actual-allocator joinable guest pthread-exit checkpoint (2026-10-06)

The same fresh ELF main startup, generated nonempty queue worker and natural
matching-libc allocator now continue through the complete **joinable guest
pthread_exit branch**. **2 native controls / 6 rollback checks** terminate
successfully at both bases. Each run has 22 actual malloc PLT calls, six caller
returns and independently counted **48 native / 48 Python nested returns**,
then three allocator, one support and one libc emutls-array destructor return.
All32 slots and virtual stack match at every default caller; full observed
image, both TLS areas, libc globals and all retained mapping pages match after
each of five callbacks and at final state. OS/clock/wait/wake/service ordering,
mapping records/protection/cursor match. TLS values clear, pthread return=9,
state=1, libc destructor/cleanup heads are empty, and guest exit(0) is reached.

[vm9_libc_emutls.py](python/vm9_libc_emutls.py) restores +0x9be24/+0x9bd10/
+0x9bd90 and +0x9bd3c from fresh ELF/explicit descriptors and actual allocation.
Its capacity/indexed-pointer ABI differs from the main image emutls header.
**20 native controls / 9 rollback checks** pass, including descriptor/template
comparisons at each return, aligned payloads, multiple descriptors/threads and
actual component free. The fixture resolves defined pthread_create's +0xd8da8
ELF relocation; it does not set a ready flag or create host threads.

[vm9_libc_release.py](python/vm9_libc_release.py) restores the bounded matching
empty small slab/extent release and default purge, using the shared bitmap
owner with actual bin-to-arena mutex transitions. Ordered explicit advisory
madvise lengths 4096/20480, advice=4 and result=0 match native. The virtual
service does not simulate kernel page discard. The full wrapper in
[vm9_libc_exit.py](python/vm9_libc_exit.py) reuses the shared pthread-exit body
under one GuestOS transaction; publication occurs only after complete success.

Busy emutls mutex, unknown cleanup handler, first/second purge failure, late
unknown key destructor and terminal provider failure reject with all guest
pages/mappings/cursor unchanged. Late checks execute both madvise calls, and
the terminal failure reaches its exit provider. External provider effects do
not roll back. All five affected regression CLIs terminate successfully:
**154 native controls / 61 rollback checks** across old key-phase, shared
pthread_exit, cached free, worker allocator and tcache.

Evidence: [full guest composition](evidence/vm9_same_startup_worker_actual_allocator_pthread_exit_native.json),
[libc emutls](evidence/vm9_libc_emutls_native_20261006.json),
[regressions](evidence/vm9_same_startup_worker_actual_allocator_pthread_exit_regression.json).
Commands, ABI and boundaries are in [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md).

Actual detached worker unregister/region reclaim is not composed; host thread
creation/termination, all allocator/emutls branches, root composition and
fresh Medusa remain unverified. Growth, whole-region release, spare-region
replacement, large cache/huge free, profiling and custom hooks still reject.
No-JVM Rust, nonempty search/pagination, Douyin/Qidian and final Pages/Actions
products remain incomplete.

That stage's first actual-root Python attempt stopped at 165 allocations /
42 frees and a full class-2 cache. [Its frontier evidence](evidence/vm9_root_actual_allocator_frontier_20261006.json)
still describes that old incomplete run. The newer 14/7 small-flush controls
above restore the branch; the current Python root stops at 170/54 and GC.
Neither partial root run proves native root comparison or fresh signing.

## Prior actual-allocator worker TLS key-exit checkpoint (2026-10-06)

The same fresh main startup, startup-generated nonempty worker, natural
matching-libc allocator and six default tasks now continue through actual
allocator/support thread-key cleanup. **2 native controls / 5 rollback checks**
pass at both relocated bases. Each run retains the prior 22 actual malloc PLT
calls, six caller returns and independently counted **48 native / 48 Python
nested returns**, then executes **three allocator +0x99584 callbacks and one
support callback across three key passes**. All32 slots and virtual stack match
at each default caller. Full observed image, both TLS areas, libc globals and
every retained mapping page also match after each of the four destructor
returns and at final exit-key state. Ordered OS/clock/wait/wake effects, mapping
records/protection/cursor match. Both allocator and support TLS key values clear.

The new [matching-libc exit owner](python/vm9_libc_exit.py) restores bounded
+0x99584/+0x9975c, tcache ring detachment and stats draining, small-cache flush
including foreign-arena slots, actual direct/internal small release, arena
reference/table cleanup and TSD fallback allocation/republication. The native
control exposed a nonempty cache slot owned by another arena; treating all
slots as belonging to the preferred arena correctly failed before recovery.
Fallback allocation now preserves the outer key-cleanup page staging chain;
no native bytes initialize Python. The pre-change composed control failed at
the missing actual allocator destructor, and the final differential CLI exits 0.

Busy cache mutex, count overflow, nonempty large cache, a late unknown key
callback and a late invalid support vector all reject with **all guest pages,
owned mappings and cursor unchanged**. The latter two run at least three actual
internal releases before rejecting, proving rollback beyond early validation.
External provider effects remain outside rollback. Fresh tcache, independent
worker allocator and generic key-cleanup regressions pass **94 native controls /
35 rollback checks**, with every CLI terminal. Evidence:
[actual allocator TLS exit](evidence/vm9_same_startup_worker_actual_allocator_tls_exit_native.json),
[shared regressions](evidence/vm9_same_startup_worker_actual_allocator_tls_exit_regression.json).

The next native-only probe enters +0x68138 -> +0x6b2a4 -> +0x9be24,
creates natural libc emulated TLS and invokes its +0x9bd3c key destructor.
With an explicit successful virtual madvise service, one base reaches two
advice=4 requests (4096 / 20480 bytes) and guest exit(0). This is a path-locating
probe, not a Python composition pass. Its getter/array destructor, empty
slab/extent release and purge services are now covered by the newer guest
joinable composition above; the old probe is still not that proof.

This older entry composes the actual allocator **key phase**. It still rejects
matching empty-slab release/purge; the newer wrapper above covers those in the
guest joinable branch. Nonempty large-cache cleanup, profiling and other
allocator branches still reject. Actual detached unregister/reclaim, host
thread termination, root composition, fresh-input Medusa and the online
header/f13 matrix remain unverified. No-JVM Rust, nonempty search/pagination,
Douyin/Qidian and final Pages/Actions products remain incomplete.

## Prior normal-return same-startup worker/actual-allocator checkpoint (2026-10-06)

The actual-allocator main startup now feeds its generated nonempty queue worker
in the same fresh native/Python run. **2 native controls / 4 rollback checks**
pass at both relocated bases: main and worker use distinct explicit IDs 137/271,
separate 64 KiB stacks and independent TLS. Each complete native run executes
**22 actual malloc PLT calls and one actual argument free**, with zero substituted
allocator returns. Six top-level default caller returns and separately measured
**48 native / 48 Python nested returns** match. At each caller all32 slots,
virtual stack, observed full image/TLS/libc globals and every retained mapping
page match; final guest/image/both TLS/global/mapping state, ordered virtual
OS/clock/wait/wake effects, mapping records/protection/cursor also match.

An early composed probe used the oracle's fixed main gettid in the worker.
Only the guard owner at +0x3e2f3c differed; it did not prove missing runtime
initialization. A callable explicit gettid provider now follows current TPIDR,
retaining the old integer path. No expected bytes, copied native TLS or relaxed
assertions supply the fix. A wrong temporary negative-fixture once address was
also corrected before the final all-case CLI reached exit 0.

The new production run_default_queue_worker publishes guest/mapping state only
on complete success. Unmapped stack, busy third once, failed third broadcast and
late reintroduced argument ownership prove rollback, including failure after
all six task bodies. External provider effects remain visible. Small free,
main-startup and independent-worker regressions pass **32 native / 24 rollback**;
all three CLI runs are terminal. The shared interpreter is unchanged.

This prior normal-return control frees the argument into the actual small
cache and retains support/TSD in TLS. The newer key-exit checkpoint above
restores the bounded +0x99584 cleanup/internal-free path. Real OS thread
creation/termination, full allocator branches and root composition stay open. Fresh Medusa/signing, online
header/f13 matrix, no-JVM Rust, nonempty search/pagination, Douyin/Qidian and final
Pages/Actions products are not complete. Evidence:
[same-startup worker](evidence/vm9_same_startup_worker_actual_allocator_native.json),
[regressions](evidence/vm9_same_startup_worker_actual_allocator_regression.json).

## Current main-startup/independent-worker allocator checkpoint (2026-10-06)

Fresh main +0x28040c startup now composes actual malloc in **2 native controls /
3 rollback checks** at both relocated bases: sixteen actual malloc PLT calls,
three explicit guest thread descriptors and two destructor registrations. All32
VM slots, full main image, main TLS, libc globals, owned mapping bytes and ordered
OS/descriptor/registration state match. The initializer publishes guest and
mapping state only after the whole startup returns; third thread-create failure
proves late rollback while external provider effects remain visible.

Independent worker allocation adds **14 native controls / 8 rollback checks**.
After natural main malloc boot, fresh worker TLS follows +0x99610 ->
+0x99600/+0x8e0ec -> +0x996d4: the temporary circular fallback node, real
128-byte TSD allocation, exact partial field initialization and key publication
are recovered. An explicit foreign live-node control verifies insertion/removal
without destroying its existing ring. Default one/two-arena selection, arena 1
construction and clean region allocation now compose. +0x7de3c/+0x8ed90 also
allocates the worker's arena pointer table through actual internal small malloc;
omitting it produced real retained-page differences, not just a counter mismatch.

Small/large/mixed requests, two workers, one CPU and forty 65536-byte requests
crossing regions match at every return, including all observed globals, TLS and
retained mapping bytes plus OS order, mapping records/protection/cursor. Related
tcache/region/cold/large/serial-task regressions pass **148 native / 70 rollback**,
with all five CLI runs terminal. These remain serial virtual-OS controls;
physical libc stack bytes and real OS thread creation are not claimed.

This earlier checkpoint proved main startup and separate worker allocations.
The newer checkpoint above now closes their same-startup nonempty worker and
normal argument cleanup. Allocator TLS exit, root, fresh request signature and
online matrix still need composed controls. Arena-table resize,
reentrant inflight TSD allocation, full-bin/GC, large cache/free/huge and remaining
callbacks remain explicit frontiers. No-JVM Rust, nonempty search/pagination,
Douyin/Qidian and final Pages/Actions products remain open. Evidence:
[main startup](evidence/vm9_main_startup_actual_allocator_native.json),
[independent workers](evidence/vm9_worker_actual_allocator_native.json),
[regressions](evidence/vm9_worker_actual_allocator_regression.json).

## Current default-task/actual-allocator checkpoint (2026-10-06)

The default +0x280554 task now composes naturally initialized matching libc and
its owned large extents in **2 fresh native controls / 4 rollback checks** at two
relocated bases. Each native execution reaches six default returns and separately
counts **48 actual nested returns**, matching Python's 48. Six malloc PLT calls
enter actual libc malloc selected from its ELF symbol; six large bodies execute,
with zero substituted allocator returns. First allocation naturally boots FILE/CPU,
atfork/table/TSD and flag 0. All32 slots/virtual stack/main image/owned mappings
match at each caller; final TLS/globals/OS/mapping state and once/broadcast order
match. Legacy default task, large and cold regressions pass **42/21**.

A private prototype's nearby stack produced stack-shaped TLS-tail differences.
Moving only the execution stack to an independent 64 KiB region closes final TLS
matching at both bases; no native TLS snapshot or relaxed assertion supplies it.
The formal fixture uses separate stack and TLS. OS/broadcast services and the
thread input remain explicit and virtual. Busy third once and failed third
broadcast also prove late whole-task page/mapping/cursor rollback.

This is a serial default-task composition, not a same-startup independent worker,
complete root or fresh Medusa result. The newer checkpoint above restores the
bounded missing-thread TSD and default one/two-arena branches. Full cache/GC and
the remaining callback/OS boundaries still need real sources and controls. Rust, nonempty search/pagination, Douyin/Qidian and final Pages/Actions
products remain open. Evidence: [task/allocator](evidence/vm9_default_task_actual_allocator_native.json),
[regressions](evidence/vm9_default_task_actual_allocator_regression.json).

## Current public-large checkpoint (2026-10-06)

Bounded empty-cache public large allocation now matches actual native bodies in
**12 controls / 8 rejection and rollback checks**. Two bases cover unaligned
14337/20481, exact 16384/65536, six consecutive 16384 requests and forty 65536
requests crossing arena regions. Natural default cold startup feeds actual extent
search/split/registration, first/last large page marks, free-tree and page accounting,
arena/class large statistics, cache event and TSD allocated bytes. Shared region
and public-context regressions pass **356 native / 141 rollback checks**.

This earlier stage recovered +0x8f6ec -> +0x7a3c8 and the default task's six
allocation requests. The newer checkpoint above now composes their six VM bodies
with actual malloc and owned mappings. The old task controls still substitute
malloc PLT output; the new verifier explicitly selects real malloc instead.
Nonempty large cache/pop/free, uncached/huge, junk/zero, GC, all-branch allocator,
real OS/thread creation, startup/root, fresh Medusa and online/product validation
remain open. Evidence: [large](evidence/vm9_libc_public_large_native.json),
[regressions](evidence/vm9_libc_public_large_regression.json).

## Current default libc cold-return checkpoint (2026-10-06)

Python now reaches the natural default empty-config malloc cold return and flag 0
from fresh ELF/TLS inputs under explicit virtual OS services. Real fgets/refill/read,
EOF/line handling and buffered fclose/cached free feed get_nprocs; real atfork public
allocation, arena-table base allocation and static-to-dynamic TSD migration then
complete. No +0x8e41c frontier shortcut, ready-flag fixture or native boot snapshot
supplies the Python result. The actual fresh atfork mutex is recursive 0x4000;
older normal-mutex component fixtures did not prove this fresh branch.

All **96 new native controls / 27 rejection and rollback checks** pass: readonly
stream **46/19**, CPU query **24**, default cold/fresh public small **26/8**.
Free/runtime-boot/stdio/readonly-FILE regressions add **152/64** passing checks,
for **248 native controls / 91 rejection and rollback checks** in the full run.
The cold CLI records separate full-case, full-cold and full-fresh-small matrix
booleans; a selected-case run does not claim full coverage.

The bounded public path covers 0..14336 bytes, including repeated requests after
TSD migration. Two separate fresh native-only probes return nonnull at 16384 bytes,
while Python rejects the unrecovered public-large size branch. The observed call in those pre-recovery probes
was **+0x8f6ec -> +0x7a3c8**, now recovered in the current checkpoint above. These two probes are not Python/native allocation
byte matches and are not included in the 96 new controls. The newer task/allocator checkpoint above now verifies their serial composition;
same-startup independent worker/root integration remains open.

All-branch malloc/free, real thread/OS creation, startup/root allocator composition,
fresh Medusa, current online headers/f13, no-JVM Rust, nonempty search/pagination,
Douyin/Qidian and final Pages/Actions products remain incomplete.
Evidence: [stream](evidence/vm9_libc_readonly_stream_native.json),
[CPU query](evidence/vm9_libc_cpu_query_native.json),
[natural cold return](evidence/vm9_libc_default_cold_return_native.json),
[regressions](evidence/vm9_libc_default_cold_regression.json),
[large frontier](evidence/vm9_libc_large_frontier_native.json).
Reproduction and boundaries: [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md).

## Independent startup and default queue worker checkpoint

Condition wait/owned wrappers, queue callable lifecycle/loop and nonrepeating
executor deque/poll/signal wait/loop now pass **92 / 94 / 62** fresh native
controls. Eight additional controls run the main startup and a generated idle
executor or queue worker in the same native execution; Python generates its own
arguments independently from ELF inputs and runs the worker with separate TLS.
Guest/main-image/both TLS/generation state, allocation/effect order and argument
cleanup match. All **256 new controls and 22 rejection/rollback checks** pass;
main startup and support/context regressions also pass.

Idle worker normal return was an earlier boundary. All six default
initialization caller bodies and +0x280554's serial task now attach to the
same-fresh-startup nonempty queue worker. Four native controls verify all
six caller returns and 48 nested returns per execution, queue wait/stop,
normal return and argument free with independent thread stack/TLS inputs.
Eight new failure cases and the eight idle-worker controls also pass.
A further same-startup control runs bionic key cleanup and releases the empty
support/wrapper after argument cleanup. Twenty key-cleanup and eight support
destructor controls, plus three rollback cases, pass.
Emulated-TLS arrays, fallback chains, nonempty support loops and the actual
registered scoped-TLS tree destructor now pass 62 further native controls and
13 rollback checks, including same-fresh registration/key cleanup and actual
registry initialization/exit. The actual executor shared/weak destructor and
matching-libc guest pthread_exit now add 70 native controls and 11 rollback
checks, including real libc registration/exit and detached list/mapping cleanup.
A further same-fresh nonempty worker completes the full guest joinable exit body
with all six default returns, 48 nested returns and support/wrapper cleanup;
14 worker rollback checks pass. Unknown callbacks/support-associated state types
still require concrete sources. Actual OS create/termination, complete worker
runtime, all-branch Python allocator and startup/root composition, fresh
Medusa, live header matrix/f13 checks, no-JVM Rust, nonempty search/pagination,
Douyin/Qidian and the final Pages/Actions products remain open.

The six individual callers pass 24 cold/hot native controls at two relocated
bases. Four separate task controls execute five calls followed by the sixth
tailcall; each cold case completes all 48 nested returns using six distinct
mapped 0x4000-byte allocation regions. At each default return, all 32 slots,
virtual stack, guest heap and all six regions match. Main image pages and
ordered allocation/broadcast/once states match. Five task rollback cases and
nine existing caller rejection cases pass. This is a serial task-body result,
not a same-startup nonempty-worker or genuine OS/allocator boot result.

The partial-arena completion claim in commit 1b8aa32 is corrected: pointer
publication alone leaves once pending; only a complete initializer can publish
-1 and broadcast. OP17/sub57 passes 240 W32-multiply controls. No captured
native input snapshot or native initialization pages feed these Python models.

Matching-libc native cold malloc returns under explicit virtual OS services
without allocator hooks in 10 fresh controls at two main-image bases. Actual
reentrant public malloc, CPU file parsing, atfork registration and TSD migration
reach flag 0; entry traces are now recorded without guest pointers or pages.
This was the earlier native-only checkpoint; the new Python default cold return
is verified in the current checkpoint above.

Python now additionally passes 94 arena/bin/bitmap/tcache/static-TSD/arena
constructor native controls and 9 rejection checks, and 46 real base allocator
and same-fresh composition controls with 10 rejection checks. Default empty-config
preinit actually returns with flag 2; initial arena construction/publication,
main TSD and init-mutex transitions compose through +0x8e41c with flag 1.
Actual base allocation owns its mappings, matching extent tree and accounting;
no initialized native pages supply the model. All-branch preinit and public
malloc remain incomplete.

Atfork +0x67374 and static TSD migration +0x99c78 add 24 native controls and
8 rollback checks. Available-slab tree pop +0x75d44 adds 12 native controls
and 3 rejection checks, with no allocation provider. The atfork/TSD
48/128-byte public/internal allocation providers are
explicit control boundaries, not recovered public malloc. NULL/key diagnostic
and TSD fallback branches reject. Mapping helper refactor regressions pass
42 native/20 owner checks; early boot regressions pass 56/7.

Matching-libc same-fresh region and direct/internal small allocation now add
56 native controls and 26 rejection/rollback checks. They compose real base
allocation, empty chunk-cache/default callback/aligned mmap, radix registration,
free extent split, class page marks, bitmap initialization and cold/hot small
allocation. Controls cover unaligned sizes, 65-slot bitmap propagation,
exhausted slabs, multiple regions and actual internal accounting. Four controls
start at the actual +0x8df44 fresh entry (flag 3), including preinit failure;
success leaves flag 2. No allocation provider or native initialization pages
supply these sequences. OS services remain explicit/virtual.

Matching-libc fresh tcache/arena binding and bounded public small now add
52 native controls and 24 rejection/rollback checks. Actual +0x98c54/+0x98490
create zeroed, aligned storage using the recovered region allocator, publish
the circular arena list and initialize all bins. +0x8dda0 restores single-arena
binding. +0x8f00c composes same-owner recursive malloc, cache caller publication,
+0x97ecc/+0x7970c empty-bin refill, cached pop and accounting. Controls cover
zero/unaligned requests, bitmap boundaries, exhausted slabs, multiple regions,
poisoned cached objects cleared by the zero option, NULL/ENOMEM and partial
refill failure. Two ready-flag controls use an explicit fixture, not actual
cold-init completion. All retained mapping bytes, globals/TLS, returns, OS calls
and mapping metadata match; no native initialization pages seed Python.

Actual free dispatch +0x1bac0 -> +0x91990 now adds 16 native controls and
13 rejection/rollback checks for NULL and nonfull clean small cache bins.
Controls include 4096-byte buffer release, six classes, pointer reuse with
preserved poison/zero clearing, batch release/reallocation and state-2 TSD.
Defined allocation returns and all mapping/global/TLS bytes match; C free's
void return is deliberately excluded. Full-bin flush, direct arena release,
large/huge, profiling, junk and GC remain unsupported.

Matching-libc stdio constructors and cleanup registration now add **38 native
controls / 13 rejection and rollback checks**. Three standard and seventeen
static FILE extensions, recursive mutex initialization, existing-pool FILE
selection, preserved padding and guarded cleanup mapping/tail replacement match.
The fresh Python fixture parses seven __sF defined-symbol relocations from the
ELF; these are loader input, never native-generated boot pages. Other unused
symbol relocations are not claimed to be repaired.

Private uncontended recursive lock/unlock, readonly fopen, unbuffered fclose
and regular-file buffer construction add **62 native controls / 27 rollback
checks**. Controls cover depth/overflow/wrong-owner returns, fd limits/failures,
reused FILE, nested locks and close EINTR behavior. Actual fstat and public small
malloc construct 1024/4096/8192-byte buffers; fstat/zero-block defaults and
malloc ENOMEM's inline one-byte fallback match as well. All defined returns,
stdio/allocator/TLS/key state, guest bytes, retained mapping pages, ordered OS
calls and mapping metadata/protection match. Void constructor/cleanup returns
are excluded. Unsupported provider/FILE/character-file/profiling branches
roll back guest state while retaining explicit external effects.

Those earlier two component batches ran the actual same-fresh cold prefix
before an explicit +0x8e41c continuation. Their controls read no file content
and computed no Python CPU count. Evidence: evidence/vm9_libc_stdio_native.json
and evidence/vm9_libc_readonly_file_native.json. The new default cold controls
now join actual fgets/refill/read, buffered fclose/free and get_nprocs to real
atfork allocation, arena-table finalization and TSD migration, reaching the
natural flag 0 return as recorded in the current checkpoint above. Fresh Medusa
and the online header matrix remain open. Multi-arena selection, GC, profiling,
large/huge, cache destruction and concurrent publication are unsupported, as
are earlier region/config/DSS/dirty branches. One radix-allocation failure probe
reached a pending-link wait without return in 300000 instructions; it is not a
successful control or proof of an infinite loop. No-JVM Rust, current nonempty
search/pagination, Douyin/Qidian and final Pages/Actions products remain open.
Evidence and reproduction: [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md).

## Independent root factory and caller (2026-10-04)

The bounded default chain +0x257578 -> +0x257084 -> +0x257308 -> VM
+0x991c0 now runs in Python from fresh ELF/TLS/reference inputs, with **no
native entry or VM prelude snapshot used as model input**. Eight controls
(two image bases x four SDK profiles) match all32 terminal slots,
main-image/guest/TLS/generation state and ordered effects. Root still returns
at716/+0x99f04; full factory counts are **206 allocations / 93 frees**,
2 destructor registrations and9 wakes. Nine caller preflight and two factory
allocation-failure cases prove page rollback and VM-base restoration.

The component verifier retains4 controls/16 VM phases and now76 subtrees,
including Python-generated root caller and constructor. Its native function
inputs remain labeled separately from the new independent factory evidence.

The factory test uses an explicit nonreusing malloc/free boundary and virtual
OS environment. Real allocator global boot/arena/OS state, the outer signer
constructor/handle and fresh request signing are still open. Complete Medusa,
no-JVM Rust, nonempty current search, other platforms and final Pages/Actions
product remain open. See [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md).

## Shared/environment dependencies and observed state/root exits (2026-10-04)

The +0x25ee84 -> +0x26cd0c -> +0x26cdc4 default chain now has Python
shared inline-reference guard/registration/copy, SDK/log initialization,
environment getters, %s/%% formatting, directory checks and cleanup.
Fresh helper differences pass **106 / 15**. JNI, live log endpoints,
interrupted IO, cold SDK-conversion singleton and unknown formatter branches
remain explicitly unsupported.

The earlier state-owner checkpoint passed **16 VM comparisons / 68 complete subtrees**; the current component verifier has76 after adding root caller/constructor. State VM
+0xa46a0 returns at **step363 / +0xa54bc**, with **28 allocations / 21 frees**
and all32 terminal virtual slots matching. Its Python caller prelude also
passes; the full48-byte owner composes **32 / 21**, including seven generated
observable constructor spill words. State caller preflight passes7 rollback
cases with VM image-base restoration.

Root now returns at **step716 / +0x99f04**, comparing **171 / 93**, all32
terminal slots, guest/main-image/TLS/generation and all ordered effects.
The root composition starts from its earlier same-run native VM input and
uses no later constructor/parser/state-owner/state-caller/state-VM entry
snapshot. Independent subtree tests retain their own native function inputs.
Parser remains returned at3318,119/47. The old root step513 phase is retained.

**Complete fresh-input Medusa is still open.** The root caller dependency
recorded here is superseded by the independent factory checkpoint above;
real allocator boot and fresh signer body/online checks remain open. Current no-JVM Rust, nonempty search,
other platforms and final Pages/Actions download product remain open.
See [STATE_OWNER_INITIALIZATION.md](STATE_OWNER_INITIALIZATION.md).

## Earlier configuration initialization and root step605 (2026-10-04)

`vm9_configuration_init.py` composes the observed +0x26194c -> +0x261c54
-> +0x261cb0 -> +0x262608 path. Fresh helper differences pass **166 / 5**;
the SUBS signed-overflow cleanup correction also passes existing stream
regression **174 / 9**. The initializer working SP is entrySP-0x340.
+0x25c71c computes linked iterator distance; the controller's second word
is not a count. +0x26ecb4 returns saved caller X29, not TLS. The wrapper
rewrites two saved frame words and its continuation; native comparisons use
actual epilogues, avoiding shared nested callback return-address collisions.

Four fresh controls pass **12 VM comparisons / 56 complete subtrees**.
Context/wrapper: **125 allocations / 69 frees**, status6. Observed 88-byte
constructor: **134 / 69**, status6. Root now advances to **step605 / +0x99cd8**
before **+0x258500 -> +0x2698f0**, comparing **138 allocations / 70 frees**,
all guest/main-image/TLS/generation state and ordered effects. The earlier
step513 prefix remains an explicit regression phase. Parser stays returned
at step3318, with 119/47 and all32 terminal slots matching.

The root continuation uses its earlier same-run native VM input snapshot;
it does not consume constructor/parser entry snapshots for that composition.
Full independent initialization is still open. Next: +0x2698f0's caller,
VM +0xa46a0 and callbacks, then remaining root/global/OS input generation.
See [CONFIGURATION_INITIALIZATION.md](CONFIGURATION_INITIALIZATION.md).
No current online signer/download success or final product completion is claimed.

## Earlier padding, descriptor unpack and parser return (2026-10-04)

`vm9_objects.py` restores +0x248dd8 -> +0x247a08 padding/reserve/alias
cleanup, verified by **190 native groups / 5 rollback cases**.
`vm9_protobuf.py` restores the bounded +0x256088 -> +0x254330 message
unpack and +0x2550cc recursive cleanup: **208 / 6**. It reads the three
generated descriptors/default templates from guest ELF pages. It rejects
heap scanned-member slabs, custom allocators, packed/oneof and unknown
schemas; it is not a complete Protobuf-C replacement.

All four same-run controls now return from parser at **step 3318 /
+0x9c95c**, with a successful non-NULL unpack of the 165-byte message.
Each compares **119 allocations / 47 frees**, every guest/main image page,
TLS/generation state, ordered effects and all 32 terminal VM slots.
Complete constructor/config/cipher/unpack subtree comparisons rise to **44**;
the unpack subtree also compares its actual returned pointer. The fill-only
intermediate checkpoint was step3134, 101 allocations / 27 frees.

`vm9_parser.py` now derives the required +0x262608 caller workspace,
VM descriptor and initial slots in Python. Four earlier-entry caller controls
also return with the same 3318 steps, 119 allocations / 47 frees and all
32 slots; **7 caller preflight/rollback cases** pass. These caller tests do
not use the native VM-entry prelude snapshot. They still use native inputs
at the earlier caller boundary, including root heap/TLS/global state.

Root remains step513 / +0x99b40. The original component VM tests retain
native VM entry snapshots; serialized guard/OS/diagnostic boundaries remain.
Next: restore +0x261c54 -> +0x261cb0 initialization and generate the state
before the now-recovered +0x262608 caller. Full independent current Medusa remains open.
See [PARSER_UNPACK.md](PARSER_UNPACK.md) for ABI, evidence and limits.

## Earlier stream reference and cleanup checkpoint (2026-10-04)

`vm9_stream_cipher.py` restores +0x243cac state construction, +0x243d50
processing, +0x243dac one-shot wrapping, +0x258fd8/+0x2592b8 configuration
reference construction and +0x166e74 string reference cleanup. Fresh synthetic
native differences and independent ARC4 checks pass **174 groups / 9 rollback
cases**, including key/state aliases, discard, split calls and pre-free bytes.
The one-shot native harness explicitly loads length into X5 and compares all
264 stack-state bytes; old generic oracle registers stopped at X4.

All four same-run controls now reach parser **step 725 / +0x9b200**, before
+0x2635ac calls +0x248dd8. It compares 100 allocations, 26 frees and all guest,
image, TLS/generation and ordered effects. Complete subtree comparisons rise
to 36, with the actual stream result reference checked even on native stack.
Root remains step 513; input prelude snapshots and serialized guard/OS
boundaries remain explicit. See [STREAM_REFERENCE.md](STREAM_REFERENCE.md).
Next: +0x248dd8 -> +0x247a08 fill/resize/cleanup, then +0x256088 and the
remaining parser/88-byte initialization. Complete Python Medusa is still open.

## Earlier configuration-decrypt milestone (2026-10-04)

`vm9_cipher.py` restores guest-table schedules and block encryption/decryption,
CBC updates and observed +0x25ab1c branches. `vm9_cipher_callback.py` composes
mode-0 +0x259dbc with context clearing, two actual singleton getters, forward
byte copy, last-byte-only trimming, reference/count construction and cleanup.
Fresh component evidence: **256 / 11** cipher and **200 / 12** callback
native-difference / rejection-and-page-rollback groups. Pre-free bytes and
allocation order are checked; independent AES is a verifier-only oracle.

The same-run verifier now crosses +0x263534/+0x259dbc, clones the resulting
string and executes another checked forward copy. Parser reaches **step 612 /
+0x9b03c**, before +0x263584 invokes +0x2592b8. All four native controls match:
93 allocations, 23 frees, all guest/image/TLS/generation bytes and ordered
allocator/clock/destructor-registration/wake effects. It compares 32 complete
configuration/constructor/cipher subtrees, including 12 new cipher comparisons.
Root remains step 513 at its 88-byte constructor prefix.

See [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) for pointer ABI, behavior,
reproduction commands and evidence use. Full Python startup remains open:
same-run VM input prelude snapshots and serialized OS/guard boundaries are
explicit. Callback initialization modes 1/2/3 and nonzero environment checks
reject. Next is +0x2592b8 -> +0x258fd8 -> +0x243dac's separate stream/reference
path, followed by remaining parser and 88-byte initialization.

## Earlier configuration-tree checkpoint (2026-10-04)

`vm9_registry.py` now models comparison +0x2473dc/+0x188a94,
configuration-container construction +0x25bf14, lookup +0x25c168,
transferred-pair insertion +0x25bf3c and setter +0x2568c8.
The comparator uses unsigned bytes, returns -32768 for invalid fields,
and terminates equality at a shared NUL. Nodes preserve four padding bytes;
insertion includes predecessor uniqueness checks, rotations and recoloring.
Duplicate insertion deletes the incoming key and frees the previous value.
Native allocator mutation at pair/node read points is explicitly tested.

[Tree evidence](evidence/vm9_registry_native_20261004.json): 96 native
difference groups / 11 rejection-and-page-rollback cases. Each tree sequence
uses one native execution with a persistent allocator and checks intermediate
states; query objects remain independent of transferred/freed keys.

[Constructor evidence](evidence/vm9_registry_initialization_native_20261004.json):
38 groups / 14 rollback cases. The complete +0x2566ec and +0x166370 bodies,
and cold/warm +0x15e694 / +0x161068 getters, match with explicit warm TLS,
clock, allocator and serialized successful-guard boundaries. The setter
returns the prior u32 or native marker 0x000a985f. All pre-free payloads are
compared before poisoning; matching final poisoned pages alone hid padding.

The [same-run verifier](evidence/vm9_root_vm_prefix_native_20261004.json)
now adds 20 constructor/setter/getter comparisons across four fresh native
controls. Each starts at that run's input prelude and executes the entire
subtree in Python, including cold emulated TLS, bionic keys, destructor
registration, map population and lazy publication. Guest/image/TLS/generation
bytes and ordered allocator/clock/registration/wake effects match.
Matching bionic unlock saves a frame pointer that is later copied as TLS
padding; node erase saves its guard pointer in that reused stack slot.
Both are derived from caller SP and modeled before later reads.

This closes the constructor-body/configuration-map dependency under the
stated serialized boundaries. Full OS concurrency, native diagnostic/stack
effects and the full Python startup remain outside the proof. At that checkpoint parser still
stopped at step 325 / +0x9aca4 before +0x259dbc; root remains step 513 at its
88-byte prefix. Next: recover +0x259dbc -> +0x276b9c -> +0x25ab1c block
processing and key/state generation, then extend the same-run parser.
Independent current Medusa, no-JVM Rust, current nonempty search/paging,
Douyin/Qidian and the final Pages/Actions tools remain incomplete.

## Singleton dependencies, cold TLS and scoped writer (2026-10-04)

The 136-byte singleton prefix +0x166370 -> +0x166544 and 320-byte
registry prefix +0x2566ec -> +0x256808 now have input-driven models.
GOT-dependent table reads, normal mutexes, the full 56-byte helper and
realtime clock wrapper pass 78 native differences / 13 rollback cases.
The clock getter +0x26cc60 is not thread startup.

Emulated TLS passes 60 differences / 12 rollback cases; matching bionic key
creation passes 36 / 4. The current libc generation table is +0xe0200,
distinct from the older checkpoint's +0x1d0200. Cold once completion also
requires its real no-waiter futex wake; matching memory alone missed that
event until the same-run comparison was expanded.

Local thread-destructor registration and cold scoped TLS-tree initialization
pass 32 / 5. Zero/one live mutex scoped writer acquire/release passes 42 / 7,
including same-mutex nesting, copied stack padding, poisoned free, condition
u32 wrap and explicit wake. Multiple live keys, shared readers, contention,
host keys and destructor execution remain outside the supported branch.

Four same-fresh-native controls compare eight original VM phases, eight
constructor prefixes, eight emulated-TLS calls, four cold TLS-tree initializers
and eight scoped acquire/release calls. Guest bytes, all main image pages,
isolated TLS, the complete 2256-byte generation table and allocation/free/
registration/wake sequences match. Cold acquire generates seven allocations;
release frees one node. Each component still starts from its own native input
prelude snapshot: this is not a fully Python startup or a completed parser.

Earlier next step, now superseded above: configuration lookup/update/insertion at +0x2568c8 ->
+0x25c168/+0x25bf3c, complete 320/136-byte constructors and singleton
publication, then +0x259dbc block processing. Parser remains step 325,
root remains step 513 at the 88-byte prefix. Independent current Medusa,
no-JVM Rust, nonempty search, other platforms and the final web tool remain
incomplete. See [construction report](SIGNER_CONSTRUCTION.md) and
[same-run evidence](evidence/vm9_root_vm_prefix_native_20261004.json).

## 88-byte configuration prefix and parser dependencies (2026-10-04)

String append/reserve/alias/cleanup now pass 166 fresh native differences
and eight rejection/rollback cases. MD5/SHA-1 reference construction and
single-byte append pass 142 differences and five rollback cases, including
raw/hex, NULL branches, realloc failures and alphabet/GOT read timing.
SHA-1's lazy padding decode is included; private constants stay in memory.
See [string evidence](evidence/vm9_strings_native_20261004.json) and
[digest evidence](evidence/vm9_parser_digests_native_20261004.json).

The +0x26194c constructor prefix through +0x261a1c is now input-driven Python:
88-byte layout, two string clones, three counts and a distinct 48-byte empty
container graph, with nine successful allocations. Serialized shared-reader
transitions and declared-length clone behavior have independent native checks:
140 differences and 23 rejection/rollback cases.

The later initializer enters +0x261c54 -> +0x261cb0 -> VM +0x9a6f0.
Its +0x258e7c base64/reference dependency, +0x245814 decoder and sized string
constructor pass 200 native differences and 11 rejection/rollback cases.
Explicit nonreusing free, diagnostic and allocation boundaries remain visible.

Four same-fresh-native runs at two bases and absent/SDK 30 give eight VM phase
comparisons. Root step 513 generates the 88-byte prefix (11 total allocations
since that VM entry). Parser step 325 at +0x9aca4 stops before +0x259dbc
(13 allocations and four explicit frees). Guest object/allocator bytes,
allocation order and all main image pages match; parser's 48-byte descriptor
also matches. Both starts use
their own native prelude snapshots for differential testing: no external
captured pages or trace/branch/opaque hooks, but no fully Python prelude claim.

This earlier checkpoint first located +0x259dbc and its
+0x276b9c -> +0x161068 -> +0x166370 dependency, followed by
+0x25ab1c block processing. The newer dependency recovery above supersedes
that earlier blocker description. Remaining parser callbacks, 88-byte
initialization and full independent
Medusa, no-JVM Rust, nonempty search, other platforms and the final web tool
remain incomplete. See [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md),
[object evidence](evidence/vm9_configuration_objects_native_20261004.json),
[decoder evidence](evidence/vm9_configuration_decode_native_20261004.json),
and [VM phase evidence](evidence/vm9_root_vm_prefix_native_20261004.json).

## Root configuration components and native baseline (2026-10-04)

The 264-byte configuration prefix now has an input-driven Python model with
30 nested allocations, separate from the 8-byte configuration singleton.
Masked-byte decoding and serialized normal mutex transitions are also modeled.
The component verifier passes 72 native differences and 25 rejection/rollback
cases. A separate fresh-ELF oracle returns from the full native configuration
generator in 16 cases at two image bases, including present/absent SDK values
and integer truncation/overflow. Each case has 206 allocations and 31 paired
mutex locks/unlocks. The old verifier's TLS/stack overlap has been isolated
and corrected by a single-variable control.

The VM initializer still executes native code in this oracle. Python VM/root
initialization, the 136-byte singleton and global effects remain open; this
does not complete independent Medusa or a no-JVM Rust download chain. See
[SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md),
[component evidence](evidence/vm9_configuration_primitives_native_20261004.json),
and [native initialization evidence](evidence/vm9_root_configuration_native_20261004.json).

## Latest bridge initialization evidence (2026-10-03)

**Correction:** `MS.b(0x1000000e)` returns `MSC.GetABSwitch()` (APK default
`2`), not time. The old bridge populated global `base+0x3d1578` with its frozen
timestamp, coupling two inputs. BC `+0x706c0` tests bit `0x20` before the
publication path. Restoring A/B `2` fixes the +999/+1000 ms and prior failing
inputs; changing only A/B to `34` recreates the failure. Old time sweeps and
monotonic-poll controls below are historical misbound-bridge measurements,
not evidence of native time constraints.

The corrected Python bridge passes success/failure/success with stale output
cleared. An unrounded fresh detail request returns HTTP 200, code 0 and 24,341
bytes. Python independently initializes this A/B global and evaluates its
three-instruction gate: 18 cases on fresh pages at two image bases match actual
bytecode execution, and three invalid cases reject. The default-A/B=2
publication helper at `+0x28c268` sends the constructed root to `0x2000001`
then `0x2000002`; `+0x2a8760` is retained only as a historical misbound
configuration branch. Child/handler construction, callback pair binding,
reference-count wrappers and JNI cleanup are now independently modeled from
fresh pages, while root configuration/global boot and other callbacks remain
open. Future same-capture work must carry corrected A/B provenance. See
[vm9_ab_switch_initialization_20261003.json](evidence/vm9_ab_switch_initialization_20261003.json)
and [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md).

### Earlier controls under the misbound A/B callback

Same-URL controls reproduce an initialization failure before the bridge
publishes the callback-1 network signer handle. The old fallback then passes
the app-manager pointer to signing and dereferences a non-vtable word at
`+0x2a6604`. The private bridge now stops with `SIGNER_INIT_UNAVAILABLE`,
retains failed-run logs, and clears a previous consumable signature. The
positive/negative/positive regression preserves successful signing and a
fresh accepted detail response (HTTP 200, code 0, 24,335 bytes).

Eleven time-input cases return seven signatures and four initialization
failures. Small offsets 0/1/15/16 ms share one output, but +999 ms already
fails within the same seconds timestamp; +2 seconds succeeds while +4
seconds fails. This is a bounded initialization observation, not a general
time-grid rule or recovery of all 16 dispatch branches. Native initialization
from arbitrary fresh inputs is still missing.

A subsequent control advances guest monotonic time by 550 ms in each of 20
readiness polls while keeping the failing wall-clock input. Both this run and
the unchanged clock control still lack the callback-1 handle. Advancing only
poll-time monotonic time is not sufficient; initialization remains open.

Details: [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md) and
[vm9_handle_initialization_20261003.json](evidence/vm9_handle_initialization_20261003.json).
The older external Java search service now has measured nonempty two-page
responses, while the current session-aware first-stage search is still
empty; see [SEARCH.md](SEARCH.md). Independent Python Medusa and no-JVM Rust
remain unfinished.

## Latest verified checkpoint: generated thread state and constructor (2026-10-03)

Python now implements generation-checked pthread TLS, mapped base allocation,
fresh TSD/arena/tcache creation and the input-driven string constructor at
`0x12508344`. The 85-case native differential checks all 4,256 pages, including
nonzero arena/TSD prefills and the entire empty-TLS path through tcache
publication. Eleven rejected cases preserve caller memory. The earlier
83-case allocator lifecycle regression still passes.

The same-capture chain completes again with 303 Python malloc/free calls and
seven Python target constructor calls, with zero native fallback for both.
Its 779-byte output equals the native control and captured MEDCOPY. Seg1 and
Seg2 retain identical nonstack memory; the earlier 15 differing Seg3 bytes
outside the body remain. Other callbacks and host continuation still run
native ARM64, and the integration retains captured thread/region state.

A separate native empty-TLS malloc now returns under an explicit guest policy
for an actual zero-filled anonymous mapping and VMA naming. Python now owns
the corresponding zero-filled mapping transaction and region registration:
from a new arena, `0x13600000..0x13640000` registers a 62-page free extent and
the first class-3 allocation returns `0x13602000`, with native metadata values.
A failed first allocation rolls back the staged mapping and allocator pages.
The global boot reader/publisher covers only the explicit arena/TLS/cache
fields; lookup-cache generation and the remaining callback/object graph are
still unfinished. This does not complete parameterized current Medusa or
prove live server acceptance.

Two native callback boundaries are now input-driven in
`python/vm9_callbacks.py`: the clock wrapper's timespec/result writes and the
active descriptor trampoline's two-field publication. Invalid clock inputs
and the still-uncaptured packed callback-object composition reject atomically.
The remaining constructor/destructor object graph still executes natively in
the same-capture chain.

The 2026-10-03 callback writer probe separates the trampoline from the missing
data flow. Static code at `+0x2584ac` is only `ldr/blr/ldp/br`: descriptor+0
is the branch target and descriptor+8 is passed as `x0`. In the paired native
capture, VM writer `+0x171268` executes `str x15,[x17,x16]`; the observed
descriptor object fields are reached from the writer frame at `x17+0x140` and
`x17+0x148` (equivalent to descriptor `+0x00` and `+0x08`) directly from
`x15`. No independent upper/lower-word packed-x8 formula was observed. The
sanitized record is
[evidence/vm9_callback_writer_20261003.json](evidence/vm9_callback_writer_20261003.json).
This explains the callback boundary but does not parameterize the VM values
that feed `x15`, so the public Python rejection remains intentional.

Details and reproducible boundaries:
[RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md),
[component and integration evidence](evidence/vm9_runtime_initialization_20261003.json).

The bounded region/global component is independently checked by
[python/verify_vm9_os_region.py](python/verify_vm9_os_region.py). It compares
the new-arena path on 4,256 trusted checkpoint pages, verifies zero-filled
guest pages, the available-tree node at `region+0x258`, first allocation
`0x13602000`, and four rejected mapping requests with no mutation. Its
sanitized result is
[evidence/vm9_os_region_register_20261003.json](evidence/vm9_os_region_register_20261003.json).

## Previous checkpoint: lifecycle and paired chain (2026-10-03)

Empty-bin refill, mapped new-slab initialization across 36 classes, compact
trees, full-bin flush, periodic cleanup and slab release/purge are now modeled
in Python. The 83-case native differential compares all 4,256 checkpoint pages;
360 continuous malloc/free operations also match after every step. Purge needs
an explicit guest OS outcome; fresh OS region/TLS/arena initialization remains
unsupported.

The same detail capture now runs from initial memory through Seg1, the actual
native host continuation, Seg2 and Seg3. It matches 95,979 VM events and 293
callbacks, replacing 303 malloc/free calls with Python and no native allocator
fallback. No trained handoff, transition free list, callback-page injection or
target-pointer patch is used. Captured entry registers/native frames and the
existing two-byte Seg1 pointer-tag normalization still remain.

An interpreter correction separates native x28 register backing from virtual
R28. Twelve native divmod/commit pairs validate it, including zero divisors.
Seg1 and Seg2 have identical nonstack memory between allocator controls. Seg3
retains 15 differing bytes at native copy sites outside the final body, plus
call-stack differences. The 779-byte body exactly matches both native control
and captured output. Whole-memory equivalence is not claimed.

Implementation, reproducible checks and limitations:
[ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md),
[lifecycle evidence](evidence/vm9_allocator_lifecycle_20261003.json), and
[paired-chain evidence](evidence/vm9_allocator_same_capture_20261003.json).
Earlier checkpoints below are historical; their refill/cleanup and artificial
transition limitations are superseded only for this verified sampled path.

Current Python Medusa parameterization, independent fresh initialization,
no-JVM Rust signing/download and live nonempty search remain unfinished. The
next step is Python OS-region/global-boot and remaining callback/object initialization, followed
by a new-input run without captured state and then the live server matrix.

## Reproduced diagnostic path

The historical `seg3_verified_final_20260929.txt` path can be reproduced with
the captured `event0_cb66_vm9_*` memory image and the real callback pages for
callbacks 9, 64, and 66. The fresh replay reached:

```text
SUMMARY events=1057/1057 callbacks=87 syscalls=3
```

This proves that the VM bytecode trace, the selected native callback execution,
and the recorded page injections are internally consistent for that captured
sample. It remains trace-assisted because the callback pages and native ARM64
execution are supplied externally.

## Current checkpoint mismatch

The newer `mem_after_seg2_full_diag_20260929.pkl` checkpoint does not reproduce
that path. It diverges at trace 758 after callback 8:

| Path | callback 8 allocator result | callback 8 writes |
| --- | ---: | ---: |
| reproduced historical path | `0x1296b940` | 80 |
| new full-Seg2 checkpoint | `0x1296ba60` | 33 |

The native callback therefore selects a different allocator/free-list branch.
The divergence is before callback 9's real-page injection and is not fixed by
adding Perseus, changing the timestamp, or replaying the same callback pages.

The follow-up allocator audit narrowed the branch further. For callback 8 the
requested size maps to size class `3` and bin `0x12282060`. The historical
checkpoint has count `0` and returns `0x1296b940` through the refill path; the
new checkpoint has count `4` and returns `0x1296ba60` from free-list index `2`.
Forcing only the count to zero, or copying the complete `0x12282000` bin page,
still returned `0x1296b9a0`. Native disassembly and a controlled transplant
then isolated the missing state to the slab counter `[0x1294110c]` and bitmap
word `[0x12941128]`; with those two fields plus the count corrected, callback 8
returned `0x1296b940`.

## Seg1 entry-base and native-frame corrections

The first independent Seg1 runner used the nested-frame jump-base field that
belongs to the later segments. That made the first apparent branch at trace
120 look like a VM or allocator mismatch. Re-running with the actual Seg1
entry base `0x1235a6f0` removed that false divergence. A second mismatch was
then isolated to the native callback context: the diagnostic runner still used
Seg2's `SP=0xe4ffbd70` and `X29=0xe4ffbe90` for Seg1, while the captured Seg1
frame has `SP=0xe4ffb320` and `X29=0xe4ffb440`. With the wrong frame, callback
19 overwrote its argument area and callback 20 reached libc's explicit
`Invalid address 0xe4ffb848 passed to free` abort. Returning zero from
`exit_group` in the early syscall probe had hidden that abort and produced an
irrelevant unmapped read and `accept4` loop.

With the Seg1 frame corrected, the real ARM64 callback runner completed the
captured Seg1 trace: `4592/4592` VM events, 85 callbacks, and one `madvise`
syscall. No callback-page injection was needed for this Seg1 run. The resulting
checkpoint advanced into Seg2 and matched its first 10 native callbacks. The
sanitized diagnostic record is
[evidence/vm9_seg1_frame_probe_20260930.json](evidence/vm9_seg1_frame_probe_20260930.json).

An earlier continuation reached callback 45 and appeared to diverge at VM
trace `12085` (`[0xe4ffcd00]` was `0x2f8` while the older checkpoint expected
`0x2f6`). Pairing the trace with its same-capture memory files showed that this
was a mixed-capture artifact: the paired trace also expects `0x2f8`. The old
`0x2f6` value came from a different capture/checkpoint and must not be copied
into the corrected run.

This is a diagnostic correction, not a completion claim. The runner still
executes captured ARM64 native code against captured memory, and its Seg1
`X22` frame value is inferred from the frame offset rather than directly
observed. The next independent proof must carry the corrected state through
Seg2 and Seg3 without captured-field transplants, then repeat with a fresh
input before treating it as a parameterized signer.

Applying that fixed checkpoint transplant at callback 8 allowed the full
captured Seg2 replay to complete at `90161/90161` events with `121` callbacks.
This closes the captured branch diagnostic, not the independent parameterization
requirement. See [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).

## Same-run full handoff capture (2026-09-30)

A fresh Unidbg capture was taken with a frozen clock and deterministic emulated
random source. Seg1 was replayed from that capture at `4592/4592` events and
85 callbacks. Full memory snapshots taken at the real host transitions were
then supplied to the offline runner:

- Seg2 reached `90153/90153` events and 121 callbacks from the real `NEXT#1`
  handoff, with no callback-page injection or allocator-field transplant.
- Seg3 reached callback 86 and event 1,028 from the real `NEXT#2` handoff. The
  first unexplained host-return boundary is the callback result slot at
  `0xe4ffe630`; setting that slot to the trace-observed zero as an explicit
  diagnostic override lets the replay complete at `1057/1057` events and 87
  callbacks.

This is stronger evidence about the segment and host handoff boundaries, but it
still consumes captured full-memory handoffs from one run. It is therefore a
trace-assisted diagnostic and not a fresh-input, pure-Python Medusa proof. The
sanitized record is
[evidence/vm9_handoff_probe_20260930.json](evidence/vm9_handoff_probe_20260930.json).

## Callback 86 clock-slot provenance (2026-09-30)

The earlier `0xe4ffe630` boundary was then watched in a real Unidbg run. At
entry to callback function `0x12545f60`, the slot contained `0x67e0c91`. The
native callback returned `x0=0`, and the write hook observed an 8-byte zero
store at `0xe4ffe630` from PC `0x12545f70`. The captured code at that PC is:

```text
0x12545f60: stp x30, x19, [sp, #-0x10]!
0x12545f64: mov x19, x0
0x12545f68: ldp x8, x0, [x0]
0x12545f6c: blr x8
0x12545f70: str x0, [x19, #0x10]
```

This identifies the zero as the ordinary result store performed by the native
callback wrapper after the indirect clock function returns. It is not an
unexplained Java-side or host-memory transplant. The sanitized record is
[evidence/vm9_clockslot_native_write_20260930.json](evidence/vm9_clockslot_native_write_20260930.json).

The offline `--clock-slot-zero` replay therefore modeled a real native store,
but it remains a diagnostic replay.

## Native clock model replay (2026-10-01)

The callback-86 path was traced through `0x125514d0 -> 0x12551488 ->
0x125e94b0 -> clock_gettime(1)`. The native helper converts the timespec to
nanoseconds, subtracts the saved start value `123456789000000` ns, then divides
the signed difference by 1000. The offline runner had supplied its wall-clock
timespec to clock ID 1. A same-input failure run returned a nonzero callback
result and diverged at VM event 1,028.

The runner now matches the real Unidbg handler: clock ID 0 uses the frozen wall
clock; nonzero IDs use the frozen monotonic value `123456789000000` ns. With
`--clock-slot-zero` disabled and no callback-page injection, the same Seg3
snapshot reached `1057/1057` events and 87 callbacks. Callback 86 naturally
returned zero and the native wrapper wrote it to `0xe4ffe630`. The sanitized
paired evidence is
[evidence/vm9_clock_model_replay_20261001.json](evidence/vm9_clock_model_replay_20261001.json).

This closes the clock-model discrepancy for one captured input. The runner
still depends on full memory handoffs and native ARM64 images from that run;
it is not yet a fresh-input pure-Python signer.

## Static constructor argument replay (2026-10-01)

The second captured URL exposed a concrete constructor-argument error in the
independent runner. Native constructor `0x12508344` treats nonzero `x1` as a
string pointer: it calls the length helper at `0x12607f40`, allocates
`strlen(x1)+1` through `0x12607fd0`, and copies through `0x12607f60`. The old
diagnostic used `0x1296ba90`, an allocator dynamic-area address. The same-capture
trace supplies `0x1232fe64` as the static argument for this replay.

The old dynamic pointer failed at trace event 13 with `r2=0` instead of
`0x122a0d00`. Re-running with `x1=0x1232fe64` completed Seg2 at
`90385/90385` events and 121 native callbacks. The resulting checkpoint matched
the ten captured `NEXT#2` handoff pages except for 153 bytes in two synthetic
native-stack pages. Starting Seg3 directly from that checkpoint still failed at
callback 9, so the full host handoff has not been removed. Supplying the
captured `NEXT#2/vm9_m0.bin` image allowed Seg3 to complete at `1057/1057`
events and 87 callbacks, with two clock syscalls and no clock-slot override or
callback-page injection.

This is a constructor-boundary improvement for one captured input, not a
parameterized signer. It still depends on captured native state for Seg3 and
does not change the pure-Python current-Medusa or no-JVM Rust status. The
sanitized evidence record is
[evidence/vm9_static_constructor_x1_20261001.json](evidence/vm9_static_constructor_x1_20261001.json).

## Dispatcher continuation and input-pairing correction (2026-10-01)

The successful `90385/90385` Seg2 result requires the paired input set used by
the evidence record: the corrected Seg1 checkpoint, the same-capture `NEXT#1`
handoff, and the clean runner whose SHA256 is
`8e1f2b031091d0588dcab46368c2f6b6ca8b1151bf2e890bfeb418b4bc2aa741`. A fresh
recheck with that tuple reproduced 121 callbacks and the existing checkpoint
SHA256 `86a379cca5c8f98cd5c47ac79d001e3a82de3ff2db2263eaaf9a814f027dd3cd`.
Running the raw trial memory files as if they were the same input is invalid:
their allocator state is different and the transition cleanup fails before
Seg2.

Starting that rechecked checkpoint with the paired `NEXT#2` handoff also
reached `1057/1057` Seg3 events and 87 callbacks, with two `clock_gettime`
syscalls, no callback-page injection, and no clock-slot override. This is the
same captured-state boundary proof as the existing static-constructor record,
not a fresh-input signer.

The later continuation experiment was a diagnostic branch, not a replacement
runner. It changed callback `0x12548a4c` to return through `0x1242aa4c`, injected
dispatcher scratch registers, copied native backing slots into the Python VM,
and stopped before `0x125083e0`. That branch observed
`e4ffc9a0=0` and `R2=0` while the trace expected `R2=0x122a0d00`; the full
backing readback therefore created a false register interpretation. The
paired clean replay completes without that injection. `e4ffc9a0` is a native
boundary object slot, not a directly readable Python R2 backing slot. The
sanitized diagnostic record is
[evidence/vm9_dispatcher_slot_refutation_20261001.json](evidence/vm9_dispatcher_slot_refutation_20261001.json).

## OP29 generic rule and second-input recheck (2026-10-01)

The native handler at `libmetasec_ml_71332.so + 0x16e8f0` was disassembled as
OP29/sub34, a signed `BLEZ` branch. Its source register is
`((dw >> 27) & 0x10) | ((dw >> 7) & 0x0f)` and its 16-bit branch immediate is
assembled from the five encoded fields. The VM advances by `4 + imm * 4` only
when the signed source value is non-positive; otherwise it advances by four.
The old `dw == 0x1800811d` fixed-jump special case was removed.

A second URL capture then exercised that exact encoding at trace event 119035:
the source was `R2`, the decoded immediate was `208`, and the native write at
`+0x16eaa4` changed BCP from `0x123ceadc` to `0x123cee20`:

```text
0x123ceadc + 4 + 208 * 4 = 0x123cee20
```

With the generic rule, the paired second-input replay reached `90385/90385`
Seg2 events and 121 native callbacks from `NEXT#1`, then `1057/1057` Seg3
events and 87 callbacks from `NEXT#2`. The clean recheck used no callback-page
injection, allocator-field transplant, clock-slot override, or dispatcher
backing-slot injection. This closes the OP29 decoder/branch assumption for the
captured pair. It still consumes captured host handoffs and native ARM64
images, so it does not close current pure-Python Medusa parameterization.
The sanitized record is
[evidence/vm9_op29_generic_20261001.json](evidence/vm9_op29_generic_20261001.json).

## Minimal paired handoff reduction (2026-10-01)

The second-input capture was rechecked with its paired trace, native images, and
`mem_after_seg1_offline.pkl`; mixed trial memory files were excluded. Comparing
the Seg1 checkpoint with the real `NEXT#1` handoff found only 14 changed pages
and 560 changed bytes:

```text
0x12240000 0x12280000 0x12282000 0x12296000 0x12297000 0x1229e000
0x1229f000 0x122a0000 0x122ac000 0x128a3000 0x1296b000
0xe4ffb000 0xe4ffc000 0xe4ffd000
```

Applying only those byte deltas, without loading the full `NEXT#1` directory and
without the old synthetic `0xe4ffcaa0=0x122a0c20` overwrite, completed Seg2 at
`90385/90385` events with 121 callbacks and zero syscalls. The clean paired
record is [evidence/vm9_minimal_handoff_pair_20261001.json](evidence/vm9_minimal_handoff_pair_20261001.json).

The resulting Seg2 checkpoint differs from the real `NEXT#2` handoff on four
pages, but Seg3 does not need those full pages. A single four-byte state patch at
`0x12641b28`, changing `0x0000001d` to `0x1250c59c`, supplies the indirect native
call target used at callback 9. Starting from the paired Seg2 checkpoint with
that patch and no other `NEXT#2` pages completed Seg3 at `1057/1057` events, 87
callbacks, and two `clock_gettime` syscalls, with no callback-page injection,
allocator-field transplant, or clock-slot override.

This reduces the captured handoff surface, but it does not make the current VM a
fresh-input pure-Python signer: the baseline checkpoint, native ARM64 images,
and callback execution are still captured-state inputs.

## Byte-rule holdout and cross-interface counterexample (2026-10-01)

The paired second URL and a new homepage capture have identical 560-byte change
masks across 14 pages. Of their target bytes, 558 are identical; the other two
are source-byte increments modulo 256: `0x12282018 += 0x1f` and
`0x12296019 += 1`. The public `python/vm9_handoff_rule.py` learned those rules
from the two captures and predicted a third homepage input using only its Seg1
checkpoint. A later comparison with that held-out `NEXT#1` found zero changed
pages or bytes. Seg2 then completed `90332/90332` events and 121 callbacks;
Seg3 completed `1057/1057` events and 87 callbacks with the previously observed
four-byte target correction, two clock syscalls, and no full handoff images,
callback-page injection, or clock-slot override.

The same byte rule fails on the captured detail input: six pages differ by 34
bytes and Seg2 diverges at event 3 (`R2=0x122a0c40`, expected `0x122a0c20`).
This is a counterexample to a general handoff rule, even though the homepage
holdout passed. The initialization-failure capture with the adjacent frozen
timestamp is excluded from the successful evidence set.

## Allocator-derived detail holdout (2026-10-02)

The detail mismatch was narrowed to structural fields. The next 24-byte object
can be derived from the Seg1 size-class state:

```text
count  = read64(0x12282070)
list   = read64(0x12282078)
object = read64(list + (count - 1) * 8)
```

The homepage state has count 6 and selects `0x122a0c40`; the detail state has
count 7 and selects `0x122a0c20`. The optional `--allocator-model` relocates
the trained object to that computed address and writes it into the four
boundary slots. It also applies the shared whole-word training deltas:

| Address | Seg1-to-Seg2 delta |
| --- | ---: |
| `0x12240730` | `+12` |
| `0x12282060` | `+1` |
| `0x12282070` | `-1` |
| `0x12296018` | `+0x78` |
| `0x12296020` | `+0x2e8` |

The scratch word at `0xe4ffb9e0` receives the shared target `0x500` as a full
word. The remaining byte at `0xe4ffbb78` is left unpatched. Static disassembly
shows that this location is a native VM dispatcher slot, slot index 3 when
`x28=0xe4ffbb60`. The available transition write watch shows two store sites
in this dispatcher family: `0x1242d8a4` uses
`str x15, [x28, x10, lsl #3]`, while `0x1242f974` uses
`str x9, [x28, x14, lsl #3]`. The current detail run was not instrumented to
attribute its final store to one site.
The new detail capture predicts `0xc4` and the captured `NEXT#1` contains
`0xb4`; this is a native dispatch-state difference, not a final Python R2
value. The sanitized provenance and body comparison are in
[evidence/vm9_detail_body_compare_20261002.json](evidence/vm9_detail_body_compare_20261002.json).
Substituting the final Python R2 is refuted: that value is `0x122974b8` in
both diagnosis runs and is not the handoff scratch value.

| Capture | Role | NEXT#1 difference after model | Seg1 | Seg2 | Seg3 |
| --- | --- | --- | --- | --- | --- |
| homepage third input | earlier holdout / regression | 0 pages, 0 bytes | `4592/4592` | `90332/90332` | `1057/1057` |
| detail first input | diagnosis; used to develop the correction | 1 page, 1 byte | `4592/4592` | `90352/90352` | `1057/1057` |
| detail new query | held out from correction development | 1 page, 1 byte | `4592/4592` | `90330/90330` | `1057/1057` |

The new detail query's uncorrected control still fails at event 3; only the
structural correction changes that result. Its prediction reads no held-out
`NEXT#1`, and the public CLI produces the same checkpoint hash as the private
prototype. Both detail replays use 85/121/87 native callbacks across the three
segments. Seg3 still uses `0x12641b28: 0x1d -> 0x1250c59c` as a four-byte
target rule. No full handoff image, callback-page injection, or clock-slot
override is supplied. These are offline captures of signed input variations;
the new detail query was not sent to the online endpoint.

The evidence is
[evidence/vm9_handoff_holdouts_20261002.json](evidence/vm9_handoff_holdouts_20261002.json).
This narrows the allocator/object boundary, while captured baseline images,
native ARM64 callbacks, trace entry registers, training target bytes, and the
Seg3 call-target rule remain inputs. Size-class refill is unsupported. The
held-out detail trace's 779-byte body was independently reconstructed from its
STORE8/STORE64 trace regions and compared with the final captured `MEDCOPY`
body; the result is exact (`0` differing bytes). That validates body assembly
for this capture while leaving fresh-input Medusa generation open. Full trace
completion is not a general pure-Python current-Medusa proof.

## Direct native transition watch (2026-10-03)

The temporary independent runner was corrected to use the detail capture's
Seg1 native frame (`SP=0xe4ffb320`, `X29=0xe4ffb440`) and the VM entry base.
With that correction, Seg1 completed `4592/4592` events, 85 callbacks, and one
syscall without callback-page injection. The transition then ran the captured
allocator/constructor, recursive cleanup, and final reference free while
watching the dispatcher slot at `0xe4ffbb78`.

The slot now has direct native attribution in this run: `0x125150d0` wrote
`0x125151b0` four times during recursive cleanup, `0x1218199c` wrote
`0xe4ffbde0` during transition cleanup, and `0x1217f00c` wrote `0x1210bb20`
on Seg2 callback 1. These are native state writes, not VM9 bytecode stores.

The first unassisted Seg2 divergence is relative event 13: the native callback
leaves `0xe4ffc9a0` as zero while the trace requires the transition object
`0x122a0ce0`. Controlled diagnostic slot repairs moved the boundary to event
747 (33 callbacks), where the native-derived word at `0x12296380` differed
(`0x32357c32` versus `0x78c1d3ab`). Supplying that one captured page word moved
the boundary to event 752, where an adjacent unaligned word still differed
(`0x30333830` versus `0xffffffffad396da4`). The repaired values included the
object slot, constructor pointer, string reference slot/refcount, object field,
and slab-derived addresses. This sequence demonstrates that the remaining gap
is allocator and host-handoff page state, not a missing VM opcode.

The direct-write and boundary log is
[evidence/vm9_detail_native_transition_watch_20261003.json](evidence/vm9_detail_native_transition_watch_20261003.json).
The interventions are diagnostic only and are not part of the public signer.

## Capture-page A/B boundary (2026-10-03)

The next diagnostic separated a page transplant from the state it represents.
Starting from the same Seg1 checkpoint and the existing boundary repairs, the
clean baseline diverged at relative event 747 when `R1` read `0x32357c32`
instead of `0x78c1d3ab`. Installing the local captured page at `0x12296000`
supplied that first word and advanced the replay to relative event 788.

The replay then read `0x1dc9821c` where the trace requires `0x440132f7`.
That adjacent value is not supplied by the page transplant, so the page alone
is not the missing constructor. The remaining state is produced by later
allocator/refill and host/native initialization. This closes the callback-page
copy shortcut while leaving fresh-input parameterization open. The redacted
comparison is in
[evidence/vm9_detail_capture_page_ab_20261003.json](evidence/vm9_detail_capture_page_ab_20261003.json).

## Dynamic native load provenance (2026-10-03)

Static disassembly and the same trace identify how the later `0x440132f7` value
enters the VM. The OP1 handler at `+0x170270` performs
`ldrsw x9, [x10, x11]` followed by `str x9, [x28, x14, lsl #3]`. In the
held-out detail trace, instruction `0x8d08d7c1` at event `131392` reads from
`0xe4ffa7b8` through `R29=0xe4ffc0b0` and produces
`R4=0xffffffff8ef8fc19`. The later instruction `0x8d02d7c1` at event
`132739` reads `0x440132f7` from `0xe4ffd098` through the same `R29` object
and stores it into `R1`.

`R29` changes from `0xe4ffbc00` at the previous exit marker to `0xe4ffc0b0`
at the first event after the native/host transition. The next callback receives
that loaded value as `x1=0x440132f7`, alongside the recorded `x0`, `x2`, `x3`,
and `x4` inputs. A second handler at `+0x168eb0` also writes a sign-extended
register-table result into a VM slot, confirming that these values are dynamic
VM/native state rather than fixed callback-page bytes.

This closes the narrow provenance question for `0x440132f7`: the value is a
handoff-backed memory load followed by a VM register store. It does not close
the constructor, allocator refill, callback-registration, or fresh-input
parameterization requirements. The sanitized record is
[evidence/vm9_native_dynamic_load_20261003.json](evidence/vm9_native_dynamic_load_20261003.json).

## Native entry `x8` liveness (2026-10-03)

The paired captures also narrow the native callback entry at `0x12506ba0`.
The callee reloads `x8` at `0x12506bcc` with `ldr x8, [x20, #8]`, so the
incoming value is overwritten before this function consumes it. The packed
entry value is assembled on the caller side: `0x125487f4` loads `x9` and `x1`
from the callback object, `0x125487f8` loads `x10` and `x8`, and
`0x12548800` performs the indirect `blr x10`.

Across the detail and second-URL captures, the packed values are
`0x440132f775952fa9` and `0x1dc9821c75952fa9`. Their upper 32 bits match the
input-dependent OP1 results recorded immediately before the callback, while
the common lower `0x75952fa9` is written by the native copy helper at
`0x125692dc` (`str w6, [x0]`) to `0xe4ffc9c8`. Therefore the entry `x8` value is caller-side
native handoff state, not a constant generated by `0x12506ba0` and not a value
that can be recovered by copying one callback page.

The exact callback-object field writer and the native composition instruction
that combines the two words remain uncaptured. The sanitized record is
[evidence/vm9_native_entry_x8_liveness_20261003.json](evidence/vm9_native_entry_x8_liveness_20261003.json).

## Callback trampoline path check (2026-10-03)

A fresh current detail run with callback and descriptor watches reached the
`+0x2584ac..+0x2584c0` trampoline. The older static candidate at `+0x2887f0`
was not executed in that run (`X8-CALL` count zero). The active path performs
`ldp x1, x8, [x0]`, then `mov x0, x8; br x1`; the observed `[obj+8]` value is
therefore the object passed to the branch target, not proof that this helper
constructs the packed entry `x8` pair from the prior liveness capture.

The descriptor fields were already populated before the trampoline was
entered. The earlier probe did not retain the writer because its narrow watch
counter was exhausted by unrelated descriptor-pool traffic.

## Active descriptor writer (2026-10-03)

The corrected probe was rerun twice with the same frozen runtime setup and a
one-digit input change. Both runs reached the same active descriptor at
`0xe4ffe290`. Immediately before the trampoline, the VM store at `+0x171268`
(`str x15, [x17, x16]`) wrote the descriptor fields:

```text
[0xe4ffe290] = 0x125ea444, then 0x125ea4fc
[0xe4ffe298] = 0x1284a288
```

The trampoline then executed `ldp x1, x8, [x0]; mov x0, x8; br x1`. This
directly closes the active descriptor-writer location and confirms that it is
a VM/native boundary store. It does not capture the separate composition that
produces the packed entry values `0x440132f775952fa9` and
`0x1dc9821c75952fa9`; later allocator/native state still diverged after the
observation. The sanitized record is
[evidence/vm9_callback_descriptor_writer_20261003.json](evidence/vm9_callback_descriptor_writer_20261003.json).

The older `+0x2887f0` static helper remains unexecuted in both fresh probes.
The writer result is evidence for the active descriptor path only and is not a
parameterized Medusa implementation.

## Static class-3 refill primitive (2026-10-03)

The empty-bin branch is now mapped through the native allocator image:
`0x1217f450` writes `-1` to `[bin+0x28]`, calls `0x12187ecc`, and that wrapper
delegates the slab/free-list work to `0x1216970c`. The existing-slab branch
uses `[slab+4]` as a remaining-slot counter, selects a set bit from the slab
bitmap with `RBIT/CLZ`, clears it by XOR, and decrements the counter. The
wrapper then publishes the returned batch in the bin list.

For class 3, the checkpoint record is `0x12240950 -> 0x12941108`. The
historical state (`counter=0x24`, `bitmap=0xfffffffff0000000`) selects bit 28
and the current full-Seg2 state (`counter=0x20`,
`bitmap=0xffffffcfc0000000`) selects bit 30. The corresponding observed
buffers are `0x1296b940` and `0x1296ba60`. The public
`python/vm9_allocator.py` now exposes only this bitmap-word transition; it
does not claim the slab address formula or a fresh-input allocator.

The sanitized evidence is
[evidence/vm9_allocator_refill_static_20261003.json](evidence/vm9_allocator_refill_static_20261003.json).

## Existing-slab batch replay (2026-10-03)

The public allocator model now covers the captured non-node branch through the
wrapper boundary. `refill_existing_slab_and_pop` replays the eight-slot class-3
batch, stores the pointers at target-list indexes `7..0`, publishes the count,
and consumes the first entry as `0x12187ecc` does. On the historical checkpoint
it returns `0x1296b940`, leaves the bin count at `7`, decrements the slab
counter from `0x24` to `0x1c`, and consumes bitmap bits `28..35` in order.

This is a stronger captured-state allocator checkpoint, not a fresh-input
implementation. The model still requires the caller to provide the selected
slab record, target list, batch width, and initialized arena pages.

The sanitized evidence is
[evidence/vm9_allocator_batch_replay_20261003.json](evidence/vm9_allocator_batch_replay_20261003.json).

## Meaning for the deliverables

- Seg2 has complete captured diagnostic runs, including the new detail holdout
  at `90330/90330` without full host handoff loading. It still uses captured
  baseline/native state and trained target bytes.
- Seg3 now completes `1057/1057` from the same-run handoff without a clock-slot
  override. The older page-assisted replay remains complete only for its
  captured sample. Neither is a general current-version signer.
- The old 225-byte Python Medusa implementation remains valid only for its old
  snapshot vectors.
- The no-JVM Rust crate must continue to return an explicit unavailable error
  for current Medusa until state initialization, constructor/allocator behavior,
  and native callbacks are reproduced independently from fresh inputs.

## Next experiment

Replace the learned target-byte state and the Seg3 target correction with the
actual constructor/cleanup/callback-registration semantics. Generate the
arena lookup cache and complete global boot fields, then repeat with a new
input and time branch. Remove captured initialization/native callbacks and
compare an independently generated body before running a fresh live
directory/reader matrix. The current all-segment diagnostic is a component
checkpoint; the pure-Python signer, no-JVM Rust chain, non-empty search, and
later usable search/download webpage remain open.

## Available-slab branch replay (2026-10-03, corrected)

The forced callback-1 probe clears class-3 bin count `0x12282090` and current
slab slot `0x12240950`, enters the empty-bin acquire path, and returns
`0x12a479b0`. The earlier claim that it created a new slab was refuted by
input-checkpoint inspection: record `0x12a403e8` was already class `3`, with
counter `0x34` and leaf bitmap `0x3fffffffffeffe00`.

Direct native `0x12165d44` selects the available node `0x12a403d8`, changes the
tree root to sentinel `0x12240960`, increments the selection count from `4`
to `5`, and returns `node+0x10 = 0x12a403e8`. It does not create that record.
Native `0x121687dc` publishes it as current and consumes the first object slot.

The Python owner now reproduces this singleton-node selection and the
four-slot refill/wrapper pop. Native and Python return `0x12a479b0`, leave
count `3`, decrement the slab counter to `0x30`, and leave bitmap
`0x3fffffffffefe000`. All 4,256 checkpoint pages match for selection, available
refill, an existing-slab regression, and an adjacent metadata-word challenge.
The native transient lock writes remain outside this single-threaded model.

The metadata challenge also exposed and fixed a field-width bug: native reads
`metadata+0x58` with `LDR W8`; the Python model now uses `read_u32` instead of
`read_u64`. Unsupported tree shapes and batches are rejected before writes in
the seven tested negative cases.

The corrected original evidence retains its filename for provenance:
[evidence/vm9_allocator_new_slab_native_replay_20261003.json](evidence/vm9_allocator_new_slab_native_replay_20261003.json).
The native differential result is
[evidence/vm9_allocator_available_slab_20261003.json](evidence/vm9_allocator_available_slab_20261003.json).

The forced full run's event-146 pointer mismatch remains an observation against
an unmodified trace, not proof of missing VM behavior. The paired control
reclaims `0x1296ba60` after the runner explicitly frees it. The diagnostic free
setup does not independently derive live transition history, and native free
has no return value.

This closes a bounded checkpoint branch. Fresh slab/arena initialization,
general tree operations, constructor/cleanup and callback registration remain
open. Current parameterized Python Medusa, the no-JVM Rust download chain,
nonempty search, the other platforms, and the usable webpage remain unfinished.
The next allocator work must reconstruct free publication and its actual
caller history, then exercise a new input without captured initialization.

## Python malloc/free fast paths (2026-10-03)

`allocate_small_object_fast` and `publish_small_object_free` now replace the
normal initialized-thread small-object native paths, with request/region class
selection, free-list publication/pop, count-floor updates, byte accounting,
class allocation counts, and the shared periodic-cleanup counter.

Ten direct native stages across classes 0, 1, 2 and 3 match return pointers,
ordered nonstack writes, and every one of the 4,256 checkpoint pages. The
class-0, class-1 and class-3 free/reallocate pairs return the same freed slots;
zero-size malloc and the signed floor update also match. Twelve unsupported
branches are rejected without writes. A second captured input's initialized
checkpoint adds nine matching malloc/free/malloc stages for classes 0, 2 and 3,
bringing the total to 19. Its `malloc(0x18)` returns `0x122a0c40` versus the
primary checkpoint's `0x122a0c20`; slot identity follows the allocator state.
Both tests still depend on captured initialization.

In a Seg2 diagnostic, Python intercepts all 44 malloc/free wrapper calls before
the existing mixed-capture event `12085`, while other callbacks still execute
native ARM64. It completes 45 callbacks and matches the native control's
ordered object sequence (four transition setup operations and 40 callback
operations). Both have `R2=0x2f8` where the old reference expects `0x2f6`.
The earlier mixed-capture correction in this file already explains that stop;
it must not be reported as a new model failure or repaired with a trace-value
injection.

Details: [ALLOCATOR_FAST_PATHS.md](ALLOCATOR_FAST_PATHS.md), with sanitized
[evidence/vm9_allocator_fast_paths_20261003.json](evidence/vm9_allocator_fast_paths_20261003.json).

This removes two native allocator fast paths from one captured diagnostic
prefix. It still does not derive fresh allocator initialization, TLS discovery,
the true transition cleanup history, empty-bin malloc dispatch, full-bin flush,
periodic cleanup, native constructor/callback state, or an independent Medusa
body. The next run must use a trace and memory from the same capture before
extending interception across the refill/cleanup boundaries. The current
Python signer, no-JVM Rust chain and live search/download remain unfinished.


## First table initializer and corrected once gate (2026-10-05)

The former arena-prefix completion claim from commit `1b8aa32` is corrected.
The prefix allocates/clears `0x4000` and publishes eight table pointers;
`begin_once_arena_boot` leaves state 1 until the nested initializer completes.
The explicit gate now follows lock -> publish 1 -> unlock -> complete
initializer -> lock -> publish -1 -> unlock -> broadcast, and refuses a
partial-prefix result. Busy-state waits remain unsupported.

The complete first initializer now executes all eight nested VM returns;
fresh controls at two relocated image bases compare every terminal slot and
heap at every return, plus all image pages and allocation order. Four further
cold/hot controls complete the first +0x280590 caller, including once and
broadcast ordering. This completes one of six default callers. The other five
entry/first-callback boundaries pass 40 controls but do not execute their
initializer bodies. No native input snapshot is used in these checks.

The controlled allocator and broadcast provider do not prove real arena/OS
boot, concurrent workers, fresh Medusa output or live header validation.
Details and correction provenance: [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md).

## Second table caller (2026-10-05)

The second +0x280610 caller completes one +0x280b54 / VM +0xeee60 and
seven +0x280bdc / VM +0xef520 returns. Four fresh cold/hot controls compare
full caller return state, heap/image, once and ordered environment effects.
Twelve additional controls compare the nested wrappers and returns; nine
failure cases leave guest pages unchanged and restore the VM base. The
allocator and broadcast remain providers. This closes two individual
callers, while six-caller composition and the final signing chain remain open.
Details: [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md).

## Complete serial default task (2026-10-05)

All six default caller bodies and the +0x280554 serial composition now pass
fresh native differential controls. This supersedes the earlier one-caller
and two-caller checkpoints above. Evidence: [individual callers](evidence/vm9_all_default_callers_native_20261005.json)
and [serial task](evidence/vm9_default_initialization_task_native_20261005.json).
The explicit mapped allocator/broadcast boundaries remain; same-startup
nonempty worker execution, OS exit destructors, real allocator initialization
and independent Medusa signing remain unfinished.


## Same-startup nonempty default worker (2026-10-05)

`run_default_queue_worker` derives queue/task stack and saved-register inputs
from the +0x3260a4/+0x326578 ABI, including the matching bionic unlock saved
words read by the sixth tailcall. Native startup outputs remain expectations
only. All four fresh controls compare every caller's 32 slots, virtual stack,
guest and six regions, then image/both TLS/generation and ordered effects.
Eight new rollback checks and eight idle controls/six old rejection checks
pass. The worker argument is freed; support remains TLS-owned.
Evidence: [nonempty worker](evidence/vm9_startup_default_worker_native_20261005.json)
and [idle regression](evidence/vm9_startup_worker_regression_20261005.json).
OS TLS destruction, real allocator/arena/OS boot and fresh signing remain open.


## Empty support key-exit cleanup (2026-10-05)

Matching bionic's +0x685a0 key dispatcher now has 20 fresh controls covering
141-key order, generation checks, value clearing before callbacks and the
four-pass bound. Empty support +0x32ce6c/+0x32ccf0 has eight controls,
including reserved-vector capacity/free order; three unknown/failure paths
roll back guest pages. A same-startup default-worker control explicitly
runs the real libc key phase at normal worker return, checks all six caller
returns/48 nested returns again, and verifies argument -> support -> wrapper
frees with zero support TLS value. Eight idle controls also pass again.
Evidence: [key/support](evidence/vm9_thread_key_cleanup_native_20261005.json)
and [same startup](evidence/vm9_default_worker_key_cleanup_native_20261005.json).
Full pthread_exit, nonempty support vectors, +0x3439bc emulated-TLS arrays
and +0x342854 fallback destructor chains remain open, along with real
allocator boot, independent signing and all downstream product work.


## Emulated/fallback TLS and nonempty support exit (2026-10-05)

Restored +0x3439bc array defer/republication/free, +0x342854 pop/callback/free
and flag cleanup, and +0x32ccf0 nonempty waiter/reference vectors with
broadcast/exit-bit/shared-counter ordering. The real +0x268cf0/+0x269060
scoped-TLS tree callback now performs postorder free and reloads the right
child after left destruction. Unknown callbacks are never replaced with RET.

Evidence: [62 native controls / 13 rollback checks](evidence/vm9_tls_exit_destructors_native_20261005.json).
Fourteen array, twelve fallback, sixteen support, six fresh registration/key
compositions, ten tree and four actual registry compositions pass at two bases.
The actual registry key order puts emulated TLS first; its defer keeps storage
alive for fallback before final array free. Registry callbacks execute the real
recovered tree body. Other fixture callbacks, shared zero destruction and the
allocator/pthread/scheduler environment remain explicit input boundaries.
Affected [key/support and same-default-worker regressions](evidence/vm9_tls_exit_regression_20261005.json)
also pass. Full OS thread exit, concrete shared/other callback bodies, real
allocator/arena/OS region boot, fresh signing and downstream products stay open.

## VM STORE64 descriptor writer (2026-10-06)

The next native boundary is now isolated at `+0x171268`. Its exact semantics
are the VM `STORE64` operation: decode the bytecode word, read the base and
value virtual-register slots, sign-extend the displacement, and write eight
bytes to `base + displacement`. The active `991c0#1` oracle stores descriptor
`+0x00` and `+0x08` with slots 29/1 and 29/17 at displacements `0x140` and
`0x148`; the public model reproduces all four fresh trace-state effects and
rejects non-STORE64 or uninitialized-target inputs.

This closes only the field-store instruction boundary. The VM word/register
file is still supplied by a captured oracle, so independent fresh input
construction, live owner-frame continuation, packed callback x8, complete
allocator/arena/OS boot and fresh Medusa remain open.
Evidence: [descriptor writer STORE64](evidence/vm9_descriptor_writer_store64_20261006.json).

## Fresh root writer inputs (2026-10-06)

The bounded root caller now produces the descriptor writer inputs from its own
fresh VM/register state. Four controls (two image bases × absent/SDK 30) match
the sequence `+0x140 branch A → +0x148 object → +0x148 object → +0x140 branch B`.
The branch words relocate with the image base. `R29` comes from the caller
frame setup (`R29 = R29 - 640`), branch A/B load `R1` from `[R20+72]` and
`[R20+88]`, and field8 is generated from the current frame by `R17 = R30 + 8`.
The deterministic allocator seed repeats that object address, so the result is
not a cross-seed entropy claim.

The owner-frame continuation and callback body remain unresolved. This evidence
closes a bounded fresh writer-input boundary, not the full Python Medusa or
online signing chain. Evidence: [fresh writer inputs](evidence/vm9_descriptor_writer_fresh_inputs_20261006.json).


## 2026-10-07 request 内部 leaf 前导：真实 JNI 与模式 builder 边界

新增30个原生对照/6个负控制，恢复 `28ddd0 → 28e788` 的采样/参数槽和
`28b05c` 的九组 lazy 全局。10个未采样路径自然返回；10个采样路径停在
`28f0f4` 前。另10个 evaluator 控制停在 `26edc4` 前，没有使用 oracle 的
既有 `env` stub；此前虚拟 env=0 的探查返回不能作为真实 JNI 获取证明。

同次 owning session 的外层仍945/+ffb48和965/+f8fd0，内部新缺口分别为
`+0x28f0f4` 和 `+0x26edc4`。暂存前导等价不代表完整 callback，新增事务
没有提交。无线上请求或签名输出。详见 [REQUEST_LEAF_PREFIXES.md](REQUEST_LEAF_PREFIXES.md)。


## 2026-10-07 signed mode 完整组件：38个原生控制/14个负控制

`28e788 → 28f0f4 → 1b40d4 → 1b414c → cleanup` 的有界完整路径已恢复：
包括token/参数向量、live signed32渲染、inline转换和五次临时分配清理。
12个builder控制只排除未指定token padding；22个完整mode控制比较完整
最终payload/对象；另4个构造后参数更新控制验证live pointer。通用grammar/
类型/扩容仍拒绝，组件allocator/free和memory imports的显式服务边界保持。

同次owning allocator组合生成 `{"x0":0}`，低基址内部推进到五参数
`+0x28e86c`；高基址仍`+0x26edc4`。外层945/965没有增加，event父事务
没有提交。详见 [REQUEST_MODE_FORMAT.md](REQUEST_MODE_FORMAT.md)。


## 2026-10-07 五参数 event format：22个原生控制/19个负控制

`28e86c → 28e91c → 1b40d4 → 1b414c → cleanup` 的144字节对象已恢复，
包括五个typed cells、index分派、live uint64/signed32和heap C++输出。
原始event caller控制真实执行到`28ff44`入口；最终payload和local窗口无mask，
builder-only仍只排除未指定token padding。双全局页对照补齐了signed mode
共用的六组hex selector；旧38/14 mode回归也验证此全局页。

同次owning allocator生成`{"x0":0}`与29字节event JSON，新增event临时
分配完成清理，请求free数17。低基址最新缺口为`+0x28ff44`发布；高基址
仍真实TLS/JNI `+0x26edc4`。外层仍945/965，完整event父事务未提交，
whole-native outer/request与fresh签名尚未通过。详见
[REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。


### 发布入口：四个原生受控probe

四个原生warm logger控制已自然返回，确认`17f5bc → 180ce4`执行move
assignment，只清零source头两个字节，heap JSON pointer不复制、不改变。
96字节record vector有空位时无新分配，容量1时扩容192并释放旧vector。
这些控制使用warm singleton与一个旧空record，Python emission owner仍未
实现，当前同次请求停止点没有改变。复现和边界见
[REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。


## 2026-10-07 warm event发布与低基址synthetic请求返回

新增40个原生控制/14个负控制，恢复`28ff44`的四个move、uncontended mutex、
96字节record vector追加/迁移/增长、199追加/200丢弃与临时析构。原始
`28ddd0/28dc40` caller在12个控制里自然返回。source头两个字节清零与
record move-construction全24字节清零分别恢复，heap ownership不重复free。

低基址同次owning Python session从945推进至957/+ffb78，R31匹配caller
sentinel，event callback与此synthetic VM模型返回；request页提交，record
从1条增至2条，33 allocations/18 frees。x8输出为configuration reference，
不是签名。高基址仍965/+f8fd0和真实JNI acquisition `26edc4`。

`op17/sub30`的native return是有条件分支；四个单指令native控制执行
`168324 → 16a974 → 172440 → ret`。request owner只接受sample PC/word和
匹配caller sentinel，不把VMExit统一视为成功。physical caller epilogue/X0
ABI、全原生request、真实URL/headers/JNI和fresh Medusa仍未通过。
详见 [REQUEST_EVENT_EMISSION.md](REQUEST_EVENT_EMISSION.md)。
