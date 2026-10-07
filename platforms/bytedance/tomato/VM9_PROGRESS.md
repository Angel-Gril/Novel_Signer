# Current VM9 progress checkpoint

## 2026-10-07：fresh outer 返回对象图与默认记录差分

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
