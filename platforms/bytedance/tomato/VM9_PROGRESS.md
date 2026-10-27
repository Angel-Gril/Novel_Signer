# Current VM9 progress checkpoint

## 2026-10-28：JNI 注册与 signing tag 归属闭合

新增只读 ELF/Java/受限捕获 verifier。pinned `libmetasec_ml_71332.so` 的动态符号
表确认 `JNI_OnLoad=+0x27b41c`；注册路径静态构造一个 `JNINativeMethod`，把
`image+0x26e684` 写入函数指针槽，并通过 JNIEnv 函数表 `+0xb8` 调用
`RegisterNatives`。`r4.onCallToAddSecurityFactor` 的 Java 代码明确以
`tag=0x3000001` 调用 `y2.a(int,int,long,String,Object)`，同一入口的参数重排
也逐条由原始指令验证。

现有 bounded unidbg 捕获只提取注册类、签名、入口和 tag 标记，不写入 URL、header、
设备标识或返回值；六个标记全部命中。该轮闭合的是 JNI entry ownership 和 signing
tag provenance，不等同于 actual JNI provider、真实 Android JVM、whole-request
native/Python differential、fresh standalone signer 或线上 acceptance。

证据：[JNI registration provenance](evidence/vm9_jni_registration_provenance_20261028.json)；
复现：[verifier](python/verify_vm9_jni_registration_provenance_20261028.py)。

## 2026-10-28：actual facade JNI/cleanup semantic boundary

在真实 outer child → normal facade 的同 CPU continuation 上增加阶段化
malloc/free 账本，并用独立生成的 Python facade fixture 做语义对照。两个
image base 均通过：native facade 返回句柄与 Python facade 返回句柄相同，
去除指针/句柄后的 JNI slot 与 object-array 操作序列逐项相同，返回数组元素
数量均为 2；native facade 阶段的 111 次分配、97 次释放最终以 free 事件
收尾。Python fixture 仍只由独立输入生成，未读取 native 对象字节。

这次只关闭 facade 的 JNI 操作形状、返回基数和 cleanup 终止边界。真实 request
VM 的内部对象图与 Python request provider 的分配图不同，因此没有宣称分配
序列/字节等价、whole-request native/Python differential、fresh standalone
signer、真实 JVM 或线上 header acceptance；输出内容仍不解释为七神 signer
结果。证据：[facade cleanup semantics](evidence/vm9_native_facade_cleanup_semantics_20261028.json)；
复现：[verifier](python/verify_vm9_native_facade_cleanup_semantics_20261028.py)。

## 2026-10-28：cold outer graph object provenance

新增只读 native provenance verifier，在两个 image base 的 cold outer getter 返回点检查
同一个 root 的依赖字段、两个 child 的虚表与 callback pair，以及各自 handler 的虚表。
`root+0x18` 指向 `image+0x2830c4` child，`root+0x20` 指向 `image+0x289190`
child；两者的 child vtable 都是 `image+0x35d5f0`，handler vtable 分别为
`image+0x35dc50` 与 `image+0x35f7e0`。`service_refs` handler 的 `+0x30/+0x40`
callback reference members 和 `+0x50/+0x60` service reference members 均为非空，
并且两个基址的对象关系一致。

该 verifier 只读取 native 返回对象图，不把 native bytes 作为 Python 输入，也不把这些
成员解释成 Java array、七神 header 或 signer 结果；`root+0x00` 保持观察到的未写入状态。
因此这次闭合的是 cold outer graph 的对象级 provenance，whole-request native differential、
真实 JVM、fresh standalone signer 和线上 header acceptance 仍未完成。

证据：[outer graph object provenance](evidence/vm9_outer_graph_object_provenance_20261028.json)；
复现：[verifier](python/verify_vm9_outer_graph_object_provenance_20261028.py)。

## 2026-10-28：request context 虚表消费者与 callback pair 发布闭合

在上一轮 actual outer child → normal facade 的同 CPU continuation 上增加窄范围
consumer ledger，并在两个 image base fresh 重跑。实际发布的 `0x136d6100`（128
字节 native request context）被 outer graph 依次以同一个 `x0` 调用：

```text
context vtable +0x58 → +0x28508c → this +0x40 → +0x19eff8
context vtable +0x60 → +0x285094 → this +0x30 → +0x28522c
context vtable +0x68 → +0x28509c → image+0x2830c4
```

三个调用的真实 caller 分别为 `+0x27cd48`、`+0x27cd74`、`+0x27cd90`；最后一个
返回 `+0x2830c4`，随后由 `+0x27cd94` 将 callable 与同一个 context 写入 16 字节
callback pair。ELF `.rela.dyn` 的 `+0x35dca8/+0x35dcb0/+0x35dcb8` 分别重定位到
这三个函数，函数体静态指令也逐条通过。两个基址的动态序列、对象地址、caller
和 pair publication 均一致。

这闭合了 request context 从真实构造对象到 pair callback publication 的对象级
provenance；`+0x30/+0x40` 目前只称为两个内部 reference subobject，不能把它们
解释成 Java array、六个七神 header 或 signer 结果。尚未修改生产对象模型，也未
宣称 whole-request native differential、真实 JVM、fresh standalone signer 或线上
header acceptance。

证据：[context consumers](evidence/vm9_native_outer_facade_context_consumers_20261028.json)；
复现：[verifier](python/verify_vm9_native_outer_facade_actual_child_20261027.py)。

## 2026-10-28：恢复 handler 的两个 callback reference member 复制

在已闭合的 consumer provenance 上增加最小对象装配 owner：
`bind_signer_handler_reference_members`。它按 native 顺序复现
`+0x28508c`（复制到 handler `+0x40`）和 `+0x285094`（复制到 `+0x30`），保留
reference wrapper 的指针、计数指针和 32 位计数增加行为；service_refs 原有
`+0x50/+0x60` 构造保持不变。

两个 image base 的 constructor、两次 virtual copy 的完整 guest page 对照和分配
顺序均通过；3 个 NULL/非法指针事务回滚也通过。该 helper 只恢复 native object
reference composition，没有把字段解释成 Java array、七神 header、signer 状态或
业务结果。

证据：[context reference members](evidence/vm9_request_context_references_20261028.json)；
复现：[verifier](python/verify_vm9_request_context_references_20261028.py)。

## 2026-10-27：真实 outer child → normal facade 的同 CPU continuation

扩展 native outer verifier，在 cold outer getter 返回点保留同一个 Unicorn
CPU，读取真实 `root+0x18` child 后直接进入 normal facade `+0x17b8f8`。两种
image base 的 provenance 相同：child vtable 为 `image+0x35d5f0`，
`vtable+0x20` 为 `image+0x27dd04`，child callback pair 首项为
`image+0x2830c4`。这次没有注入 receiver/tree 或 dispatch table。

两边都观察到真实 child ABI `+0x27dd04`，随后进入 owning VM `+0x2830c4` 和
native VM `+0x168324`；facade 的 x0/x1/x2/x3/x8 与同一 outer child 以及新的
URL/header fixture 关联。运行在 `+0x2859dc` 的 descriptor branch 停止：
`x0=0x13708000`、`x3=0`，下一条 `br x3` 因未知 callback target 触发
`UC_ERR_FETCH_UNMAPPED`。这关闭了真实 child provenance、facade 输入 ABI 和
同 CPU continuation 到 callback descriptor 的边界，但没有 facade cleanup/return，
也没有签名输出。

JNI、URL/header 和继续分配仍是显式 fixture provider；native outer 的 libc
malloc/free 与 facade 分支共用同一 CPU，但没有宣称 whole-request native/Python
差分、live JVM、fresh standalone signer 或线上 header acceptance。

证据：[真实 outer child facade](evidence/vm9_native_outer_facade_actual_child_20261027.json)；
复现：[verifier](python/verify_vm9_native_outer_facade_actual_child_20261027.py)。

## 2026-10-26：normal fixture facade 的 receiver/vtable/target provenance

未修改 synthetic receiver 虚表的 fresh native facade 运行记录了完整读取链：
`facade+0x18 → receiver+0 → vtable+0x20`，对应 PC 偏移分别为
`+0x17b9e4`、`+0x17ba24`、`+0x17ba38`，两个 image base 一致，随后调用显式
request service；调用期间没有 native 对这三个 chain field 的写入，它们来自
`facade.fixture` 的显式 provider。该证据只闭合 fixture-path 的读取 provenance；receiver、vtable、
JNI provider 和 request service 仍是 synthetic，normal child handoff、whole-request
differential、standalone signer 与线上接受均未验证。

证据：[facade target provenance](evidence/vm9_java_facade_target_provenance_20261026.json)；
复现：[verifier](python/verify_vm9_java_facade_target_provenance_20261026.py)。

## 2026-10-26：same-CPU bootstrap → facade → child → owning VM continuation

在 fresh native bootstrap 完成后，复用同一 Unicorn CPU 进入 facade `+0x17b8f8`，
再到人工安装的 child target `+0x27dd04`、owning VM `+0x2830c4` 和 VM
`+0x168324`。修正为已接受的一节点树布局并复用 bootstrap-owned mapped stack 后，
两个基址各执行 7,751 条 native 指令并返回 oracle STOP；child ABI 为
`x0=receiver`、`x1/x2=转换后的栈引用`、`x3=0x138`、`x8=栈上的 output reference`，
facade epilogue `+0x17baa0/+0x17bac0` 均执行。native callback object 到达真实
`+0x347f60` memcpy PLT 五次，runtime-table canary 页读写均为零，未观察 unmapped。
child target、receiver/tree、JNI provider 和 URL/header 仍是显式 probe 输入，oracle
STOP 与 x0=0 只证明 continuation 返回，不能计为 normal target、whole-request
differential 或 signer 输出。

证据：[same-CPU facade child](evidence/vm9_native_bootstrap_java_facade_child_20261026.json)；
复现：[verifier](python/verify_vm9_native_bootstrap_java_facade_child_20261026.py)。

## 2026-10-26：人工 child continuation 到 native return

在上一条 facade ABI 探针的 synthetic receiver 上补齐最小 receiver/mutex/tree 字段，
让注入的 `image+0x27dd04` 真正执行。两个基址均执行 11,617 条 native 指令，
返回 `x0=0`，最后位于 facade epilogue `+0x17bac0`；未观察 unmapped 访问。
该 child target、输入对象和 provider 都是人工 fixture，零返回不是 signer 输出，
因此不计作 normal facade handoff、whole-request differential 或签名成功。

证据：[child continuation](evidence/vm9_java_facade_injected_child_continuation_20261026.json)；
复现：[verifier](python/verify_vm9_java_facade_injected_child_continuation_20261026.py)。


## 2026-10-26：native facade 到 child 的 ABI 边界观察

在 fresh ELF native `+0x17b8f8` facade 上，独立探针只把 synthetic receiver
虚表 `+0x20` 改为 `image+0x27dd04`，并在 child 第一条指令前停止。两个基址
均到达 child，入口 ABI 为 `x0=receiver`、`x1=url reference`、`x2=header
reference`、`x3=0x138`、`x8=output reference`，child stack 相对 facade fixture
为 `0xb0`。child 没有执行，JNI/allocator/URL/header 仍是显式 fixture；因此这只
闭合人工 target 注入下的寄存器边界，不能证明 normal facade target、whole-request
differential 或签名成功。

证据：[injected child-entry](evidence/vm9_java_facade_injected_child_entry_20261026.json)；
复现：[verifier](python/verify_vm9_java_facade_injected_child_entry_20261026.py)。


## 2026-10-26：guard-reset 人工状态分支观察

独立探针在 native bootstrap 返回后只清零 `image+0x3d1558`，随后继续进入真实
`+0x27dd04`。两个基址都读到 source low bit 0，却仍观测到 `+0xf8554`，
`+0xf858c` 仍得到 -5，最终返回合法的一节点 `X-Neptune` 诊断树，value 仍为
`-5|`；没有生成其他 signer header。该人工分支每次有 37 个 callback（正常 guard=1
continuation 为 29 个），因此只说明这个 guard reset 没有打开可见 signer 分支，
不能宣称正常路径等价、签名成功或业务含义。

证据：[guard-reset](evidence/vm9_request_output_reference_guard_reset_20261026.json)；
复现：[verifier](python/verify_vm9_request_output_reference_guard_reset_20261026.py)。


## 2026-10-26：确认 native output reference 为单项诊断树

两个基址的 fresh bootstrap/request continuation 均返回合法 owning tree：
container vtable 为 `+0x35b7c0`，40-byte container 与 4-byte counter 分配可追溯，
counter 为 1；controller/sentinel、节点父子指针、计数、排序和首尾节点均通过检查。
树内只有 **X-Neptune**，value 由 `%d|%s` 使用 `-5` 和空字符串生成；格式化对象、
`+0x25bf3c` 插入对象与最终返回节点的地址、长度和 payload hash 逐项相同。
output pair 的最终 native writers 为 `+0x27e804/+0x27e80c`。这说明返回对象有效，
同时明确本 fixture 没有生成其他签名头；不能把“返回且非零”作为 signer 成功证据。

状态来源也已串起：bytecode `+0xf83f8` 读取 `image+0x3d1558` 的低字节，
`+0xf8404` 在其低位为 1 时跳到 `+0xf8554`，随后 `+0xf858c` 的原始 word
`0x7f60f97b` 执行 `R2 = sext32(R0)-5`。native 观察确认 R0 为 0、R2 为 -5，
之后经过 packed int32 参数与原始 formatter 写入 value。该地址属于已有 registry
getter 的 guard：从 fresh ELF 的全零值开始，bootstrap 原始 `+0x32d514` 写入 1，
其 caller 为 `+0x15e714`；四条 guard 写事件完整保留，没有改写 guard 或请求分支。

正式结果为 **2 次 fresh native continuation**，不计入 native/Python 差分或 rollback
数量。新增 observer 在 bootstrap 前安装 guard hook，在 request 前清理 translation
cache；每次记录 29 个完整 VM callback（含 nested getter），无外部 canary mapping。
两个 continuation 的全部返回 metadata 与上一份 dispatch-table evidence 完全一致。
证据只发布 synthetic payload 的长度/hash、静态 header 名和 guest 地址，不发布实际
URL、完整 header value、设备字段或 native snapshot。生产 owner 未修改。

下一步应核对真实 Java facade/constructed child 的输入和该 registry guard 在请求中的
角色。guard 的业务含义、fresh whole-request native/Python 差分、完整 callback/provider
组合、独立 Medusa/signer、live JVM 与线上验签仍未完成。

证据：[output reference](evidence/vm9_request_output_reference_fresh_20261026.json)；
复现：[verifier](python/verify_vm9_request_output_reference_20261026.py)。

## 2026-10-26：纠正 external runtime-table owner 假设

五个 relocation slot 中的 `image+0x13bb...` 值是编码指针。原生
`+0x1683f4..+0x1684ac` 的 mask/OR/XOR 地址运算得到修正量
`0xfffffffffef91678`（`-0x106e988`），对应的真实表依次位于 ELF
`.data.rel.ro` 的 `+0x34cf68/+0x34d168/+0x34d368/+0x34d490/+0x34ce68`。
这些表含 `64/64/37/37/32` 个连续 relative relocation，共 234 项；表值减去
live frame bias `0x33dc5` 后得到 native handler。现有
`vm9_request_dispatcher.py` / `vm9_request_nested.py` 已包含同类修正运算，
本批不修改生产 VM，也不合成 table、handler、vtable 或 snapshot 输入。

两个基址共 **468 项 native selector controls** 通过，逐项执行真实选择指令，
在 handler body 前停止。另 **4 次 fresh bootstrap/request continuation** 在有/无
外部 canary 页时各观察到 **1,191 次 table load + 实际 BR destination**，其中
table 0 为 1,032 次、table 1 为 159 次；这条 continuation 未走 table 2/3/4。
每个读取值与独立 ELF PT_LOAD/relative relocation 输入一致。移除 canary 后，
dispatch ledger 和 continuation 返回结果完全一致，其余 **6,168 个物理页**的
完整地址/字节流 SHA-256 一致；request 观察期内五个 relocation slot 无 native
writer，五张表也无 native 修改。

bootstrap 已执行过部分 VM block，因此新增 memory hook 后清理 Unicorn translation
cache；否则会漏记旧 block 的读事件。早期未清理的诊断中两次日志相差一项，
尽管所有页面与返回一致；正式证据保留完整重跑事件，不用不完整 ledger 宣称相等。

这替代下方历史记录中的“外部表 owner/五个 slot 的 runtime writer 缺失”推断：
这些 slot/table 由 ELF relocation loader 提供，本 continuation 无需外部 dispatch
mapping。loader candidate 的实际调用与 custom mapping 仍未验证，但不再作为这
五张表的前置阻塞项。下一主线是 fresh whole-request native/Python 差分、完整
callback graph 与真实输入/provider 组合；完整 Medusa、独立 signer、live JVM/OS
全 ABI、线上验收与 Rust 下载链仍未完成。

证据：[dispatch encoding](evidence/vm9_dispatch_table_encoding_fresh_20261026.json)；
复现：[verifier](python/verify_vm9_dispatch_table_encoding_20261026.py)。

## 2026-10-25 Asia/Shanghai：timed transfer 与完整 executor worker schedule fresh rerun

在完成 follow-up callback 重跑后，先重跑 timed poll/queue 组合。两基址、两个
startup 分支共 **4 项 fresh native/Python controls、20 项回滚**通过，11502 项
allocation/free、checksum VM 8606106、lookup VM 301、15 callbacks、GetEnv 2/JNI 0、
两段 image VM、wrapper/task 清理和空队列均匹配；结果与
2026-10-11 正式 JSON 逐字节一致。该项仍使用显式 poll/queue driver，完整 worker
wait cycle 尚未由这份证据单独声明。见 [timed-cycle rerun](evidence/vm9_jni_timed_cycle_rerun_20261025.json)。

随后重跑完整 cooperative executor worker schedule。两基址、两个 startup 分支共
**4 项 fresh native/Python controls、23 项回滚**通过，并与正式 JSON 逐字节一致：
三条 worker 的 wait counts 为 **3、1、2**，共 **6 次 futex wait / 9 次 scheduler
step**，返回和退出顺序均为 **1、2、0**；timed follow-up、两段 image VM 和清理
继续匹配。该 schedule 使用 guest/Python provider，没有创建 host worker thread；
live JVM/OS、live Java string conversion、fresh Medusa、standalone signer 与线上
验收仍未完成。见 [worker-schedule rerun](evidence/vm9_jni_worker_schedule_rerun_20261025.json)。

随后重跑 initialized live Java lookup：48 项 native/Python controls、11 项回滚，
与正式证据逐字节一致。warm encoded SDK getter、Java array/byte 提取、MD5 string
构造、reference cleanup 和异常/NULL 分支均匹配；JNI/JavaVM 仍为显式 synthetic
provider，因此 live Android JVM、cold initializer、fresh Medusa 与 standalone
signer 仍未验证。见 [live-lookup rerun](evidence/vm9_jni_live_lookup_rerun_20261025.json)。

继续重跑 cold receiver initializer 与 complete SDK lookup：92 项 controls、6 项
回滚，跨两个 image base 与正式 2026-10-12 evidence 逐字节一致。cold SDK property
转换、receiver/class/global 初始化、完整 lookup continuation 以及 NULL/exception
分支均通过；provider 仍为 synthetic，live Android JVM、fresh Medusa 与 standalone
signer 仍未验证。见 [initializer rerun](evidence/vm9_live_initializer_rerun_20261025.json)。

另外重跑 delayed live-provider boundary：evaluator、callable 和 worker-entry 共
8 项 controls、16 项回滚通过。当前 verifier 的 case schema/order 已相对旧 formal
JSON 重组，因此只记录 fresh controls，不宣称逐字节一致；仍为有限 synthetic
Android provider，尚未证明 live 三 worker、真实 JVM 或 signer 输出。见
[delayed-provider rerun](evidence/vm9_live_delayed_providers_rerun_20261025.json)。

最后重跑当前 native outer signer-boundary control：两基址、四个 property profile
和两组 relocated input 共 **10 项 native controls**通过，执行 outer getter/
constructor、matching-libc allocator 与 publication/JNI ledger，未创建 host thread
或 JVM。当前 rerun 增加了旧 formal JSON 没有的 allocation/publication trace 字段，
因此不宣称 byte-identical；Python outer、current Medusa、standalone signer 与线上
header acceptance 仍未验证。见 [outer native rerun](evidence/vm9_outer_signer_native_rerun_20261025.json)。

随后重跑 outer finalization：10 项 hash controls、6 项 publication/JNI integration、
5 项 negative controls 与 2026-10-24 formal evidence 逐字节一致。current-input hash、
caller 高位零扩展及 service ledger 均匹配；allocation 308 的 unused native
short-string padding 仍是唯一 live mismatch。见
[outer-finalize rerun](evidence/vm9_outer_finalize_rerun_20261025.json)。

继续重跑 provider-effect rollback journal：32 项 controls、32 项回滚，与 formal
evidence 逐字节一致，覆盖 facade/owning-request/child-dispatch nested journals。
GuestOS mapping rollback 也逐字节一致（4 controls、3 guards）；这只验证 owner-side
transaction，不宣称真实 OS mapping 或 live JVM。见 [provider rollback rerun](evidence/vm9_provider_effect_rollback_rerun_20261025.json) 与 [GuestOS rollback rerun](evidence/vm9_guest_os_effect_rollback_rerun_20261025.json)。

随后重跑 environment-service 与 environment-release scope。前者复现 **36/6**，后者
复现 **38/7** 的全部 case/guard 结果；当前 verifier 没有输出 formal evidence 的
cumulative/provenance metadata，因此只记录 fresh rerun，不宣称逐字节一致。两项仍
使用显式 allocator/TLS/JNI service，live JVM、完整 request state 与 fresh signer
仍未验证。见 [service-scope rerun](evidence/vm9_environment_service_scope_rerun_20261025.json)
与 [release-scope rerun](evidence/vm9_environment_release_scope_rerun_20261025.json)。

随后重跑 stack-evaluator/request-entry boundary：78 项 evaluator controls、34 项
rollback guards 通过；owning request entry 到达 `+0xffb78`，共 2475 steps/105
callbacks，并完成 JNI environment、空 header tree、计数器、清理和 caller sentinel
返回。当前输出比 2026-10-12 formal JSON 多 14 项 guard 和更深的 request-entry
字段，因此不宣称逐字节一致；request/JNI 仍是 synthetic provider，whole-native
request、live JVM 与 fresh signer 仍未完成。见
[stack-evaluator rerun](evidence/vm9_request_stack_evaluator_rerun_20261025.json)。

同时重跑 +287474 second VM 与 +287500 token VM 的 caller/prefix component：两项各
20 项 controls、8 项 rollback guards，在两个 image base 均通过。当前 component
verifier 没有重放旧 formal evidence 的 constructed outer/second metadata，因此不
宣称逐字节一致；完整 second/token VM return、whole-request equivalence 与 signing
仍未完成。见 [second-VM rerun](evidence/vm9_request_287474_vm_rerun_20261025.json)
与 [token-VM rerun](evidence/vm9_request_token_vm_rerun_20261025.json)。

随后重跑 lazy state-service component：两基址共 8 项 controls、7 项 rollback guards，
每个 formal case/guard 结果均复现。当前 verifier 没有输出 formal cumulative/provenance
字段，因此不宣称逐字节一致；cold/decoded-key/warm singleton 已覆盖，但完整 state
memory、live JVM 与 fresh signer 仍未完成。见
[state-service rerun](evidence/vm9_state_service_rerun_20261025.json)。

继续重跑 state diagnostic enter/leave wrappers：两基址共 36 项 controls、8 项 rollback
guards 通过。当前 verifier 使用重组后的 schema，没有 formal cumulative/provenance
字段，因此不宣称逐字节一致；allocation 仍是显式 provider，完整 state/request
memory 与 signer output 仍未完成。见
[state-diagnostics rerun](evidence/vm9_state_diagnostics_rerun_20261025.json)。

随后重跑 state prefix scoped-reference constructor：两基址共 16 项 controls、8 项
rollback guards，通过分配/锁顺序与 provider failure rollback。当前 case-level schema
与旧 formal aggregate-only JSON 不同，因此不宣称逐字节一致。见
[state-prefix reference rerun](evidence/vm9_state_prefix_reference_rerun_20261025.json)。

同一轮继续重跑 inline shared-reference getter：两基址共 36 项 controls、8 项 rollback
guards，覆盖 count/null/alias profiles 与 diagnostic lock effects。当前 case-level
输出与 formal aggregate schema 不同，因此不宣称逐字节一致。见
[inline-reference rerun](evidence/vm9_inline_reference_scope_rerun_20261025.json)。

随后重跑 environment assignment scope：两基址共 **28 项 native/Python controls、8 项
rollback guards**，覆盖 cold/warm diagnostics 下的 empty、one、text、long、count-wrap
和 high-output assignment。当前 verifier 只输出 case-level 结果，没有 formal
cumulative/provenance metadata，因此不宣称逐字节一致；allocation/TLS/JNI 仍是显式
provider，完整 environment memory、live Android JVM、fresh signing 与线上验收仍未完成。
见 [environment-assignment rerun](evidence/vm9_environment_assignment_scope_rerun_20261025.json)。

随后重跑 state final-reference scope：两基址的 direct reference lifecycle 与
cold/decoded-key final constructor 共 **20 项 native/Python controls、4 项 rollback
guards** 通过。当前 case-level 输出与 formal aggregate metadata 不同，因此不宣称
逐字节一致；没有使用 native snapshot 或历史 native group，allocator/diagnostic/JNI
相邻服务仍是显式 provider，完整 state/request memory、live JVM、fresh signing 与线上
验收仍未完成。见 [state final-reference rerun](evidence/vm9_state_final_reference_scope_rerun_20261025.json)。

随后重跑 SHA-1 hexadecimal reference scope：两基址、helper/state wrapper、cold/warm
diagnostics、边界长度、`0xffffffff` flag 与高地址栈共 **64 项 native/Python controls、8
项 rollback guards** 通过。当前 case-level 输出与 formal aggregate metadata 不同，因此
不宣称逐字节一致；未使用 native snapshot 或历史 native group，allocator/diagnostic lock
仍是显式 provider，完整 state/request memory、live JVM、fresh signing 与线上验收仍未完成。
见 [SHA-1 hex rerun](evidence/vm9_sha1_hex_scope_rerun_20261025.json)。

随后重跑 request x8 tree-reference constructor：两基址×四个 output placement 共 **8 项
native/Python controls** 与 **1 项 unmapped-output rejection** 通过，覆盖 cross-page
output 和 alias guard。该报告保持为独立 component schema，不宣称与旧 aggregate 逐字
一致，也不等同于完整 request callback、live JVM 或 fresh signer。见
[request tree-reference rerun](evidence/vm9_request_tree_reference_rerun_20261025.json)。

随后重跑 request-object constructor/clock/reference boundary：两基址共 **60 项
native/Python controls、48 项 rollback guards**，另有 **1 项 request-entry check**。
覆盖 cold/warm、长度/时间边界、direct/null ownership、wrapper tail、provider failure
及 owning request entry。当前输出比 formal aggregate 多 14 项 entry guards，因此不宣称
逐字节一致；未使用 native snapshot，physical spill、whole-request differential、live
JVM、fresh signing 与线上验收仍未完成。见
[request-object rerun](evidence/vm9_request_object_rerun_20261025.json)。

随后重跑 request configuration-tree/iterator boundary：两基址共 **24 项 native/Python
controls、24 项 rollback guards**，另有 **1 项 request-entry check**，覆盖 construct/
begin/end、iterator compare、cross-page、alias/NULL words 与 tree-provider failures。
当前输出比 formal aggregate 多 11 项 entry guards，因此不宣称逐字节一致；physical
spills、whole-request differential、live JVM、fresh signing 与线上验收仍未完成。见
[request-tree rerun](evidence/vm9_request_tree_rerun_20261025.json)。

随后重跑 request tree local/delete destruction：两基址共 **32 项 native/Python controls、
32 项 rollback guards**，另有 **1 项 request-entry check**，覆盖 empty/raw/string、
balanced/descending trees、direct/wrapper 与 free/provider failures。当前输出比 formal
aggregate 多 5 项 entry guards，因此不宣称逐字节一致；physical spills、whole-request
differential、live JVM、fresh signing 与线上验收仍未完成。见
[tree-destruction rerun](evidence/vm9_request_tree_destroy_rerun_20261025.json)。

随后重跑 normal Java facade → child dispatcher → owning request VM handoff：4 项
absent/SDK-30 cases、8 项回滚，与 2026-10-24 formal evidence 逐字节一致；每项
2583 VM steps、115 callbacks。JNI/JavaVM 与 request input 仍为 synthetic，whole
native differential、live Android JVM、fresh signing 和 online header acceptance
仍未验证。见 [handoff rerun](evidence/vm9_java_request_handoff_rerun_20261025.json)。

继续重跑 owning allocator → request VM continuation：两基址×absent/SDK-30 共 4 项
与 2026-10-24 formal evidence 逐字节一致；低基址 957 steps/26 callbacks，高基址
2475 steps/105 callbacks，并保持 high-base JNI acquisition 与 request cleanup。
仍是 Python composition，synthetic request/JNI provider，whole-request native
differential、fresh signing 与线上验收未完成。见
[allocator handoff rerun](evidence/vm9_request_allocator_handoff_rerun_20261025.json)。

继续重跑 Java facade service：两基址共 22 项 native/Python controls、15 项回滚，
覆盖 normal/NULL/error、duplicate/three-pair headers 与 cleanup。当前输出增加了
旧 formal JSON 未包含的 source/TDD/cumulative metadata，因此不宣称 byte-identical；
request 仍为 synthetic provider，whole-request native differential、live JVM、fresh
signing 和线上验收未完成。见 [facade rerun](evidence/vm9_java_request_facade_rerun_20261025.json)。

随后重跑 child request dispatcher：36 项 controls、18 项回滚，与 2026-10-24 formal
evidence 逐字节一致；callback/fallback route、reference assignment 和 shared mutex
effects 在两基址均匹配。actual request VM、fresh standalone signer 与线上验收仍为
独立未完成边界。见 [dispatch rerun](evidence/vm9_request_dispatch_rerun_20261025.json)。

继续重跑 selected-slot second VM return component：两基址×10 stack/TLS layouts 共
20 项 native/Python cases、15 项回滚通过；七个 physical return values、caller stack
和 TLS restoration 均匹配。当前 verifier 未重放 2026-10-19 formal JSON 后续的
constructed/owning control，因此不宣称 byte-identical。见
[second-return rerun](evidence/vm9_request_second_return_rerun_20261025.json)。

随后重跑 second-VM shared-reader callback component：18 项 native/Python cases、11
项回滚，覆盖 reader counts、packed alias、cross-page boundary 和 process-shared
mutex transitions，两基址均通过。当前脚本未重放 formal evidence 的 owning callback/
constructed-second metadata，因此不宣称 byte-identical。见
[second-reader rerun](evidence/vm9_request_second_reader_rerun_20261025.json)。

同轮重跑 shared-reader release component：18 项 cases、12 项回滚，覆盖 release
counts、alias、cross-page boundary 与 mutex transitions，两基址通过；owning/
constructed second entry 仍未由该 component 脚本重放，因此不宣称 byte-identical。
见 [reader-release rerun](evidence/vm9_request_second_reader_release_rerun_20261025.json)。

继续重跑 outer configuration setter component：38 项 controls、64 项回滚，覆盖
insert/replacement、alias、padding 与 failure paths，两基址通过。formal evidence
中的 owning/constructed-second metadata 未由该 component 脚本重放，因此不宣称
byte-identical。见 [configuration-set rerun](evidence/vm9_request_configuration_set_rerun_20261025.json)。

随后重跑 public second-VM service guard suite：30 项 early provider rejection 全部
通过，guest pages 与 provider effects 均保持不变。formal evidence 的 constructed
request control 未由该 guard-only verifier 重放，因此不宣称 byte-identical。见
[second-services rerun](evidence/vm9_request_second_services_rerun_20261025.json)。

随后重跑 JNI header-input conversion component：52 项 controls、22 项回滚，覆盖
normal/cold diagnostics、NULL/length/exception、duplicate keys 与 multi-pair headers，
两基址均通过。formal evidence 还包含 tree-release/roundtrip 旧批次和 cumulative
metadata，本轮不宣称 byte-identical。见
[header-input rerun](evidence/vm9_jni_header_input_rerun_20261025.json)。

继续重跑 cached-class/header-array component：42 项 controls、42 项回滚，覆盖 class
retention、ordered Java array values、string conversion 与 provider failures，两基址
通过。formal JSON 的 strict-TDD/pre-change metadata 未由该 verifier 输出，因此不
宣称 byte-identical。见 [header-array rerun](evidence/vm9_jni_header_array_rerun_20261025.json)。

继续重跑 cold String-class lookup/promotion component：24 项 controls、16 项回滚，
覆盖 NULL/exception、global/weak 与 mutex publication paths，两基址通过。formal
JSON 的 constructed-request/source metadata 未由该 verifier 输出，因此不宣称
byte-identical。见 [header-class rerun](evidence/vm9_jni_header_class_rerun_20261025.json)。

继续重跑 child environment-acquisition wrapper：16 项 controls；child cleanup/
destructor wrapper：16 项 controls、7 项回滚。GetEnv ownership、temporary attach/
detach、object reset 与 matching-libc free 均通过；formal files 的 owning callback
和 metadata 未由 wrapper-only verifier 重放，因此不宣称 byte-identical。见
[environment rerun](evidence/vm9_request_child_environment_rerun_20261025.json) 与
[cleanup rerun](evidence/vm9_request_child_cleanup_rerun_20261025.json)。

继续重跑 request caller-return/entry verifier：16 项 caller-return cases、1 项
request-VM boundary、26 项回滚，覆盖 callback clobber、stack/TLS restoration、
canary 与 provider failures，两基址通过。formal JSON 的 TDD/ownership metadata
未由该 verifier 输出，因此不宣称 byte-identical。见
[caller-return rerun](evidence/vm9_request_caller_return_rerun_20261025.json)。

## 2026-10-25 Asia/Shanghai：B reader AST/factory fresh rerun

按当前 pinned `libmetasec_ml_71332.so` 与 matching libc 重跑 B reader 的两层
组合：factory 通过 **26 项 native/Python、38 项回滚**，含两个基址的 **2 个
完整实际 ELF module**（278 descriptors、109066 runtime instructions）；attached
segment/custom AST 通过 **406 项 native/Python、36 项回滚**，含 **2 个完整实际
ELF module**、12 项实际 custom payload。两份 rerun JSON 与 2026-10-11 正式证据
逐字节一致，未使用 native snapshot。

这确认实际 AST 已经接入 factory/parse/root/cleanup 组合边界；它仍是 fresh ELF
组件对照，不等同于完整 B VM、whole-native request、fresh Medusa 或 standalone
signer。最新证据见 [factory rerun](evidence/vm9_alternative_factory_composition_rerun_20261025.json)
与 [reader AST rerun](evidence/vm9_alternative_ast_module_segments_custom_rerun_20261025.json)。

随后重跑完整 JNI/bootstrap 组合：两个 image base、两个 conditional startup 分支共
**4 项 fresh native/Python controls、38 项回滚**通过；13 个 ELF constructors、JNI
OnLoad、JavaVM/JNI、conditional startup 和入口 SP 恢复均保持一致，结果与 2026-10-11
正式证据逐字节一致。worker body、真实 JVM/OS 并发、fresh Medusa、standalone signer
和线上验收仍未验证。见 [JNI/bootstrap rerun](evidence/vm9_jni_complete_bootstrap_rerun_20261025.json)。

在进入 fresh standalone signer 前新增只读 public-boundary audit。审计锁定
`construct_default_outer`、`run_elf_constructors`、`+17b8f8`、`+27dd04` 和
`+2830c4` 五个生产入口，确认当前 normal facade 调用链和四项 handoff case 的
边界字段。request object 仍为 synthetic，未使用实际 JVM/OS thread；完成的 request
现在由 owning outer session 的 `publish_request_state` 显式提交，重复提交会拒绝。
因此 standalone signer 仍为 false，下一步继续恢复真实 provider 输入与 native
output differential。见
[signer boundary audit](evidence/vm9_signer_boundary_audit_20261024.json)。

随后重跑 JNI 后的两个实际 worker 与 guest exit：两基址、两个 startup 分支共 **4 项
native/Python controls、28 项回滚**通过；两个 worker 的 TLS/key generation、等待、
自然返回和 joinable guest pthread exit 均一致，结果与正式证据逐字节一致。第三个请求
worker、finalizer callback、真实 OS 线程和 signer 仍未完成。见 [worker rerun](evidence/vm9_jni_requested_workers_rerun_20261025.json)。

再重跑完整 finalizer worker：4 项完整 native/Python controls、4 项 copied probe、47 项
回滚全部通过，并与正式 JSON 逐字节一致；两基址、两 startup 分支的三条 worker、三次
guest exit 和 finalizer queue 状态保持一致。下一步进入实际 delayed follow-up callback。
见 [finalizer rerun](evidence/vm9_jni_finalizer_worker_rerun_20261025.json)。

随后重跑实际 delayed follow-up callback：两基址、两个 startup 分支共 **4 项完整
native/Python controls、22 项回滚**通过；三条 worker/guest exit、delayed callable
两段 image VM、Java unavailable 分支、配置发布与 cleanup 均与正式证据逐字节一致。
完整 timed executor poll、live Java string conversion、fresh Medusa 和 standalone
signer 仍未完成。见 [follow-up rerun](evidence/vm9_jni_followup_rerun_20261025.json)。

新增 facade service 的 nested provider journal 回归：`+17b8f8`、`+27dd04` 和
`+2830c4` 现在有直接入口级 forwarding 证明；provider rollback 批次更新为
**32 Python controls / 32 rollback controls**。该项仍是显式 synthetic provider
边界，不代表真实 JVM 或线上 signer。

## 2026-10-24：owning allocator handoff 重新接回 request VM

`verify_vm9_request_allocator_handoff_fresh_20261007.py` 现在在继续 request VM
前先对 fresh ELF 的 35 个匹配内存重定位执行 `resolve_request_memory_imports`，
并用同一 owning allocator session 构造合成配置树/reference、VM/JNI 表和
请求输入；现在通过正式 `invoke_request_vm_callback` owning entry，而不是
诊断 prefix 直接调用。原先高基址在 `+0x2859cc` 因 NULL imported `malloc`
停止的问题已消除。

四个 absent/`sdk_30` 组合均在 caller sentinel `+0xffb78` 返回：低基址
`0x122c0000` 为 957 步、26 callbacks；高基址 `0x775c205000` 为 2475 步、
105 callbacks，并实际执行现有 JNI environment acquisition、树计数/遍历、清理
和 VM return owner；strict callback ABI 校验和 staged request transaction
也通过。新增证据为
[`vm9_request_allocator_handoff_fresh_20261024.json`](evidence/vm9_request_allocator_handoff_fresh_20261024.json)。

这仍是同一 Python 状态组合：请求对象、JavaVM/JNI provider 和 URL/header 输入
是显式合成服务，未证明 whole-native handoff、真实 Android JVM、fresh 独立
Medusa/signer 输出或线上验收。

## 2026-10-24 Asia/Shanghai：outer finalization fresh boundary rerun

当前 pinned `libmetasec_ml_71332.so` 与 matching libc 上完成 outer finalization
fresh differential 重跑：10 个独立 u32 hash controls、6 个 publication/JNI
integration cases，以及 5 个负向/既有 rollback controls 全部通过。hash 由当前
输入 counter 生成，caller 高位零扩展、lazy formatter constants/guards、publication
与 JNI service ledger 均相等；6 个 integration case 的唯一 live allocation
mismatch 仍为 allocation 308 的 logger record/vector padding，字段内容保持一致。
结果见 [outer finalization fresh evidence](evidence/vm9_outer_finalize_fresh_20261024.json)。

这仍是 sample-verified fresh native boundary 与 Python publication 对照，不是完整
physical stack/ABI、fresh-input Medusa、完整 signer 或线上 header acceptance；
`complete_native_outer_state_equal=false`、`fresh_input_signer_output_verified=false`
和 `current_online_header_matrix_verified=false` 保持。

同次只读 allocation trace 已定位 live allocation 308：native/Python 都是第 309 个
96-byte allocation，调用点为 `+0x32a210`。4 个 24-byte vector 的 tag、长度、
payload 和终止字节均一致；21 个差异全部落在未使用的短字符串 padding，因此没有
形成生产 RED，也没有修改模型。证据见 [allocation 308 padding attribution](evidence/vm9_outer_allocation_308_padding_20261024.json)。

同日重跑 normal Java request facade fresh 组合：两个 image base、11 个输入 profile
共 **22 项 native/Python controls** 和 **15 项 rollback guards** 全部通过。URL/header
转换、合成 virtual request provider、Java 输出数组和 owning cleanup 的返回与顺序保持
一致；本批仍明确标记为 synthetic JNI/request provider，actual request VM integration、
alternate facade、fresh standalone signer 和线上 acceptance 未验证。证据见
[Java facade fresh rerun](evidence/vm9_java_request_facade_fresh_20261024.json)。

随后把 normal Java facade 的生产入口正式接到同一 owning allocator session：
`+17b8f8 → +27dd04 → +2830c4`。两个 image base、`absent`/`sdk_30` 四项组合
均返回 `+0xffb78`，每项 2583 VM steps、115 callbacks；URL/header 转换、child
callback 路由、owning request VM、Java 输出清理和 allocator mapping 均在同一
staged session 内完成。JNI/JavaVM 仍为 synthetic provider，未宣称 whole-native
differential、真实 Android JVM、fresh standalone signer 或线上 acceptance。证据见
[Java request handoff](evidence/vm9_java_request_handoff_fresh_20261024.json)。

随后重跑 child dispatcher：callback/fallback 路由与 scoped tree assignment 共 **36 项
native/Python controls、18 项 rollback guards** 全部通过，两个 image base 的 callback
顺序、共享 mutex、reference ownership 和 free effects 保持一致。该层仍只接到显式
request provider；完整 request VM、fresh standalone signer 和线上 acceptance 未验证。
证据见 [request dispatch fresh rerun](evidence/vm9_request_dispatch_fresh_20261024.json)。

caller/VM return 边界随后重跑通过：16 项 physical caller-return controls、1 项
request-entry control 和 26 项 refusal/rollback guards 全部通过；saved PC/SP、X19/X28/X29、
TLS canary、callback X0 preservation 与请求入口错误回滚保持一致。request body 仍是
bounded component 验证，完整 standalone signer 和线上 acceptance 未验证。证据见
[request caller return fresh rerun](evidence/vm9_request_caller_return_fresh_20261024.json)。

正式 owning request VM entry 也完成 fresh import/rollback rerun：2 项 Python prefix
controls 与 24 项 rollback guards 通过；生产入口没有导入 native oracle、Unicorn 或
重放历史 native group。该项只验证入口边界和旧函数/异常 identity，whole-request
differential、完整 signer 与线上 acceptance 仍未验证。证据见
[request VM entry fresh rerun](evidence/vm9_request_vm_entry_fresh_20261024.json)。

同次 outer→request prefix handoff 也重跑通过：6 项 fresh request VM prefix controls
与 4 项独立 Python outer handoff controls 均通过。outer 本轮输出只提供当前独立
Python 构造的 callback pair，request prefix 在 synthetic URL/header/context 上自然
执行到 `+0x2858bc` 边界；没有使用 native snapshot。分配型 request callback、完整
request VM、fresh Medusa 和线上 acceptance 仍未验证。证据见
[request prefix fresh rerun](evidence/vm9_request_prefix_fresh_20261024.json)。

## 2026-10-24 Asia/Shanghai：outer native signer boundary rerun

The existing fresh-ELF native outer control was rerun against the pinned
`libmetasec_ml_71332.so` and matching libc at both image bases. Ten controls
passed: absent, `30`, negative and signed-suffix SDK-property profiles, plus
relocated stack/mapping inputs. Each case returned through the native outer
getter with the expected root flag, singleton/configuration counts, child and
handler callback pairs, recursive publication mutex release, warm getter reuse,
and ordered JNI/destructor publication ledger. The run used no native input
snapshot, JVM, or real OS thread; allocator, property, clock and virtual thread
services remain explicit. It is **Sample verified** native boundary evidence only:
Python outer construction, fresh-input Medusa output, online header acceptance,
and whole-request memory equivalence remain open.

## 2026-10-24 Asia/Shanghai：full outer residual attribution

对同一独立构造的 `0x2830C4` 终态做只读来源归因：1437 个共同页中 1424 页相同，
13 页仍差 5042 字节。差异被分成 4860 字节的六个 physical stack/ABI scratch 页、
3 字节保存 caller-stack 指针高位的 scoped-lock alias、166 字节 format-token
native vector-store padding，以及 13 字节 event-record 短字符串尾部。token 的
tag/pointer/length/index/reserved 字段相同，event 的 tag/payload 相同；这些内容没有
形成生产 RED，因此没有修改生产模型。两个 native-only 页仍是全零服务页的存在性差异。

该归因没有把 native 输出作为模型输入，也没有计入 native controls；完整 physical
stack 等价、whole-request 内存等价、fresh Medusa 和完整 signer 仍未验证。证据见
[full outer residual diff](evidence/vm9_full_outer_residual_diff_20261024.json)。

同日用当前 pinned library/matching libc 重跑四组相关边界，共 138 项 native controls
和 27 项回滚检查全部通过；回归只确认组件边界稳定，不改变 full outer 的未完成结论。
证据见 [residual-boundary regression](evidence/vm9_residual_boundary_regression_20261024.json)。

## 2026-10-21 Asia/Shanghai：environment service reference scope

冷 environment-service 172D40 的 172EB0 构造现在复用既有 scoped constructor。
generic lazy owner 接受显式构造回调；environment 贯通既有 state provider，未修改 state 源码。
getter scope 位于入口 SP-70，padding 高两字节由 libc68D28 写零，低两字节保留调用前内容；
environment 前序 counter-new 的 32A1F4 保存 LR=image+1629A8，其高位成为该调用链的低两字节。
36 项原生对照、6 项页面回滚、96 项 Python 回归通过，累计 4045 native / 1796 guards。
12 个完整 context 事件轨迹相等，24 个含 C++ guard 观察差异的轨迹完整保留；引用诊断窗口一致。
孤立冷 state fixture 的 guest 差异 833->0，image/TLS 及分配/释放/注册/wake、新 scope24 字节一致。
这是该 fixture 的结果，不覆盖所有 state 分支、完整物理栈或 guard 事件。
完整 2830C4 的 322 packed 回调、七项返回及映射一致；两侧输出各自与 6.253 相同。
13 个共同页仍差 5042 字节，两个 native-only 页仍计存在性差异；完整 signer 尚未完成。
下一步定位完整请求中剩余页面的字段来源，并核对 raw allocation 的观察边界。
见 [environment service 报告](REQUEST_JNI_STARTUP_WORKERS.md#6254-environment-service-reference-scope2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-21 Asia/Shanghai：default shared factory reference scope

冷 shared factory 26CDC4 尾部 1625A4 现在通过显式 provider 复用既有 scoped constructor。
provider 贯通 getter/environment/StateCallbacks；仅 state diagnostic_scope 启用，默认裸构造保持。
入口 factory SP-70，scope SP-C0；padding 来自 26EA54 保存的 logger entry SP 高位。
44 项原生对照、7 项回滚、60 项 Python 回归通过，累计 4009 native / 1790 guards。
getter 的完整 guard PLT 事件轨迹仍不等，两侧完整记录保留；引用作用域事件单独验证一致。
冷 state 的首次分配差异从 20 移到 28，guest 差异 868->833 字节，image/TLS 差异区域 1->0。
下一处为 environment service 引用构造：原生 scope caller LR172EE4，模型仍为裸 lazy reference。
完整 2830C4 的 322 个 packed 回调、七项返回及映射一致；两侧输出各自与 6.252 相同。
13 个共同页面仍差 5042 字节、两个 native-only 服务页仍计存在性差异。完整 signer 尚未完成。
见 [shared factory 报告](REQUEST_JNI_STARTUP_WORKERS.md#6253-default-shared-factory-reference-scope2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-21 Asia/Shanghai：environment reference release scope

environment 尾部 25EF80 释放现在通过显式 provider 复用既有 scoped release owner。
state 在 diagnostic_scope 下绑定；入口 environment SP-60，scope SP-A0。
padding 按路径来自 canary、目录调用保存 LR 或 faccessat 包装器保存 X23，均由模型输入生成。
新增 38 项原生对照、7 项页面回滚和 46 项 Python 回归，累计 3965 native / 1783 guards。
完整 2830C4 的 322 个 packed 回调、七项返回与 GuestOS 映射继续一致。
原生/模型结果各自与 6.251 相同：1424/1437 共同页一致，13 页仍差 5042 字节。
两个 native-only 服务页仍计入页面存在性差异。完整冷诊断表 state 仍在 allocation20 分歧，
868 字节 guest 差异及一个 image/TLS 差异区域全部保留。完整 signer 尚未完成。
见 [environment 释放报告](REQUEST_JNI_STARTUP_WORKERS.md#6252-environment-reference-release-scope2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-21 Asia/Shanghai：state service final reference scope

state显式diagnostic_scope现在将尾部25728C引用构造绑定到既有scoped reference owner。
构造入口factory SP-60，scope SP-B0；padding由原生1625B4保存uint32 flag1的高位生成。
新增20项原生对照、4项页面回滚、10项Python回归。完整诊断表预热state用例通过；
完整冷诊断表state失败保留，environment作用域的独立缺口仍未修复。
完整2830C4的322根packed回调全部一致，七项返回和GuestOS映射一致。
共同页相同1424/1437；差异20页5504字节->13页5042字节，减少462。
原生1439页、初态hash保持；两个native-only服务页仍是页面存在性差异。
raw分配轨迹首次分歧157->181，native free对model malloc10；须先区分realloc观察边界。
累计3927 native/1776 guards。完整signer和全内存等价仍未完成。
见 [state尾部引用报告](REQUEST_JNI_STARTUP_WORKERS.md#6251-state-service-final-reference-scope2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-21 Asia/Shanghai：SHA-1 hexadecimal reference scopes

state显式diagnostic_scope现在绑定258780 SHA-1 hex生命周期，复用digest和reference owner。
恢复构造、赋值、释放的独立frame与完整24字节scope；padding来自当前digest、临时地址与canary。
新增64项原生对照、8项页面回滚、42项Python回归；公开state factory实际绑定，默认路径保持。
完整2830C4首个分配分歧132->157；20共同页仍差5504字节，1417/1437共同页相同。
七项返回、GuestOS映射、原生1439页和初态hash保持；5个packed记录和2个native-only页仍不同。
下一诊断LR2572C0定位state service尾部25728C引用构造；environment release独立缺口仍在。
累计3907 native/1772 guards。完整signer和全内存等价仍未完成。
见 [SHA-1作用域报告](REQUEST_JNI_STARTUP_WORKERS.md#6250-sha-1-hexadecimal-reference-scopes2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-21 Asia/Shanghai：environment owned reference scope

state显式diagnostic_scope绑定environment的reference_assigner，复用162944拥有引用赋值，
传递environment入口SP-60；15F590保存X19的高位生成后续scope padding，无native快照输入。
新增28项原始environment前缀对照、8项拒绝/页面回滚、38项Python回归；默认行为全部保持。
完整2830C4首个分配分歧117->132；20共同页差异5508->5504字节，减少4。
七项返回和GuestOS映射一致，原生1439页及初态hash保持；1417/1437共同页相同。
5个packed记录和2个native-only服务页仍不同。下一诊断LR1625D8定位1625A4，需继续关联上层caller。
environment release scope仍未恢复。累计3843 native/1764 guards。完整signer及全内存等价仍未完成。
见 [environment赋值作用域报告](REQUEST_JNI_STARTUP_WORKERS.md#6249-environment-owned-reference-scope2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-21 Asia/Shanghai：inline shared reference scope

state显式diagnostic_scope通过environment转发reference_copier，由getter传递入口SP-40，
复用15F580 scoped copy；默认getter/state全部字节和事件保持。
新增36项原始getter对照、8项拒绝/页面回滚、46项Python回归，累计3815 native/1756 guards。
完整2830C4首个分配分歧114->117；20共同页差异5554->5508字节，减少46。
七项返回和GuestOS映射一致，原生1439页及初态hash保持；1417/1437共同页相同。
5个packed记录、2个native-only服务页仍不同。下一诊断LR16299C对应162944拥有引用赋值。
完整signer、全内存等价、live/JVM、完整ABI及provider/mapping回滚仍未完成。
见 [inline引用作用域报告](REQUEST_JNI_STARTUP_WORKERS.md#6248-inline-shared-reference-scope2026-10-21-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：state prefix reference

state prefix通过显式reference_constructor复用1625A4作用域；state的diagnostic_scope启用该组合。
新增16项原始前缀对照、8项拒绝/页面回滚、26项Python回归；默认prefix/state返回与全部字节保持。
完整2830C4的首个分配分歧从110移至114；20共同页字节差异从5638降至5554，减少84。
七项返回与GuestOS映射一致，原生1439输出页及初态hash保持；1417/1437共同页相同。
5个packed记录、2个native-only全零服务页仍不同，未过滤。累计3779 native/1748项拒绝或回滚。
完整state/request内存等价、signer、live/JVM及完整ABI仍未完成。
见 [state前缀引用报告](REQUEST_JNI_STARTUP_WORKERS.md#6247-state-prefix-reference2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：state VM diagnostics

state VM通过显式diagnostic_scope启用26A544/26A560进入与清理；公开factory/caller已转发。
新增36项原始包装器对照、8项拒绝/页面回滚、28项Python回归通过；默认排除模式逐字节保持。
完整original2830C4首次返回，5182步/322根回调，七项返回及完整映射元数据一致。
全部1439原生输出页与上一轮逐字节一致；1417/1437共同页面相同，20页仍差5638字节，
比统一返回地址后的对照减少10字节。5个packed回调记录仍不同，未过滤差异。
另有2个全零native provider stub页未在Python模型映射；页面集合不相同，未按零页算通过。
首个分配分歧在state prefix的1625A4引用作用域；该项及environment helper仍未恢复。
累计3763 native/1740项拒绝或回滚。完整request内存等价、signer、live/JVM及完整ABI未完成。
见 [state诊断报告](REQUEST_JNI_STARTUP_WORKERS.md#6246-state-vm-diagnostics2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：printf caller spills

second printf恢复两个由调用本身确定的保存字：SP-48处LR=image+288AE8、SP-18处X19=packed。
新增32项原始入口对照、48项纯Python回归通过；6项既有拒绝/页面回滚检查重跑通过，未重复累计。
整段original287474仍为97156步/391回调、七项返回值一致；1436/1439页逐字节相同，
三页差异106/1624/1174字节，合计2904，减少5。累计3727native/1732项拒绝或回滚。
完整second/request内存等价、signer、live/JVM及完整ABI仍未完成。
见 [调用保存字报告](REQUEST_JNI_STARTUP_WORKERS.md#6245-caller-spills2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：consumed printf variadic state

second printf通过原有两遍live格式化恢复SP-C0/SP-E0两份32字节va_list副本及GP消费游标。
新增32项原始入口对照、10项拒绝/页面回滚检查；68项纯Python回归保持旧返回、事件及
声明帧以外全部字节，默认shared/token路径逐字节保持。历史native组未重跑。
整段original287474保持97156步、391回调和七项返回值一致，1436/1439页逐字节相同；
剩余三页106/1624/1179字节，合计2909，比上一阶段减少21字节。
累计3695native/1732项拒绝或回滚；完整内存等价、signer、live/JVM及完整ABI未完成。
见 [消费参数状态报告](REQUEST_JNI_STARTUP_WORKERS.md#6244-consumed-printf-variadic-state2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：deterministic printf formatter frame

second allocated printf恢复八个由输入计算的格式化器帧字，以及成功第二遍保存的分配尺寸。
新增20项原始包装入口对照、6项拒绝/页面回滚检查；48项旧Python路径的返回、payload、
事件及声明帧以外全部字节保持。历史native组没有重跑。
整段original287474保持97156步、391回调及七项返回值一致，1436/1439页逐字节相同；
剩余三页差异106/1624/1200字节，合计2930，比上一阶段减少45字节。
累计3663native/1722项拒绝或回滚；完整内存等价、signer、live/JVM及完整ABI未完成。
见 [格式化器帧报告](REQUEST_JNI_STARTUP_WORKERS.md#6243-deterministic-printf-formatter-frame2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：saved printf variadic state

共享token/second printf owner恢复保存的X2和两份未消费va_list，共72字节声明栈状态。
新增24项原始包装入口对照和6项拒绝/页面回滚检查；GP/FP spills与已消费副本仍未恢复。
整段original287474保持97156步、391回调和七项返回值一致，1436/1439页逐字节相同。
剩余3页栈差异106/1624/1245字节，合计2975，比上一阶段减少45字节；没有过滤差异。
累计3643native/1716项拒绝或回滚；完整second/request内存等价、signer、替代Java、
live/JVM、完整ABI和外部回滚仍未完成。
见 [printf保存参数报告](REQUEST_JNI_STARTUP_WORKERS.md#6242-saved-printf-variadic-state2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：live VM register memory

second VM使用客体内存中的32个寄存器槽和bytecode cursor，按执行顺序保留写入与别名读取。
新增36项原始解释器对照和17项拒绝检查；旧abstract/hidden-only模式保持原契约。
整段original287474保持97156步、391回调和七项返回值一致；1436/1439页逐字节相同。
原7004D000页的83字节差异已全部消除；剩余3页栈残留106/1624/1290字节，未过滤。
累计3619native/1710项拒绝或回滚；完整second/request内存等价、signer、替代Java、
live/JVM、完整ABI和外部回滚仍未完成。
见 [寄存器内存报告](REQUEST_JNI_STARTUP_WORKERS.md#6241-live-vm-register-memory2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：matching libc integer dtoa

显式format_number服务接通公开owning VM至JSON printer，恢复已观察整数double的
匹配bionic静态池、mantissa与free链，新增16项原始对照、29项拒绝/页面回滚。
整段original287474保持391回调、七项返回值一致；1435/1439页相同，全部libc页一致。
剩余4页栈残留106/1624/1290/83字节未过滤，完整second/request内存等价仍未通过。
支持范围为abs(integer double)<1e9、precision15；通用float/17位/heap分支未完成。
累计3583native/1693项拒绝或回滚；完整signer、替代Java、live/JVM、完整ABI和外部回滚仍未完成。
见 [整数dtoa报告](REQUEST_JNI_STARTUP_WORKERS.md#6240-matching-libc-integer-dtoa2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：matching libc clock cache

共享session的时钟路径恢复bionic冷guard/cache与热缓存，新增8项原始对照、14项拒绝。
整段original287474复核仍为391回调、七项返回值一致；1433/1439页相同，时钟页已一致。
剩余2页dtoa状态和4页栈残留，均未过滤；whole second/request完整内存对照仍未通过。
最后写入证据将dtoa定位到第223个JSON打印回调。累计3567native/1664项拒绝或回滚。
完整standalone signer、替代Java、live/JVM、完整physical ABI及provider/mapping回滚仍未完成。
见 [时钟缓存报告](REQUEST_JNI_STARTUP_WORKERS.md#6239-matching-libc-clock-cache2026-10-20-asiashanghai)。

## 2026-10-20 Asia/Shanghai：live native provider bridge

公开 LiveCpuPages/NativeService 桥接与显式 opt-in 输入页映射通过2项原始GetEnv对照、13项拒绝检查。
实际构造输入上的 original287474 与 Python 均完整返回：391回调逐项一致，七项物理返回值一致；
1439页中1432页相同，库映像与堆页均相同。剩余3页libc时钟/dtoa缓存及4页栈残留不同，
whole second/request完整内存对照仍不通过；整段探索不计入已验收native数量。
累计3559native/1650项拒绝或回滚。JNI/OS仍为显式synthetic服务；完整standalone signer、
替代Java、live/JVM、完整physical ABI及provider/mapping回滚仍未完成。
见 [native服务桥报告](REQUEST_JNI_STARTUP_WORKERS.md#6238-live-native-provider-bridge2026-10-20-asiashanghai)。

## 2026-10-20 Asia/Shanghai：reusable owning request VM entry

正式 vm9_request_vm 入口与 normal Java facade 适配已接通。五个迁移定义 AST 保持，
455 旧 Python 文件逐字节不变；旧函数/异常直接导出同一对象，正式导入无需 native oracle。
2 项 Python prefix、24 项局部拒绝/回滚及 1 项完整构造输入提前停止检查通过。
新入口构造链返回 outer5182/322、second97156/391、14 Java 元素；对象与 counter 各释放一次。
本轮新增 native 对照0；累计3557native/1637checks。JNI/OS仍为显式synthetic服务。
下一步 whole second/request original-native 对照与 fresh 完整 standalone signer；替代Java、
live/JVM、physical ABI和provider/mapping回滚仍未完成。
见 [正式入口报告](REQUEST_JNI_STARTUP_WORKERS.md#6237-reusable-owning-request-vm-entry2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：signer child request dispatch

恢复27DD04分发器与27E798树引用赋值。36双基址native/18回滚通过。
真实构造child连接JNI输入、mode138 owning VM及Java输出清理：outer5182/322、second97156/391，
14元素与7项树一致；三个对象及counter在各自引用生命周期内各free一次。JNI/OS为显式synthetic服务。
454旧AST/81bindings/1060private hashes保持；旧native未重跑。
累计3557native/1612checks。下一步正式owning VM适配入口及whole native/fresh完整standalone signer验证。
替代Java分支、live/JVM、physical ABI和provider/mapping回滚仍未验证。
见 [分发器报告](REQUEST_JNI_STARTUP_WORKERS.md#6236-signer-child-request-dispatch2026-10-20-asiashanghai)。

以下各节为历史检查点，当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：normal Java request facade

新增17B8F8常规外层，组合URL/header输入、request虚调用、Java输出及全部scoped清理。
22双基址native和15回滚通过；虚request为显式synthetic服务，非实际request VM证明。
452旧AST/80bindings/1045privatehashes保持；历史native未重跑。
累计3521native/1594checks。下一步将真实URL/header引用接入拥有状态的request VM并验证外层完整组合。
替代Java路径、whole request/second native、fresh完整signer及live/JVM仍未完成。
见 [Java外层报告](REQUEST_JNI_STARTUP_WORKERS.md#6235-normal-java-request-facade2026-10-20-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：JNI header input and tree reference release

恢复26FC94 Java ObjectArray→拥有的树及1628E4/166EC8树引用释放。
52输入/20释放双基址native与32回滚通过；synthetic 6元素→2项树→4个Java输出及最终删除通过。
450旧AST/79bindings/1028privatehashes保持；历史native未重跑。
累计3499native/1579checks。实际Java request facade与URL/header到request接入、whole request/second native、
fresh完整signer及live/JVM仍未完成。见 [header输入报告](REQUEST_JNI_STARTUP_WORKERS.md#6234-jni-header-input-and-tree-reference-release2026-10-20-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：cold String class and constructed output

JNI数组组件恢复cold String class lookup/global retention，显式serial lock服务。
24双基址native/16回滚通过；构造request5182步/322callbacks的7项结果转为14个Java元素。
449旧AST/78bindings/1016privatehashes保持；历史native未重跑。
累计3427native/1547checks。实际Java request wrapper与URL/header JNI输入、whole request/second native、
fresh完整signer及live/JVM仍未完成。见 [冷class报告](REQUEST_JNI_STARTUP_WORKERS.md#6233-cold-string-class-and-constructed-output2026-10-20-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：cached-class JNI header array

新增271384树到Java数组组合，复用既有tree/UTF/reference owner，显式cached String class。
42双基址native与42回滚检查通过；447旧AST/77bindings/1008privatehashes保持。
累计3403native/1531checks。实际request输出接入、URL/header JNI输入、whole request/second native、
fresh完整signer及live/JVM仍未完成。见 [JNI数组报告](REQUEST_JNI_STARTUP_WORKERS.md#6232-cached-class-jni-header-array2026-10-20-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：public second services

公共outer入口显式传入identifier file及mutex绑定，second调用预算500000，outer预算8000。
构造request无需修改second执行参数即可返回：second96740/+112434/391callbacks；outer5182/+FFB78/322callbacks。
新增1项构造入口验收及30项拒绝检查，native新增0项。446旧AST/76bindings/994privatehashes保持。
累计3361native/1489checks；完整signer、whole second/request native、actual URL/header JNI、fresh/live/JVM未证明。
见 [公共服务报告](REQUEST_JNI_STARTUP_WORKERS.md#6231-public-second-services2026-10-20-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-20 Asia/Shanghai：outer configuration set

外层配置写入恢复，39项新增native/64项拒绝检查通过；实际3572instructions/1238ranges、6次真实分配/1次释放一致。
构造outer5182/+FFB78/322callbacks正常返回，second96740/+112434/391callbacks和child return保持。
公共outer预算8000，公共second仍20000；该构造入口继续依赖私有second500000预算。
445个旧AST、75个历史绑定/974项私有哈希保持；累计3361native/1459checks。
完整signer、whole second/request native、actual URL/header JNI、fresh/live/JVM未证明。见 [配置写入报告](REQUEST_JNI_STARTUP_WORKERS.md#6230-outer-configuration-set2026-10-20-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-19 Asia/Shanghai：second VM return

Second selected-slot返回与caller epilogue恢复，21项新增native/15项拒绝检查通过。
实际9instructions/1437完整页及7个物理返回值一致；旧token caller owner未修改。
second96740/+112434完成有界caller return；outer3900→4000/+FE5B0，下一285EF0→2568C8。
444个旧AST、74个历史绑定/959项私有哈希保持。
累计3322native/1395checks；完整signer/whole second/request/fresh/live/JVM未证明。见 [second返回报告](REQUEST_JNI_STARTUP_WORKERS.md#6229-second-vm-return2026-10-19-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-19 Asia/Shanghai：second allocated printf

288AD4→278314双遍格式化分配恢复，50项新增native/39项拒绝或回滚通过。
两次实际调用逐次核对，声明内存/非栈写入/W0/canary/原生分配效果一致；旧format owner未修改。
second96740/+112434到达VMExit，返回流程待恢复；旧计数/child return保持，second页未发布。
443个旧AST、73个历史绑定/941项私有哈希保持。
累计3301native/1380checks；完整signer/fresh/live/JVM未证明。见 [格式化分配报告](REQUEST_JNI_STARTUP_WORKERS.md#6228-second-allocated-printf2026-10-19-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second Base64 reference

288A4C→258C14 Base64引用构造wrapper恢复，31项新增native/33项拒绝或回滚通过。
实际1次调用逐次核对，声明内存/非栈写入/原生allocator/free效果一致；旧Base64/scoped owner未改动。
second96588/0x1121d4，下一0x288ad4→0x278314；旧计数/child return保持。
442个旧AST、72个历史绑定/926项私有哈希保持。
累计3251native/1341checks；完整signer/fresh/live/JVM未证明。见 [Base64报告](REQUEST_JNI_STARTUP_WORKERS.md#6227-second-base64-reference2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second flagged cleanup

288AC8→1B55F8 条件字符串清理wrapper恢复，34项新增native/19项拒绝或回滚通过。
实际2次调用逐次核对，声明内存/非栈写入/原生free效果一致；旧destructor owner未改动。
second96519/0x1120c0，下一0x288a4c→0x258c14；旧计数/child return保持。
441个旧AST、71个历史绑定/911项私有哈希保持。
累计3220native/1308checks；完整signer/fresh/live/JVM未证明。见 [清理报告](REQUEST_JNI_STARTUP_WORKERS.md#6226-second-flagged-cleanup2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second memory fill

288AB4→347F20 内存填充wrapper恢复，50项新增native/20项拒绝或回滚通过。
实际2种输入形态与真实libc memset/X0一致；模型总调用17次，未逐次原生比较。
second93021/0x111bc0，下一0x288ac8→0x1b55f8；旧计数/child return保持。
440个旧AST、70个历史绑定/894项私有哈希保持。
累计3186native/1289checks；完整signer/fresh/live/JVM未证明。见 [填充报告](REQUEST_JNI_STARTUP_WORKERS.md#6225-second-memory-fill2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second sized string

288A74→2481FC 显式长度字符串构造wrapper恢复，35项新增native/28项拒绝或回滚通过。
实际3次调用逐次核对，声明内存/非栈写入/原生malloc效果一致；旧sized owner未改动。
second86800/0x11387c，下一0x288ab4→0x347f20；旧计数/child return保持。
439个旧AST、69个历史绑定/877项私有哈希保持。
累计3136native/1269checks；完整signer/fresh/live/JVM未证明。见 [构造报告](REQUEST_JNI_STARTUP_WORKERS.md#6224-second-sized-string2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second string clone

288A64→2483E0 二进制字符串复制wrapper恢复，31项新增native/29项拒绝或回滚通过。
实际155指令/1200范围/352字节栈，1malloc/0free与声明内存一致；旧clone owner未改动。
second11263/+10BDB0，下一288A74→2481FC；旧计数/child return保持。
438个旧AST、68个历史绑定/862项私有哈希保持。
累计3101native/1241checks；完整signer/fresh/live/JVM未证明。见 [复制报告](REQUEST_JNI_STARTUP_WORKERS.md#6223-second-string-clone2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second decoded reference

288A4C→258E7C 解码引用wrapper恢复，31项新增native/33项拒绝或回滚通过。
实际3159指令/1243范围/512字节栈，4malloc/1free与声明内存一致；旧decoded/reference owner未改动。
second11128/+10BB50，下一288A64→2483E0；旧计数/child return保持。
437个旧AST、67个历史绑定/846项私有哈希保持。
累计3070native/1212checks；完整signer/fresh/live/JVM未证明。见 [解码引用报告](REQUEST_JNI_STARTUP_WORKERS.md#6222-second-decoded-reference2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second configuration lookup

288A30→263174 配置解析查找与嵌套引用 scope 恢复，19项新增native/33项拒绝或回滚通过。
实际304121指令/1981范围/5120字节栈，65malloc/57free及完整声明内存一致。
second11118/+10BB28，下一288A4C→258E7C；旧计数/child return保持。
430个完整旧AST、136个扩展owner内未改动函数/类、
66个旧绑定/830项私有哈希保持，旧native不重跑。
空/无效完整配置的原生终止分支仍拒绝；SHA1 hex未恢复。outer原页保持/64新增OS页，second页未发布。
累计3039native/1179checks；完整signer/fresh/live/JVM未证明。见 [配置查找报告](REQUEST_JNI_STARTUP_WORKERS.md#6221-second-configuration-lookup2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second JSON delete

288A24→2614EC JSON清理恢复，53项新增native/30项拒绝或回滚通过。
实际8409指令/1230范围/592字节栈，31次原生free顺序和字节一致。
45旧AST、65旧绑定/809私有哈希保持。second11108/0x10bb00，下一0x288a30→0x263174。
JSON清理1次，旧计数/child return保持；outer原页无差异/64新增OS页，second页未发布。
累计3020native/1146checks；完整signer/fresh/live/JVM未证明。见 [清理报告](REQUEST_JNI_STARTUP_WORKERS.md#6220-second-json-delete2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second mutex unlock

2889A8显式pthread_mutex_unlock回调恢复，复用既有owner，15项新增native/24项拒绝或回滚通过。
实际30指令/1187范围/96字节栈，mutex1→0；44旧AST、64旧绑定/788私有哈希保持。
second10788/+10B3EC，下一288A24→2614EC；解锁1次，旧计数/child return保持。
outer原页无差异/64新增OS页，second页未发布；累计2967native/1116checks。
完整signer/fresh/live/JVM未证明。见 [解锁报告](REQUEST_JNI_STARTUP_WORKERS.md#6219-second-mutex-unlock2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second protobuf pack

2889F4→2A337C编码回调复用size验证，57项新增native/32项拒绝或回滚通过。
实际706字节编码/9402指令/1439范围/592字节栈；43旧AST、63旧绑定/765私有哈希保持。
second10680/+10B23C；下一2889A8，+383490 pthread_mutex_unlock导入尚未绑定、target NULL。
编码1次，旧计数/child return保持；outer原页无差异/64新增OS页，second页未发布。
累计2952native/1092checks；完整signer/fresh/live/JVM未证明。见 [Protobuf编码报告](REQUEST_JNI_STARTUP_WORKERS.md#6218-second-protobuf-pack2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second string fill

2889E0→248DD8填充回调复用既有owner，29项新增native/26项拒绝或回滚通过。
实际请求3657指令/1245范围/3072字节栈，原始分配器；42旧AST、62旧绑定/742私有哈希保持。
second10671/+10B218，下一2889F4→2A337C；填充1次，旧计数/child return保持。
outer原页无差异/64新增OS页，second页未发布；累计2895native/1060checks。
完整signer/fresh/live/JVM未证明。见 [字符串填充报告](REQUEST_JNI_STARTUP_WORKERS.md#6217-second-string-fill2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second protobuf packed size

2889C4→2A3378长度回调恢复，独立有界proto3模型，53项新增native/35项拒绝或回滚通过。
实际请求706/7168指令/1186范围/448字节栈；41旧AST、61旧绑定/719私有哈希保持。
second10662/+10B1F4，下一2889E0→248DD8；长度回调1次，旧计数不减少/child return保持。
outer原页无差异/64新增OS页，second页未发布；累计2866native/1034checks。
完整signer/fresh/live/JVM未证明。见 [Protobuf长度报告](REQUEST_JNI_STARTUP_WORKERS.md#6216-second-protobuf-packed-size2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second raw realtime milliseconds

28876C→26CC60毫秒回调恢复，复用现有有符号回绕运算，精确8字节结果；15项新增native/14项拒绝或回滚通过。
实际请求48指令/1186范围；40旧AST、60旧绑定/699私有哈希保持。second10651/+10B1C8，下一2889C4→2A3378。
毫秒回调1次，旧计数不减少/child return保持；outer原页无差异/64新增OS页，second页未发布。
累计2813native/999checks；完整signer/fresh/live/JVM未证明。见 [实时毫秒报告](REQUEST_JNI_STARTUP_WORKERS.md#6215-second-realtime-milliseconds2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second explicit mutex lock

显式ELF/libc导入绑定与2889A8普通锁回调恢复，精确4字节结果；15项新增native/24项拒绝或回滚通过。
实际请求26指令/1187范围；39旧AST、59旧绑定/680私有哈希保持。second10599/+10B0F8，下一28876C→26CC60。
锁回调1次，旧计数不减少/child return保持；outer原页无差异/64新增OS页，second页未发布。
累计2798native/985checks；并发与完整signer/fresh/live/JVM未证明。见 [普通锁报告](REQUEST_JNI_STARTUP_WORKERS.md#6214-second-mutex-lock2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second compact JSON printing/reference

49项新增原生对照、36项拒绝或回滚检查通过；256字节起始缓冲、转义/数字/容器、扩容与失败清理、字符串引用已恢复。
实际原始allocator回调27222指令/1375范围；scope的4字节padding和libc内部浮点状态未比较。
37个旧AST owner及660个历史绑定哈希保持；second10494/+10AF54，下一2889A8绝对target为NULL。
JSON print1次，其余旧计数与child return保持；outer原页无差异/64新增OS页。
累计2783native/961checks；完整signer/fresh/live/JVM未完成。见 [JSON序列化报告](REQUEST_JNI_STARTUP_WORKERS.md#6213-second-json-print2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second JSON bool insertion

41项新增原生对照、22项拒绝或回滚检查通过；最低位布尔节点、键复制、链表追加和失败清理已恢复。
实际原始allocator回调384指令/1208范围通过；36个旧AST owner及646个历史绑定哈希保持。
second10481/+10AF20，下一288990→2616B4；JSON bool1次，其余旧计数和child return保持。
outer原页无差异/64新增OS页；累计2734native/925checks；完整signer/fresh/live/JVM未完成。
见 [JSON布尔报告](REQUEST_JNI_STARTUP_WORKERS.md#6212-second-json-bool2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-18 Asia/Shanghai：second configuration string lookup

29项新增原生对照、24项拒绝或回滚检查通过；配置树命中按长度克隆、缺失/NULL构造空字符串，均持有shared reader。
实际原始allocator/libc锁回调909指令/1215范围通过；35个旧AST owner及630个历史绑定哈希保持。
second10471/+10AEF8，下一288968→261580；configuration string1次/JSON string3次/number9次，其余旧计数和child return保持。
outer原页无差异/64新增OS页；累计2693native/903checks；完整signer/fresh/live/JVM未完成。
见 [配置字符串报告](REQUEST_JNI_STARTUP_WORKERS.md#6211-second-configuration-string2026-10-18-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second numeric string construction

31项新增原生对照、34项拒绝或回滚检查通过；9个u32全局及1个TLS u32转十进制，libc++ reserve/append/shrink恢复。
实际原始allocator/TLS回调2579指令/1224范围对照通过；34个旧AST owner和617个历史绑定哈希保持。
second10403/+10AD04，下一28890C→256CE0；numeric string1次/string16次/json string2次，其余旧计数与child return保持。
outer原页无差异/64新增OS页；累计2664native/879checks；完整signer/fresh/live/JVM未完成。
见 [数字字符串报告](REQUEST_JNI_STARTUP_WORKERS.md#6210-second-numeric-string2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second JSON string insertion

53项新增原生对照、24项拒绝或回滚检查通过；type0x10字符串节点及value/key复制、链表追加和失败清理恢复。
实际原始allocator/copy回调923指令/1221范围对照通过；旧AST owner和历史私有证据保留。
second10341/+10AABC，下一2888F4→28794C；json string1次，旧计数/child return保持。
outer原页无差异/64新增OS页；累计2633native/845checks；完整signer/fresh/live/JVM未完成。
见 [字符串报告](REQUEST_JNI_STARTUP_WORKERS.md#6209-second-json-string2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second five-argument unsigned64 formatter

17项新增原生对照、16项拒绝或回滚检查通过；已有printf支持%lu/%llu，2888B4传W2与4个X参数。
旧单W2默认/格式分支保持；实际原始allocator/formatter12997指令/1193范围对照通过。
second10332/+10AA98，下一2888D0→2613E4；string format2次，旧计数/child return保持。
outer原页无差异/64新增OS页；累计2580native/821checks；完整signer/fresh/live/JVM未完成。
见 [格式化报告](REQUEST_JNI_STARTUP_WORKERS.md#6208-second-five-argument-format2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second TLS uint32 getter

15项新增原生对照、15项拒绝或回滚检查通过；288898→2850A8复用已有TLS provider，packed+16仅写4字节。
14项两基址cold/warm组件及1项实际63指令/1190声明范围对照通过；旧TLS owner保持。
second10320/+10AA68，下一2888B4→248908；TLS getter1次，旧计数/child return保持。
outer原页无差异/64新增OS页；累计2563native/805checks；完整signer/fresh/live/JVM未完成。
见 [TLS读取报告](REQUEST_JNI_STARTUP_WORKERS.md#6207-second-tls-u322026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：VM int32 to double

32项新增原生对照、6项拒绝检查通过；operation34将R4低signed int32转为R2 double。
旧operation30及全部旧owner保持；abstract/backed寄存器和定义backing bytes与原生一致。
构造second prefix恢复返回至10294/+10AA00，下一288898→2850A8；JSON number累计8次。
旧计数/child return保持；outer原页无差异/64新增OS页；累计2548native/790checks。
完整signer与fresh/live/JVM未完成。见 [有符号转换报告](REQUEST_JNI_STARTUP_WORKERS.md#6206-vm-int32-to-double2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second serial atomic field getter

19项新增原生对照、14项拒绝或回滚检查通过；恢复256F58读取receiver+138并写packed+16。
旧locked getter保持；原始LDAR串行值一致，并发语义未证明。
执行到10266/0x10a848，opcode34 operation34仍拒绝；异常帧保留旧计数/child return，second prefix未返回。
outer原页无差异/64新增OS页；累计2516native/784checks；完整signer/fresh/live/JVM未完成。
见 [原子读取报告](REQUEST_JNI_STARTUP_WORKERS.md#6205-second-atomic-u322026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：third second-VM global uint32 getter

17项新增原生对照、10项拒绝或回滚检查通过；恢复1E53D0读取3D60D4，旧两getter/helper语义保持。
16项两基址组件+1项实际owning；uint32结果、padding及全部声明范围一致。
构造prefix10208/0x10a760，下一0x28887c→0x256f58；旧计数及child return保持。
outer原页无差异/64新增OS页；累计2497native/770checks；旧原生组未重跑。
完整signer和fresh/live/JVM未完成。见 [第三getter报告](REQUEST_JNI_STARTUP_WORKERS.md#6204-second-global-u32-c2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second environment helper

27项新增原生对照、14项拒绝或回滚检查通过；复用204E50 owner接通28863C，旧wrapper默认契约保持。
26项两基址返回+1项实际warm helper；32 virtual slots/4 callbacks/7物理返回值及声明范围一致。
构造prefix10169/0x10a574，下一0x28863c→0x1e53d0；旧计数及child return保持。
outer原页无差异/64新增OS页；累计2480native/760checks；旧原生组未重跑。
完整signer和fresh/live/JVM未完成。见 [helper报告](REQUEST_JNI_STARTUP_WORKERS.md#6203-second-environment-helper2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second global uint32 getter

17项新增原生对照、10项拒绝或回滚检查通过；恢复1C3024读取37A790，旧getter语义保持。
16项两基址组件+1项actual owning；4字节结果、unsigned W0、padding及全部声明范围一致。
构造prefix10150/0x10a528，下一0x28863c→0x204e50；旧计数及child return保持。
outer原页无差异/64新增OS页；累计2453native/746checks；旧原生组未重跑。
完整signer和fresh/live/JVM未完成。见 [getter报告](REQUEST_JNI_STARTUP_WORKERS.md#6202-second-global-u32-b2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second JSON number

69项新增原生对照、16项拒绝或回滚检查通过；恢复数值节点创建、owned key、链表追加和失败释放。
68项两基址组件+1项actual owning；NaN int32为0，原double位和1字节bool/padding一致。
构造prefix10131/+10A4DC，下一28863C→1C3024；旧记录及child return保持。
outer原页无差异/64新增OS页；累计2436native/736checks；旧原生组未重跑。
完整signer和fresh/live/JVM未完成。见 [数值写入报告](REQUEST_JNI_STARTUP_WORKERS.md#6201-json-number2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：VM uint32 to double

32项新增原生对照、6项拒绝检查通过；opcode34/operation30取隐式R4低uint32转R2 double。
abstract/backed两种模式的全部32寄存器与定义backing一致；其他浮点操作仍拒绝。
构造入口在+10A4A8转换1次，second prefix恢复返回到10124/+10A4C0，下一288854→261350。
旧记录/child return保持，outer原页无差异/64新增OS页；累计2367native/720checks。
完整signer和fresh/live/JVM未完成。见 [转换报告](REQUEST_JNI_STARTUP_WORKERS.md#6200-vm-uint32-to-double2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second VM global unsigned word

17项新增原生对照、10项回滚通过；28863C→1C3018全局unsigned32与精确4字节写回恢复。
实际owning10指令/1189范围一致；无allocator/diagnostic/JNI/file/syscall。
入口完成global getter1后在第10118次尝试执行时拒绝opcode34/001E0022/+10A4A8。
入口探针exit1、second prefix未返回；旧记录/child return在失败frame保持。
原outer页无差异/64新增OS页；累计2335native/714rollback。下一步恢复opcode34。
完整signer和fresh/live/JVM未完成。见 [global u32报告](REQUEST_JNI_STARTUP_WORKERS.md#6199-second-vm-global-unsigned-word2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-16 Asia/Shanghai：second VM empty JSON reference

25项新增原生对照、16项回滚通过；28883C→261404恢复NULL/empty-object引用构造。
实际owning1603指令/1248范围与matching-libc allocator/free/递归锁及全部非栈写入一致。
入口10101→10110/0x10a488，下一28863C→1C3018；JSON reference1，旧记录/child return保持。
原outer页无差异/64新增OS页，second页未发布。累计2318native/704rollback。
完整JSON parser、signer和fresh/live/JVM未完成。见 [empty JSON报告](REQUEST_JNI_STARTUP_WORKERS.md#6198-second-vm-empty-json-reference2026-10-16-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM deleting destructor

17项新增原生对照、12项回滚通过；2884CC→2484FC复用既有删除析构owner。
实际owning295指令/1198范围与matching-libc payload/object free及prefree字节一致。
入口10070→10101/0x10a464，下一28883C→261404；diagnostic leaves23，其他旧记录/
child return保持。原outer页无差异/64新增OS页，second页未发布。
完整signer和fresh/live/JVM未完成。见 [删除析构报告](REQUEST_JNI_STARTUP_WORKERS.md#6197-second-vm-deleting-destructor2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM deallocation callback

17项新增原生对照、12项回滚通过；288610→32A264→free复用已有显式allocator
服务，无packed结果。实际owning137指令/1193范围与真实matching-libc free一致。
入口10059→10070/0x10a3e8，下一2884CC→2484FC；frees1及旧记录/child return保持。
原outer页无差异/64新增OS页，second页未发布。完整signer和fresh/live/JVM未完成。
见 [释放回调报告](REQUEST_JNI_STARTUP_WORKERS.md#6196-second-vm-deallocation-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM CRC callback

33项新增原生对照、18项回滚通过；288820→258BAC→24B298复用未修改的guest
CRC表owner，W0和4字节packed写回一致。实际owning247指令/1439范围及真实
SP/TP保持。入口10030→10059/0x10a3bc，下一288610→32A264；crcs1、diagnostics23
及旧记录/child return保持。原outer页无差异/64新增OS页，second页未发布。
完整signer和fresh/live/JVM未完成。见 [CRC回调报告](REQUEST_JNI_STARTUP_WORKERS.md#6195-second-vm-crc-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM digest reference callback

33项新增原生对照通过，旧8项回滚按hash保留、未计作新增；2887D0→25874C
完整32字节wrapper与旧token相同，复用未修改的MD5/reference owners。
owning4955指令/1194范围及真实allocator/recursive mutex一致。入口10021→10030/
0x10a348，下一288820→258BAC；digests1及旧记录/child return保持。原outer页
无差异/64新增OS页，second页未发布。完整signer和fresh/live/JVM未完成。
见 [摘要引用回调报告](REQUEST_JNI_STARTUP_WORKERS.md#6194-second-vm-digest-reference-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM string pair callback

17项新增原生对照、8项回滚通过；2887F0→248780与旧token wrapper完整28字节
相同，复用同一clone/append owner。owning629指令/1191范围及真实allocator一致。
入口10009→10021/0x10a324，下一2887D0→25874C；string_pairs1及旧记录/child
return保持。原outer页无差异/64新增OS页，second页未发布。完整signer和
fresh/live/JVM未完成。见 [字符串拼接回调报告](REQUEST_JNI_STARTUP_WORKERS.md#6193-second-vm-string-pair-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM string format callback

21项新增原生对照、12项回滚通过；28880C→248908复用现有formatter，单个W2
参数、matching-libc printf和真实allocator保持；owning1839指令/1193范围一致。
outer仅转发prepare_format及提高second预算10000→20000。入口9998→10009/
0x10a2f4，下一2887F0→248780；string_formats1及旧记录/child return保持。
原outer页无差异/64新增OS页，second页未发布。完整signer和fresh/live/JVM未完成。
见 [字符串格式回调报告](REQUEST_JNI_STARTUP_WORKERS.md#6192-second-vm-string-format-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM allocation callback

22项新增原生对照、9项回滚通过；288508→32A1F0复用显式allocator，0大小转1，
向packed+16写X64指针。两次实际owning分配24/4字节，144/579指令、各1190范围
一致。入口9950→9998/0x10a2c8，下一28880C→248908；allocations2，旧diagnostic
enter/leave增加1对，其余旧记录/child return保持。原outer页无差异/64新增OS页，
second页未发布。完整signer和fresh/live/JVM未完成。见 [分配回调报告](REQUEST_JNI_STARTUP_WORKERS.md#6191-second-vm-allocation-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM cold cached identifier

45项新增原生对照、19项回滚通过；2886B0→25BD8C冷工厂恢复显式文件seed、
两次状态推进及模板formatter，复用guard/mutex/string/reference owners。
owning3918指令/1192范围一致。入口9940→9950/0x10a208，下一288508→32A1F0；
identifiers1与所有旧记录/child return保持。原outer页无差异/64新增OS页，
second页未发布。完整signer和fresh/live/JVM未完成。见 [标识符工厂报告](REQUEST_JNI_STARTUP_WORKERS.md#6190-second-vm-cold-cached-identifier2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM tree pointer getter

41项新增原生对照、18项回滚通过；2887B0→256B84复用shared-reader与树查找，
在release前读取X64并写packed+24。owning321指令/1191范围一致。入口9813→9940/
0x10a1e0，下一2886B0→25BD8C；tree_pointers1、strings15、registry_reads12，
其他旧记录和child return保留。原outer页无差异/64新增OS页，second页未发布。
完整signer和fresh/live/JVM未完成。见 [树指针读取报告](REQUEST_JNI_STARTUP_WORKERS.md#6189-second-vm-tree-pointer-getter2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM locked pointer getter

19项新增原生对照、13项回滚通过；288794→282B84复用normal mutex，在scope
保留mutex owner后读取receiver+0x40，X64写packed+16。owning86指令/1191范围
一致。入口9780→9813/0x109e08，下一2887B0→256B84；strings14、locked_pointers1，
child return保留。原outer页无差异/64新增OS页，second页未发布。完整signer和
fresh/live/JVM未完成。见 [加锁读取报告](REQUEST_JNI_STARTUP_WORKERS.md#6188-second-vm-locked-pointer-getter2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM environment acquisition

17项新增原生对照通过；288788→26EDC4复用既有TLS/JavaVM owner，12字节tail
wrapper无新增frame/store。owning160指令/997范围及一次GetEnv一致。复用旧
6项回滚，不重跑/不新增计数，旧owner AST保持。入口9752→9780/0x109c44，
下一288794→282B84。原outer页无差异/64新增OS页，second页未发布；JNI显式
fixture。完整signer/fresh/live/JVM未完成。见 [环境报告](REQUEST_JNI_STARTUP_WORKERS.md#6187-second-vm-environment-acquisition2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM cached thread pointer

15 项新增原生对照、7 项回滚通过；28876C→204F58 恢复全局缓存或 TPIDR_EL0
初始化、X64 packed+8 写入，包含混淆 LR helper 原始执行。owning65 指令、
1188 范围一致；旧 PID/random/realtime/outer/ELF/JNI AST 保持。
实际入口 9729→9752/0x109bbc，下一288788→26EDC4；TP1、PID2，child return
保留。outer 原页无差异、64 新增 OS 页，second 页未发布。完整 signer 和
fresh/live/JVM 未完成。见 [线程指针报告](REQUEST_JNI_STARTUP_WORKERS.md#6186-second-vm-cached-thread-pointer2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM process ID callbacks

26 项新增原生对照、12 项回滚通过；28863C 调用显式导入 getpid/getppid，
保留 PID 缓存/冷 syscall172/父 syscall173/errno 语义，W32 写 packed+8。
owning 18/13 指令、1190/1189 范围一致。fixture 仅绑定 ELF 元数据中的两处
ABS64 导入；生产 ELF loader 和旧 random/realtime AST 不变。
实际入口 9557→9729/0x109b60，下一 28876C→204F58；PID 2、reader 7 对、
diagnostic 21 对，child return 保留。outer 原页无差异，64 新增 OS 页保留，
second 页未发布；JNI 为显式 fixture。完整 signer/fresh/live/JVM 未完成。
见 [PID 报告](REQUEST_JNI_STARTUP_WORKERS.md#6185-second-vm-process-id-callbacks2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM realtime unsigned seconds

15 项新增原生对照、10 项回滚通过；28876C→26CC64 复用有符号毫秒 owner，
按 uint64 做 UDIV1000，完整 X64 写 packed+8。outer 转交既有 clock provider。
owning 54 指令/1188 范围及一次显式 clock_gettime(0) 响应一致。
实际入口 9374→9557/0x10963c；下一 28863C 的 target 为 NULL，初始化来源待查。
registry_reads 11、strings 13、reader 5 对、diagnostic 17 对，child return 保留。
原 outer 页无差异、64 新增 OS 页保留，second 页未发布；JNI 为显式 fixture。
完整 signer 和 fresh/live/JVM 未完成。见 [时钟报告](REQUEST_JNI_STARTUP_WORKERS.md#6184-second-vm-realtime-unsigned-seconds2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM configuration u32 read

22 项新增原生对照通过；12 项既有回滚按绑定复用，未重跑或计为新增。
28874C 与旧 child wrapper 32 字节完全一致，直接复用已有配置读取组合。
10 次 owning 回调各 1190 范围、W32/padding/scoped guard 及四次锁操作一致。
探针末尾单次预期修正为 10 次，已核对原始比较回执，未重放原生。
实际入口 9050→9374/0x109144，下一 0x28876c→0x26cc64；strings 12 次。
child return 和旧记录保留；原 outer 页无差异、64 新增 OS 页保留，second 页未发布。
JNI 是显式 fixture，完整 signer 及 fresh/live/JVM 未完成。见 [配置读取报告](REQUEST_JNI_STARTUP_WORKERS.md#6183-second-vm-configuration-u32-read2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM static guard release

25 项新增原生对照、12 项回滚通过；恢复 32D4F8 非 broadcast 分支并接入 28854C。
仅访问两个 guard 字节，无 packed store；保留旧共享和内联 guard 函数 AST。
owning 71 指令/1189 范围及锁顺序一致；实际入口
8951→9050/0x1080e0，下一 0x28874c→0x256a18。
child return 和旧记录保留，strings 累计 3 次；原 outer 页无差异、64 新增 OS 页
保留，second 页未发布。JNI 为显式 fixture，完整 signer 及 fresh/live/JVM 未完成。
见 [guard release 报告](REQUEST_JNI_STARTUP_WORKERS.md#6182-second-vm-static-guard-release2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM C-string format callback

27 项新增原生对照、12 项回滚通过；恢复自定义 %s/%% 格式化并接入 288718。
NULL 为空串，截断返回完整长度，零容量不写；其他格式与未建模别名拒绝。
owning 1013 指令/1188 范围一致；实际入口
8938→8951/0x107e18，下一 0x28854c→0x32d4f8。
child return 和旧记录保留，原 outer 页无差异、64 新增 OS 页保留，second 页未发布。
JNI 为显式 fixture，完整 signer 及 fresh/live/JVM 未完成。见 [格式化报告](REQUEST_JNI_STARTUP_WORKERS.md#6181-second-vm-c-string-format-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM environment constant callback

21 项新增原生对照、8 项回滚通过；2886FC 复用 256330 环境常量 getter。
写入完整 X64 指针，receiver 不解引用；冷/热、缺页和声明别名覆盖。
owning 热路径 19 指令/1188 范围一致；实际入口
8902→8938/0x107de4，下一 0x288718→0x2781f4。
child return 和旧记录保留，原 outer 页无差异、64 新增 OS 页保留，second 页未发布。
JNI 为显式 fixture，完整 signer 及 fresh/live/JVM 未完成。见 [环境常量报告](REQUEST_JNI_STARTUP_WORKERS.md#6180-second-vm-environment-constant-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM static guard acquire

33 项新增原生对照、14 项回滚通过；恢复 32D3A0 并接入 2884EC wrapper。
仅写 W32；声明 packed 别名与任意非零 guard 首字节覆盖，等待/递归拒绝。
owning 94 指令/1185 范围和锁/gettid 顺序一致；实际入口
8844→8902/0x107d54，下一 0x2886fc→0x256330。
child return 和旧记录保留，原 outer 页无差异，64 新增 OS 页保留，second 页未发布。
JNI 为显式 fixture；完整 signer 及 fresh/live/JVM 未完成。见 [guard acquire 报告](REQUEST_JNI_STARTUP_WORKERS.md#6179-second-vm-static-guard-acquire2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM cached reference callback

17项新增原生对照、8项回滚通过；2886B0直接委托已有1CF55C缓存owner。
owning5571指令/1189范围及有序服务一致，实际入口
8809→8844/0x107b24，下一0x2884ec→0x32d3a0。
显式JNI fixture，真实TLS获取；原outer页保持，64新增OS页保留，second页未发布。
完整signer及fresh/live/JVM仍未完成。见 [second cached reference报告](REQUEST_JNI_STARTUP_WORKERS.md#6178-second-vm-cached-reference-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：cached reference initialization and refresh

44项新增原生对照、18项回滚通过；恢复1CF55C的inline guard、首次初始化、
进程析构注册、空值判断、64位计数及有符号余数刷新。复用producer/reference/
mutex/string比较owner。声明字段及有序services一致；等待/递归/broadcast拒绝。
旧AST和8809步入口证据保持，没有新owning/入口执行。下一步补2886B0 wrapper
及second接线。完整signer未完成。见 [cached reference报告](REQUEST_JNI_STARTUP_WORKERS.md#6177-cached-reference-initialization-and-refresh2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：cached dispatch byte producer

26项新增原生对照、13项回滚通过；恢复1CF688的两次环境获取、精确dispatch
words、26FE2C转换和空StringObject回退。环境替换证明live pair重读及保留环境
用于最终JNI删除。声明字节及有序services一致，旧JNI/reference/diagnostic/
request AST保持。此组合显式提供acquisition/JNI，未执行真实TLS body。
入口仍为8809步/2886B0→1CF55C，没有新owning/入口执行。下一步恢复缓存冷
初始化/刷新和second接线。完整signer未完成。见 [cached dispatch bytes报告](REQUEST_JNI_STARTUP_WORKERS.md#6176-cached-dispatch-byte-producer2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：Java object byte reference composition

28项新增原生对照、12项回滚通过；恢复26FE2C，用1个UTF reference参数调用
JNI method并组合已有byte array/reference owners。声明字段及有序JNI/allocator/
free/diagnostic effects一致，旧JNI/reference/diagnostic/request AST保持。
该child组件没有新owning/入口执行，原有8809步/2886B0→1CF55C入口证据保持。
下一步恢复1CF688、全局缓存冷初始化/刷新及second接线。完整signer未完成。
见 [Java object bytes报告](REQUEST_JNI_STARTUP_WORKERS.md#6175-java-object-byte-reference-composition2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM pair reference getter

29项新增原生对照、10项回滚通过；owning198指令/1187范围及诊断有效字段一致。
2633A4仅将receiver+18 tail-call到15F580，直接复用已有scoped reference copy。
覆盖cold/warm、计数边界/NULL、跨页和partial/packed/counter别名。修改前入口
复用既有8760步证据和AST缺失证明，无新入口RED或旧分组重跑。
second8809/+10769C，下一2886B0→1CF55C；旧AST/registry/共享owners/outer保持，
原页无差异，64新增OS页保留。完整second/request/signer/fresh/live/JVM仍未完成。
见 [second pair getter报告](REQUEST_JNI_STARTUP_WORKERS.md#6174-second-vm-pair-reference-getter2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM cached u32 getter

27项新增原生对照、13项回滚通过；owning237指令/1185范围一致。
复用已有shared reader；receiver+E8在release之前缓存，packed+16仅写4字节。
count/flag别名、跨页、近reader上限均通过；实际观察四次shared mutex调用。
修改前入口复用既有8539步证据和AST缺失证明，没有新入口RED或旧分组重跑。
second8760/+107594，下一28868C→2633A4；旧AST/共享owners/outer保持，原页
无差异，64新增OS页保留。完整second/request/signer/fresh/live/JVM仍未完成。
见 [second cached u32报告](REQUEST_JNI_STARTUP_WORKERS.md#6173-second-vm-cached-u32-getter2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM reference getter

33项新增原生对照、13项回滚通过；owning429指令/1186范围及有效诊断字段一致。
复用已有shared reader和scoped reference copy；观察四次shared mutex调用，
没有owning分配。诊断字段在dead copy frame被outer release复用前比较；physical
padding/spills未覆盖。second8539/+107018，下一288670→257880。旧AST/共享owners/
outer保持；原页无差异，64新增OS页保留。完整second/request/signer/fresh/live/JVM
仍未完成。见 [second reference getter报告](REQUEST_JNI_STARTUP_WORKERS.md#6172-second-vm-reference-getter2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM random callback

17项新增原生对照、11项回滚通过；warm owning126指令/1191范围/实际libc random
及两次mutex调用一致。共享random owner未改，outer仅透传已有services。second
8532/+106FFC，下一288658→257804；acquire/release各3、scope entry/leave各5。
旧AST和所有既有owners保持；原页无差异，64新增OS页保留。完整physical ABI/
second/request/signer/fresh/live/JVM仍未完成。见 [second random报告](REQUEST_JNI_STARTUP_WORKERS.md#6171-second-vm-random-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM string assignment

37项新增原生对照、13项回滚通过；owning347指令/1185范围/实际libc malloc/free。
赋值复用reserve，outer仅透传既有reallocator，保留字段重读和失败效果。second
8416/+106DE8，下一28863C→26CC8C随机数。旧AST/既有StringObject与reserve owner
保持；原页差异为空，64新增OS页保留。完整second/request/signer/fresh/live/JVM
未完成。见 [second assignment报告](REQUEST_JNI_STARTUP_WORKERS.md#6170-second-vm-string-assignment2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM string equality

27项新增原生对照、9项回滚通过；owning32指令/1185范围/无分配或外部服务。
packed低byte结果及padding/alias匹配；新适配器拒绝原生会fault的NULL receiver。
second8405/+106DBC，下一28861C→2485A4字符串赋值；scope entry/leave各3次。
旧AST/共享owner及child/string/readers保持，原页差异为空，64新增OS页保留。
完整second/request/signer/fresh/live/JVM未完成。见 [second equality报告](REQUEST_JNI_STARTUP_WORKERS.md#6169-second-vm-string-equality2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM shared-reader release

19项新增原生对照、12项回滚通过；owning83指令/1185范围/两次真实mutex一致。
second8355/+106CA4，下一2885EC→24880C字符串比较。实际scope entry/leave各2次，
release1次，旧AST/共享owner及child/string/acquisition保持。原页差异为空，64新增
OS页保留。完整second/request/signer/fresh/live/JVM未完成。见 [second reader release报告](REQUEST_JNI_STARTUP_WORKERS.md#6168-second-vm-shared-reader-release2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM diagnostic scope cleanup

21项新增原生对照、9项回滚通过；owning53指令/1185范围/真实递归锁一致，无分配。
second8309/+106BC8，下一2885E0→32A4FC共享读锁释放。entry/leave分别记录，旧
AST/共享owner及child/string/reader保持。原页差异为空，64新增OS页保留。完整
second/request/signer/fresh/live/JVM未完成。见 [second diagnostic cleanup报告](REQUEST_JNI_STARTUP_WORKERS.md#6167-second-vm-diagnostic-scope-cleanup2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM diagnostic scope entry

13项新增原生对照、7项回滚通过；owning110指令/1185范围/真实递归锁一致，
本项无分配。second8298/+106B9C，下一288540→26C9D0清理。旧AST/共享owner及
child/string/reader保持；原页差异为空，64新增OS页保留。完整second/request/
signer/fresh/live/JVM未完成。见 [second diagnostic报告](REQUEST_JNI_STARTUP_WORKERS.md#6166-second-vm-diagnostic-scope-entry2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM shared-reader acquisition

19项新增原生对照、11项回滚通过；owning94指令/1185范围/两次真实mutex一致。
second8279/+106B50，下一288530→26C858 diagnostic scope。旧AST/共享owner和
child return/second字符串保持；原页差异为空，64新增OS页保留。完整second/
request/signer/fresh/live/JVM未完成。见 [second reader报告](REQUEST_JNI_STARTUP_WORKERS.md#6165-second-vm-shared-reader-acquisition2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：second VM StringObject construction

23项新增原生对照、8项回滚通过；owning155指令/1186范围/一次真实malloc一致。
second8261/+106B08，下一2885E0→32A444共享读锁；child19566及物理返回保持。
旧AST/共享owner保持，原页差异为空，64新增OS页保留。完整second/request/
signer/fresh/live/JVM未完成。见 [second strings报告](REQUEST_JNI_STARTUP_WORKERS.md#6164-second-vm-stringobject-construction2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：child physical caller/wrapper return

23项新增原生对照、16项回滚通过；owning10指令/1184范围/七个物理返回值一致。
child19566步经退出校验返回父callback，second8251/+106AE0，下一2885D0→248344。
旧AST/共享owner保持，原页差异为空，64新增OS页保留。完整second/request、
whole-child native/physical/PAC、signer/fresh/live/JVM未完成。见
[child return报告](REQUEST_JNI_STARTUP_WORKERS.md#6163-child-physical-caller-and-wrapper-return2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：child StringObject cleanup and VM exit

17项新增原生对照、7项回滚通过；owning152指令/1186范围/一次真实free一致。
child19566/+ED3DC观察VM exit07C00791，R31匹配2885C8；物理child/wrapper返回
和second恢复尚未完成。旧AST/共享owner保持，原页差异为空，64新增OS页保留。
完整request/signer/fresh/live/JVM未完成。见 [child cleanup报告](REQUEST_JNI_STARTUP_WORKERS.md#6162-child-stringobject-cleanup-and-vm-exit2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：child configuration u32 read

41项新增原生对照、12项回滚通过；owning524指令/1186范围/四次mutex一致。
child19549/+ED398，下一28158C→2484B8。共享reader/tree owner复用，旧AST
保留；原页差异为空，64新增OS页保留。完整child/request/signer/fresh/live/JVM
未完成。见 [child registry read报告](REQUEST_JNI_STARTUP_WORKERS.md#6161-child-configuration-u32-read2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：child StringObject construction

23项新增原生对照、8项回滚通过。owning155指令含真实libc malloc，1186范围/
payload指针/一次分配一致。child19541/+ED378，下一28156C→256A18。旧AST与
默认verifier保持；原页差异为空，64新增OS页保留。完整child/request/signer/
fresh/live/JVM未完成。见 [child strings报告](REQUEST_JNI_STARTUP_WORKERS.md#6160-child-stringobject-construction2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：child environment acquisition

17项新增原生对照通过：16项新2814E4地址、1项owning160指令/993范围/一次
GetEnv。child19533/+ED358，下一28155C→248344。旧owner/default AST保留，
原页差异为空，64新增OS页保留。完整child/request/signer/fresh/live/JVM未完成。
见 [child environment报告](REQUEST_JNI_STARTUP_WORKERS.md#6159-child-environment-acquisition2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：child JNI availability callback

1项新增owning callback原生对照、6项入口拒绝通过。request显式JNI服务传入
child，204B80实际callback375指令/十个物理返回值/996范围一致，W=1。child
19470/+ED084，下一2814E4→26EDC4；原页回滚，64新增OS页保留。完整child/
request/signer/fresh/live/JVM未完成。见 [child callback报告](REQUEST_JNI_STARTUP_WORKERS.md#6158-child-jni-availability-callback2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：JNI availability wrapper

26项新增原生对照、9项回滚、4项native RED通过。实际2814C8→204B80 wrapper
返回的十个物理值/声明保存帧/packed一致，含结果与保存槽别名。request初始化
合约已构造；child19302/+ECE3C待callback接入。完整request/signer/fresh/live/JVM
未完成。见 [wrapper报告](REQUEST_JNI_STARTUP_WORKERS.md#6157-jni-availability-wrapper2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：JNI static method availability

32项新增原生对照、10项回滚、4项native RED通过。实际204B80语义与finalizer
共用owner，cache原byte/真实acquisition/异常低byte/table刷新通过。旧AST及
注册retained stack word保持。child19302/+ECE3C的2814C8→204B80 wrapper尚待
接入；完整request/signer/fresh/live/JVM仍未完成。见 [availability报告](REQUEST_JNI_STARTUP_WORKERS.md#6156-jni-static-method-availability2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-15 Asia/Shanghai：request environment helper return

53项新增原生对照、8项回滚、4项入口拒绝通过。owning204E50 helper与2814C8
wrapper实际返回，262步body/七个物理返回值/完整packed与原生匹配；child
19302/+ECE3C，下一2814C8→204B80 JNI。helper页提交到child；原页回滚，64
新增OS pages保留。204ED4 body、完整child/request、actual JNI/physical/mapping/
signer/fresh/live/JVM仍未完成。见 [helper return报告](REQUEST_JNI_STARTUP_WORKERS.md#6155-request-environment-helper-return2026-10-15-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-14 Asia/Shanghai：request environment logger and cleanup

13项新增原生对照、9项回滚、3项入口拒绝通过。actual205074复用literal logger；
owning helper执行日志/清理，到262/+8A4E8 VM退出边界；全部32寄存器/完整8回调/
14声明范围/slot31原生一致。helper调用者返回待恢复；outer3900/second8184/
child19295。原页回滚，64新增OS pages保留。完整helper/request、actual JNI/
physical/mapping/signer/fresh/live/JVM仍未完成。见 [logger报告](REQUEST_JNI_STARTUP_WORKERS.md#6154-request-environment-logger-and-cleanup2026-10-14-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-14 Asia/Shanghai：request environment StringObject callbacks

39项新增原生对照、9项回滚、3项入口拒绝通过。actual205064构造/205094析构
复用对象owner；owning helper226/+8A3C4，下一205074→26E9E0 logger，尚未
在owning路径执行析构。全部32虚拟寄存器/完整ledger/11声明范围与原生一致。
outer3900、second8184、child19295；原页回滚，64新增OS pages保留。完整
helper/child/request、physical/JNI/mapping/signer/fresh/live/JVM仍未完成。见
[environment StringObject报告](REQUEST_JNI_STARTUP_WORKERS.md#6153-request-environment-stringobject-callbacks2026-10-14-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-14 Asia/Shanghai：request environment acquisition callback

17项新增原生对照、6项回滚、3项Python入口拒绝检查通过。actual205058 tail
callback复用实际环境获取/TLS/GetEnv/temporary attach-detach；owning helper
214/+8A394，下一205064→248344 StringObject。全部32虚拟寄存器、完整ledger/
9声明范围与原生匹配。outer3900、second8184、child19295；原页回滚，64新增
OS pages保留。完整return/request、full physical/JNI/mapping/signer及fresh/live/
JVM仍未完成。见 [environment acquisition报告](REQUEST_JNI_STARTUP_WORKERS.md#6152-request-environment-acquisition-callback2026-10-14-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-14 Asia/Shanghai：request environment helper VM callers and prefixes

33项新增原生对照、11项回滚通过。204E50/204ED4实际caller、2814C8包装与
decoder恢复；全部32 backing/virtual words及声明范围匹配。owning helper
134/+8A254，下一205058→26EDC4。204ED4独立prefix70/+8A604，下一205104 getenv。
outer3900、second8184、child19295；原页回滚，64新增OS pages保留。
完整return/request、full physical/JNI/mapping/signer及fresh/live/JVM仍未完成。
见 [environment helper报告](REQUEST_JNI_STARTUP_WORKERS.md#6151-request-environment-helper-vm-callers-and-prefixes2026-10-14-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request child VM consumers

83项新增原生对照、13项回滚和5项Python入口拒绝检查通过。四个实际child
wrapper恢复；共享copy owner保留。owning child19295/+ECE20，下一2814C8→204E50。
全部32虚拟寄存器、完整callback ledger、16声明范围与原生有界前缀匹配。
outer3900、second8184；原页回滚，64新增OS pages保留。完整return/request、
full physical/JNI/mapping/signer及fresh/live/JVM仍未完成。
见 [child consumer报告](REQUEST_JNI_STARTUP_WORKERS.md#6150-request-child-vm-consumers2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request child VM caller and prefix

26项新增原生对照、10项回滚通过。actual2885AC hidden-X8 wrapper、28048C
caller/prelude与首个decode恢复，全部32 backing/virtual words及声明范围匹配。
Owning child290/+A7654，下一281434→248274 filled；outer3900、second8184。
原页回滚，64新增OS pages保留。owning child native差分、完整return/request、
full physical/JNI/mapping/signer及fresh/live/JVM仍未完成。
见 [child VM报告](REQUEST_JNI_STARTUP_WORKERS.md#6149-request-child-vm-caller-and-prefix2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request second VM consumers

153项新增原生对照（152 wrappers+1 owning bounded second VM）、12项回滚与
5项Python入口拒绝通过。default/destroy/filled、imported memcpy及实际ARM64
copy接入。Owning第二VM8184/+1069D4，下一2885AC→28048C；32虚拟寄存器、
callback ledger及声明内存范围匹配native。outer3900，原页回滚、64新增OS
pages保留。完整第二VM/whole-request/full physical/JNI/mapping/signer及
fresh/live/JVM仍未完成。见 [second consumer报告](REQUEST_JNI_STARTUP_WORKERS.md#6148-request-second-vm-consumers2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request second VM caller and prefix

20项新增caller/prefix原生对照、8项回滚通过，287474/102BB0入口、完整
caller/prelude、三个decode callback恢复。Owning outer3900，second617/
1035D4到2884CC→2481AC；cold fixture650。bounded页不发布，原页字节回滚，
64新增OS pages保留。second return、whole-request/full physical/JNI/mapping/
完整signer及fresh/live仍未完成。见 [第二VM报告](REQUEST_JNI_STARTUP_WORKERS.md#6147-request-second-vm-caller-and-prefix2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request URL condition

40项actual wrapper对照、7项回滚通过，3lazy flags、disabled URL shortcut、
ordered CString searches与一字节packed结果恢复。Owning outer3900/+FE2D0，
下一285F38→287474；nested574已返回。原页字节回滚，64新增OS pages保留。
全JNI、whole-request、physical ABI、mapping回滚、完整signer及fresh/live
未完成。见 [URL条件报告](REQUEST_JNI_STARTUP_WORKERS.md#6146-request-url-condition2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested caller return

32项actual caller/outer wrapper对照、10项回滚及5项constructed入口检查通过。
Nested return验证、canary与caller恢复接入显式continuation，旧default保留。
Owning nested574/40callbacks返回，outer3879/+FE27C，下一285F14→2828D4。
原页字节回滚，64新增OS pages保留。whole nested/request差分、全JNI、full
physical ABI/PAC、mapping回滚、完整signer及fresh/live未完成。
见 [nested return报告](REQUEST_JNI_STARTUP_WORKERS.md#6145-request-nested-caller-return2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested allocated printf

36项actual wrapper对照、10项回滚通过，packed W0/padding、live两次format、
defined child canary恢复；formatter owner不变。owning inner574/+118F44、
outer3767，cleanup后到达明确拒绝的nested return。原页字节回滚，64新增OS
pages保留。全JNI、whole-request、physical ABI、mapping回滚、完整signer与
fresh/live仍未完成。见 [nested printf报告](REQUEST_JNI_STARTUP_WORKERS.md#6144-request-nested-allocated-printf2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested append/Base64 reference

34项actual consumer对照、8项回滚通过，append与Base64 reference复用既有
owner，actual hidden-X8/child-SP布局及query/live encoding/scoped reference
恢复。独立owning inner505/+118E30，outer3767，下一288C28→278314 printf。
原页字节回滚，64新增OS pages保留。全JNI、whole-request、physical ABI、
mapping回滚、完整signer及fresh/live仍未完成。见 [append/Base64报告](REQUEST_JNI_STARTUP_WORKERS.md#6143-request-nested-append-and-base64-reference2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：matching-libc cross-bin small realloc

18项actual export/allocator对照、9项回滚通过，cross-bin realloc组合owning
allocate/copy/free，same-bin owner保留。独立owning inner430/+118D04，outer
3767，下一288BF0→248684 append。原页字节回滚，64新增OS pages保留。
全JNI、whole-request、physical ABI、mapping回滚、完整signer及fresh/live
仍未完成。见 [cross-bin报告](REQUEST_JNI_STARTUP_WORKERS.md#6142-matching-libc-cross-bin-small-realloc2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request allocated/StringObject cipher callers

48项新caller对照、10项回滚通过，287A78/287580/288BDC恢复，复用既有
schedule/block/string owner。独立owning入口仍inner422/outer3767，actual
cross-bin realloc32→64、class2→4是下一owner边界。原页字节回滚，64新增
OS pages保留。全JNI、whole-request、physical ABI、mapping回滚、完整
signer及fresh/live仍未完成。见 [cipher caller报告](REQUEST_JNI_STARTUP_WORKERS.md#6141-request-allocated-and-string-cipher-callers2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request round schedule/block helpers

32项新helper对照、8项回滚通过，287EDC schedule/2881CC block、编码slot
解析与guest bytecode绑定恢复。287580/287A78 caller尚未接入，已接受
owning入口仍422步，未重放。全JNI、whole-request、physical ABI、mapping
回滚、完整signer及fresh/live仍未完成。见 [round/block报告](REQUEST_JNI_STARTUP_WORKERS.md#6140-request-round-schedule-and-block-helpers2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested scoped MD5

32项actual consumer对照、8项回滚通过；actual hidden-X8/byte flag/child
SP-16恢复，MD5及scoped reference复用既有owner，matching-libc recursive
mutex执行。独立owning inner422/+118CE4，外层3767，下一288BDC→287580
obfuscated helper。原页字节回滚，64新增OS pages保留。整段nested prefix、
全JNI、physical ABI、mapping回滚、完整signer及fresh/live仍未完成。
见 [nested MD5报告](REQUEST_JNI_STARTUP_WORKERS.md#6139-request-nested-scoped-md52026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested string transforms

46项actual consumer对照、10项回滚通过；format/sized/pair复用既有owner，
actual hidden-X8/W2布局恢复，matching-libc vsnprintf执行。独立owning inner
321/+118B50，外层3767，下一288BBC→25874C MD5 reference。原页字节回滚，
64新增OS pages保留。整段nested prefix、全JNI、physical ABI、mapping回滚、
完整signer及fresh/live仍未完成。见 [nested strings报告](REQUEST_JNI_STARTUP_WORKERS.md#6138-request-nested-string-transforms2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested string lifecycle

36项actual consumer对照、8项回滚通过；clone/default/free/destroy/delete复用
已接受owner。独立owning inner287/+118AC8，外层3767，下一288B74→248908
格式化；原页字节回滚，64新增OS pages保留。未对照整段nested prefix；
全JNI、physical ABI、mapping回滚、完整signer及fresh/live仍未完成。
见 [nested lifecycle报告](REQUEST_JNI_STARTUP_WORKERS.md#6137-request-nested-string-lifecycle2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested diagnostic scopes

16项actual consumer对照、5项回滚通过，288B30 enter/288B40 leave复用scope
owner，之后288B24 release已接入。独立owning inner231/+1189A8，外层3767。
下一288B4C→2483E0 clone；原页回滚，64新增OS pages保留。未对照整段
nested prefix/whole-request；physical X0/PAC、全JNI、mapping回滚、完整
signer、fresh/live及真实JVM仍未完成。见 [nested scopes报告](REQUEST_JNI_STARTUP_WORKERS.md#6136-request-nested-diagnostic-scopes2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested shared readers

28项新增对照、7项回滚通过。288B24 acquire/release重用已有reader owner，
native unlock return0和定义的acquire scratch一致。fresh inner211，独立
owning inner178/+1188B8，外层3767/+FDDE0。下一288B30→26C858；旧default
和outer源码AST保留，旧helper组不重跑。原页回滚，64新增OS pages保留。
全JNI、整链、physical ABI、mapping回滚、完整signer、fresh/live和真实JVM
均未完成。见 [nested readers报告](REQUEST_JNI_STARTUP_WORKERS.md#6135-request-nested-shared-readers2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request nested random continuation

12项新增对照、5项回滚通过。288B08 random owner与285EA8实际consumer
已接入；fresh inner191，独立owning inner158/+118868，外层3767/+FDDE0。
下一288B24→32A444，未宣称完整callee返回。旧default/outer callbacks AST
一致。原page bytes回滚，64个新增OS pages保留。全JNI、整链、physical
ABI、mapping回滚、完整signer、fresh/live及真实JVM均未完成。
见 [nested random报告](REQUEST_JNI_STARTUP_WORKERS.md#6134-request-nested-random-continuation2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request random state and getter

98项新增对照、15项回滚通过；matching libc random arithmetic、seed/warmup、
normal mutex、2728F4 time helper、26CC8C getter和288B08 consumer一致。
实际guard3DEDB0，纠正旧私有摘要；timeval在独立helper返回点对照。
嵌套callback未接入，内层179/外层3767；全JNI、整链、physical ABI、mapping
回滚、完整signer、fresh/live及真实JVM均未完成。见 [random报告](REQUEST_JNI_STARTUP_WORKERS.md#6133-request-random-state-and-getter2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request token VM caller and prefix

20项新增原生对照、8项回滚通过；287500 caller完整frame及已定义prelude
slots、嵌套两个decode与32虚拟寄存器一致。内层179步/+118838，下一
288B08→26CC8C。外层仍3767步，尚未接入。全JNI、整链、generic physical
spills、mapping回滚、完整signer、fresh/live及真实JVM均未完成。
见 [token VM报告](REQUEST_JNI_STARTUP_WORKERS.md#6132-request-token-vm-caller-and-prefix2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request left character-set trim

94项新增原生对照、11项回滚通过；forward bitmap、erase memmove、left trim
与actual callback一致，旧reverse AST展开一致。入口3559→3767/+FDDE0，
下一285EA8→287500。原页bytes回滚，64个新增OS pages保留。actual JNI、
整链差分、full physical ABI、完整signer、fresh/live及真实JVM仍未完成。
见 [left-set报告](REQUEST_JNI_STARTUP_WORKERS.md#6131-request-left-character-set-trim2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request right character-set trim

64项新增原生对照、9项回滚通过；bitmap/canary、reverse search、length/NUL
与actual callback一致。入口3550→3559/+FDAA0，下一285B44→248EB4。原页bytes
回滚，64个新增OS pages保留。actual JNI、整链差分、full physical ABI、完整
signer、fresh/live及真实JVM仍未完成。见 [right-set报告](REQUEST_JNI_STARTUP_WORKERS.md#6130-request-right-character-set-trim2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request character string

30项新增原生对照、7项回滚通过；live ELF fields、低byte、allocation
publication与actual callback一致。入口3538→3550/+FDA7C，下一285B44→248EF8。
原页bytes回滚，64个新增OS pages保留。actual JNI、整链差分、full physical
ABI、完整signer、fresh/live及真实JVM仍未完成。见 [character报告](REQUEST_JNI_STARTUP_WORKERS.md#6129-request-character-string2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request Base64 encode

68项新增原生对照、10项回滚通过；query/NUL、guest alphabet aliases、
live source、scratch与actual bool callback一致。入口3520→3538/+FDA4C，
下一285E98→2482EC。原页bytes回滚，64个新增OS pages保留。actual JNI、
整链差分、full physical ABI、完整signer、fresh/live及真实JVM仍未完成。
见 [Base64报告](REQUEST_JNI_STARTUP_WORKERS.md#6128-request-base64-encoder2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request metadata与unsigned printf

46项新增原生对照、12项回滚通过；metadata两个outputs、unsigned W0、
actual source callback一致。非空入口3405→3520/+FDA04，下一285C94→258D6C。
原页bytes回滚，64个新增OS pages保留。actual JNI、整链差分、full physical
ABI、完整signer、fresh/live及真实JVM仍未完成。见 [metadata报告](REQUEST_JNI_STARTUP_WORKERS.md#6127-request-metadata-formatting2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request outer suffix组合与raw free

32项新增原生对照、11项回滚通过；suffix输出和cleanup、actual raw
free一致。非空入口3307→3405/+FD838，下一285E8C→287168。原页bytes
回滚，64个新增OS pages保留。actual JNI、整链差分、full physical ABI、
完整signer、fresh/live及真实JVM仍未完成。见 [suffix报告](REQUEST_JNI_STARTUP_WORKERS.md#6126-request-outer-suffix-and-raw-free2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request allocated printf依赖

36项新增原生对照、9项回滚通过；两次live格式化、truncation、pointer
publication和allocator效果一致。2869F0外层组合和cleanup继续恢复，
非空入口3307步。actual JNI、整链差分、完整signer、fresh/live及真实JVM
仍未完成。见 [allocated printf报告](REQUEST_JNI_STARTUP_WORKERS.md#6125-request-allocated-printf2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-13 Asia/Shanghai：request version word getter

40项新增原生对照、10项回滚通过；packed version、独立status槽、
encoded table重读和cached guard语义一致。2869F0外层格式化和cleanup
继续恢复，非空入口3307步。actual JNI、整链差分、完整signer、fresh/
live与真实JVM仍未完成。见 [version报告](REQUEST_JNI_STARTUP_WORKERS.md#6124-request-version-word2026-10-13-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request raw MD5与scoped assignment依赖

54项新增原生对照、12项回滚通过；raw16 MD5、scratch/scope重叠与
reference assignment所有权及alias顺序一致。2869F0外层getter、格式化
和cleanup继续恢复，非空入口3307步。actual JNI、整链差分、完整signer、
fresh/live及真实JVM仍未完成。见 [raw MD5报告](REQUEST_JNI_STARTUP_WORKERS.md#6123-request-raw-md5-and-reference-assignment2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request hexadecimal reference组件

20项新增原生对照、8项回滚通过；192494/19364C的guest alphabet、
逐半字节live读取及reference scope一致。2869F0外层组装/publication/
cleanup仍待恢复；非空入口3307步。actual JNI、整链差分、完整signer、
fresh/live及真实JVM仍未完成。见 [hex报告](REQUEST_JNI_STARTUP_WORKERS.md#6122-request-hexadecimal-reference2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request binary transform组件

24项新增原生对照、10项回滚通过；286084的SDK-zero分支、pointer/seed
key、S-box/forward mixing及reference构造一致。2869F0外层组装/hex/
cleanup仍待恢复；非空入口3307步。actual JNI、整链差分、完整signer、
fresh/live及真实JVM仍未完成。见 [transform报告](REQUEST_JNI_STARTUP_WORKERS.md#6121-request-binary-transform2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：actual request TLS读写

34项新增actual wrapper对照通过；cold/warm TLS、uint32/padding与
allocation/wake一致。非空入口3307步，下一285E80->2869F0。原有页
回滚，64个新增OS页保留。actual JNI、suffix整链差分、完整signer、
fresh/live及真实JVM仍未完成。见 [request TLS报告](REQUEST_JNI_STARTUP_WORKERS.md#6120-request-tls-uint32-读写2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request contained reference与table hash64

84项新增actual wrapper对照、6项回滚通过；hidden输出、source+18、
scope/count回绕及loaded-table uint64 hash一致。非空入口3257步，下一
285E54->2850A8。原有页回滚，64个新增OS页保留。actual JNI、suffix
整链差分、完整signer、fresh/live及真实JVM仍未完成。
见 [request reference/hash报告](REQUEST_JNI_STARTUP_WORKERS.md#6119-request-stringobject-table-hash642026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：actual request elapsed getter

36项新增actual wrapper对照、12项回滚通过；读取start顺序、wrapped
signed delta选择、unsigned除1000及reader清理一致。非空入口3167步，
下一285E14->2633A4。64个新增OS页保留；actual JNI、
suffix整链差分、完整signer、fresh/live及真实JVM仍未完成。
见 [request elapsed报告](REQUEST_JNI_STARTUP_WORKERS.md#6117-request-elapsed-seconds2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：actual request state构造

16项新增actual wrapper对照、7项回滚通过，26BDFC构造、signed默认值、
reference/scoped writer清理一致。非空入口推进2911步，下一285D80->26BF90。
64个新增OS页保留；actual JNI、suffix整链差分、完整
signer、fresh/live及真实JVM仍未完成。见 [request state报告](REQUEST_JNI_STARTUP_WORKERS.md#6116-request-state-构造与清理2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：lazy state service

8项新增原生对照、7项回滚通过；warm singleton136前置条件下cold42
次分配/22次释放/2次注册/3次wake及ELF/TLS一致。全冷singleton136
额外60次分配的路径明确拒绝。非空request仍2850步，下一接入26BDFC。
actual JNI、suffix整链差分、完整signer、fresh/live及真实JVM未完成。
见 [state service报告](REQUEST_JNI_STARTUP_WORKERS.md#6115-lazy-state-service2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：state numeric member读取

60项新增原生对照、18项回滚通过；linked-node ASCII搜索、double到W0
转换及nested reader/matching-libc mutex一致。该依赖已恢复，非空入口
仍停2850步的+285D74 -> +26BDFC，lazy state service与callback尚待恢复。
actual JNI、suffix整链差分、完整signer、fresh/live及真实JVM未完成。
见 [state numeric报告](REQUEST_JNI_STARTUP_WORKERS.md#6114-state-numeric-member-读取2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：VM signed64 product与low-copy

238项新增原生/Python对照通过；恢复sub53的MUL/SMULH和sub39的low
slot读取。非空构造入口推进到2850步，当前边界为
`unknown request callback +0x285d74 -> +0x26bdfc`。64个新增OS页保留。
actual JNI、suffix整链差分、完整signer、fresh/live及真实JVM未完成。
见 [signed product报告](REQUEST_JNI_STARTUP_WORKERS.md#6113-vm-signed-product-与-low-copy2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：CString pattern搜索

76项新增原生对照、24项回滚通过；恢复paired扫描、contiguous检查及
unsigned/signed边界。非空入口推进到2761步，当前阻塞为VM op17 sub53。
64个新增OS页保留；actual JNI、suffix整链差分、完整signer、fresh/live
及真实JVM未完成。见 [CString搜索报告](REQUEST_JNI_STARTUP_WORKERS.md#6112-cstring-pattern-搜索2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：StringObject ASCII casefold搜索

72项新增原生对照、20项回滚通过；恢复declared binary搜索、short circuits
和same-pointer fast path。非空入口推进到2590步，下一CString-pattern
搜索callback待恢复。64个新增OS页保留；actual JNI、suffix整链差分、
完整signer、fresh/live与真实JVM未完成。见 [casefold报告](REQUEST_JNI_STARTUP_WORKERS.md#6111-stringobject-ascii-casefold-搜索2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：matching-libc同类别realloc

18项新增原生对照、28项回滚通过；恢复current small cache内的same-bin
realloc和TSD wrapping统计。非空入口推进到2538步，下一StringObject
搜索callback仍待恢复。cross-bin/NULL/zero realloc、actual JNI、suffix
整链原生差分、完整signer、fresh/live及真实JVM未完成。64新增OS页保留。
见 [同类别realloc报告](REQUEST_JNI_STARTUP_WORKERS.md#6110-matching-libc-同类别-realloc2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：StringObject/CString构造

68项新增原生对照、24项回滚通过；复用clone和live CString append。
非空入口仍为2520步，当前阻塞为matching-libc realloc未恢复，下一步
恢复真实allocator realloc。64个新增OS页仍保留；actual JNI、suffix
整链原生差分、完整signer、fresh/live及真实JVM未完成。
见 [对象/CString报告](REQUEST_JNI_STARTUP_WORKERS.md#6109-stringobjectcstring-构造2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：CString/StringObject拼接与清理

84项新增原生对照、28项回滚通过；恢复temporary构造、clone/append及析构。
构造非空入口推进到2520步；下一StringObject/CString组合待原生验证。
64个新增allocator OS页仍不回滚；actual JNI、suffix native整链差分、
完整signer、fresh/live及真实JVM未完成。见 [组合报告](REQUEST_JNI_STARTUP_WORKERS.md#6108-cstringstringobject-拼接2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：field clone与substring

74项新增原生对照、20项回滚通过；恢复borrowed fields复制与X8 substring。
构造非空入口推进到2510步；下一temporary-string组合仍需核实。64个
新增allocator OS页不回滚；actual JNI、suffix native差分、完整signer、
fresh/live与真实JVM未完成。见 [substring报告](REQUEST_JNI_STARTUP_WORKERS.md#6107-field-clone-与-substring2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：constructed nonempty effective ABI

2395步的构造非空入口与原caller/interpreter在98次callback路径、packed
addresses和有效输入上全部一致。native停止在substring body入口，97个
body已执行；全部payload/heap/stack/OS差分、actual JNI与完整signer
未完成。拒绝仍保留64个新增allocator OS页。见 [非空effective ABI报告](REQUEST_JNI_STARTUP_WORKERS.md#6106-constructed-nonempty-request-effective-abi2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request binary equality

48项新增原生对照、8项回滚通过，含16项actual matching-libc memcmp。
已有owner修正短路读取与同pointer的bound顺序，request wrapper写一个
packed boolean byte。构造非空入口推进到2395步，下一callback为substring；
原有bytes回滚，但新增64个allocator OS页保留。actual JNI转换、非空
native差分、完整signer、fresh/live与真实JVM未完成。见 [binary equality报告](REQUEST_JNI_STARTUP_WORKERS.md#6105-request-binary-equality2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request sized string dispatch

18项新增原生wrapper对照、10项回滚通过，复用已有owner；构造非空入口
推进到2243步。拒绝保留原有bytes，但新增64个allocator OS页不回滚。
下一callback为binary equality；actual JNI转换、非空native差分、完整
signer、fresh/live与真实JVM未完成。见 [sized dispatch报告](REQUEST_JNI_STARTUP_WORKERS.md#6104-request-sized-string-dispatch2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request byte search

80项新增原生/Python对照、12项回滚、8项扫描上限检查通过。恢复declared-
length byte search与packed uint32 result；构造非空prefix推进到2224步。
下一callback为sized string constructor。actual JNI转换、非空native差分、
完整signer、fresh/live与真实JVM未完成。见 [byte search报告](REQUEST_JNI_STARTUP_WORKERS.md#6103-request-byte-search2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：ASCII case与request receiver byte flag

92项新增原生/Python对照、8项回滚通过。恢复ASCII upper/lower与receiver
byte52/getter的packed bit0。构造URL与一项header的prefix推进到2174步；
下一callback是byte search。实际JNI转换、非空prefix native差分、完整
signer、fresh/live与真实JVM未完成。见 [ASCII与flag报告](REQUEST_JNI_STARTUP_WORKERS.md#6102-ascii-case-与-request-byte-flag2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：NULL raw cleanup与整链有效字段

16项新增原生/Python对照、6项回滚通过；NULL raw值不调用free。
构造请求2475步/105回调，105次有效packed输入、10次显式服务、physical
caller返回一致。15个token释放缓冲区与6页/167字节RAM差异均定位padding。
libc globals/全部syscall参数、真实URL/header/JNI转换与JVM、完整signer、
fresh/live未完成。见 [NULL raw cleanup与整链报告](REQUEST_JNI_STARTUP_WORKERS.md#6101-null-raw-cleanup-与整链有效字段2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：request caller物理返回恢复

16项原生/Python对照、1项入口、26项拒绝通过。恢复canary与physical
PC/SP/X0及saved registers；请求2475步/105回调返回。25项全部页面不变，
canary入口保留原有页面bytes但新增64页allocator映射不回滚。
完整请求有效参数/heap/服务差分、完整signer、fresh/live与真实JVM未完成。
见 [caller返回报告](REQUEST_JNI_STARTUP_WORKERS.md#6100-request-caller-物理返回2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：VM64 load与compare-store恢复

114项原生/Python对照、1项入口、21项拒绝/回滚通过。opcode36读取word，
opcode57使用hidden slot34串行compare/store；请求2475步/105回调返回。
私有整链main ELF字节差异消失；有效callback参数、heap/服务和physical
caller ABI需继续对照。完整signer、fresh/live与真实JVM未完成。
见 [VM load/store报告](REQUEST_JNI_STARTUP_WORKERS.md#699-vm-load-与串行-comparestore2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：请求scoped tree构造顺序恢复

24项原生/Python对照、1项入口、31项回滚通过。实际 `+25C324/+163DDC`
diagnostic reference构造、descriptor可观察时机与分配顺序恢复；2475步、
105次回调的VM返回保持。下一项修复native compare-and-store内存差异。
完整signer、fresh/live、真实JVM和整链原生差分未完成。
见 [scoped tree报告](REQUEST_JNI_STARTUP_WORKERS.md#698-请求-scoped-tree-reference-构造2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：请求清理完成并到达VM返回

78项原生/Python对照、1项入口检查、36项回滚通过。请求object清理、
free与tree delete完成；空header/NULL JNI输入在2475步、105 callbacks
到达 `+FFB78` 并匹配caller sentinel。请求事务已提交到传入页面。
物理native返回ABI、整链native差分、事件发送分支、真实JVM和完整
signer/fresh/live未完成。见 [清理与VM返回报告](REQUEST_JNI_STARTUP_WORKERS.md#697-请求对象与树删除清理和-vm-返回2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：请求局部树析构

32项原生/Python对照、1项请求入口检查、27项回滚通过。实际pair清理、
节点释放与sentinel/controller清理完成，逻辑iterator scratch一致；
owning请求2321到2329步。下一边界请求对象析构 `+25CF98`。
完整signer、fresh/live继续。见 [局部树析构报告](REQUEST_JNI_STARTUP_WORKERS.md#696-请求局部树析构2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：请求树计数、value与iterator

128项原生/Python对照、1项请求入口检查、40项回滚通过。实际u64 size、
string-value清理/回调reload、iterator pair/advance及clone wrapper完成；
owning请求1995到2321步。旧2000预算实际耗尽后调整为有限4000。
下一边界局部树析构 `+25C01C`；完整signer、fresh/live继续。
见 [树遍历报告](REQUEST_JNI_STARTUP_WORKERS.md#695-请求树计数与-value-清理和-iterator-遍历2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：guest table折叠比较

48项原生/Python对照、1项请求入口检查、26项回滚通过。实际ELF字节
映射、两次warm singleton getter SP/scratch及wrapper W0写宽匹配；
owning请求1812到1995步，下一边界树计数 `+25C150`。完整signer、
fresh/live继续。见 [折叠比较报告](REQUEST_JNI_STARTUP_WORKERS.md#694-实际-guest-table-折叠比较与-singleton-接线2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：请求collection wrappers

28项原生/Python对照、1项请求入口检查、20项回滚通过。树查询与NULL
安全C-string长度复用既有owner；实际wrapper写回8字节结果。请求1567
到1812步，下一边界guest-table comparison `+2765C4`。完整signer、
fresh/live继续。见 [collection报告](REQUEST_JNI_STARTUP_WORKERS.md#693-实际树查询与-c-字符串长度-wrapper2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际填充字符串构造

40项原生/Python对照、1项请求入口检查、20项回滚通过。按actual wrapper
BYTE fill/u32 length恢复填充构造，复用sized布局。请求1558到1567步，
下一边界树查询 `+25C168`。完整signer、fresh/live继续。
见 [填充字符串报告](REQUEST_JNI_STARTUP_WORKERS.md#692-实际填充字符串构造与-wrapper-字节参数2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：进程析构导入与注册

16项原生/Python对照、1项请求入口检查、17项回滚通过。实际ELF绑定
`__cxa_atexit`，请求转发到owning进程注册服务；1539到1558步，下一边界
为 `+248274` 填充字符串构造。真实libc exit table/析构执行未验证；
完整signer、fresh/live继续。见 [进程注册报告](REQUEST_JNI_STARTUP_WORKERS.md#691-实际进程析构导入与注册2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：请求树与iterator ABI

24项原生/Python对照、1项请求入口检查、13项回滚通过。请求复用树
constructor，恢复begin/end pair及node/table比较；入口独立生成有效空
header reference，NULL输入仍拒绝。请求从1444到1539步，当前缺失
`__cxa_atexit` ABS64导入与进程析构注册。完整signer、fresh/live继续。
见 [树与iterator报告](REQUEST_JNI_STARTUP_WORKERS.md#690-实际请求树构造与-iterator-abi2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际registry计数与拥有者TLS接线

40项原生/Python对照、1项请求入口检查、36项回滚通过。计数回调恢复
scoped lookup、signed饱和/回绕、克隆键并插入和旧u32返回。请求显式
使用拥有者TLS/registry/broadcast服务，从1419到1444步，下一处为
`+25BF14` 树构造。完整独立signer、fresh签名与线上矩阵继续。
见 [registry计数报告](REQUEST_JNI_STARTUP_WORKERS.md#689-实际-registry-计数回调与拥有者-tls-接线2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际请求对象构造与临时引用

60项原生/Python对照、1项请求入口检查、34项回滚通过。对象构造复用
StringObject克隆与诊断reference生命周期，写入realtime毫秒和状态字段；
临时NULL reference计数最终由对象保留为1。公开请求从1019到1419步，
下一处为 `+256AB0` 回调。完整独立signer、fresh签名与线上矩阵继续。
见 [请求对象报告](REQUEST_JNI_STARTUP_WORKERS.md#688-实际请求对象构造与临时引用生命周期2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际JNI发布器与请求byte gate

44项原生/Python对照、1项请求入口检查、20项回滚通过。实际发布器
恢复environment acquisition、双tag dispatch与双reference cleanup。
纠正此前归属：请求byte gate `+28C0EC` 实际调用 `+28BB54` 零返回叶函数，
没有JNI effects。公开请求入口从993推进到1019步，下一处为 `+25CDD4`
对象构造。完整独立signer、fresh签名与线上矩阵继续。
见 [发布器与byte gate报告](REQUEST_JNI_STARTUP_WORKERS.md#687-实际-jni-发布器与请求-byte-gate2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际boolean scope清理与elapsed event

46项原生/Python对照、1项请求入口检查、28项回滚通过。实际scope清理
执行elapsed时钟、uint64 fetch-add、采样、两参数formatter和warm logger
生命周期；全部payload/ELF页、服务及临时清理匹配。请求VM从965继续
到993步，下一处为 `+28C0EC` 发布callback。完整独立signer、fresh/live
继续。见 [scope报告](REQUEST_JNI_STARTUP_WORKERS.md#686-实际-boolean-scope-清理与-elapsed-event2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际request stack evaluator与请求VM接线

78项原生/Python对照、1项请求入口检查、20项回滚通过。76项执行实际
acquisition，2项使用显式NULL acquisition边界。warm singleton、guest
payload/ELF页、JNI/getter顺序、logical va_lists及清理一致。请求VM入口
转发JNI与getter，fresh拥有者的请求到965步后停在scope cleanup。
下一步恢复 `+28C09C`；cold/request整链、完整独立signer、fresh/live
继续。见 [evaluator报告](REQUEST_JNI_STARTUP_WORKERS.md#685-实际-request-stack-evaluator-与请求-vm-接线2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：delayed VM/callable/worker live服务接线

4项evaluator及2项完整callable原生/Python对照、2项bounded worker入口
检查、16项回滚通过。callable执行完整live lookup与最终配置值7发布，
上层入口转发显式服务。live output-reference栈padding经原生写入恢复，
free前TLS节点字节匹配。worker在live callable后的wait按显式上界停止，
完整live三worker调度对照、完整独立signer、fresh/live继续。见
[provider报告](REQUEST_JNI_STARTUP_WORKERS.md#684-delayed-vmcallableworker-的-live-provider-接线2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际live initializer与cold lookup

88项initializer及4项完整cold lookup原生/Python对照、6项回滚通过。
SDK22/23/27/28/34/35与NULL/exception清理、once flag、global引用发布、
全部guest页面与服务顺序匹配。公开lookup可在cold初始化后继续MD5输出。
VM/worker provider接线、真实Android JVM、完整独立signer、fresh/live
继续。见 [initializer报告](REQUEST_JNI_STARTUP_WORKERS.md#683-实际-live-initializer-与-cold-lookup2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-12 Asia/Shanghai：实际UTF构造与Java service查找

UTF20项及service22项原生/Python对照、9项回滚通过。short/heap string、
exception scope、引用返回、临时locals与free前字节一致。service路径
需要live default Java对象。实际initializer私有草稿已有两基址×SDK27/30
四项页面/服务对照；公开组合及其异常验收、VM/worker接线、完整独立
signer、fresh/live继续。见 [Java service报告](REQUEST_JNI_STARTUP_WORKERS.md#682-实际-utf-构造与-java-service-查找2026-10-12-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：带参数JNI方法与静态字段

实例/静态方法、静态字段通过140项原生/Python对照、11项回滚。
支持非浮点参数/返回和void；GP/stack参数、consumed va_list、字宽、
异常顺序及旧reference subset一致。实际initializer+2191D4已有4项
原生live对照，旧路径拒绝且页面回滚；class resolver+218660和完整
initializer组合、VM/worker接线、独立signer/fresh/live继续。
见 [JNI member报告](REQUEST_JNI_STARTUP_WORKERS.md#681-带整型引用参数的-jni-方法与静态字段2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：cold encoded SDK与initialized live lookup

SDK getter 52项对照/9项回滚，完整lookup组合10项对照/4项回滚通过。
encoded/plain cache独立，共用十进制转换；cold属性缺失→SDK0以及
SDK27/30的完整JNI清理、scope、MD5输出均一致。singleton136仍须
初始化。cold live initializer、VM/worker live provider接线、完整
signer、fresh输出和线上矩阵继续。见 [cold SDK报告](REQUEST_JNI_STARTUP_WORKERS.md#680-cold-encoded-sdk-getter-与实际-live-lookup2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：实际 initialized live Java lookup

两基址×SDK27/30通过48项完整helper对照/11项回滚；binary MD5hex、
JNI local清理、全部payload/image页面与scope/effects顺序一致。cold
initializer/encoded SDK、live worker接线、完整signer和fresh/live继续。
见 [live lookup报告](REQUEST_JNI_STARTUP_WORKERS.md#679-已初始化对象的实际-live-java-lookup2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：实际 reference scopes 与 MD5 生命周期

共享作用域接口通过64项对照/12项回滚，MD5实际生命周期通过16项对照/
4项回滚。原有摘要回归结果一致。实际Python live lookup、完整独立
signer、fresh/live继续。见 [作用域报告](REQUEST_JNI_STARTUP_WORKERS.md#678-实际-reference-作用域与-md5-生命周期2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：JNI 引用字段、方法与清理

三项实际JNI component通过74项原生/Python对照、18项页面回滚；status
byte、NULL/exception路径、va_list copy、reference type清理和服务顺序一致。
原有environment定义执行AST一致。四项+21CBEC实际原生live RED已通过，
Python组合、独立signer、fresh/live继续。见 [JNI引用报告](REQUEST_JNI_STARTUP_WORKERS.md#677-jni-引用字段无参数方法与引用清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：Java byte array 转引用

实际+2700A8/sized string/诊断reference边界通过52项原生/Python对照、19项
页面回滚；二进制长度、NULL/非正长度、分配失败、JNI table重读和服务顺序
一致。原有environment定义的执行AST一致。实际live lookup+21CBEC、独立
signer及fresh/live继续。见 [byte array报告](REQUEST_JNI_STARTUP_WORKERS.md#676-java-byte-array-转引用与实际诊断锁2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：三条 worker 协作等待与完整退出

两基址×A/B四项fresh完整对照、23项页面回滚通过；6次等待（3、1、2）后
实际timed task转交follow-up，worker按1、2、0返回并退出。全部存活页面、
allocation/free、VM/JNI和有序服务组一致。共享startup generator统一拥有
同步与协作等待；旧executor62/6、queue94/5回归逐字节一致。
live Java转换、完整独立signer及fresh/live继续。
见 [协作worker报告](REQUEST_JNI_STARTUP_WORKERS.md#675-三条-worker-协作等待转交与完整退出2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：实际 timed poll、queue 转交与清理

两基址×A/B四项fresh完整对照、20项页面回滚及共享callable旧回归通过。
每组11502项allocation/free，task与wrapper释放、队列最终为空；两段VM
自然退出，15callbacks和GetEnv2/JNI0一致，全部存活页面和有序服务组匹配。
恢复mutex lock临时地址保存及后续TLS padding。采用显式poll/queue driver，
完整executor worker等待周期、live Java转换、完整signer与fresh/live继续。
见 [timed转交报告](REQUEST_JNI_STARTUP_WORKERS.md#674-实际-timed-poll转交与-queue-清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：实际延时 callback 与两段 image VM

两基址×两分支4项fresh完整对照、22项页面回滚通过。实际callable自然返回；
checksum VM8,606,106steps、lookup VM301steps/15callbacks，真实Java错误
reference、guest CRC、配置发布与owning清理匹配。新增GetEnv2次/JNI0次，
所有存活页面和有序服务组一致。使用显式body driver，完整timed executor
周期、live Java字符串转换、完整signer与fresh/live继续。
见 [实际延时回调报告](REQUEST_JNI_STARTUP_WORKERS.md#673-实际延时-jni-callable-与两段-image-vm2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：完整 finalizer worker 与 guest 退出

两基址×两分支完整ELF/13constructors/JNI/三条worker/三次guest退出，通过
4项完整对照、4项copied probe和47项回滚；所有存活页面和服务组一致。
临时原有代码真实执行返回1，image VM6435steps自然退出，首条后续任务
与deque一致。继续后续callback、独立signer及fresh/live。
见 [完整finalizer报告](REQUEST_JNI_STARTUP_WORKERS.md#672-jni-finalizer-完整-worker-与-guest-退出2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：JNI finalizer 的延时任务提交

首条非零 delay 提交、heap wrapper/task、executor deque 与 controller signal
通过8项原生对照、24项callable和25项回滚；两组旧callable结果逐字节一致。
第三条finalizer完整worker、后续callback执行、独立signer和fresh/live继续。
见 [延时提交报告](REQUEST_JNI_STARTUP_WORKERS.md#671-jni-finalizer-的首条延时任务提交2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：完整 JNI 到 executor/初始化 queue 与退出

两基址×两分支4项原生对照/28项回滚通过。完整13constructors/JNI后执行
executor和实际A/B queue；独立线程TLS与两次完整joinable guest退出、全部
存活页面及服务组匹配。继续第三queue的finalizer callback与延时任务、
独立signer和fresh/live。见 [完整worker报告](REQUEST_JNI_STARTUP_WORKERS.md#670-完整-jni-后的两条-worker-与-guest-退出清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：完整 JNI 与条件主线程 startup

fresh ELF映射/链接、13项constructor、JNI_OnLoad与一次A/B主线程startup
组合通过4项完整原生对照/38项回滚。JNI自然返回10006，全部存活页面与
服务组匹配；两queue各含一个callable，3个worker请求延后执行。Finalizer
callable通过32/9项检查，旧callable84/12结果逐字节一致。继续同次worker/
cleanup、finalizer callback body、独立signer及fresh/live。
见 [完整JNI报告](REQUEST_JNI_STARTUP_WORKERS.md#669-完整-jni-与两条主线程-startup-组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：ELF 映射与完整符号链接

当前样本全部PT_LOAD/BSS、18481项重定位、符号版本/绑定和init/fini数组
独立加载。10项映射对照、2项完整原生/Python构造序列、42项拒绝通过。
继续完整同次JNI/bootstrap、startup/worker/cleanup、独立signer和fresh/live。
见 [ELF加载报告](REQUEST_JNI_STARTUP_WORKERS.md#668-elf-映射与完整符号链接2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：完整 init_array 顺序组合

全部13项constructor共享一个分配计划、TLS、catalog与诊断状态，4项fresh
原生对照/40项回滚通过。每项6272次分配/5156次free/11次注册，全部存活
页面与各自有序效果匹配。继续完整二进制mapping/linking、JNI/bootstrap、
独立signer与线上验收。见 [顺序组合报告](REQUEST_JNI_STARTUP_WORKERS.md#667-elf-init_array-完整顺序组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：ELF configuration constructor

+2679F0通过16项fresh原生对照、72项回滚；既有registry38项对照/14项
负例结果逐字节一致。实际诊断scopes、libc广播、全部存活页面、有序
服务和同次warm匹配。13/13个init_array成员已有独立实现；继续完整
顺序loader/JNI、独立signer和线上验收。见 [配置报告](REQUEST_JNI_STARTUP_WORKERS.md#666-elf-configuration-constructor2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：ELF guarded string constructor

+15DB50通过18项fresh原生对照、25项回滚检查；六个既有入口通过12项
fresh回归。全部存活页面、guard/thread id、分配与注册匹配。现覆盖
12/13个init_array成员；继续2679F0、完整loader/JNI、独立signer和线上验收。
见 [guarded string报告](REQUEST_JNI_STARTUP_WORKERS.md#665-elf-guarded-string-constructor2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：六个 ELF support constructors

六个支持constructor通过48项fresh原生对照、51项回滚检查；复用既有
object/JNI owner。两基址、GOT、时钟signed wrap、NULL malloc和property
分支的全部存活页面及有序服务匹配。连同五个module入口覆盖11/13成员；
继续剩余入口、完整顺序loader/JNI组合、独立signer和线上验收。
见 [ELF support报告](REQUEST_JNI_STARTUP_WORKERS.md#664-六个-elf-support-constructors2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：五个 ELF module constructors

同一owner现已恢复五个实际module constructor。新增四个入口通过8项
fresh原生对照、2项既有B回归及77项回滚检查；全部非原生栈页面、root、
descriptor发布、有序分配与清理一致。继续其余loader constructors、
完整JNI/bootstrap、独立signer、新鲜输出及线上验收。
见 [module constructor报告](REQUEST_JNI_STARTUP_WORKERS.md#663-另外四个-elf-module-constructors2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B 同次 startup 的队列 worker 与清理

B实际队列任务、正常worker返回、TLS key清理及完整joinable guest
pthread_exit组合。12项原生对照、24项回滚检查通过，覆盖cold/warm key、
两基址及不同worker SP。每次任务120847次分发，全部非原生栈页面、
生命周期内的context、两份TLS和有序效果匹配。继续完整JNI/bootstrap、
独立signer、新鲜输出及线上验收。
见 [B 队列与清理报告](REQUEST_JNI_STARTUP_WORKERS.md#662-b-同次-startup-的队列-worker-与清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B 完整 worker callable 与嵌套初始化

六个外层及48个嵌套程序与共享once/CAS64/memset组合。18项原生对照、
36项回滚检查通过，输入来自两份fresh ELF独立构造。每次cold任务匹配
120847次分发、54次descriptor、18次导入、6次分配及6次唤醒。
继续同次startup的队列worker/TLS清理、JNI/bootstrap及完整signer。
见 [完整 B callable 报告](REQUEST_JNI_STARTUP_WORKERS.md#661-b-完整-worker-callable-与嵌套初始化2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B 复用共享 once 状态机

共享 owner 接受B六个控制字，复用锁/状态/广播/回滚。60项原生对照
（36B、24A回归）与22项回滚检查通过。原始once与真实libc broadcast
自然返回，初始化体仍为显式provider。完整worker和signer继续。
见 [共享 once 报告](REQUEST_JNI_STARTUP_WORKERS.md#660-b-复用共享-once-状态机2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B worker 完整算术与内存内置函数

28个基础tag、47个组合tag与CAS64/memset恢复。310项runtime、30项builtin、
4项startup回归及69项回滚检查通过。24项实际嵌套descriptor使用真实memset
回调；输入来自独立ELF构造。完整once/worker组合和signer仍未完成。
见 [B worker arithmetic 报告](REQUEST_JNI_STARTUP_WORKERS.md#659-b-worker-完整算术与内存内置函数2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B worker 分支与组合指令

既有执行器扩展两个基础 tag 和六个组合 tag。112项 runtime 原生对照、
4项实际startup回归、40项回滚检查通过；其中24项实际worker descriptor
仍使用显式纯导入provider。回调返回PC与读取PC时的先后顺序已对照。
继续worker实际回调及嵌套初始化、完整JNI/bootstrap、独立signer和线上验收。
见 [B worker runtime 报告](REQUEST_JNI_STARTUP_WORKERS.md#658-b-worker-的分支与组合指令2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B 主线程 startup 与真实导入回调

B +2a0028 已组合独立 constructor 发布的初始化程序与真实 enqueue/destroy。
28项原生对照、41项回滚检查通过；四项完整 startup 来自两份新鲜 ELF 模块。
每次19次分发、2次导入、3个线程请求、22项有序效果，完整context和非原生栈页面匹配。
线程体仍延后执行；继续 B worker、完整 JNI/bootstrap、独立 signer 和线上验收。
见 [B startup 报告](REQUEST_JNI_STARTUP_WORKERS.md#657-b-主线程-startup-与真实导入回调2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：共享B callable生命周期

在既有vm9_startup共享owner扩展B虚表的move/destroy，复用队列契约。
84项原生对照、12项回滚检查通过，含32项B和52项原有A/queue回归。
完整guest/image和有序释放一致，其他共享owner定义AST未变。
继续真实B startup回调组合、worker、JNI/bootstrap、独立signer和线上验收。
见 [B callable 报告](REQUEST_JNI_STARTUP_WORKERS.md#656-b-callable-的共享移动与清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：B context与有界描述符执行

48项执行、6项context初始化、27项回滚检查通过。两基址从fresh ELF
经独立Python构造器生成实际初始化描述符，各19次分发、2次显式纯
provider调用。完整页面、回调context、active frame与SP匹配。
实际导入函数体及线程/队列工作仍待连接；继续完整JNI/bootstrap、worker、
独立signer、新鲜输出与线上验收。
见 [运行时报告](REQUEST_JNI_STARTUP_WORKERS.md#655-b-运行状态与有界描述符执行2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：独立构造器与121项描述符发布

2 份 fresh 完整原生/Python 构造器对照、22 项回滚检查通过，覆盖
两个基址和重定位/padding。共242发布槽、278描述符、109066指令；
每次2330分配、1836释放、4个finalizer，完整页面和有序效果一致。
ELF静态指令独立生成所有绑定/codec输入，最后发布故障也全页回滚。
继续完整 JNI/bootstrap、B VM 执行、独立 signer、新鲜输出与线上验收。
见 [构造器报告](REQUEST_JNI_STARTUP_WORKERS.md#654-构造器输入生成与描述符发布2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：factory 独立组合与两层清理

26 个原生/Python factory 对照、38 项回滚检查通过。两个基址从 fresh
ELF 独立完成 XOR/AST/parse/root/cleanup，各139描述符、54533指令、
2330分配、1836释放、4个finalizer；完整页面和有序发布效果匹配。
修复 reader 对 ELF 内合法输入的重叠误判。继续 constructor 的121项
publication、完整 bootstrap、独立 signer、新鲜输出与线上验收。
见 [factory 报告](REQUEST_JNI_STARTUP_WORKERS.md#653-factory-独立组合与两层清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：root 构造、全局数据搬移与运行时链接

62 个原生/Python root 对照、34 项回滚检查通过。两份 fresh 实际模块
含 278 个描述符、109066 条运行时指令；每个 root 的 544 次分配、
52 次释放和 3 个 finalizer 匹配。全页、212 字节临时存储和有序发布
效果一致，旧 owner AST 未变。继续 factory/bootstrap、独立 signer、
新鲜输出及线上验收。
见 [root 报告](REQUEST_JNI_STARTUP_WORKERS.md#652-root-构造全局数据搬移与运行时链接2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：imported descriptor 解析与构造

106 个原生/Python descriptor 对照、72 个 batch、36 项回滚检查通过。
两份 fresh 实际模块全部 36 项导入使用 ELF 构造器回调引用；完整
页面、名称临时存储和有序效果一致，旧 owner AST 未变。继续完整
root、factory/bootstrap、独立 signer、新鲜输出及线上验收。
见 [imported descriptor 报告](REQUEST_JNI_STARTUP_WORKERS.md#651-imported-descriptor-解析与构造2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：builtin function catalog 与名称哈希

32 个原生/Python catalog 对照、198 个名称哈希对照、34 项回滚/类型
检查通过。恢复 73 项 owned name/function 和 128 桶 predecessor 链。
完整 guest/heap/image pages、32 字节临时存储和有序效果一致；名称
来源由原始 ELF 静态独立复核，旧 owner AST 未变。继续 imported
descriptor、完整 root、factory/bootstrap、独立 signer、新鲜输出和线上验收。
见 [builtin catalog 报告](REQUEST_JNI_STARTUP_WORKERS.md#650-builtin-function-catalog-与名称哈希2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：defined descriptor 构造与失败清理

288 个原生/Python descriptor 对照、35 项回滚检查通过。48 个 batch
构造 113762 条指令，包含两次 fresh 实际模块的全部 242 个函数和
109066 条指令。完整 guest/heap/image pages、96 字节临时栈和有序
效果一致，旧 owner AST 未变。继续 imported descriptor、完整 root、
factory/bootstrap、独立 signer、新鲜输出和线上验收。
见 [defined descriptor 报告](REQUEST_JNI_STARTUP_WORKERS.md#649-defined-descriptor-构造与失败清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：runtime 二次转换与 root linking

3918 个原生/Python descriptor 对照、27 项回滚检查通过；18 个 batch
覆盖全部 600 种副表规则和两份完整实际模块。共比较 138454 条记录、
23490 次副表重写、1246 次 root 指针写入。全部 guest/heap/image
pages 一致，已有 owner AST 未变。继续 defined descriptor 构造与
清理、完整 root、factory/bootstrap、独立 signer、新鲜输出和线上验收。
见 [runtime linking 报告](REQUEST_JNI_STARTUP_WORKERS.md#648-runtime-descriptor-二次转换与-root-linking2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：decoded instruction 运行时构造

生产 builder 通过 **116422 次原生对照、24 项回滚检查**，22 个 batch
含 109066 次完整实际 ELF 指令调用，覆盖 187 个叶子方法和 graph/
padding/SP 变化。独立 reader/parse 输入、全部 64 字节输出和 guest/
heap/image pages 一致；已有 owner AST 未变。继续 runtime vector
move、二次转换/root linking、descriptor/root、factory/bootstrap、
独立 signer、新鲜输出和线上验收。见 [runtime builder 报告](REQUEST_JNI_STARTUP_WORKERS.md#647-decoded-instruction-运行时构造2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：instruction builder catalog

`+2cc038` 的 Python 初始化通过 **40 项原生对照、22 项回滚检查**，
含 cold/warm、padding、两基址及 heap/SP/thread 变化。主表 529 个
节点/99 张分发表，副表 600 个节点；源自静态 ELF stores，无原生
快照输入。原有 owner AST 未变。继续 opcode builders 执行、root/
descriptor、factory/bootstrap、独立 signer、新鲜输出和线上验收。
见 [builder catalog 报告](REQUEST_JNI_STARTUP_WORKERS.md#646-instruction-builder-catalog2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：converted module 清理

`+2cb968` 的 Python 清理通过 **146 项原生对照、21 项回滚检查**。
含 2 项独立 reader/parse 生成的完整实际 ELF、4 项 SP 移位、6 项高位
guest；完整 guest/heap/image pages 和有序释放一致。原有 owner AST
未变。继续 root/descriptor builders、factory/bootstrap、独立 signer、
新鲜输出与线上验收。见 [converted cleanup 报告](REQUEST_JNI_STARTUP_WORKERS.md#645-converted-module-清理2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：parse 模块转换

`+2cd5a4` 的 Python 模块转换通过 **170 项原生对照、25 项回滚检查**。
4 项完整实际 ELF 每次匹配 128 分配、139 函数、54533 decoded words，
覆盖完整 guest/额外 heap/image pages 与有序 effects/finalizers。输入
独立生成；原有 owner AST 未变。当前继续 converted cleanup、root/
descriptor、factory/bootstrap、独立 signer、新鲜输出与线上验收。
见 [parse conversion 报告](REQUEST_JNI_STARTUP_WORKERS.md#644-parse-模块转换与-builtin-catalog2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：parse 指令格式转换

`+2db778` 的 Python 指令格式转换通过 **434 项原生对照、10 项拒绝检查**，
含 198 项实际构造器格式、16 项 SP 移位、12 项高位 guest。无原生快照
输入；已有 owner 代码 AST 未变。当前继续完整 parse、root/descriptor、
factory/bootstrap、独立 signer、新鲜输出与线上验收。
见 [parse codec 报告](REQUEST_JNI_STARTUP_WORKERS.md#643-parse-指令格式转换2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：零条目 type 的 incoming X22

显式 `entry_x22` 恢复 type-count helper 保存，允许零条目 type 后组合
table/memory/global imports。默认 `None` 保留拒绝，未输入原生快照。
**198 项原生/Python 对照、9 项回滚**通过，含 12 项 SP 移位与 6 项
高位 guest。同一最终版的 **36 项选定旧对照、77 项旧回滚** 与历史证据
一致；其中两个完整实际 ELF module 仍逐字节匹配。
当前推进 parse/root、独立 factory/bootstrap、signer、新鲜输出及线上
验收。见 [零条目 type 报告](REQUEST_JNI_STARTUP_WORKERS.md#642-零条目-type-与-incoming-x222026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：完整实际 module 的 reader AST

element/data/special-custom attached 组合通过 **406 项原生/Python 对照、
36 项回滚**，包含 12 项 SP 移位、6 项高位 guest、12 项实际 custom。
完整实际 ELF 的 229328 字节 module 在两个基址自然返回 0，每次 121 个
code bodies、54533 个 raw words、55369 次 callbacks；完整 input/guest/
额外 1 MiB heap/effects/cleanup/image globals 一致，无原生快照输入。
连续 raw words 的 ownership 校验避免重复扫描全 AST；所有字仍逐个处理。
前一版本的三组旧回归 **1502/99** JSON 逐字节一致，最终 X28 padding
修复对其执行范围的 AST 等价检查通过。非空 element abort、
零条目 type 的 incoming X22、parse/root、独立 factory/bootstrap、signer
及线上验收仍未完成。见 [完整模块 reader AST 报告](REQUEST_JNI_STARTUP_WORKERS.md#641-完整实际-module-的-reader-ast2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：短名称 export 的 attached 组合

`enable_inline_exports=True` 要求 `enable_exports=True` 和显式 `entry_x28`。
恢复所有 0..22 字节名称及此前 caller stores、连续名称保留尾部。
**386 项原生/Python 对照、25 项回滚**通过，含 12 项 SP 移位、6 项高位
guest、884 个完整 records/clones。两组旧回归 **656/293** 的
JSON 逐字节一致。两个基址下完整实际 ELF 的 121 条 export payload 均通过，
声明与 code 为合成输入，扩展 1 MiB heap 全量比较；未公开名称/payload。
其余 attached handlers、incoming X22、parse/root、完整 reader/factory/
bootstrap、独立 signer 与线上验收尚未完成。
见 [短名称 export 报告](REQUEST_JNI_STARTUP_WORKERS.md#640-短名称-export-的-attached-ast-组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：长名称 export 的 attached 组合

`enable_exports=True` 默认关闭，支持至少 23 字节名称、kind 0..3 的实际
export AST 与清理。**294 项合成对照、46 项回滚**通过，含 12 项 SP 移位、
12 项高位 guest 和 618 个完整 export/clone 检查。callback SP=`state-0xd0`，
名称 header=`state-0x160`；保留映射且独立的 `[state-0x210,state)`。
三组旧回归 **832/372** 通过，三份历史 JSON 逐字节一致。
短名称继承的 caller 字节仍待恢复；实际 ELF 的 121 个 export 名称全部为
短名称，因此实际非空 export 原生/Python 对照仍为 0。一个实际短名称拒绝
并全页面回滚。其余 attached handlers、parse/root、完整 reader/factory/
bootstrap、独立 signer 与线上验收仍未完成。
见 [长名称 export 报告](REQUEST_JNI_STARTUP_WORKERS.md#639-长名称-export-的-attached-ast-组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：code definitions 的 attached 组合

section 10 的 metadata/local/raw-word/begin/end 实际 AST 与清理另通过
**256 项对照、42 项回滚**，含 8 项完整实际 ELF body 对照、12 项 SP
移位、12 项高位 guest、362 个完整 function records 和 340 个
完整 child records。新开关默认关闭，可独立使用。callback SP=`state-0xe0`，
保留映射且独立的 `[state-0x210,state)`，globals 组合沿用更大 frame。
raw words 只保存不执行；section 总预算约束短输入反复产生零的路径。
8 项主动截停的原生观察单独记录，未声称其自然返回或清理通过。
四组旧回归 **1,124/235** 通过，四份 JSON 逐字节一致；旧 unsupported
slot guard 从已开放的 `+b0` 移至仍关闭的 `+100`。
其余 attached handlers、parse/root、完整 reader/factory/bootstrap、真实
allocator/异常、独立 signer 与线上验收仍未完成。
见 [code module 报告](REQUEST_JNI_STARTUP_WORKERS.md#638-code-definitions-的-attached-ast-组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：global definitions 与初始化表达式的 attached 组合

section 6 的实际 global/constant-expression AST 回调、完整 u64 result 与清理
另通过 **398 项对照、37 项回滚**，含 12 项 SP 移位、12 项高位 guest 和
780 个独立完整 global record 检查。新开关默认关闭，可独立使用。
caller result=`state-0xb0`，initializer integer scratch=`state-0x108`；
end-only 保留高 32 位，包含前置 memory handler 保存的 ELF dispatcher 指针。
映射且独立保留 `[state-0x2a0,state)`，未使用原生 snapshot 作为模型输入。
五组受影响旧回归 **1,614/315** 通过，五份 JSON 逐字节一致。
code/其他剩余 attached handlers、parse/root、完整 reader/factory/bootstrap、
真实 allocator/异常、独立 signer 与线上验收仍未完成。
见 [global module 报告](REQUEST_JNI_STARTUP_WORKERS.md#637-global-definitions-与初始化表达式的-attached-ast-组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：table/memory definitions 的 attached 组合

section 4/5 的实际 AST reserve/entry、imports 后的 definition index 和清理
另通过 **470 项对照、32 项回滚**，含 12 项 SP 移位、12 项高位 guest
与 1142 个独立完整 record 检查。新开关默认关闭，不依赖 import 选项。
descriptor 的真实 caller 地址、尾五字节、table padding 和 custom/type/
import/function caller stores 由独立输入推导，未使用原生栈 snapshot。
零条目 type 后 definitions 已验证；旧的零 type 后其他 import 限制继续适用。
八组旧回归 **2,582/463** 通过，八份 JSON 逐字节一致。
global expression/code 的 attached 组合、parse/root、完整 reader/factory/
bootstrap、真实 allocator/异常、独立 signer 与线上验收仍未完成。
见 [definitions 报告](REQUEST_JNI_STARTUP_WORKERS.md#636-tablememory-definitions-的-attached-ast-组合2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-11 Asia/Shanghai：短名称其他 import 与 caller 栈传递

table/memory/global 的空名称、短名称、长短混用和四类 import 连续组合
另通过 **612 项对照、41 项回滚**，含 12 项 SP 移位、436 项独立完整
inline padding 检查。新 inline other-import 开关默认关闭，需要原有
table/memory/global 开关；短 function 名称仍需两个 function 开关。
恢复 type-copy FP/LR、import helper 保存和临时 clone 清零，值均从
独立 caller/AST 输入推导，没有喂入原生栈 snapshot。零条目 type section
仍依赖未建模的 caller 寄存器，继续回滚；空 type 向量已经支持。
旧四组 **1,248/262** 通过，四份 JSON 逐字节一致。
definitions/expression/code 的 attached 组合、parse/root、完整 reader/
factory/bootstrap、真实 allocator/异常、独立 signer 与线上验收仍未完成。
本轮验证跨越 10 月 10 日至 11 日。见 [短名称其他 import 报告](REQUEST_JNI_STARTUP_WORKERS.md#635-短名称其他-import-与-caller-栈传递2026-10-11-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：table/memory/global attached imports

真实 module/parser 的长名称 table/memory/global import、descriptor、第九
ABI 参数、AST 与清理另通过 **406 项对照、72 项回滚**，含 12 项 SP 移位。
新开关默认关闭，全部 import 名称需至少 23 字节；函数仍需原有 opt-in。
恢复 type/helper stores 与 global 临时清空，未使用原生 frame snapshot。
零条目 type section 后的其他 import 依赖未建模的入口寄存器，继续回滚；
空 type 向量已支持。旧三组 **842/190** 通过，JSON 逐字节一致。
其他 import 的短名称、definitions/expression/code、parse/root、完整 reader/
factory/bootstrap、真实 allocator/异常、独立 signer 与线上验收仍未完成。
见 [其他 import 报告](REQUEST_JNI_STARTUP_WORKERS.md#634-tablememoryglobal-import-的-attached-ast-组合2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：inline 函数 import 与 caller 栈写入

函数 import 的短名称/空名称/长短混用组合另通过 **448 项对照、64 项回滚**。
需同时开启 function-import 与 inline opt-ins；两者默认关闭。按 caller
state/image/type 数量恢复三处影响 padding 的 helper save stores，未喂入
原生栈 snapshot。含 12 项 SP 移位、282 项独立完整 inline padding 检查。
旧默认 module/heap-only 两组 **394/126** 通过，历史 JSON 逐字节一致。
其他 import/definition/expression/code、parse/root、完整 reader/factory/
bootstrap、真实 allocator/异常、独立 signer 和线上验收仍未完成。
见 [inline import 报告](REQUEST_JNI_STARTUP_WORKERS.md#633-inline-名称函数-import-与真实-caller-栈写入2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：heap 名称函数 import 的 attached 组合

真实 module/parser/function-import AST 与清理另通过 **180 项对照、43 项回滚**。
`enable_function_imports` 默认关闭，开启后两名称均需至少 23 字节；额外
caller frame 必须映射且独立。旧 module/import 两组 **1072/493** 通过，
JSON 逐字节一致。解析失败保留已生成 AST，guard 全页面回滚。
短名称 caller 栈、其他 import/definition/expression/code、parse/root、完整
reader/factory/bootstrap、独立 signer 和线上验收仍未完成。
见 [函数 import module 报告](REQUEST_JNI_STARTUP_WORKERS.md#632-heap-名称函数-import-的-attached-ast-组合2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：有界 attached parser 与真实 AST

`run_reader_ast_module` 贯通真实 `+31b360/+324444` 的 generic/type/function/
start/data-count 与空 export 路径、parser 临时向量和 callback cache 清理。
**214 项对照、83 项回滚通过**；旧 section 与 AST/cleanup 两组（510/66）
JSON 逐字节一致。解析失败/数量不匹配返回 1 并保留部分 AST；guard 完全回滚。
output 需初始为空，allocation 地址不得复用，frames/scratch 由 caller 显式提供。
其余 attached handlers/caller frames、parse/root、完整 reader/factory/bootstrap、
独立 signer 和线上验收仍未完成。见 [module 报告](REQUEST_JNI_STARTUP_WORKERS.md#631-attached-parser-与有界-ast-module2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：完整 Output wrapper 清理

实际 `+2cbadc` 对 12 个 output vector headers 的完整清理已恢复，通过
**330 个对照、214 个回滚**。全部容器按原生顺序清理，名称/节点/nested
vectors 各自释放；kind4 直接清理，table/memory 不读取记录。支持空节点
和非零空容量指针。旧 import/export 两组回归 JSON 逐字节一致。
attached parser/AST/root、完整 reader/factory/bootstrap/signer 仍未完成。
见 [output 清理报告](REQUEST_JNI_STARTUP_WORKERS.md#630-完整-output-wrapper-清理2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：Import AST 回调与专属输出清理

五类 `+28/+30/+38/+40/+48` import AST 回调和仅含 import 的实际 `+2cbadc`
输出清理已恢复，通过 **858 个对照、410 个回滚**。output 两个名称/节点
独立复制，cache 在临时释放后独立追加；旧 cache 向量在增长时转移。
table import 默认 max 为 zero-extended u32 `ffffffff`；table/global 栈参数
与显式 frame padding 已核对。17 组旧回归 JSON 逐字节一致，包含 export。
完整 AST/output wrapper、attached parser/root、reader/factory/bootstrap/signer
仍未完成。见 [import 报告](REQUEST_JNI_STARTUP_WORKERS.md#629-import-ast-回调与专属输出清理2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：Export AST 回调与专属输出清理

实际 `+98 → +31d500` export 回调、五类 virtual clone/deleting destructor 和
仅含 export 的 `+2cbadc` 输出清理已恢复，通过 **362 个对照、247 个回滚**。
扩容复制名称并重新克隆旧节点；短名称显式使用入口栈 padding。
16 组旧回归 JSON 逐字节一致。unsupported guard 移至未恢复的 `+28`。
import `+28/+30/+38/+40/+48`、完整 wrapper/AST/parser/reader/factory/bootstrap/signer
仍未完成。见 [export 报告](REQUEST_JNI_STARTUP_WORKERS.md#628-export-ast-回调与专属输出清理2026-10-10-asiashanghai)。

以下各节记录历史检查点；当前状态以本节为准。

## 2026-10-10 Asia/Shanghai：AST 字符串复制基础

AST 字符串复制基础 `+32a9c4` 通过 **68 个对照、12 个回滚**；两组相关旧回归 JSON 逐字节一致。import/export 回调尚待接入。见 [字符串复制报告](REQUEST_JNI_STARTUP_WORKERS.md#627-ast-字符串复制基础2026-10-10-asiashanghai)。

## 2026-10-10 Asia/Shanghai：global expression 与内联 AST 回调

同一 AST owner 恢复 `+88/+90`，通过 **212 个原生/Python 对照、54 个回滚**，
每基址 106 项，全部合成输入；414 次回调，200 项包含 global 记录的独立析构。
五项行为 RED 在生产修改前成立，相同输入在两基址通过。begin 选择 global
`+18`，重置 frame 并记录 u32 raw 起点；end 保存完整 u64 于 `+a8`，修补树/raw，
pop frame 并保留 active。global active 的 local/function-end 原生行为也已对照。

自然返回/SP、guest `0xa000`（无屏蔽）、副作用顺序和每次 owner 字节一致。
54 项 guard 包含 20 项分配别名和 6 项晚期写入回滚；三项预算拒绝有正常预算
对照，精确节点预算 2 的两基址对照通过。十四组历史 AST 回归均通过，十四份
JSON 逐字节一致。共享原生 driver、其它生产函数、class methods、API 默认值
和 parser 不变；unsupported guard 移至 `+98`。

其余 import/export AST、完整 wrapper、attached parser/AST/root、reader/factory/
bootstrap/signer 尚未完成。见 [global expression 证据](evidence/vm9_alternative_ast_global_expression_fresh_20261010.json)
和 [第 6.26 节报告](REQUEST_JNI_STARTUP_WORKERS.md#626-global-expression-与内联-ast-回调2026-10-10-asiashanghai)。

以下为历史批次，其范围以当时验证为准。

## 2026-10-09 Asia/Shanghai：global 预留、创建与记录清理

同一 AST owner 恢复 `+78/+80`、`output+78` 的 176 字节记录、`callback+c8`
独立 24 字节缓存及 `+2cc3b4` 记录析构：**328 个原生/Python 对照、120 个回滚**，
每基址 164 项，全部合成输入。原生批次完成于 10 月 9 日，十三组回归完成于
10 月 10 日。共 334 次回调、182 次创建；192 项控制包含输出
记录的独立析构。五项行为 RED 在生产修改前成立，同一输入在两基址通过。

完整 u64 type、mutable 低位、单个 owned result 和 destination 的 12 字节
padding 与原生一致。两容器独立增长；输出转移四个 vector，发布后倒序析构
旧记录并 free，cache 也在发布后倒序清理。独立析构释放 children、locals、
type results/params，保留外层记录。自然返回/SP、guest 0xa000（无屏蔽）、
副作用顺序和每次 owner 字节一致；精确节点预算 7/12 的四项对照通过。

120 项 guard 含 64 项五次分配别名、21 项晚期写入及 9 项独立析构保护；
七项预算拒绝有正常预算对照，三个字节上限明确发生于分配。页面全部回滚。
十三组历史 AST 回归通过，十三份 JSON 逐字节一致。共享 driver 只增加 global
析构，既有 callback 分支/API 默认值/parser 不变；unsupported guard 移至 +88。
global expression/imports、完整 wrapper、attached parser、reader/factory/bootstrap/
signer 仍未完成。见 [global 证据](evidence/vm9_alternative_ast_global_fresh_20261009.json)与
[第 6.25 节报告](REQUEST_JNI_STARTUP_WORKERS.md#625-global-预留创建与记录清理2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：memory 预留、创建与独立缓存

同一 AST owner 恢复 `+68/+70`、`output+60` 与 `callback+b0` 的 40 字节记录：
**272 个原生/Python 对照、65 个回滚**，每基址 136 项，全部合成输入，共 304 次
实际回调、248 次创建。五项行为 RED 在生产修改前成立，同一输入在两基址通过。

完整 24 字节 descriptor 复制至 record+10；destination +0c 的 4 字节 padding
保留。maximum flag 为零时，按 memory64 flag 选择 `0x10000` 或
`0x1000000000000`；显式 maximum 保留。reserve 截为 u32、保持 size；两容器
独立增长，发布后 output 只 free，cache 另倒序析构旧节点。无需未初始化栈字。

自然返回/SP、guest 前 0xa000（无屏蔽）、副作用顺序和每次 owner 字节一致。
独立预期另核对容量、descriptor、两种 maximum、padding、搬移、分配与借用
输入。65 项 guard 含 25 项分配别名、12 项晚期写入；五项预算拒绝有正常预算
对照，两个字节上限明确发生于 memory 分配。原始页面全部回滚。

十二组历史 AST 回归全部通过，十二份 JSON 逐字节一致。parser、其它回调、
现有 API 默认值及共享 driver 不变；unsupported guard 移至仍未恢复的 +78。
完整 output wrapper、剩余 AST/import、attached parser、reader/factory/bootstrap/
signer 与线上矩阵仍未完成。见 [memory 证据](evidence/vm9_alternative_ast_memory_fresh_20261009.json)与
[第 6.24 节报告](REQUEST_JNI_STARTUP_WORKERS.md#624-memory-预留创建与独立缓存2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：table 预留、创建与显式栈 padding

同一 AST owner 恢复 `+58/+60` 和 `output+48` table 所有权：**184 个原生/Python
对照、77 个回滚**，每基址 92 项，全部合成输入与实际 relocated vtable；共
216 次回调、160 次 table 创建。生产修改前四项真实行为 RED，原生自然返回 0，
Python 拒绝槽位；后来新增的错误 vtable GOT guard 另取得 RED 后修复。

`+58` 将容量预留至低 u32 count，保留 size。`+60` 忽略 index，向输出和
`callback+98` 缓存各追加 48 字节记录：kind 1、完整 u64 type 和 19 字节
descriptor，原生实际读取 24 字节。flag 为零时将 maximum 改为 u64 ffffffff。
输出增长倒序复制、发布后释放；缓存增长另在发布后倒序调用旧节点析构。
保留 destination 尾部 5 字节，callback cleanup 只拥有临时缓存。

三项独立原生实验确认 record `+14` 复制未初始化的 temporary stack word；
实际 table clone 也继续复制这一字段。因此 `+60` 要求显式 `entry_stack_address`，
读取映射 frame 中 SP-7c 的真实 4 字节，并保留整个 b0-byte frame 的所有权边界。
缺少、非法或别名栈上下文拒绝执行；没有固定填充值，也没有屏蔽 guest 字节。
此有界入口没有整体模拟 native stack/TLS；后续组合必须提供每次真实入口上下文。

两基址核对自然返回/SP、guest 前 `0xa000` 字节、分配/析构/free 顺序和每次
副作用的 owner 字节。独立预期另核对容量、完整 type、descriptor、stack padding、
分配尺寸和借用输入；精确节点预算 5/12 的两基址正向对照通过。77 项 guard
含 27 项两次分配的地址/别名检查、9 项晚期写入失败、5 项有正常预算对照的
预算拒绝，所有原始页面回滚；两个字节 guard 明确触发 table 分配上限。

十一组旧回归全部通过：AST 308/54、data 176/30、create 148/105、payload
104 AST/34 ABI/30 回滚、expression 148/36、element 282/159、nested 230/133、
instruction 398/122、local 252/37、function 188/136、code-begin 284/100。
十一份 JSON 与历史证据逐字节一致。生产 parser/其它函数不变；共享 driver
只转发可选入口栈地址，旧 unsupported guard 从 `+58` 移到未恢复的 `+68`。

下一候选为 memory `+68/+70` 与 `output+60` 所有权；先核对原生契约并取得 RED。
其余 AST、完整 output wrapper、attached parser、reader/factory/bootstrap/signer
与线上矩阵仍未完成。见 [table 证据](evidence/vm9_alternative_ast_table_fresh_20261009.json)与
[第 6.23 节报告](REQUEST_JNI_STARTUP_WORKERS.md#623-table-预留创建与显式栈-padding2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：code-begin、双修补树与 child 追加

同一 AST owner 恢复 `+a8 → +31d7d8`：**284 个原生/Python 对照、100 个回滚**，
每基址 142 项，全为合成输入。全部通过真实 relocated vtable，共 338 次回调、
310 次 code-begin。三项槽位缺失 RED 在生产修改前成立；另两项预算 RED 在
最后修正前成立，不能合并描述为五项生产修改前 RED。

按低 u32 function index 减去 cache/function 数量差选择 logical function，设置
active，保存 metadata、修补前 raw 长度和 cursor offset，忽略 body length。
后序释放 frame 修补树、重置 frame end，再使用 function 修补树修补 raw 并删除
匹配节点。追加 16 字节 frame 与 56 字节 child；后者保存修补后 raw 长度和
local 条目数，保留 padding。child 扩容倒序转移 vectors、清源、发布后释放旧块。
共享 `apply_fixup` 同时服务既有 expression end；没有第二个所有权 owner。

两基址核对自然返回/SP、guest 前 `0xa000` 字节、分配/析构/free 顺序和各副作用
时的 owner 字节；独立预期核对 function 选择、metadata/raw/cursor、双树、frame、
child、local 数量与 padding。覆盖导入数量差回绕、spare/full/null/non-null-zero
容量、修补增长/旋转/连续删除、重复 begin，以及创建/local/常量/end/析构组合。
预算修正避免重复计算旧 child；预算 6/10 的四项两基址对照通过。100 项 guard
含 63 项分配地址/别名检查和 8 项晚期写入失败，全页回滚，不执行无效 native 路径。

十组旧回归重新通过：AST 308/54、data 176/30、create 148/105、payload 104 AST/
34 ABI/30 回滚、expression 148/36、element 282/159、nested 230/133、instruction
398/122、local 252/37、function 188/136；十份 JSON 与历史证据逐字节一致。
最后只修正 `+a8` 的预算条件，旧原生 suites 不执行该槽位。旧 unsupported guard
从 `+a8` 移至仍未恢复的 `+58`。parser、其它生产函数/API、共享 native driver 不变。

下一候选为 table `+58/+60` 与 `output+48` 所有权；先核对原生契约并取得 RED。
其余 AST、attached parser/wrapper、完整 reader/factory/bootstrap/signer 和线上
矩阵仍未完成。见 [code-begin 证据](evidence/vm9_alternative_ast_code_begin_fresh_20261009.json)与
[第 6.22 节报告](REQUEST_JNI_STARTUP_WORKERS.md#622-code-begin双修补树与-child-追加2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：function 创建、类型缓存与清理

同一 AST owner 恢复 `+50 → +31c7b8`：**188 个原生/Python 对照、136 个回滚**，
每基址 94 项，全部输入合成。162 项经实际 relocated vtable 执行，另 26 项直接
验证 function 析构；共执行 286 次回调、创建 238 个 function。三项生产修改前
行为 RED 在实现后转为 GREEN。

两索引截为 u32，type index 必须选中 logical 类型。先将源 params/results 按
实际长度深拷贝至 `output+30` 的 144 字节 function，再独立拷贝至
`callback+80` 的 64 字节 type cache。两边各自扩容，向后搬移、清空源 headers、
发布后倒序析构并释放旧块。复用现有 nested/type 搬移与析构；新增 function
记录析构 API 仍归同一 owner。`+b8/+f8` 可使用 logical function active，拒绝
spare capacity。源类型、两份独立所有权、u32 标量、padding 和实际长度容量均验证。

两基址核对自然返回/SP、guest 前 `0xa000` 字节、所有分配/析构/free 顺序及
每个副作用时的 owner 字节；独立预期另核对类型字节、标量/索引/padding、独立
指针、分配尺寸序列、local/end 和析构后的 ends。136 个 guard 包括 89 个分配
位置/别名检查及 8 个晚期写入失败，全部原始页面回滚，无效 native 内存路径未执行。

旧 AST 308/54、data 176/30、create 148/105、payload 104 AST/34 ABI/30 回滚、
expression 148/36、element 282/159、nested 230/133、instruction 398/122、local
252/37 重新通过，九份 JSON 与历史证据逐字节一致。parser 与其它生产函数不变；
共享 driver 只增加可选 function 析构步骤。

纠正上一交接的候选槽位：`+58 → +31c9f4` 预留 table，`+60 → +31cabc` 创建
table；Section 3 只发 `+50`，没有单独的 function reserve/count callback。
下一步恢复 `+a8` code-begin。table 等其余 AST、attached parser/wrapper、完整
reader/factory/bootstrap/signer 和线上矩阵仍未完成。见
[function 证据](evidence/vm9_alternative_ast_function_fresh_20261009.json)与
[第 6.21 节报告](REQUEST_JNI_STARTUP_WORKERS.md#621-function-创建类型缓存与清理2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：local group 与函数结束回调

同一 AST owner 恢复 `+b8 → +31d984` 和 `+f8 → +31dbb4`：**252 个原生/Python
对照、37 个回滚**，每基址 126 项，全为合成输入。真实 vtable 共执行 348 次
callback。三项行为 RED 在生产修改前成立，实现后同三项 GREEN；完整正向验证
通过后增加五个有具体风险的 guard，重新验证全部 37 项，保留全部正向结果。

`+b8` 忽略 group index，向 active 的 `+50` local vector 追加 16 字节：完整
u64 type、低 u32 count 和 u32 累计 count。`callback+7c` 先回绕相加；count 零
仍追加。容量满时按 `max(size+1,capacity*2)` 扩容，复制、发布后释放旧块。
`+f8` 忽略 index，先清除 active，再将低 u32 length 写入原 active `+70`，
保留 frame 和树。复用现有 ownership class，仅接受 data/element inline 或
element nested 的既有 144 字节布局；nested spare capacity 不能作为 active。

核对自然返回/SP、guest 前 `0xa000` 字节、分配/析构/free 顺序和各副作用时
owner 字节；独立断言 local 原始内容、累计回绕、active/length、frame/tree。
覆盖三个布局、第二个 nested、零计数、完整高位类型、连续追加扩容、group reset、
end/predicate/常量与析构组合。晚期写入和所有权/分配/预算错误全页回滚，
无效 native 内存路径未执行。

旧 AST 308/54、data 176/30、create 148/105、payload 104 AST/34 ABI/30
回滚、expression 148/36、element 282/159、nested 230/133、instruction 398/122
全部重新通过；八份 JSON 与历史证据逐字节一致。旧 unsupported guard 从
`+b8` 移至 `+a8`；共享 driver、parser、ownership class 与其它函数保持不变。
`+a8` code-begin、独立 function output 容器、attached parser/wrapper、完整
reader/factory/bootstrap/signer 和线上矩阵仍未完成。见
[local group 证据](evidence/vm9_alternative_ast_local_fresh_20261009.json)与
[第 6.20 节报告](REQUEST_JNI_STARTUP_WORKERS.md#620-local-group-与函数结束回调2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：instruction predicate 与带类型常量

同一 AST owner 恢复 slots `+c0/+c8/+d0/+d8/+e0/+e8`，**398 个原生/Python
对照、122 个回滚**，每基址 199 项，全部合成输入、真实 vtable 入口执行。
八项行为 RED 在生产修改前成立。两基址均核对自然返回/SP、guest 前 `0xa000`
字节、分配/析构/free 顺序与每个副作用时的 owner 字节；另有独立 status、
frame、raw 字节断言。22 项对照包含 predicate 返回 1。

`+c0` 忽略 kind，active 指针为零或 frame 为空返回 1，否则 0；不解引用
active 指针。`+c8` 保留唯一外层 frame，多层共享现有 u32 修补/树删除/pop；
模型拒绝空 frame。f32/f64/i32/i64 分别写入 u32 tag `4/5/2/3`，随后追加
`4/8/4/8` 字节原始位；浮点不经转换。原生 `+32140c/+321490` 的两步增长
分别发布、释放，复用既有 `grow_bytes`，未引入第二个 owner。

覆盖未对齐 raw 长度、容量边界、u32 高位截断、NaN/符号位、连续常量、
各类树旋转与连续 inner end，以及 data/nested begin/常量/end/析构组合。
五类两次分配的失败与晚期写入失败均全页回滚；无效 native 路径未执行。
旧 AST 308/54、data 176/30、create 148/105、payload 104 AST/34 ABI/30
回滚、expression 148/36、element 282/159、nested 230/133 全部重新通过，
七份 JSON 与历史证据逐字节一致。旧 unsupported guard 移至 `+b8`。

生产修改仅 `run_reader_ast_callback`；ownership class、parser、其它函数
未改。共享原生 driver 只增加显式期望 status，默认仍检查 0。Detached callback、
纯地址计划与逻辑 free 仍为边界。其余 AST、attached parser/wrapper、完整
reader/factory/bootstrap/signer 和线上矩阵仍未完成。见
[instruction 证据](evidence/vm9_alternative_ast_instruction_fresh_20261009.json)与
[第 6.19 节报告](REQUEST_JNI_STARTUP_WORKERS.md#619-instruction-predicate-与带类型常量2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：element 结果类型与嵌套表达式

同一 AST owner 恢复 slots `+120/+128/+130/+138`，**230 个原生/Python 对照、
133 个保护/回滚**通过，两个基址各 115 项，全部合成。四个修改前 RED 均由
实际槽位自然返回与 Python 未支持边界取得。+120 保存完整 u64 结果类型；
+128 将 count 截断 u32、预留 144 字节 nested vector，保持 logical size。
倒序移动四组 vectors，保留 padding，发布后倒序析构和释放旧 block。

+130 为 element 的结果类型创建 original/temporary result 两份八字节存储，
把临时 result 转移至新的 nested 记录；spare 或按倍增容量扩容。原记录移动/
发布/析构之后 free original，然后指向新记录、保存 raw 字节长度并开始 frame。
+138 复用现有 frame/raw/u32 fixup/libc++ erase owner。Nested destructor 从原
element 清理中提取为共享内部 helper；没有第二套树或新的公开析构 API。

独立类型/记录/容量/frame/raw 断言、预填非零 guest 字节、自然返回/SP 和所有
效果时的根 owner 状态通过。逐次创建/扩容/frame/end 分配失败和晚期错误全部
回滚。旧 AST 308/54、data 176/30、create 148/105、payload 104 AST/34 ABI/30
回滚、expression 148/36、element 282/159 均重跑，六份 JSON 逐字节一致。
Parser AST 未改；section 9 非空 vector 仍原生 abort，不发出 +130/+138。
两槽的一个忽略参数为当前独立 API 约定，不宣称 parser ABI 验证。其余 AST、
attached parser/wrapper、完整 reader/factory/bootstrap、signer 与线上验收仍未完成。
见 [nested 证据](evidence/vm9_alternative_ast_element_nested_fresh_20261009.json)与
[第 6.18 节报告](REQUEST_JNI_STARTUP_WORKERS.md#618-element-结果类型与嵌套表达式2026-10-09-asiashanghai)。

## 2026-10-09 Asia/Shanghai：element 回调与嵌套记录清理

同一 AST owner 恢复 slots `+f0/+100/+108/+110/+118`，**282 个原生/Python 对照、
159 个保护/回滚**通过，两个基址各 141 项，全部合成。五个实际槽位与直接
element 析构在修改前取得六个行为 RED，修改后同一最小输入 GREEN。
F0 为零参数、追加 u32 零；element count/entry 预留/创建 184 字节记录。
记录读取 image+6e210 常量，table index/flags 截断 u32，结果含一项 u64 -1。
倒序搬移转移五组 ownership，保留 padding，发布后析构旧记录并释放旧 block。

`destroy_reader_ast_element_record` 恢复 +2cc2b8，先倒序释放 children、locals、
内嵌 type，随后通过 +2cc470 倒序清理拥有的 144 字节 nested records。每个
nested record 自有 type/locals/children。Element begin/end 与 data 使用同一
frame/raw/tree owner；保存起始字节长度至 +90，16 字节 frame、u32 patch、
libc++ 树删除及所有释放顺序与原生一致。原生临时栈析构自然执行，全部 free
对照；仅 guest ownership 的 destroy 事件与前 0xa000 guest 字节进入比较。

独立布局、image 常量、frame/raw 断言通过；159 项参数/所有权/预算/每次分配
失败均全页回滚，包含已经写入 active pointer 或第一处 raw patch 后的失败。
旧 AST 308/54、data 176/30、create 148/105、payload 104 AST/34 ABI/30 回滚、
expression 148/36 全部重跑，五份 JSON 逐字节一致。Parser owner 未改；其
nonempty element vector 的原生 abort 边界仍保留。完整 AST/reader/factory/
bootstrap、attached parser/wrapper、signer 与线上矩阵尚未完成。见
[element 证据](evidence/vm9_alternative_ast_element_fresh_20261009.json)与
[第 6.17 节报告](REQUEST_JNI_STARTUP_WORKERS.md#617-element-回调与嵌套记录清理2026-10-09-asiashanghai)。

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

## 2026-10-25：owning request callback ledger continuation

在完整 Python handoff 返回路径中持久化本次 VM 的 callback ledger。四项 fresh
facade→child→owning request controls 均记录 115 个 callback，ledger 由当前 staged
VM 生成并写入 diagnostic scope；首尾 wrapper/target、参数地址和四个 ABI words
可供下一次 callback continuation 直接定位。该 ledger 不是 native snapshot，也没有
把 Python trace 提升为 whole-native differential；JNI/JavaVM、physical ABI、真实
Android JVM、fresh standalone signer 和线上 acceptance 仍未验证。

证据：[callback-ledger handoff](evidence/vm9_java_request_handoff_fresh_20261025.json)。

## 2026-10-25：fresh native child→owning request dispatch preflight

复用已闭合的 fresh receiver/tree/iterator/mutex fixture，把 callback pair 的
synthetic host target 改为真实 `+0x2830c4`，直接执行 native `+0x27dd04`。
两个 image base 均进入真实 owning request VM `+0x2830c4 → +0x168324`，在
`+0x170308` 的 VM dispatch-table load 停止；`R_AARCH64_RELATIVE` slot
`image+0x3798d8` 指向 `image+0x13bb8f0`，该运行时表不在 fresh main PT_LOAD
pages 中。失败前 guest pages 保持不变，未调用 synthetic callback。

这确认了 whole-request native differential 的第一项真实 bootstrap 缺口，未合成
runtime table，也未把停止误报为 callback 成功。证据见
[evidence/vm9_request_native_dispatch_preflight_fresh_20261025.json](evidence/vm9_request_native_dispatch_preflight_fresh_20261025.json)。

## 2026-10-25：request VM relocation owner probe（只读）

新增两项 native owner probe，直接沿 `+0x27dd04 → +0x2830c4 → +0x168324`
运行，并在 `+0x3798d8` 等五个 relocation slot、所有 import、分配、native
memory read/write 和 unmapped 访问处记录事件。两个 image base 都加载同一个
`image+0x13bb8f0` relocation pointer；当前 probe 没有观察到 constructor/JNI 或
request 对五个 slot 的写入，也没有对外部 `image+0x13bb000` canary 页的实际读写。

进一步记录到 VM 会用该 pointer 经过地址运算得到 fresh main-image 内的有效
handler 读取地址，随后仍在 `+0x170308` 对 guest VM workspace 地址 `0xc`
失败。也就是说，现阶段不能把 slot pointer 直接等同于已读出的外部 dispatch
table；slot owner 与其内容来源仍未闭合。canary 只用于观察映射，未填充任何
handler，也没有把这次失败当作 request 返回或 signer 输出。

证据：[runtime table owner probe](evidence/vm9_request_runtime_table_owner_fresh_20261025.json)
及其 verifier `python/verify_vm9_request_runtime_table_owner_20261025.py`。

## 2026-10-25：VM handler 语义与失败寄存器来源（fresh）

在同一只读 probe 中增加六类关键 handler 的 opcode/寄存器语义记录：
`+0x1692fc`（64 位加法）、`+0x16db74`（有符号 32 位立即数加法）、
`+0x16e254`/`+0x16e41c`（值物化）、`+0x16f974`（带有符号偏移加载）和
`+0x17030c`（有符号 word 加载）。两个 image base 各记录 283 次 handler
语义事件，结果逐次显示相同的 VM workspace 布局。

失败前最后一次 slot 1 零结果不是外部 dispatch table 写入，而是
`+0x16f974`：源 slot 为 18，目的 slot 为 1，偏移为 0，实际操作地址为
`0x7000ee38`，该地址的 8 字节值为零，因此 slot 1 被写成 `0x0`。随后
`+0x170308` 使用 `x10=0` 与 `x11=0xc`，形成 guest read `0xc` 并停止。
这闭合了“零值由哪个 VM 操作产生”的当前边界，但没有恢复 VM 程序、缺失
workspace 输入或 dispatch table 内容，也没有把 canary/handler 观察当作签名成功。

证据仍为 [runtime table owner probe](evidence/vm9_request_runtime_table_owner_fresh_20261025.json)，
复现脚本为 `python/verify_vm9_request_runtime_table_owner_20261025.py`。

## 2026-10-25：零值 operand 的上游 native 写入（fresh）

继续沿同一次观察窗口追踪 `0x7000ee38` 的指针来源，发现 native
`+0x171268` 将 `0x7000ee38` 写入 `0x7000df38`，两基址的写入前内容均为
canary。随后 `+0x16f974` 读取 `0x7000df38` 得到该指针，再从
`0x7000ee38` 读取零并把零结果写入 VM slot 1。由此当前链条为
`+0x171268 → 0x7000df38 → +0x16f974 → slot1=0 → +0x170308 → read 0xc`。

这定位了 fresh workspace 中零值 operand 的 native 构造点，但没有说明真实
启动路径为何产生同样的 workspace 内容，也没有恢复 VM code、完整表或 signer。

同一事件序列还显示 pointer 的两个 VM producer：`+0x16f974` 从 slot 4 的
`0x7000d668+0x8` 得到 `0x7000ee38` 写 slot 1，稍后从 slot 29 的
`0x7000d840+0x6f8`（`0x7000df38`）得到同一值写 slot 18。随后
`+0x171268` 把 slot 1 复制到 `0x7000df38`，最终 slot 18 参与零偏移加载。

## 2026-10-25：request frame operand writers（fresh）

继续在同一只读 native request VM probe 中追踪 owning frame 对 VM workspace 的直接
写入。两个 image base 都得到相同的四项 frame-store 语义：`+0x2830ec` 将
`0x7000ee48` 写入 `0x7000d668`、将 `0x7000ee38` 写入 `0x7000d670`；
`+0x283100` 将 `0x138` 写入 `0x7000d680`；`+0x28310c` 将 `0x7000ee28`
写入 `0x7000d678`。这些结果补上了 slot 4 以及后续 pointer producer 使用的
frame operand 来源，并与两组 283-handler 序列一致。

这只是当前 fresh request frame 的 native store 证据，不等同于真实 JNI/Android
启动输入，也没有恢复完整 VM code、dispatch table 或 signer。内存写回调仍记录
写入前旧值；实际值以 frame-store `written_value` 和后续 workspace 读取为准。
证据：[runtime table owner probe](evidence/vm9_request_runtime_table_owner_fresh_20261025.json)，
复现脚本：`python/verify_vm9_request_runtime_table_owner_20261025.py`。

## 2026-10-25：same-CPU bootstrap → request runtime-table creator spike

新增只读 feasibility probe，在同一 Unicorn CPU 上先执行完整 13 项
`.init_array`/JNI bootstrap，再覆盖 fresh request 输入并继续真实
`+0x27dd04 → +0x2830c4 → +0x168324`。两个 image base 都进入 owning VM，
随后在 `+0x170308` 对 guest 地址 `0xc` 停止；两页 canary runtime region
没有读写，bootstrap→request 期间也没有 `mmap/mprotect/munmap/calloc` creator
调用（`pthread_create` 仅是已恢复 startup worker 服务）。

这说明当前组合执行仍未到达外部 dispatch table 内容读取，外部表 owner 仍在
更外层 loader/runtime state；不能把 canary、relocation pointer 或这次停止当成
真实表内容、请求成功或 signer。证据：[same-CPU runtime-owner spike](evidence/vm9_bootstrap_request_runtime_owner_spike_fresh_20261025.json)，
脚本：`python/verify_vm9_bootstrap_request_runtime_owner_spike_20261025.py`。

## 2026-10-25：零 operand 的 native 对象来源（fresh）

继续沿 `0x7000ee38` 追踪到对象 helper：`+0x15f5a8` 先将该 16 字节对象清零，
随后 `+0x15f5bc/+0x15f5c4` 从 `0x70001800` 和 `0x70001808` 复制源字段；两字段
在本次 fresh fixture 中均为零。`0x70001800` 正是 `dispatch.fixture` 的 URL
reference（`G+0x1800`），所以当前最终零值不仅能归因到 VM 的 `+0x16f974`，还
能追溯到 fresh direct-dispatch 输入没有提供 URL reference 内容。该证据解释了
为什么对象 pointer 已正确产生而其目标内容仍为零。

这闭合的是当前合成 fixture 的输入来源，不代表真实 Java/JNI URL 对象应为空，
也没有恢复真实启动输入、完整 VM code/dispatch table 或 signer。证据同一份
[runtime table owner probe](evidence/vm9_request_runtime_table_owner_fresh_20261025.json)，
复现脚本：`python/verify_vm9_request_runtime_table_owner_20261025.py`。

## 2026-10-25：outer runtime owner 静态 inventory

对真实样本的整个 `.text` 扫描五个 relocation slot 的短地址链写入，未发现
相邻 `ADRP/(ADD)/STR` 形式的 slot writer；同时确认 VM 入口通过五条
`ADRP #0x379000 → LDR X` 链在 `+0x16848c/+0x168570/+0x16ba18/+0x16c37c/+0x16cf90`
读取五个 slot；后续索引分别为 `w9 & 0x3f`、`(w21/w27/w26 >> 6) & 0x3f` 和
`(w8 >> 22) & 0x1f`，对应五组 VM dispatch base。另记录 39 个 loader-like PLT 调用点；
其中 `+0x184ad4` 由 `+0x18a314` 调用，静态路径包含 `dlopen`、`munmap` 和
`mmap`；其内部还经 `+0x27295c → +0x271d9c` 发起 syscall 222 的匿名映射，
再释放旧映射、重映射并复制段、`dlclose`，是当前最具体的自定义 DSO
映射/替换线索。same-CPU bootstrap→request 运行没有
进入该候选，因此它仍不是已确认的 dispatch-table owner。

同一静态扫描现在固化了候选调用前的参数链：`+0x18a30c` 读取
`[x23,#0x20]`，`+0x18a310` 再读取该对象的 `+0x40` 字段并将结果作为
`x0` 传给 `+0x184ad4`，即 `x0 = *(*(x23+0x20)+0x40)`。这只定位了
path field 的 native 入口边界；`x23` 对象的构造者、实际 path 值和 loader
执行时机仍未由静态证据闭合。

进一步把这条链向函数入口展开：`+0x189ecc` 保存初始 `x0` 到
`[x29-0xd8]`，`+0x18a008` 建立 `x23=x29-0x40`，`+0x18ab1c/+0x18ab20`
将保存的初始 `x0` 发布到 `[x23+0x20]`，因此候选 loader 的 path 参数可化为
`x0 = *(initial_x0 + 0x40)`。这仍是静态寄存器/栈数据流，不是运行时 path
值观察，也没有证明 `+0x184ad4` 在真实 Android 启动中执行；外部对象构造者、
custom mapping 和 runtime-table owner 继续保持未闭合。

证据：[outer owner static scan](evidence/vm9_outer_runtime_owner_static_scan_fresh_20261025.json)，
脚本：`python/verify_vm9_outer_runtime_owner_static_scan_20261025.py`。

## 2026-10-26：历史成功 unidbg 路径外部页观察

在历史成功的 `HookMain` signer 命令上加入默认关闭的
`runtimetablewatch=true` 观察器，覆盖 `0x13600000-0x13800000` 的真实读写，
并在首次访问时保存 `0x1367a000-0x1367f000`。该次运行使用固定 ELF、原有
冻结时间和同一请求 URL，正常到达 `DONE`，输出 `X-Argus/X-Gorgon/X-Helios/
X-Khronos/X-Ladon/X-Medusa`；观察日志为 **0 个读写事件**，没有首次访问 dump。

因此旧日志中的 `x13=0x1367b8f0` 只能说明一个历史寄存器值，不能说明这次成功
样本创建或读取了重定位 runtime table。没有合成页面、handler 或 relocation
内容；这仍是 unidbg 输出，不是 fresh standalone signer、whole-native differential
或线上 header acceptance。证据见
[unidbg runtime-table watcher](evidence/vm9_unidbg_runtime_table_watch_fresh_20261026.json)，
复现校验见 [verify_vm9_unidbg_runtime_table_watch_20261026.py](python/verify_vm9_unidbg_runtime_table_watch_20261026.py)。

## 2026-10-26：非空 URL reference 推进 request VM

只读 continuation probe 按 native 两字布局给 `G+0x1800` 写入 URL `char*` 与
refcount pointer，并固定 clock provider。两个 image base 都从 945 条推进到
45679 条，完成 285 个 VM handler、经过一次 `clock_gettime`，仍无外部 runtime
table read；因此 `+0x170308` 的 `read 0xc` 已确认是空 URL fixture 的边界，而非
runtime table 读失败。

路径随后在 `+0x2858a8` 的 callback-object trampoline 停止：对象
`0x7000e948` field 0 为 NULL，`+0x2858b4` 执行 `br x3` 到零。没有注入 vtable、
handler 或 signer 输出。证据见
[URL continuation](evidence/vm9_request_url_pointer_continuation_fresh_20261026.json)，
复现脚本为 [verify_vm9_request_url_pointer_continuation_20261026.py](python/verify_vm9_request_url_pointer_continuation_20261026.py)。

## 2026-10-26：真实 callback 的 memcpy import continuation

在同一只完成 JNI/bootstrap 的 Unicorn CPU 上继续非空 URL request。callback object
field 0 指向真实 ELF `image+0x347f60` memcpy PLT；探针执行标准三参数字节复制并
通过 `x30` 返回，保留原 bootstrap 已安装的 import hooks。两个 image base 均执行
**99927** 条 native 指令、记录 **194** 个 import 事件并回到 oracle STOP；输出
reference 两个 word 均非零，runtime-table canary 页面仍无读写。

这是 native continuation/return 边界的推进，不是 whole-request differential、fresh
standalone signer 或线上验收，也没有合成 callback vtable/dispatch table。证据见
[memcpy continuation](evidence/vm9_bootstrap_request_memcpy_continuation_fresh_20261026.json)，
复现脚本为
[verify_vm9_bootstrap_request_memcpy_continuation_20261026.py](python/verify_vm9_bootstrap_request_memcpy_continuation_20261026.py)。

## 2026-10-26：真实 APK/Java native-library provenance boundary

新增只读 provenance verifier，读取固定 `fq_7xz.apk`、反编译的 `p3.java`/
`h.java`/`o4.java` 和 pinned native DSO。APK 中的
`lib/arm64-v8a/libmetasec_ml.so` 与 `libmetasec_ml_71332.so` 均为 3,971,808
字节，SHA-256 均为
`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。源码特征
同时闭合了 `System.loadLibrary(name)`、`ApplicationInfo.sourceDir`/
`splitSourceDirs` 的 ABI-qualified ZIP 查找、私有 `lib` 目录解压和
`System.load(absolutePath)` fallback。

这只闭合了真实 `libmetasec_ml.so` 的 APK 来源和 Java loader 边界；没有证明
另一个 APK DSO 提供 `image+0x13bb8f0` 外部 runtime table，也没有恢复 custom
mapping/table owner。没有执行 synthetic loader 或写入 dispatch table。证据见
[DSO/Java provenance](evidence/vm9_dso_java_loader_provenance_fresh_20261026.json)，
复现脚本为
[verify_vm9_dso_java_loader_provenance_20261026.py](python/verify_vm9_dso_java_loader_provenance_20261026.py)。

## 2026-10-26：outer loader vtable 与 constructor provenance

对真实 ELF 的 `.rela.dyn` 与 `.text` 做了只读交叉校验：`0x34db08` vtable 的
`0x34db18` 槽是 `R_AARCH64_RELATIVE`，addend 精确为 `+0x189eac`；该方法内部
在 `+0x18a30c/+0x18a310` 读取初始对象的 `+0x40` 字段，再把它传给
`+0x184ad4`。同一 DSO 的 `+0x18ceb0` 真实 constructor 由 `0xb8` 分配路径进入，
先安装临时 `0x34db68` vtable，再安装最终 `0x34db08` vtable，并初始化
`+0x30` inner member。

该 constructor 的可观察写入覆盖 `+0x0/+0x8/+0x10/+0x48/+0x58/+0x60/+0x68`，
没有写入 loader 后续消费的 `+0x40` path field。进一步核对同一 vtable 的
`0x34db48` 槽，确认它指向 `+0x188ac0`；该方法从初始对象的 `+0x30` 成员和
辅助输入计算值，并在 `+0x189184` 写入 `[object+0x40]`。因此 native writer
provenance 已闭合，但该虚调用是否发生、运行时 path 值、custom DSO mapping、runtime
table、whole-request native differential、fresh signer 和线上验收仍未闭合。相邻 vtable
槽 `0x34db50 -> +0x189cbc` 还把同一 `+0x40` 当作 callable 消费，因此不能仅按偏移
把字段唯一命名为 path string；没有合成表、path 或 callback。证据：[loader vtable constructor](evidence/vm9_loader_vtable_constructor_fresh_20261026.json)，
脚本：[verify_vm9_loader_vtable_constructor_20261026.py](python/verify_vm9_loader_vtable_constructor_20261026.py)。


## 2026-10-26：callback-object field writer provenance

在同一只完成 JNI/bootstrap 的 Unicorn CPU 上继续 URL-bearing request，并保留真实
`memcpy` PLT 服务。两个 image base 都观察到 native VM 的 `+0x171268` 向
`0x7000e948` callback object field 0 写入 `image+0x347f60`；随后
`+0x2858a8/+0x2858ac/+0x2858b0/+0x2858b4/+0x2858b8` 五条桥接指令读取该
target，memcpy 完成后回到 oracle STOP。该轮没有写入 runtime dispatch page 或
callback vtable，确认的是这个 continuation 的 target-field writer 与 consumer
闭环，不是完整 signer callback-object graph、runtime-table owner、fresh signer 或
线上验收。证据见 [callback-object trace](evidence/vm9_bootstrap_request_callback_object_trace_fresh_20261026.json)，
复现脚本为 [verify_vm9_bootstrap_request_callback_object_trace_20261026.py](python/verify_vm9_bootstrap_request_callback_object_trace_20261026.py)。

该 writer 的 VM store ABI 也已记录：两个基址均由 `+0x171268` 使用 source slot
`x14&0x1f = 3`、base slot `x13&0x1f = 29`，以 `x17+x16` 指向 callback object，
并将 slot 3 的值写入 field 0；slot 3 值与 `image+0x347f60` 一致。这个结果把
target 从常量猜测推进到当前 VM slot dataflow 证据，但没有恢复完整 VM code、五组
外部 dispatch table 或 signer。

## 2026-10-27：actual outer child descriptor provenance

继续复用同一只 Unicorn CPU，把真实 outer cold getter 返回的 `root+0x18`
child 送入正常 facade，并在 `+0x2859cc..+0x2859dc` 的 descriptor bridge
保留寄存器、读写和 syscall ledger。两个 image base 都闭合出相同的参数写入：
`+0x171268` 用 `x15=0` 写 argument object `0x7000e738+0x00`，再用
`x15=0x13708000` 写 `0x7000e738+0x08`；随后 `+0x2859cc` 原样加载这两个
字段，`+0x2859dc` 对该 descriptor 执行 `br x3`。

`0x13708000` 位于 native syscall 222 返回的匿名零填充映射
`0x13700000..0x13740000` 的 `+0x8000`。在该 descriptor 的 `+0x00`、
`+0x08` 或其周边观察不到 target-field 写入；停止时 0x100 字节窗口全为零，
因此 `x3=0` 是当前 fresh continuation 的真实状态，不是 verifier 注入的 callback
target。进一步收窄 workspace 写入后，两个基址都在 `image+0x16e118` 观察到
`str x9, [x28, x12, lsl #3]`，当时 `x28=0x7000eba8`、`x12=1`、`x9=0`，
正好写入最终 source slot `0x7000ebb0`；这闭合了 slot 1 的 VM-handler provenance，
不把它解释成 fixture 保持零、缺失输入或 target 注入。该轮仍停在 `+0x2859dc`，
没有 cleanup/return、whole-request native/Python differential、fresh standalone
signer 或线上 header 验收。

证据：[actual child descriptor probe](evidence/vm9_native_outer_facade_actual_child_20261027.json)，
复现脚本：[verify_vm9_native_outer_facade_actual_child_20261027.py](python/verify_vm9_native_outer_facade_actual_child_20261027.py)。

## 2026-10-27：APK Java → native loader handoff provenance

补齐 APK 侧 `MSManagerUtils.init → g.c → n3.a → p3.a` 的真实调用链检查。
`g.c` 将应用上下文和 `metasec_ml` 交给 `n3.a`，`n3.a` 构造 `p3`，随后
`p3` 先走 `System.loadLibrary(name)`；失败时由 `h` 扫描
`ApplicationInfo.sourceDir` 与 `splitSourceDirs` 的 ABI-qualified ZIP entry，
解压到私有 `lib` 目录并调用 `System.load(absolutePath)`。固定 APK 的
`lib/arm64-v8a/libmetasec_ml.so` 与 pinned DSO 仍逐字节一致。

这闭合的是 Java 侧真实库来源和进入 native loader 的 handoff；它没有证明
native `+0x184ad4` 自定义 mapper 在本次启动执行，也没有填充
`0x13700000` descriptor、恢复 callback target 或定位 runtime-table owner。
因此 `+0x2859dc` 的零 target 停止和完整 signer 状态不变。

证据：[APK Java loader handoff](evidence/vm9_dso_java_loader_provenance_fresh_20261027.json)，
复现脚本：[verify_vm9_dso_java_loader_provenance_20261026.py](python/verify_vm9_dso_java_loader_provenance_20261026.py)。

## 2026-10-27：native facade result-source ledger

actual-child continuation 现在保留最终 facade frame 的受限栈写入 ledger：仅记录
facade 启动后、主 ELF PC、`0x7000ee50..0x7000ef00` result 临时区，两个 image base
各 42 条，已排除 outer/libc/深层 allocator 噪声。`+0x17ba6c` 的 native request
call 返回 `G+0x1e10`，该值在 `+0x17bac0` epilogue 保持不变；证据字段
`facade_result_source_verified` 为 true。`+0x27e804/+0x27e80c` 的 native
清理写入也在同一 ledger 中。

native facade frame 的对象图快照直接解析出一个配置树节点：counter=1，
`X-Neptune -> -11|50:51:59`。独立 observation-only output-reference continuation
则是 `X-Neptune -> -5|`；两条 continuation 的输入/guard/状态语义尚未闭合，
所以该差异只作为 whole-request differential 的定位证据，不能作为 signer 输出。

formatter ledger 将两个候选值定位到 request VM bytecode：`image+0xfb548` 产生
`-7`，`image+0xfefbc` 产生 `-11`，二者共享 `50:51:59` 时间字符串，最终树只
保留 `-11`。差异位于 VM 状态/字节码路径，不在 Java array 转换或 cleanup。

这闭合了 native result handle 的来源和 facade 返回边界，但 JNI/Java 仍由显式
fixture 提供，因此 whole-request native differential、真实 Android JVM、fresh
standalone signer 和线上 header acceptance 仍未验证。证据：
[vm9_native_outer_facade_actual_child_20261027.json](evidence/vm9_native_outer_facade_actual_child_20261027.json)；
脚本：[verify_vm9_native_outer_facade_actual_child_20261027.py](python/verify_vm9_native_outer_facade_actual_child_20261027.py)。

## 2026-10-27：formatter bytecode source-slot closure

对两个 `%d|%s` formatter 调用点做了真实 ELF 静态解码，并在同一轮 actual-child
continuation 中保存 formatter 前后的 VM 游标、字节码字和 32 个虚拟槽。`image+0xfb520`
的 `0x7f20f97b` 是 `OP59`：`R2 = sext32(R0) - 7`，随后在 `image+0xfb548`
调用 formatter；`image+0xfef94` 的 `0x7ea0f97b` 是同一操作但立即数为 `-11`，
随后在 `image+0xfefbc` 调用 formatter。两个 image base 都观察到候选点的 `R0=0`，
时间字符串由 `R3` 指向的同一 `50:51:59` 缓冲区提供；因此 `-7/-11` 差异来自
字节码路径内嵌的有符号立即数，不是 Java array、JNI 转换或外部输入槽差异。

动态窗口只保留候选窗口内去重后的 VM 游标事件，完整槽数组仍在证据 JSON 中保存；
实际-facade 路径的游标顺序为 `0xfb520 → 0xfb548 → 0xfb5dc → 0xfee00 →
0xfef94 → 0xfefbc`，因此 `-7` 与 `-11` 是同一次 continuation 中先后生成的
两个值，并非两个输入槽的二选一分支。独立 output-reference 的 `-5` 仍在
`0xf8404 → 0xf8554 → 0xf858c` guard 路径；该 guard 路径没有出现在 actual-facade
轨迹中。它用于复核槽来源，不把 `-11` 解释为已闭合的 signer 语义。最终树继续保留
`-11|50:51:59`，与独立 `-5|` output-reference continuation 的状态差异仍未闭合。
证据和复现脚本仍为：
[vm9_native_outer_facade_actual_child_20261027.json](evidence/vm9_native_outer_facade_actual_child_20261027.json)；
脚本：[verify_vm9_native_outer_facade_actual_child_20261027.py](python/verify_vm9_native_outer_facade_actual_child_20261027.py)。


## 2026-10-28：request entry ABI provenance closure

新增只读 ABI verifier，按真实 ELF 指令和 actual-child 动态 ledger 对照同一个
`+0x2830c4` wrapper 的两种入口。normal Java facade 在 `+0x27e6a8` 先从
`*(receiver+0x20)+0x08` 取 native header-vector 指针；本轮动态值为
`0x136d6100`，随后 `+0x283130` 将它放入 VM argument array 的 `+0x20`，再进入
`+0x168324`。`+0x168324` 的直接 `x3` 是独立的 image-relative dispatch 常量，
用户输入仍在 packed argument array 的 word 4。

独立 output-reference continuation 也到达 `+0x2830c4`，但入口 `x3=0x101`，
因此不能把 `0x101` 解释为 facade 的 header-vector 或把 `-5` guard 结果归因于
同一输入。该差异闭合的是 request ABI/provenance 入口，不是 signer 业务语义；
whole-request native differential、真实 Android JVM、fresh standalone signer 和
线上 header acceptance 仍未验证。

证据：[request entry ABI provenance](evidence/vm9_request_entry_abi_provenance_20261027.json)，
复现脚本：[verify_vm9_request_entry_abi_provenance_20261027.py](python/verify_vm9_request_entry_abi_provenance_20261027.py)。


## 2026-10-28：独立 output-reference 的 x3 生产者闭合

在 fresh output-reference continuation 中从 `+0x27dd50` 开始记录 x3 变化，确认
初始 request ABI 为 `x0=0x70001100`、`x1=0x70001800`、`x2=0x70001900`、
`x3=0x138`。后续在 `+0x27e470` 执行 `ldr x3, [x8,#8]`（下一条观测 PC 为
`+0x27e474`），当时 `x8=0x70002400`，读取 `[0x70002400+0x08]=0x101`，随后
`+0x2830c4` 入口保持 `x3=0x101`。两基址的动态轨迹一致。

这说明独立 `-5` guard continuation 的 `0x101` 是其 request 对象字段产生的输入，
不是 facade native header-vector、也不是 `-5` 的输出值；normal facade 则在
`+0x27e6a0/+0x27e6a4` 从真实 header-vector 取得 `x3=0x136d6100`。ABI 差异的
上游生产者已定位，但完整 signer 语义、whole-request differential、真实 JVM、
standalone signer 和线上验签仍未闭合。

证据：[output-reference rerun](evidence/vm9_request_output_reference_20261027_rerun.json)、
[request entry ABI provenance](evidence/vm9_request_entry_abi_provenance_20261027.json)。

## 2026-10-28：actual vector object writer provenance

在 actual outer child → normal facade 的同一只 Unicorn CPU 上新增受限 native memory-write ledger，
对动态观测到的 16 字节 vector object `0x136d70d0` 与 128 字节 header-vector
`0x136d6100` 记录写入地址、覆盖范围、写入前/后字节、绝对 PC、image-relative PC
和入口寄存器。两个 image base 的轨迹均闭合：vector object 记录 32 次写入，header-vector
记录 50 次写入；两对象都能与 continuation allocator ledger 的同址分配事件连接，分配
来源包含 `+0x246988`，并在后续复用路径出现 `+0x2548dc`、`+0x246a78` 和
`+0x32a210`。写入事件均发生在 facade 启动前，说明这些对象由 outer/初始化链构造，
不是 facade 或 verifier 注入。

证据见
[vm9_native_outer_facade_vector_writer_20261028.json](evidence/vm9_native_outer_facade_vector_writer_20261028.json)，
复现脚本仍为
[verify_vm9_native_outer_facade_actual_child_20261027.py](python/verify_vm9_native_outer_facade_actual_child_20261027.py)。
本轮只闭合对象分配与 native writer provenance；没有把对象字段解释成 signer 业务语义，
whole-request native differential、真实 Android JVM/JNI、fresh standalone signer 和线上 header
验收仍未闭合。

## 2026-10-28：vector publication 与最终分配 epoch

把地址历史按最后一次 `+0x32a210` operator-new 分配切开后，两个 image base 都闭合了
最终对象的发布链：16 字节 callback pair `0x136d70d0` 的最终分配由 caller
`+0x27d15c` 触发，128 字节 request context `0x136d6100` 的最终分配由 caller
`+0x27ccec` 触发；最终 epoch 内 pair 只有 `+0x27cd94` 的两次 8-byte store，
随后 `+0x27cd98` 读回 `[callable=+0x2830c4, context=0x136d6100]`。

ELF 静态检查确认 `+0x27cd94` 是 `stp x0, x19, [x8]`，`+0x27e69c/+0x27e6a0`
从 receiver+0x20 的 pair 取出 context，context vtable 的 `R_AARCH64_RELATIVE`
槽 `0x375050` 指向 `+0x35dc50`。动态检查在两个基址均通过：最终 pair store、
context vtable writer `+0x263fe4`、facade consumer `+0x27e6a4` 和 wrapper 输入全部一致。
因此 `0x136d6100` 当前应称为 native request context；它不是 Java array 或 signer
header 的语义证明。

新增的 `vector_publication_provenance` 与静态证据包含在
[vector writer evidence](evidence/vm9_native_outer_facade_vector_writer_20261028.json)；
这仍是对象生命周期/ABI provenance，不是六个七神 header 的完整生成或线上验签。
