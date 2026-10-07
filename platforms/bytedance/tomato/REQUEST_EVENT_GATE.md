# 番茄请求事件、boolean gate 与 C++ 字符串

更新：2026-10-07。私有 metasec SHA-256：
`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。
本阶段原生组件使用匹配 ELF 与 fresh guest 输入；不加载 JVM 或捕获内存。

## 1. 当前结果与验收边界

新增 **76 个组件控制、10 个拒绝/回滚控制**通过：52 个 C++ 字符串构造/复制/
析构，16 个 boolean gate，8 个事件包装。后两类执行原生外围函数，但 evaluator、
scope cleanup 和事件 formatter 是明确的测试服务，**未执行这些叶函数的原生
body**。因此这是有界调用编排的对照，不能描述成完整 callback、request 或 signer。

同次 owning allocator/request 组合已调用这些模型，产生下一层的输入，并在未恢复
叶函数处拒绝。外层步数保持原值，没有把 callback 的内部阶段计成新 VM 步数：

| image base | 外层 stop | 已恢复的内部前导 | 下一处缺口 |
| --- | --- | --- | --- |
| `0x122c0000` | 945 / `+0xffb48`，`+0x285fb4 → +0x28dc38` | 两个 event 名称、C++ string 构造和首个 clone | `+0x28ddd0` 事件 formatter |
| `0x775c205000` | 965 / `+0xf8fd0`，`+0x285a80 → +0x28bb5c` | encoded 全局、时钟/scope、参数槽与 counter%74 分支 | `+0x28b05c` boolean evaluator；随后还需 `+0x28c09c` scope cleanup |

未知叶函数导致模型事务不提交。报告的 `supported_prefix_staged` 表示观察到的
受支持前导；`body_transaction_committed=false` 表示这些新增页变化没有发布到
原请求页。诊断 observer 读取同次 Python 暂存页，不把 native 输出写回模型。
外部 clock 等 provider 的调用记录仍存在，guest 回滚不承诺回滚任意外部副作用。

## 2. 24 字节 C++ string ABI

`vm9_cpp_strings.py` 只拥有本阶段 C++ 字符串布局，与 vtable/capacity/length/
pointer 的 Medusa StringObject 分开：

| 入口 | 行为 |
| --- | --- |
| `+0x165b78 → +0x32aba0` | 从 C-string 取得 length，再构造 |
| `+0x32aba0` | length<23 时 tag=length*2，bytes 从 object+1 开始；否则 capacity=(length+16)&~15，写 capacity|1、length、payload pointer |
| `+0x32a9c4` | short source 复制全部24字节，包括 padding；heap source 按 length 生成目标，复制 length+1，包括源 terminator |
| `+0x32aa70 → +0x32a264` | tag bit0 非零才释放 object+0x10 的 payload；不清空 object |

控制覆盖长度0/1/22/23/31/65、tagged heap 转 inline，以及 poison padding。
原生 allocator/free 与 Python 使用独立的显式 Effects；比较 payload 全部0xA000
字节、有序 allocator/free 和 live block 状态。未证明 matching-libc allocator。

```python
from vm9_cpp_strings import construct_cpp_string, clone_cpp_string, destroy_cpp_string

construct_cpp_string(pages, object_address=destination, source_address=source,
                     allocate=allocator)
clone_cpp_string(pages, object_address=copy, source_object_address=destination,
                 allocate=allocator)
destroy_cpp_string(pages, object_address=copy, free=release)
```

constructor/clone helper 返回 object address 供 Python 使用；原生 X0 可在不同
路径保留 object、inline payload 或 heap payload。这组不比较 native 返回 ABI，
不能把 helper 返回等同于 X0。NULL allocation、过长输入和 native length-error
路径拒绝；guest 页事务不保证 allocator 外部状态回滚。

## 3. `+0x28dc38 → +0x28dc40` 事件包装

wrapper `+0x285fb4` 从 packed+8/+0x10/+0x18/+0x20 取得四个 raw word，
`+0x28dc38` 将第五个 W4 固定为0。直接 `+0x28dc40` 还可接受非零 mode。
两条 lazy decode 的 destination/flag 为 `+0x3e1990/+0x3e19a4` 与
`+0x3e19b0/+0x3e19c4`；原样本的 event 名称是 `http_sign_gen_all` 与
`http_sign_gen_error`，这些是内部标签，不是可调用 URL。

若 S 为 target 入口 SP，first/second/first_copy/second_copy 位于 S-0x90、
S-0xb0、S-0xd0、S-0xf0。模型先构造两字符串，clone first 并调用 formatter；
随后按原生顺序清理 clone。非零 mode 再 clone second、格式化、清理，最后
析构原 second 和 first。该样本两 literal 为 inline，组合没有额外分配。

```python
from vm9_request_event import execute_request_event
result = execute_request_event(
    pages, image_base=image, entry_stack_address=target_sp,
    argument_words=(x0, x1, x2, x3), emit_error_event=0,
    allocate=allocate, free=free, format_event=formatter)
```

`formatter(pages, cpp_object, x0, x1, x2, x3, w4)` 对应 `+0x28ddd0`；这里
它仅是显式叶接口，缺失时停止。native 控制使用独立服务比较传入参数、128字节
C++ local窗口及全局页，mode0/1/7和非零warm flag 均通过。完整事件包装的
native 返回 ABI 未比较。后续 formatter 内含采样分支、格式化框架与对象转换，
仍须按原指令恢复；不能用写入一条固定文本替代。

## 4. `+0x28bb5c` boolean gate

`resolve_boolean_gate_addresses` 从原 ELF 的 encoded table 读取12个角色，并用
本函数地址计算 offset 解码。两个控制基址解析的地址角色一致：first/second 名称
在 `+0x3e1628/+0x3e1634`，counter 在 `+0x3e1620`；解码 guard 为32位非零检查。
间接目标分别为 scope constructor `+0x28c088`、evaluator `+0x28b05c` 和
scope destructor `+0x28c09c`；不匹配样本的 target layout 拒绝。

前导读取 clock id1，保存 start，然后 `+0x28c088` 将 start pointer 和一字节
active flag 写到 scope。boolean local 初始0，两个名称的参数槽按实际顺序填入。
原生条件为：

```text
invoke_evaluator = (counter % 74 == 0) or (receiver[1] != 0)
```

counter 在这里不递增。调用时 X0 是两个 first-name pointer 的 descriptor，
W1=2，X2 是 second-name pointer；结果取 raw ABI word 的 bit0。跳过时 local
仍为0。随后把 boolean 写到 receiver+1，调用 scope cleanup，再返回 boolean。
16个原生控制覆盖cold/warm、counter0/1/73/74/75、receiver字节0/1/2以及
raw返回0/1/2/3/uint64最大值，并比较调用顺序、96字节初始化local和全局页。

```python
from vm9_request_boolean_gate import execute_boolean_gate
result = execute_boolean_gate(
    pages, object_address=receiver, image_base=image,
    entry_stack_address=target_sp, read_clock=read_clock,
    evaluate=evaluate, leave_scope=leave_scope)
```

`evaluate(pages, descriptor_address, 2, second_name_address)` 与
`leave_scope(pages, scope_address)` 是显式组件服务。当前同次 request 没有提供
假的默认值，自然 counter=0、receiver[1]=0 仍进入未恢复 evaluator 并拒绝。
函数地址、clock和参数槽由当前页推导；不是从 native capture 注入。

`+0x285a80` wrapper 为target增加16字节SP帧，外层VM物理SP公式仍由此前prefix
证据约束。target S=caller_stack-0x190；事件tail-branch target S=caller_stack-0x180。
整个 outer/request 原生分支对照尚未完成。

## 5. realloc 验证纠正

此前格式化控制 `truncation_retry_and_realloc` 实际 realloc_calls=0，走的是
malloc/copy/free。旧 verifier 还把 `+0x347fe0` 误当 realloc hook；原 ELF `.plt`
解析显示这里是 **memcmp**，真正 realloc 在 **`+0x348320`**。此前文档称该控制
已经覆盖 realloc 的表述不成立。

现已更名为 `truncation_retry_and_growth`，纠正 hook 并增加
`forced_destination_realloc`：目标capacity=8/length=8，两个基址各触发并断言
**1次显式 realloc**。完整格式化控制由14增加至16，字符串/格式化/guard 总数
由56增加至58，11个负控制保持。新的 JSON 保存 hook 来源、实际 calls 和计数。
该证明仅涵盖组件 Effects；owning session 的 matching-libc realloc 仍拒绝。
本次请求组合 realloc 请求数仍为0。

## 6. 复现与证据用途

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_event_gate_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_event_gate_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_string_callbacks_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_string_callbacks_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

[组件证据](evidence/vm9_request_event_gate_fresh_20261007.json) 可用于证明C++布局、
受支持路径的padding/所有权、counter与receiver条件、parameter槽及leaf调用顺序。
[组合证据](evidence/vm9_request_diagnostic_continuation_20261007.json) 证明可从
同次outer/session独立生成受支持内部前导，并保留未提交/未完成边界。
[格式化纠正证据](evidence/vm9_request_string_callbacks_fresh_20261007.json) 提供
ELF import 与实际强制realloc控制。引用须带sample hash、入口、输入、窗口和
显式服务列表；这些都是研究组件，不能用于声称当前下载器已经可用。

完整 fresh Medusa、线上全头矩阵、真实URL/headers/JNI、无JVM Rust下载链路、
非空搜索/分页、抖音/起点闭环与最终Pages/Actions产品仍未完成。本阶段没有
服务器请求、签名输出或小说正文。
