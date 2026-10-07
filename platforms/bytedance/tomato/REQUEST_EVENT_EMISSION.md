# Warm 事件发布、所有权移动与请求 VM 返回

2026-10-07。本阶段恢复 `+0x28ff44` 的warm logger record-vector路径，并让
`+0x28ddd0/+0x28dc40` 完成发布后的caller清理。新增 **40个原生控制、14个
负控制**。同次 owning Python session 的低基址合成请求模型在
**957步 / +0xffb78 返回**，其状态已提交；高基址仍停于真实
`+0x26edc4` JNI acquisition。**完整独立Medusa、真实请求签名和线上闭环
仍未完成。**

样本 SHA-256：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。
matching-libc SHA-256：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
基址：`0x122c0000`、`0x775c205000`。

## 1. 恢复范围和实现 owner

[vm9_request_event.py](python/vm9_request_event.py) 的 `execute_event_emission`
处理warm singleton、四个C++字符串move assignment、normal mutex、record
追加/扩容/丢弃，以及临时record清理。
[vm9_cpp_strings.py](python/vm9_cpp_strings.py) 统一持有24字节string的move
assignment语义。[vm9_request_leaf_prefixes.py](python/vm9_request_leaf_prefixes.py)
接回发布owner，随后执行caller的三个C++string cleanup并返回。

使用 `image+0x3e1b08` 已有logger pointer；logger头部是normal mutex，
+28/+30/+38分别为96字节record vector的begin/end/capacity-end。
一个record包含四个24字节tagged C++string。
`image+0x3e1b20` bit0=1的另一发布路径仍拒绝；singleton=NULL的冷初始化
`+0x295de8` 也仍拒绝。warm emission不能作为通用冷singleton恢复证据。

## 2. 两种move语义必须区分

| 原生路径 | 作用 | 来源对象变化 |
| --- | --- | --- |
| `17f5bc → 180ce4` | move assignment：先释放destination原heap，再复制24字节 | 只清零前两个字节，保留其余22字节 |
| `2901d4` | move construction：四个string移入record或迁移旧record | 清零整个24字节来源object |

heap pointer、declared length和capacity tag作为对象字段移动，不重新分配
或复制heap payload。输入string被置空后，caller cleanup不再释放已经转交
record的heap。负控制拒绝self-alias和重叠object，避免把未恢复的alias语义
当作正常路径。

`+0x28ff44` 在entry SP-140+8构造96字节临时record，依次move输入。
原生和Python都保留move后来源object的未清零尾部；最终payload对照不mask
这些字节。append时临时record被move-construction清零，drop时临时record
仍保留tag/length/pointer，析构按第四、第三、第二、第一string顺序释放heap。

## 3. record vector与边界

已有count<=199时追加一条；count>=200时丢弃该输入，解锁后清理临时record。
原生控制分别验证199→200追加和200→200丢弃，不以固定成功返回替代。

有空位直接在end移入record；容量不足时：

1. 容量增长为 `max(2*old_capacity,count+1)`，分配capacity×96字节。
2. 先将新record放到新buffer的count位置。
3. 从后往前迁移旧record，清零其原object，heap payload所有权保持。
4. 更新logger vector并清理旧buffer；迁移后的旧string为空，不重复free其heap。
5. 解锁logger mutex，再析构临时record。

原生增长scratch是 **40字节**：四个vector pointer与logger capacity槽pointer。
它位于entry SP-140+68；后一个pointer在scratch+20。对照比较整个scratch，
包括迁移和cleanup后的最终值。先前只知道32字节vector布局不足以描述它。
显式模型上限为512个capacity slots；更大vector、异常geometry、contention
和输入与logger/vector/temporary的alias均拒绝。

同次启动默认logger已有一条96字节record；追加后分配192字节并释放旧96字节
buffer。两条record的旧内容、mode、29字节event JSON和辅助 `{}` 都通过断言。
请求分配总数为33、free记录为18；最后一次free是旧logger vector。

## 4. 组件对照与证据边界

| 控制 | 数量 | 验证内容 |
| --- | ---: | --- |
| 原始warm emission | 16 | 空vector/有空位/扩容、非空旧record、22/23字节边界、199/200、完整payload与scratch |
| 完整formatter/event wrapper caller | 12 | `28ddd0/28dc40`原始body自然返回；单条/双条错误事件/未采样、发布后清理 |
| C++ move assignment | 8 | destination原heap释放、inline/heap来源、完整24字节field及source尾部 |
| VM返回 | 4 | 原始dispatcher、`16a974`返回handler、`172440`epilogue及ret |
| 负控制 | 14 | 冷singleton/另一发布/contention/vector、数量/alias/SP、分配失败、错误VM退出 |

malloc/free由显式Effects提供，matching libc实际执行string imports和normal
mutex body；oracle memcpy/memset仍为显式字节服务。组件比较完整0xa000 payload，
并比较logger、临时record、增长scratch与相关全局页；没有payload padding mask。
全原生stack/TLS/OS、native X0 return ABI和实际matching-libc allocator等价
不在本批范围。支持路径的Guest页成功后提交；外部Effects失败不自动回滚。

## 5. VMExit不能一律当作原生return

当前request退出word为 `0x07c00791`：op17/sub30，选中slot31。
原生 `+0x16a974` 读取该slot，匹配caller保存的返回标记时才进入
`+0x172440` epilogue。解释器原先把sub30统一抛成VMExit；这不能单独证明
native返回。本阶段没有改写通用解释器，而是在request caller owner上验证
具体PC、匹配样本word和slot target。

[vm9_request_caller.py](python/vm9_request_caller.py) 的 `validate_request_vm_exit`
只接受 `image+0xffb78`，slot31必须等于当前caller sentinel。错误PC、word和
slot值均拒绝。四个原生控制用显式单指令fixture和matching ELF的dispatch
tables，两个基址×两个sentinel，实际执行 `168324 → 16a974 → 172440 → ret`。
它们验证返回条件，不是全原生request执行或X0返回值等价。

## 6. 同次startup/session结果

[组合证据](evidence/vm9_request_diagnostic_continuation_20261007.json) 使用同次
Python outer输出、owning allocator和已声明的虚拟OS/clock/JNI-publication服务，
没有native入口快照。startup的初始logger仍来自有界默认record模型；本批恢复
的是后续warm发布。请求输入仍是合成对象。

| 分支 | 当前结果 | 事务情况 |
| --- | --- | --- |
| 0x122c0000 | 957 / +0xffb78，slot31=0xdead0000，合成请求VM模型返回 | event callback返回，request页提交回owning session |
| 0x775c205000 | 965 / +0xf8fd0，真实JNI acquisition +0x26edc4拒绝 | 该callback的新增父事务不提交 |

低基址保留旧record，新增record包含mode `{"x0":0}`、event
`{"x1":0,"x2":0,"x3":0,"x4":0}` 和辅助 `{}`，logger最终unlocked。
x8输出是configuration-tree reference，初始refcount=1；**没有生成Medusa签名**。
此前synthetic路径的signed formatter仍为-5，不能据此宣称真实请求成功。

本批没有模拟 `+0x2830c4` caller全部physical epilogue、stack canary或原生
X0 ABI，也没有whole-native outer/request对照。低基址synthetic分支返回不代表
高基址/JNI、真实URL/headers或成功签名分支已经恢复。

## 7. 使用与研究引用

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_event_emission_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_event_emission_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

[组件证据](evidence/vm9_request_event_emission_fresh_20261007.json) 可以支撑具体
object move、heap ownership、record迁移/增长/drop、caller cleanup和return条件
的逆向结论。引用时须保留样本hash、输入、比较窗口和服务边界；不能拿组件
自然返回作为线上签名、API可用或小说正文成功的证据。

下一步是恢复真实`+0x26edc4`的TLS guard/environment对象、JavaVM GetEnv与
attach/清理分支，继续真实request转换及签名输出。无JVM Rust、非空搜索/分页、
抖音/起点与最终Pages/Actions下载产品仍未完成。
上一阶段见 [REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。
