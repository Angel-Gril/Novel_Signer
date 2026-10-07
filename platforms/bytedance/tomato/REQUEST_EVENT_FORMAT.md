# Request 五参数 formatter 与事件发布前导

2026-10-07。本阶段恢复 `+0x28e86c → +0x28e91c` 的144字节 formatter、
四个 borrowed uint64 参数和一个 borrowed signed-int32 参数，以及渲染、C++
string 转换、临时向量清理。新增 **22个原生控制、19个负控制**。
同次 owning allocator 请求组合推进到 `+0x28ff44`，**事件发布、完整 request
callback、fresh Medusa 签名和线上下载仍未完成**。

样本 SHA-256：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。
matching-libc SHA-256：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
基址为 `0x122c0000`、`0x775c205000`。

## 1. 原生 ABI、布局和默认格式

X0 为 format C-string pointer，X1..X5 为五个参数 pointer，X8 为 formatter
输出地址。原生 `+0x28ec40` 将四个 `+0x34da48` vtable 和最后一个
`+0x35f858` vtable 写入连续16字节 typed cells。基础对象64字节，五个 cells
占80字节；总大小144字节，不能使用单参数 mode 的80字节布局。

| offset | 内容 |
| --- | --- |
| +0 / +8 | 借用 format pointer / strlen |
| +16 / +24 / +32 | 参数 pointer 向量 begin / end / capacity-end |
| +40 / +48 / +56 | 64字节 token 向量 begin / end / capacity-end |
| +64 / +80 / +96 / +112 | uint64 typed cells：vtable 和借用 pointer |
| +128 | signed-int32 typed cell：vtable 和借用 pointer |

`+0x28ddd0` 将参数存放于 caller local 的 +50/+48/+40/+38/+34，
formatter 位于 local+58，144字节转换 buffer 位于 local+e8，输出 C++ string
位于 local+0。默认 `image+0x6ff77` 格式串为：

```text
{"x1":{0},"x2":{1},"x3":{2},"x4":{3}}
```

第五个 cell 仍会构造并进入参数引用向量；默认格式没有引用它。mode 单独
生成 `{"x0":...}`。受控 `{4}` 输入证明 signed-int32 槽也能按 live pointer
渲染；这不是默认格式新增了 x5 字段。

原生验证明确通过 `extra_registers` 设置 X5：现有 oracle 的 `REGS` 只有 X0..X4，
仅传入六项 arguments 会遗漏第六项。非零 mode 控制发现过该 fixture 问题，
修复的是 oracle 输入，随后非零 mode 和第五槽控制全部通过。

## 2. 索引、渲染和全局初始化

实现位于 [vm9_request_format_objects.py](python/vm9_request_format_objects.py)。
mode 与 event 共用 token/vector owner，保留各自的参数个数和 vtable 范围。
只接受 plain literal、单字符 decimal index `{0}`..`{4}`、空 spec、最多32个
64字节 token 和最多128字节 inline conversion。mode 仍只接受 `{0}`。
通用 grammar、brace escape、其他 index/spec、unknown vtable、allocation
failure 和 conversion buffer growth 均明确拒绝。

argument token 的 +24 保存 index。renderer 据此选择 pointer 向量中的
cell，并读取该 cell 保存的 live scalar pointer。uint64 的
`18446744073709551615` 保留 unsigned decimal；signed-int32 的
`0xffffffff/0x80000000` 分别输出 `-1/-2147483648`。构造后更改参数的控制
验证输出跟随新值，没有在构造时固定 scalar 或注入 JSON。

原生 `+0x1869fc` 初始化 unsigned 的 N/n/D/d；它和 signed renderer
`+0x28e9b4` 都调用 `+0x186c84`，即使 spec 为空也初始化六组
x/x-/X-/x+/X+/X 名称。双全局页比较发现 mode owner 之前未生成后六组
副作用；现已补齐，旧38个 mode 控制也增加 `+0x3d2000` 全页比较。
parser bracket/whitespace 和 radix lazy 名称继续由原有 owner 生成。

## 3. 分配、转换和清理

默认格式有9个 token；token vector 分配64/128/256/512/1024字节。
随后 reserve 40字节参数向量，构造另一个40字节临时引用向量，释放原
reserve，并移动临时所有权。最终引用 `formatter+64+16*i`。

默认全零 event JSON 为29字节：

```json
{"x1":0,"x2":0,"x3":0,"x4":0}
```

转换 buffer 仍为 inline；输出24字节 tagged C++ string 则分配32字节 heap
存储。原生 `+0x1b414c → +0x32aba0` 按 length 复制，输出补 NUL。
之后依次释放 token vector 和参数引用向量；临时分配全部清理，只留下
caller 拥有的最终输出 heap block。`+0x165b78` 又在 formatter 的首24字节
构造 `image+0x6e844` 的辅助 `{}` string，再进入 emission。

本批默认 caller 的完整前导原生实际执行，停止于 `+0x28ff44` 入口。
没有替换 emission 返回，也没有执行其 body 或调用后的三个 string cleanup。

## 4. 对照范围与负控制

| 控制 | 数量 | 比较内容 |
| --- | ---: | --- |
| 五参数 builder | 12 | 144字节 formatter、token 初始化字段、payload、全局页、分配/free |
| 原始 event caller 至 emission | 6 | 完整0xa000 payload、local+0..+177窗口、两个全局页、ordered Effects |
| 构造后更新参数 | 4 | 原生 renderer、live uint64/int32、144字节 buffer、payload、两个全局页 |
| 负控制 | 19 | grammar/index/spec/escape/数量、八处 allocation failure、vtable/selector/增长 |

builder token 有未指定栈 padding：所有 token 的 +4..7，literal 的 +44..47，
argument 的 +45..47。**仅 builder 比较排除这些字节**；实际差异数与位置
保存在证据中，不把 padding 当作语义字段或写回 Python。

**完整 event prefix 比较不排除任何 payload 字节**。临时块已清理，可比较
完整 payload；local 窗口还包含输出 strings、参数槽、formatter 尾部和
完整转换 buffer。两页 `+0x3d2000/+0x3e1000` 都作完整比较。

malloc/free 使用显式 Effects；matching libc 的真实代码执行 string imports；
oracle memcpy/memset 仍为显式字节服务。本批没有宣称 matching-libc allocator、
完整动态加载器、全原生 stack/TLS/OS 或未约定的 X0 返回 ABI 等价。
失败时 guest 页不提交，外部 allocator/OS effects 不因此自动回滚。

## 5. 同次启动与当前缺口

[同次组合证据](evidence/vm9_request_diagnostic_continuation_20261007.json)
使用 fresh Python outer 的 owning allocator/session，无 native 输入快照。
低基址已生成 mode、event 和辅助 strings，mode 五次临时分配与 event
临时向量均完成清理；请求 free 数为17，新 event 分配后缀为
64/128/256/512/1024/40/40/32。默认 event output 的 heap ownership 保留。

| 基址 | 外层 VM | 当前实际停止点 |
| --- | --- | --- |
| 0x122c0000 | 945 / +0xffb48 | event emission +0x28ff44 |
| 0x775c205000 | 965 / +0xf8fd0 | 真实 TLS/JNI acquisition +0x26edc4 |

mode 和 event formatting 子过程在父事务里完成；完整 callback 仍未返回，
整个新增父事务尚未提交。原生组件前导验证与 Python 同次启动组合是两种证据，
不能将其合称 whole-native outer/request 等价。

下一处 `+0x28ff44` 已静态定位到四个24字节 C++ string 的初始化/赋值，
`+0x290158` logger singleton、mutex，以及96字节 record vector 的插入/扩容。
此路径 body 尚未恢复。高基址的 TLS/JavaVM 获取仍不得用既有 env=0 stub
替代。真实 URL/headers/JNI、fresh Medusa 输出和新的线上矩阵仍未通过。

## 6. 复现与研究引用

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_event_format_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_event_format_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_mode_format_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_mode_format_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

[原生组件证据](evidence/vm9_request_event_format_fresh_20261007.json) 可支撑
formatter ABI/layout、index 分派、borrowed pointer 生命周期、unsigned/signed
区分、heap 输出与临时所有权转移的结论。引用必须保留输入、样本 hash、比较
窗口、padding 边界和显式服务说明。它不能支撑线上签名校验或完整下载结论。

无 JVM Rust、非空搜索与分页、抖音/起点闭环及最终 Pages/Actions 下载产品
仍待完成。上一阶段见 [REQUEST_MODE_FORMAT.md](REQUEST_MODE_FORMAT.md)。


## 7. 发布入口的原生受控探针

后续新增4个**仅原生探针**：两个基址各测试warm logger vector容量1和2，
输入已有一个内容为空的96字节record；新输入包含29字节heap event JSON。
原始`+0x28ff44` body在四个控制里自然返回。matching libc实际执行
uncontended mutex lock/unlock，allocator/free仍为显式Effects。

`+0x17f5bc → +0x180ce4`在这里执行move assignment：复制24字节object并
仅清零source的前两个字节，其余22字节保持；输入event JSON的heap pointer
原样进入新record。vector有空余容量时无分配/free；容量1时分配192字节，
移动旧record并释放原96字节vector。最终count/capacity都是2，旧空record
保留，JSON内容和heap pointer均通过断言。

[探针证据](evidence/vm9_request_event_emission_probe_20261007.json) 与
[复现脚本](python/verify_vm9_request_event_emission_probe_20261007.py) 已归档。
这是受控warm状态原生行为观察；**没有恢复Python emission owner，也没有
把受控singleton fixture称为同次自然启动状态或完整request callback**。
非空旧record、drop阈值、冷singleton、其他发布分支和完整回接尚待验证。
后续实现须遵循move ownership，避免在caller cleanup中重复释放已转交record
的heap存储。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_event_emission_probe_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_event_emission_probe_20261007.json
```
