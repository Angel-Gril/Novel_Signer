# Request mode format construction, rendering and cleanup

2026-10-07。本阶段恢复 `+0x28e788` 的有界完整模式路径：构造 formatter、token
与参数向量，读取 live signed-int32 参数，转换为 C++ string，清理临时对象。
新增 **38 个原生控制、14 个负控制**。同次 owning allocator 组合能生成
`{"x0":0}`，mode阶段随后在五参数 formatter `+0x28e86c` 明确停止；
后续恢复已推进至发布 `+0x28ff44`，见 [REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。
**完整 request callback、独立 Medusa 签名和线上下载仍未完成。**

样本 SHA-256：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。
matching-libc SHA-256：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
两个基址为 `0x122c0000`、`0x775c205000`。

## 1. 恢复范围与原生依赖

实现 owner 为 `python/vm9_request_format_objects.py`。原始 ELF 的以下函数体
在组件预期侧实际执行，没有替换成固定 JSON 或固定返回：

- `+0x28f0f4/28f16c`：CString view、formatter 初始化、typed 参数槽、指针向量移动。
- `+0x187310/296b54`：格式串/token 向量构造与参数向量 reserve。
- `+0x1875bc/187710`：临时参数引用向量构造、释放旧 destination、移动所有权。
- `+0x1b40d4/295528/28e9b4`：inline buffer 与 signed-int32 渲染。
- `+0x1b414c/32aba0`：按长度复制为24字节 tagged C++ string。
- `+0x1b4320/186780`：inline 转换对象检查、token/参数向量清理。

原生 string imports（包括 strlen、memchr、__strlen_chk）重定向到 matching libc
实际代码；malloc/free 为显式 Effects，memcpy/memset 为 oracle 字节服务。
本批不是完整动态加载器、matching-libc allocator 或全原生栈/TLS/OS 等价证明。
同次组合另外使用已有 owning Python allocator 模型，不把组件 Effects 当作该实现。

只接受本路径已恢复的 plain literal / `{0}`、单个 borrowed signed-int32 参数、
128字节以内 inline conversion。其他 index/spec、brace escapes、unknown vtable、
修改过的 parser/radix/renderer 常量、vector/output 超界及 allocation failure
均拒绝。通用格式化语法、多种参数类型和扩容仍未恢复。

## 2. formatter 的80字节布局与分配轨迹

`+0x17d6b8` 保存 C-string pointer 和 strlen；NULL pointer 的长度为0。
formatter 的布局为：

| offset | 内容 |
| --- | --- |
| `+0/+8` | 借用 format pointer / length |
| `+16/+24/+32` | 参数引用向量 begin / end / capacity-end |
| `+40/+48/+56` | 64字节 token 向量 begin / end / capacity-end |
| `+64/+72` | int32 vtable `+0x35f858` / 借用参数 pointer |

token 向量按1、2、4、8…元素扩容，每个元素64字节。新元素先写入新 block 的
末尾，旧元素再复制到前部，最后移动 owner 并释放旧 block。参数向量先 reserve
8字节，再构造临时8字节指针向量；`+0x187710` 释放 reserved destination，
然后移入 temporary owner。

fresh `{"x0":{0}}` 有三个 token：literal prefix、index0 argument、literal suffix。
完整路径的 malloc 顺序是 `64 → 128 → 256 → 8 → 8`，free 顺序是旧64、旧128、
reserved8、最终token256、最终argument8。本批 full mode 控制结束时所有临时
block 已释放；输出 string 均为 inline 表示。

parser 会发布 bracket/whitespace 的两组 lazy 名称，以及 radix detection 的
`0x/0X/0b/0B/0o` 五组前缀。render 会发布 `N/n/D/d` 四组 selector。它们的
flag=0时解码并发布1，warm 非零 flag保留。即使当前参数为0，也必须恢复这些
初始化副作用；不能只写最终 JSON。

## 3. token 字段与 padding 的证据边界

renderer 消费 token 的 tag、literal pointer/length、index、width、style、fill
和 spec pointer/length。对当前分支，literal tag=2、argument tag=1，argument
index=0、width=0、style=2、fill=ASCII space、spec为空。

原生64字节 token 中有未指定的栈 padding：所有 token 的 `+4..7`；literal
的 `+44..47`；argument 的 `+45..47`。原生复制这些字节时可能带入旧栈值，
它们不能作为已恢复的字段，也不应从原生观测写回 Python。

**12个 builder 控制仅排除这些未指定字节。** 其他初始化字段、80字节
formatter、unused vector capacity、全局页和分配/清理轨迹均比较。JSON 记录
具体排除窗口和实际差异字节数，明确设置
`full_unmasked_builder_payload_equivalence_claimed=false`。

**22个完整 mode 控制不排除 payload 字节。** 临时 block 清理后，比较全部
`0xA000` payload、24字节输出 string、144字节转换 buffer、80字节 formatter
及全局页；原生完整 mode 函数自然返回。原生整个栈和未约定的 X0 返回 ABI
仍未比较。该证明只覆盖声明的 mode 分支。

## 4. 参数化与转换

uint32 ABI 输入通过 renderer 的 signed load 解释为 int32：

| 输入 | 输出 |
| --- | --- |
| `0` | `{"x0":0}` |
| `0x7fffffff` | `{"x0":2147483647}` |
| `0x80000000` | `{"x0":-2147483648}` |
| `0xffffffff` | `{"x0":-1}` |

参数槽保存 pointer，没有在构造时保存 scalar 快照。另有 **4个原生转换控制**：
先使用已单独原生对照的 builder fixture，构造后将0改为uint32_max，或将
uint32_max改为7，再执行原生 `+0x1b40d4` 与独立 Python renderer。结果跟随
更新后的参数，完整 buffer/payload/global page 对照通过。

转换对象是144字节：pointer 指向自身+16，length/capacity 分别为两个uint32，
capacity初值128，后接128字节 inline storage。按 token 顺序追加 literal 与
signed decimal，最终 C++ constructor 按 declared length 复制并补 NUL。
不将 Python 预制 JSON 注入 guest；文本来自已生成的 token 和参数引用。

## 5. 同次启动请求链

[当前组合证据](evidence/vm9_request_diagnostic_continuation_20261007.json) 使用
同次 outer/session 输出和真实 owning Python allocator，未提供 native 输入快照。

低基址链已贯通 `28dc38 → 28ddd0 → 28e788 → 28f0f4 → 1b40d4 → 1b414c`，
生成 inline `{"x0":0}` 并完成五次临时分配的清理。请求 free 记录从5增加为10，
新增 malloc request 后缀为64/128/256/8/8。下一调用为五参数 `+0x28e86c`：
format pointer `+0x6ff77`，四个uint64 parameter pointer和一个int32 pointer。
本阶段未恢复该函数，不继续写入其输出对象。

高基址仍在 `28bb5c → 28b05c → 26edc4` 的真实 TLS/JNI 获取处停止。原生
`26edc4` 的依赖包括 `34377c` emulated-TLS、`17caac` JavaVM GetEnv，以及冷启动
构造/析构注册；没有把既有 env=0 stub 当作恢复证据。

外层仍为945/+ffb48和965/+f8fd0。mode 子过程在父事务内完成；随后缺少
五参数 formatter 导致整个 event callback 的新增父事务不提交。完整 callback
尚未返回，whole-native outer/request 等价未验证，真实 URL/headers/JNI 尚未通过。

## 6. 复现、负控制和研究用途

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_mode_format_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_mode_format_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

[组件证据](evidence/vm9_request_mode_format_fresh_20261007.json) 包含12个 builder、
22个完整 mode、4个 late parameter 控制和14个负控制。负控制覆盖index/spec/
escapes/超界、五处 allocation failure、修改后的parser/radix/renderer 常量、
unknown vtable和inline growth。失败时 guest 页不提交；外部 Effects/OS 服务
副作用不能据此视为自动回滚。

本证据可用于说明具体 formatter layout、token 字段、借用 pointer 生命周期、
signed int32 ABI、向量移动/清理，以及独立参数化构造 JSON 的有效性。引用时须
保留样本hash、输入、比较窗口、padding排除和显式服务列表。
此前前导阶段见 [REQUEST_LEAF_PREFIXES.md](REQUEST_LEAF_PREFIXES.md)。

fresh Medusa 签名、新的线上全头矩阵、无 JVM Rust 下载链路、非空搜索与分页、
抖音/起点闭环和最终 Pages/Actions 产品仍未完成。本阶段没有服务器请求、
线上签名或小说正文。


## 2026-10-07 后续：event format 与扩大全局比较

五参数formatter已由另22个原生控制/19个负控制恢复；当前同次组合的低基址
停止点为`+0x28ff44`。本页第5节记录mode阶段的历史边界。event的双全局页
对照还发现signed renderer调用`+0x186c84`会发布六组hex selector，现已
补齐到mode owner，并扩大本页38个mode回归的全局比较到`+0x3d2000`。
详见 [REQUEST_EVENT_FORMAT.md](REQUEST_EVENT_FORMAT.md)。完整callback与签名仍未完成。


## 后续：warm发布与当前返回边界

后续warm event emission已由40个原生控制/14个负控制恢复；低基址同次
owning session的synthetic请求VM模型在957/+ffb78返回，event callback
及request页状态已提交，record数2、33 allocations/18 frees。高基址仍
965/+f8fd0的真实JNI `26edc4`。本页旧停止点属于其阶段历史；完整Medusa
签名与whole-native request仍未通过。详见
[REQUEST_EVENT_EMISSION.md](REQUEST_EVENT_EMISSION.md)。
