# 番茄请求字符串 callback：比较、格式化、guard 和 ELF 输入依赖

更新：2026-10-07。本报告绑定的私有 metasec 样本 SHA-256 为
`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`，matching
libc 为 `d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
二进制、实际设备资料和线上请求均不在仓库内。

本轮完成了此前两个请求停止点的正常路径：C-string 相等性 callback 和
`%d|%s` 格式化 callback。新增 **56 个原生对照、11 个负控制**；同次 Python
outer/request 组合低基址推进至 **919 / +0xffae0**，高基址推进至
**793 / +0xf87bc**。组件对照与外层组合必须分别引用：后者仍不是整个原生请求
对照，请求输入仍是合成对象，没有真实 URL/headers/JNI 或 Medusa 输出。

## 1. callback ABI 与 owner

| wrapper → target | 行为与输出 | Python owner |
| --- | --- | --- |
| `+0x2858ec → +0x24880c → +0x247374` | object+8 的字段与 C-string 做完整相等性检查；wrapper 将布尔结果写到 packed+0x18 的单字节 | 复用 `vm9_configuration_init.string_equals_cstring` |
| `+0x285990 → +0x248908` | packed+8 为目标 StringObject，+0x10 为 format，+0x18 的 W2 为第一个变参，+0x20 为第二个变参 | 扩展 `vm9_configuration_init.format_string_object` 的 `%d` 子集 |
| `+0x28591c → +0x2484b8` | 析构 getter 临时字符串；释放 payload、重置字段，保留对象本身 | 复用 `vm9_objects.destroy_string_object` |
| `+0x285944 → +0x32d3a0` | serial guard acquire；wrapper 将 W0 写到 packed+0x10 | `vm9_startup.acquire_serial_guard`，复用已有 guard transition |
| `+0x2859cc → memset PLT +0x347f20` | destination / uint8 fill / uint64 size 来自 packed；当前请求清零 160 字节 | request callback 中的显式 PLT memory service |
| `+0x2859a8 → +0x248344` | 从 guest C-string 构造 StringObject | 复用 `vm9_objects.construct_string_object` |
| `+0x2859b8 → +0x25bf3c` | 转移 key/value 所有权，创建 pair 并插入配置树 | 复用 `vm9_registry.insert_configuration_pair` |

这些 offset 只适用于上述样本。callee、wrapper、输出槽和 native ABI 不能混用。
配置树当前组合只覆盖新 key 的插入；其他 cleanup descriptor 或重复 key 分支仍受
原 owner 的拒绝规则约束。

### 相等性检查不是排序比较

`+0x247374` 依次检查字段指针、C-string 指针、payload 指针和 int32 length。
原生内部结果是 -1（无效）、0（不等）或 1（相等）；`+0x24880c` 返回“结果 > 0”。

读取每个位置时先读 C-string 字节，遇到 NUL 立即不等，不再读该位置的 payload；
只有全部 declared-length 字节相同，且 C-string[length] 为 NUL，才相等。因此
`b'ab\0cd'` 和同样内存字节的 C-string 不相等，prefix 与较长字符串也不相等。
不能复用配置树的排序 comparator 来实现它。

### signed `%d` 与 native 返回值

无长度修饰的 `%d` 从 GP 变参槽消耗 signed int32。模型使用：

```text
raw32 = ABI_word & 0xffffffff
value = raw32 - 0x100000000  if raw32 >= 0x80000000  else raw32
```

当前 wrapper 还会以 `ldr w2` 丢弃更高 32 位。`%s` 每次 formatter 重试都从 live
mapped guest 输入读到首个 NUL；`%%` 不消耗变参。仅 `%d/%s/%%` 已实现，width、
precision、unsigned 及其他 conversion 拒绝。缺参数、NULL `%s`、无效 uint64 ABI
word 和输出超限也拒绝；没有完整实现通用 printf。

`+0x248a8c` 调用 `+0x246d7c` 清理临时字段，成功路径显式将 W0 置零；所以 native
格式化函数成功返回 **0**。Python helper 返回目标对象地址以供上层使用，
这不是 native X0 的模型。验证器分别断言二者，并比较实际对象与副作用。

### guard 的实际状态与边界

`acquire_serial_guard` 使用 actual global mutex 地址 `image+0x3e2f40`：

1. guard[0] 的整个字节非零时返回 false，不碰 mutex；不是只检查 bit0。
2. 否则进入无竞争 normal mutex；guard[1] == 1 时不获取初始化权。
3. 冷路径用显式 uint32 thread id 写 guard+4，guard[1] 置 2，返回 true。
4. 释放 global mutex，保留 guard padding；本轮 acquire 不等于后续 guard release。

递归/等待中的 guard、缺少或溢出的 thread id，以及 contended/global 非正常 mutex
均拒绝且不发布 staged guest 页。没有模拟真实 OS 线程或等待。组件 oracle 执行
matching-libc 的真实 mutex，gettid 则使用明确的测试服务。

## 2. ELF `memset` 的 NULL target 纠正

高基址早期在 bytecode `+0xf879c` 读取到 NULL target。指令追踪表明
`+0xf877c` 从 `image+0x382c80` 加载函数指针；原 ELF 在这个槽有：

```text
r_offset = 0x382c80
r_type   = 257  (ABS64)
symbol   = memset
addend   = 0
```

该槽的文件初值为零，relative-only fixture loader 尚未绑定这个外部符号。
这是一处明确的 loader 输入依赖，不是 Medusa 算法产生 NULL 的证据。

`resolve_request_memory_imports` 从 matching ELF 的 `.rela.plt` 和 `.plt` 推导
memset/memcpy 的 PLT 地址，再解析 257/1025/1026 类型的对应符号。共 **35 个
重定位槽**绑定到两个显式服务：`memset +0x347f20` 和 `memcpy +0x347f60`。
槽 `+0x382c80` 由真实 relocation 定义绑定；没有填写 captured/native 输出。

这只提供受控研究 fixture 的 memory imports，不是完整 Android dynamic loader。
PLT memory service 与真实 matching-libc `vsnprintf` 的证据范围不同；其他未恢复
imports/callback 继续拒绝。resolver 保留 `_PageTransaction` 链，不能复制页后
绕过 owning allocator 的 OS 状态。

## 3. 对照矩阵与比较范围

| 组 | 数量 | 控制与比较 |
| --- | --- | --- |
| C-string equality target / wrapper | 32 | 两 image base；空串、相同、prefix、提前 NUL、嵌入 NUL、负 length、NULL payload/source；布尔槽及 0xA000 字节 payload |
| signed format wrapper | 14 | 两基址；-5、0、int32 极值、忽略高 32 位、截断重试/realloc、转义百分号 |
| serial guard wrapper | 10 | 两基址；冷状态、byte0/byte1 completed、非零 byte0、shared normal mutex；全部 guard/padding、global mutex 和 gettid ledger |
| 拒绝/回滚 | 11 | 未知格式、缺参数、NULL `%s`、超限、无效 ABI word；递归/等待 guard、缺少/溢出 thread id、contended mutex |
| outer prefix 回归 | 6 | 两基址 × 三 flag/clock profile；32 virtual slots、callback descriptor、30 个 physical frame 入口和解析出的 memory imports |
| same-session continuation | 2 | 单独检查低基址的 getter/format/cleanup/tree 与高基址的 equality/guard/memset；都停在未知 callback |

format oracle 执行 matching-libc 的真实 `vsnprintf`，malloc/realloc/free 使用彼此独立
但规则相同的显式 Effects。比较有序分配/释放/realloc/wake、live allocation、释放前
bytes、payload 0xA000 字节、已加载主 image 页、TLS 0xB00 字节，以及 generation
0x800 字节的观测窗口。不要把窗口比较扩大成整个 OS/TLS 状态已证明。

重试控制覆盖了非空目标的 realloc；这证明调用顺序和显式服务契约，**不证明
matching-libc realloc 实现**。主组合使用真正的 owning allocator 模型及其 free；
低基址本次增长走 malloc/copy/free，reallocation 请求数为零。进入其他 realloc
路径仍会由 session 明确拒绝。

## 4. Python 调用与复现

`execute_prefix` 的相关额外输入为：

```python
state, frame, vm, ledger, decoded = execute_prefix(
    staged_pages, request_inputs, vm_full, seconds, nanoseconds,
    allocate=session.allocate,
    reallocate=session.reallocate,
    free=session.free,
    prepare_format=session.prepare_format,
    diagnostic_scope={"thread_id": session.thread_id},
)
```

调用前用 `resolve_request_memory_imports(staged_pages, matching_library, image_base)`
解析上述限定 imports。pages 必须沿 owning session 的原事务链；URL/headers/JNI
转换不由这些函数提供。`session.reallocate` 仍明确拒绝，不能替换为不记录旧块状态的
简单 malloc。helper 的 guest 回滚也不承诺外部 provider 副作用回滚。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_string_callbacks_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_string_callbacks_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_prefix_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_prefix_callback_abi_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

证据分别在 [组件差分](evidence/vm9_request_string_callbacks_fresh_20261007.json)、
[外层前缀/PLT 输入](evidence/vm9_request_prefix_callback_abi_fresh_20261007.json) 和
[同次 composition](evidence/vm9_request_diagnostic_continuation_20261007.json)。
之前的 getter 字段/返回证据见 [REQUEST_NESTED_VM.md](REQUEST_NESTED_VM.md)。

## 5. 本字符串阶段边界与如何引用关键证据

| 加载基址 | 本字符串阶段 stop | 下一 callback |
| --- | --- | --- |
| `0x122c0000` | 919 / `+0xffae0` | `+0x285f60 → +0x2914d0`；原生经 `+0x291488` 做时间差，再 signed divide by 1000；时间单位和 clock/provider 需继续核对 |
| `0x775c205000` | 793 / `+0xf87bc` | `+0x2859e0 → +0x32a330`；原生连续写零覆盖 140 字节状态；应分清 raw state 和外层对象 constructor |

低基址本次形成长度 11 的 `%d|%s` 字符串、清理 getter 临时 payload、插入一对配置。
高基址相等性为 false，随后 cold guard acquire 与 160 字节 memset 完成。两者都是
合成 request 上的 Python composition；分支差异仍未获得 whole-native 对照。

在逆向分析中，应把 sample hash、wrapper/target、输入类型、有序副作用和相应
证据 JSON 一起引用。这样可独立证明 int32 位宽、NUL/length 行为、native/helper
返回差别，并区分未解析 ELF import 与未恢复 callback。不要用单次“无异常”、
resolver 填槽或字符串摘要证明线上 signer 完成。

完整 request 返回、真实 URL/headers/JNI、fresh Medusa、新线上全头矩阵、无 JVM
Rust、非空搜索/分页、抖音/起点闭环与最终 Pages/Actions 产品仍未完成。本轮没有
服务器请求、真实正文或签名输出；不同平台仍按独立目录与证据维护。

后续 clock/raw state/guard release 已继续推进这些边界；最新 stop 与证据见
[REQUEST_CLOCK_STATE.md](REQUEST_CLOCK_STATE.md)。上述字符串控制的范围不变。
