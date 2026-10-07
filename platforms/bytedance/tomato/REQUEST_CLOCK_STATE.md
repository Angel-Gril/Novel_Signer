# 番茄请求时钟、140 字节状态、guard release 与 shared pointer getter

更新：2026-10-07。绑定 metasec SHA-256
`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`；
guard 对照绑定 matching-libc SHA-256
`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
私有样本、真实请求和凭证不随报告发布。

## 1. 本阶段结果与范围

新增 **82 个原生组件控制、18 个负控制**，并有 **4 个既有外层构造器回归**：
48 个时钟 target/wrapper、8 个 raw storage target/wrapper、6 个 guard release
和 20 个 shared pointer target/wrapper。
原 ELF 函数在 Unicorn 中执行，clock_gettime 是显式 status/sec/nsec 服务；
guard lock/unlock 执行 matching-libc。全部 payload `0xA000` 比较，相关 packed
slots 包含在该窗口；guard 额外比较全局 mutex 的 40 字节。
这些控制没有比较全部原生栈、TLS 或 image/OS 状态。

同次 owning allocator/request 组合的新边界为：

| image base | stop | 下一 callback |
| --- | --- | --- |
| `0x122c0000` | 945 / bytecode `+0xffb48` | `+0x285fb4 → +0x28dc38` |
| `0x775c205000` | 965 / bytecode `+0xf8fd0` | `+0x285a80 → +0x28bb5c` |

该组合通过精确 stop、回调顺序、clock 参数与副作用断言；不把未知 callback
当成请求成功。请求仍为 synthetic object，没有真实 URL/headers/JNI 转换。

## 2. 时钟 ABI、位宽与返回

`+0x28589c` 从 packed `+0/+8` 加载 target 和 start 地址，调用 `+0x291440`。
后者读取 `+0x3294b0`，把返回的 uint64 nanoseconds 写到 start[0]。
`+0x3294b0` 调 `clock_gettime(1)`，成功分支执行
`seconds * 1_000_000_000 + nanoseconds` 的 64 位 MADD；溢出按低 64 位保留。
这里的单位来自该样本原生指令，不能把另外使用 clock id 0 的 registry clock
混作此处 provider。

`+0x285f60` 调 packed target `+0x2914d0(start)`，将返回 word 写到 packed `+0x10`。
`+0x2914d0 → +0x291488` 先读取当前 clock，再读取 start[0]，执行 64 位 SUB，
随后 signed divide by 1000。因此结果为 **microseconds**；负数向零截断，
不能使用 Python 对负整数的普通 `//` 直接替代。Python helper 返回 signed int，
wrapper 写入时按 uint64 word 编码。

原生控制包括零、nanosecond 尾数、signed timespec ABI、MADD wrap、正负不足
1 microsecond、-1001ns、SUB 后的 int64 两端，以及 provider 内更新 start 的
读取顺序。负/超大秒数仅是 ABI 控制，未主张实际设备 monotonic clock 会产生
这些值。clock 错误走原生 abort；Python 对该路径及无效 timespec 明确拒绝。

调用示例：

```python
import vm9_callbacks as callbacks

start_word = callbacks.store_monotonic_start(
    pages, object_address=start_address, read_clock=session.read_clock)
elapsed_us = callbacks.elapsed_monotonic_microseconds(
    pages, object_address=start_address, read_clock=session.read_clock)
```

`read_clock(staged_pages, 1)` 必须返回 `(status, seconds, nanoseconds)`，成功
status 为 0，seconds 为 int64，nanoseconds 在 `[0, 1_000_000_000)`。
provider 接受沿 owning session 的 staged pages；helper 只承诺 guest 页事务，
不承诺外部 provider 的副作用回滚。

本次低基址两次 provider 返回 `(0, 1791023800, 500000000)`，elapsed 为 0。
这是显式固定 clock 输入的结果，**不是 Medusa f13 时间戳冻结实测**。
实际 Android OS clock 和在线请求尚未执行。

## 3. raw state 与外层对象

`+0x2859e0 → +0x32a330` 只对参数指向的位置清零 `0x8c`，即 140 字节。
末次 vector store 从 `+0x7c` 开始并与前面的 store 重叠，终点仍为 `+0x8c`。
它不写 vtable，也不额外写 `+0x94` flag。

```python
import vm9_objects as objects
objects.initialize_mutex_storage(pages, storage_address=raw_address)
```

既有 `construct_mutex_state` 对应 `+0x17d7e0`，仍写外层 vtable、调用同一
raw helper 清零 object+8，并清零外层 flag。这两种入口共享清零 owner，
保留各自 ABI；4 个低/高基址及跨页回归证明已有外层行为没有改变。
raw 控制使用非零 poison、前后保护窗口及跨页地址；未映射尾页拒绝且不改前页。

## 4. 无 waiter 的 guard release

`+0x28596c → +0x32d4f8` 使用 packed `+8` 的 guard 地址：先发布 guard[0]=1，
再锁 `image+0x3e2f40`，读取 guard[1] 并置为 1，最后解锁。若原 guard[1]
含 bit2，原生会 broadcast；本阶段仍拒绝这一分支。

```python
import vm9_startup as startup
startup.release_serial_guard(
    pages, guard_address=guard_address, image_base=image_base)
```

三个初始 byte/mutex 控制在两基址通过，比较 padding、global mutex 和 lock/unlock
顺序；原生与 Python 写顺序比较确认 byte0 在 lock 前、byte1 在 lock 内各发布一次。contended mutex
和 waiter/broadcast 负控制回滚 guest 页。没有实际 OS 线程、host 并发或 atomicity
实测。helper 没有业务返回值，该 wrapper 也不发布返回槽。

## 5. shared-reader pointer getter

`+0x2859ec` 调 packed target `+0x172ca4(receiver)`，将 uint64 返回值写到
packed `+0x10`。target 跳至 `+0x1727e0`：先调用 `+0x32a444` acquire，读取
receiver+0x90，再调用 `+0x17288c → +0x32a4fc` release，返回已读取的 word。

```python
pointer = objects.read_shared_state_pointer(pages, object_address=receiver)
```

这个 helper 复用已有 serialized shared-reader owner，不解引用返回的 pointer。
两基址的 target/wrapper 控制覆盖 NULL、普通 word、高地址、uint64 最大值与跨页
receiver；原生读字段时 reader count 已增加一，返回后恢复原 count，mutex
lock/unlock 顺序和完整 payload/packed 内存相符。writer 标记、saturated count
与 contended mutex 拒绝并回滚 guest 页；不主张真实 concurrent reader 行为。

同次高基址组合读取自然初始化的 raw state，没有注入 getter pointer fixture，
其 reader count 在调用前后为 0。此后继续到 `+0x28bb5c`，仍未进入之前的
`+0x256ed4` StringObject getter/formatter。

## 6. 请求接入、复现与证据用法

`execute_prefix` 增加 `read_clock=session.read_clock`；开头 store 和后面的 elapsed
使用同一 provider。无 allocator 的 bounded prefix 回归仍可使用传入的
seconds/nanoseconds 作为显式 clock fixture。新增参数不提供 URL/header 转换。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_clock_state_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_clock_state_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_prefix_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_prefix_callback_abi_fresh_20261007.json
```

[组件证据](evidence/vm9_request_clock_state_fresh_20261007.json) 证明本样本 clock
id/单位、wrapped subtraction、signed truncation、raw state 范围、serial release 与 shared pointer 读取顺序。
[同次组合](evidence/vm9_request_diagnostic_continuation_20261007.json) 证明这些组件
能沿同一 staging/allocator/clock 链推进到上述边界；6 个
[prefix 回归](evidence/vm9_request_prefix_callback_abi_fresh_20261007.json) 继续验证
32 slots、descriptor、decoded bytes 与 30 个 physical callback frame。
引用时须同时给出 sample hash、入口、输入和比较窗口；组件通过不能替代
whole-native outer/request 对照。

下一处低基址 `+0x28dc38 → +0x28dc40 → +0x28ddd0` 涉及字符串构造、格式化与
后续回调；当前 packed 的四个请求参数都为零，仍是合成输入。高基址
`+0x285a80 → +0x28bb5c` 是 boolean packed-output callback，其冷分支涉及
地址混淆的全局 decoded input 与后续 body，尚未恢复。已完成 pointer getter
不能替代这个 boolean callback，不能把未知返回直接填为成功。

matching-libc realloc 仍明确拒绝；本次组合没有 realloc 请求。完整请求返回、
真实 URL/headers/JNI、fresh Medusa、新线上全头矩阵、无 JVM Rust、非空搜索/分页、
抖音/起点闭环，以及最终 Pages/Actions 下载产品仍未完成。本阶段没有服务器
请求、签名输出或小说正文。
