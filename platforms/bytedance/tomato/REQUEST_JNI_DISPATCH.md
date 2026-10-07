# JNI dispatcher、异常处理与 Long 转换

> 验证日期：2026-10-07。对象为本仓库所研究的 `v7.1.3.32` ELF 样本。
> 已验证的是受控服务下的原始 ARM64 函数/Python 组件对照；完整独立 Medusa 尚未完成。

## 1. 本轮结果与样本边界

后续2026-10-08的14个caller组合及四条原生cold once完成观察见
[REQUEST_JNI_COLD_ONCE.md](REQUEST_JNI_COLD_ONCE.md)。本报告保留此前96/27及once1停止点。

关闭 verifier 的 dispatcher oracle stub 后，新增 **54 个原生/Python 对照和10个负控制**：
30个 `+0x26E70C` dispatcher、20个异常 helper、4个 actual TLS acquisition→dispatcher 组合。
另新增 **34个 Long 转换对照和11个负控制**。后续cache mutex构造又增加 **8个对照、6个负控制**（第7节），本轮累计96/27。
两条原始 JNI_OnLoad 入口观察单独计数：
它们执行 actual dispatcher 后停在 `+0x270854` 前，**Python 完整 bootstrap 对照数为0**。

样本 SHA256：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`。
matching libc SHA256：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
原生 oracle 通过 Unicorn 执行这些样本中的实际 ARM64 body；JNI/JavaVM/OS/allocator
服务仍为明确的受控输入，没有运行 Android JVM，也没有访问线上接口。

验证起点为调用者构造的 guest 页、重定位 ELF 和 fixture，未使用 native 入口前导快照。
首次运行时原生 dispatcher/Long body 能执行，Python 分别因缺少 `invoke_java_dispatch` /
`convert_java_long` 报 AttributeError；实现后对照通过。这两次初始 RED 不计入负控制。

## 2. Dispatcher 与异常的实际语义

`+0x26E70C` 在获取环境前保存五个输入：前两个仅保留低32位，后三个保持64位。
它调用实际 TLS 环境获取 `+0x26EDC4`，然后检查 encoded class/method 存储。
默认解码后的存储位置为 `+0x3DEEB8/+0x3DEEC0`；两者非空才经 `+0x26E944`
调用 live JNI table 的 `0x398`（CallStaticObjectMethodV）。已知方法签名为
`(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;`，本轮只恢复其整数参数 ABI。

- NULL environment 直接返回0，不访问 JNI table。
- class或method缺失时跳过 static call，但仍执行两次异常处理。
- `+0x27184C` 调用 ExceptionCheck `0x720`，仅检查返回值低8位。
  非零则按 ExceptionOccurred `0x78` → ExceptionClear `0x88` → DeleteLocalRef `0xB8` 顺序执行。
  exception reference为NULL时仍调用 DeleteLocalRef。
- 第一次检查发现异常时，dispatcher 把返回引用改为0；没有补造原代码不存在的 returned-object 删除。
- `+0x26F258` 独立执行第二次 ExceptionCheck，必要时 ExceptionClear。
  第二次异常不会再次改变已选择的返回引用。
- 每次 JNI 调用重新读取 live env table；提供替换 table 的控制验证了这一点。

设 dispatcher 入口 SP为 `S`：

| 观察位置 | 地址/大小 | 比较内容 |
|---|---|---|
| 环境获取/helper入口 | `S-0x70` | TLS owner消费的实际入口位置 |
| environment output pair | `S-0x68` | 获取服务写入的env/context；不比较该pair的物理栈窗口 |
| 五个GP save slots | `S-0x108` / 40字节 | 两个低32位整数及三个原始64位word |
| copied va_list | `S-0xE0` / 32字节 | stack/gr_top/vr_top/gr_offs/vr_offs |
| original va_list | `S-0xB8` / 32字节 | 与原始 helper 的两份结构一致 |

两份 va_list 的字段分别为 `S-0x70, S-0xE0, S-0x110, -40, -128`。
128字节SIMD save、canary、FP/LR和全部物理栈均未恢复或比较；不得把此 helper 当成任意
浮点 JNI 签名的实现。对照包含整数高位/符号位、NULL env/class/method/object、两次异常、
low-byte-zero、NULL exception reference、live vtable 替换和 encoded cache 地址重定位。

## 3. Long 转换与缓存

`+0x270854` 无论 cold/warm 都先检查三组 lazy-decode flags，再判断 env是否为NULL：

| source → destination | mask | flag | 解码结果 |
|---|---|---|---|
| `+0xA5828 → +0x3DEF6C` | `+0xA5A1C` | `+0x3DEF7C` | `java/lang/Long` |
| `+0xA5854 → +0x3DEFA8` | `+0xA59E8` | `+0x3DEFB4` | `longValue` |
| `+0xA5860 → +0x3DEFB8` | `+0xA59E4` | `+0x3DEFBC` | `()J` |

正确的 cache 地址如下，注意 `3DF` 与后续偏移的位数：

- mutex object pointer：**`image+0x3DF0A8`**，实际 mutex 位于 `pointer+8`。
- cached global class：**`image+0x3DF0C0`**。
- cached method ID：**`image+0x3DF0C8`**。

class/method均非空时跳过锁和查找。否则构造 `SP-0x70` 的 lock scope，调用 matching-libc
uncontended normal mutex body，在锁内重新检查缓存；仍缺失时执行 FindClass，经
`+0x26F154` 保留其 global reference 并发布 class，再调用 JNI `0x108`
GetMethodID(longValue, ()J)，发布 method。`+0x15F778` 清理 scope并释放其保存的mutex。
Python支持串行、无竞争、成功锁状态；竞争、错误状态和缺少mutex明确拒绝。
锁内缓存发布的控制使用显式注入事件，不是宿主多线程竞争证明。

class/method就绪后，`+0x224FF8` 调用 live JNI `0x1A8`（CallLongMethodV）。
本函数即使 object reference为NULL也会把它传给服务；它没有异常检查，本实现也未添加。
返回值保留原始64位word；服务应按该 ABI 返回uint64，调用者需要时自行解释其有符号值。

`()J` 实际消费零个 variadic 参数。原 caller 把 object放在X1和X3，因此本轮比较它的
冗余8字节 GP spill及两份32字节va_list；其余四个未消费的GP寄存器、SIMD/canary/FP/LR
不比较，也不在Python中补造值。此 helper 不实现任意 variadic JNI 签名。

34个控制覆盖两基址和17种 profile：cold/warm、只缓存class/method、NULL env/object、
FindClass/global/method失败、已有global、live table替换、shared normal mutex、全部/部分
warm decode、锁内复查发布、零返回值和64位全1。比较fresh guest前`0xA000`、全部主ELF页、
实际消费的variadic窗口、lock scope、JNI顺序和返回值。mutex对象/全局指针由fixture提供，
**这34个组件对照未执行其全局构造与发布**；后续构造对照见第7节。

11个负控制覆盖无效输入/栈、缺失/竞争mutex、缺JNI服务/function、溢出返回、未支持的锁状态
和最后Long服务拒绝。失败时 guest页保持不变；已经发生的外部JNI服务效果不会回滚，晚期
拒绝控制专门验证了这一限制。

## 4. 同次原始 JNI_OnLoad 前缀

扩展此前 cold-TLS verifier 的 `--through-dispatch` 模式。两种基址均在同次原生调用中经过：

```text
JNI_OnLoad +0x27B41C → publication/initializer → cold call_once
→ +0x165658 → actual TLS acquisition → +0x26E70C/+0x26E944
→ +0x27184C/+0x26F258 → caller +0x1656B4 → 停在 +0x270854 前
```

实际va_list五个word为 `[0x1000000E,0,0,0,0]`，四次GetEnv，六次malloc大小仍为
`[128,16,39,16,24,23]`。JNI服务返回明确的opaque object handle；观察到caller把
`[env,该handle]` 传给Long转换入口。once `+0x3D1570` 仍为1。

136/320 reference、emulated-TLS全局/OS keys仍为预初始化输入，当前线程TLS slot从空开始。
这个模式没有 host continuation，没有执行 dispatcher旧stub，没有执行Long转换。
边界处正确地址的cache mutex/class/method均为0。不能把另外的34个Long组件对照接算成
这两条原始入口已经完成Long/once/bootstrap，也没有向已有owning-session请求注入探针VM/env。

## 5. 研究API与复现

[vm9_jni_environment.py](python/vm9_jni_environment.py) 新增的主要入口：

```python
invoke_java_dispatch(pages, *, image_base, entry_stack_address, argument_words,
                     acquire_environment, invoke_jni)
convert_java_long(pages, *, image_base, entry_stack_address,
                  environment_pointer, object_reference, invoke_jni,
                  lock_mutex=..., unlock_mutex=...)
```

`acquire_environment` 接收pages及 keyword-only `entry_stack_address/output_pair_address`，
写入真实消费的env/context pair；可组合已恢复的 `acquire_thread_environment`。
`invoke_jni(pages, function_address, argument_tuple)` 是显式服务，不构造 Android 类或对象。
`convert_java_long`要求cold cache下已有有效mutex对象；它不在缺指针时绕过锁或生成替代对象。
另提供异常helper及两个限于已知签名的variadic frame helper，全部边界见源码docstring。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_dispatch_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_dispatch_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_jni_long_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_long_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cold_switch_tls_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --through-dispatch --output platforms/bytedance/tomato/evidence/vm9_jni_cold_switch_dispatch_fresh_20261007.json
```

不加 `--through-dispatch` 时保留此前停在`+0x26E70C`前的观察。`native()`新增
`real_jni_dispatch=True`开关；默认旧stub用于旧对象测试的兼容回归，不能用于实际getter证据。

机器证据分别为 [dispatcher](evidence/vm9_jni_dispatch_fresh_20261007.json)、
[Long转换](evidence/vm9_jni_long_fresh_20261007.json) 和
[原始入口前缀](evidence/vm9_jni_cold_switch_dispatch_fresh_20261007.json)。
受影响回归通过：旧对象92/13、JNI初始化56/9另6入口探针、publication54/11另4探针、
TLS/JavaVM环境40/14；前面的计数格式为“对照/负控制”，原始入口观察不混入组件计数。

## 6. 如何引用及下一步

这批证据可证明本hash版本的参数截断、live JNI table消费、两次异常处理差异、具体引用清理、
Long字符串/缓存/锁内复查、64位返回和受控原始入口到达的位置。引用时保留样本hash、基址、
fixture/services、比较窗口和边界；不要只引用“通过”或将不同组件拼接成完整执行证据。

cache mutex构造来源已在后续第7节恢复；下一步将该构造和Long转换接回同次fresh启动，
再验证caller释放返回object、cold once完成及后续actual startup VM。真实全局TLS/OS/arena
启动、完整请求返回和真实URL/headers/JNI转换仍需继续。fresh Medusa、新的线上全头矩阵、
无JVM Rust、搜索非空/分页、抖音/起点闭环和最终Pages/Actions下载产品仍未完成。


## 7. 后续：`.init_array +0x271940` 的 mutex 构造已恢复

直接检查本hash ELF的13项`.init_array`后，定位到`+0x271940`。原始body顺序为：

1. `+0x32A1F0` 分配48字节，经 `+0x15DEA8`、flag0构造normal mutex对象。
2. 将其地址发布到 `+0x3DF0A8`；class/method等已有cache字段保持不变。
3. 在 `+0x3DF118` 原地构造另一48字节normal mutex对象。
4. 尾调用 `__cxa_atexit(+0x165388, image+0x3DF118, image+0x34C700)`。
   这里只注册inline对象的析构，未补造allocated cache对象的析构/free；原始body不检查
   注册返回值。非零返回控制证明状态不会导致本构造器拒绝或回滚已发布对象。

`initialize_java_cache_mutexes(pages, *, image_base, allocate, register_exit)` 已实现以上顺序。
`allocate(pages, 48)` 与 `register_exit(pages, fn, object, dso)` 为显式服务；构造布局复用
已验证的normal mutex owner。返回allocated/inline对象地址及32位注册状态。
它不是完整ELF loader、allocator boot或OS退出实现，也没有执行`+0x165388`析构body。

新增 **8个原生/Python对照、6个负控制**。两基址各覆盖cold、预置class/method cache、
非零注册返回值和替代分配地址；比较guest payload、全部主ELF页、allocation/registration
顺序参数与构造器返回状态。native执行真实`+0x271940`及matching-libc mutex init；
不使用native入口前导快照。NULL/unmapped allocation、缺服务、溢出注册状态和晚期服务
拒绝均明确拒绝且guest页不变；allocator/注册服务的外部效果仍不自动撤销。

该验证同样先观察到原生body返回、Python因缺少函数报AttributeError，随后实现并通过。
它与第4节的两条原始入口观察分别执行。第4节没有执行本构造，因此其cache指针仍为0、
once仍1；不能把本节组件对照拼成同次原始JNI_OnLoad已经完成Long/once的证据。
下一步把本构造、dispatcher、Long和object cleanup接回同次fresh启动，再进入actual startup VM。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cache_mutex_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_cache_mutex_fresh_20261007.json
```

- [cache mutex构造验证器](python/verify_vm9_jni_cache_mutex_fresh_20261007.py)
- [8/6机器证据](evidence/vm9_jni_cache_mutex_fresh_20261007.json)
