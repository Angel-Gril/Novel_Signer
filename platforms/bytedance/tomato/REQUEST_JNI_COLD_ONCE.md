# Cold JNI getter、对象清理与 once 完成

> 本机验证日期：2026-10-08（Asia/Shanghai）。样本仍为此前`v7.1.3.32` ELF。
> **14个caller组合对照、4个负控制、另4条原生启动前缀观察通过；完整独立Medusa尚未完成。**

## 1. 已贯通什么

本轮将此前分别验证的cache mutex构造、JNI初始化、实际TLS环境获取、dispatcher、
Long转换和returned-object清理放进同一组fresh输入的连续执行中。新增Python owner
`initialize_cold_java_switch`恢复`+0x165658`的整个caller body。

两类证据必须分别计数：

| 证据 | 数量 | 原生路径与比较边界 |
|---|---:|---|
| caller组合差分 | 14 | 实际`+0x271940 → +0x26E19C → +0x165658`，两个显式driver continuation；Python运行对应构造/初始化/caller |
| Python负控制 | 4 | 无效栈、缺环境获取、缺JNI、晚期对象删除拒绝；guest页回滚 |
| 原始JNI_OnLoad前缀观察 | 4 | 实际ctor→原始JNI_OnLoad→cold once→getter/Long/cleanup→startup入口前；一个显式driver continuation |
| 完整Python bootstrap对照 | **0** | 尚未验证所有ELF constructor、JNI_OnLoad、once wrapper及startup VM的整段Python等价 |

两种基址为`0x122C0000/0x775C205000`。样本SHA256为
`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`，matching libc为
`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`。
原生oracle执行实际ARM64 body，`+0x26EDC4/+0x26E70C`两个legacy stub均关闭。
输入由ELF/重定位及fixture生成，没有使用native入口前导快照。

## 2. Caller的实际顺序与API

`+0x165658`为cold once initializer实际调用的caller：

1. 入口SP为`S`，进入`S-0x50`栈帧，以`S-0x48`为env/context output pair调用TLS acquisition。
2. 保存第一份outer env；NULL时直接离开，switch word保持原值。
3. 以固定五个word`[0x1000000E,0,0,0,0]`调用实际dispatcher。dispatcher独立再次获取env。
4. dispatcher返回引用非零时，用**保存的outer env**调用`+0x270854` Long转换。
5. 将返回的完整64位word写到`image+0x3D1578`，然后用同一outer env调用DeleteLocalRef。
6. 返回引用为NULL（包括dispatcher第一次异常将其清零）时跳过Long/store/object cleanup。

Long方法查找失败时转换返回0，caller仍把0写入switch word并删除returned object。
这与NULL returned object时保持旧word不同。未添加原始代码没有的额外对象删除。

```python
initialize_cold_java_switch(pages, *, image_base, entry_stack_address,
                            acquire_environment, invoke_jni)
```

`acquire_environment(pages, *, entry_stack_address, output_pair_address)`写入实际消费的pair，
可接已恢复的`acquire_thread_environment`及其TLS/JavaVM/析构provider。
`invoke_jni(pages, function_address, argument_tuple)`仍为显式服务。
返回诊断结构包括outer env、object reference、可选written switch word、是否删除object；
**这不是原始void caller的全部物理返回ABI，也不是Medusa签名。**

14个对照为两基址×7种profile：cold零值、cold bit0x200、NULL object、缺Long method、
dispatcher异常、warm TLS高位64位值、两次获取返回不同env。最后一项为受控服务输入，
证明Long/cleanup保留outer env，而static call及其异常检查使用dispatcher env；
不把这种fixture描述成真实JVM线程生命周期。

## 3. 组合验证的内存与栈生命周期

比较fresh guest前`0xA000`、所有主ELF页、单独的JNI table页、caller output pair，
以及allocation、VM/TLS、JNI、exit registration各自的参数/顺序。
两个显式driver只连接constructor的exit注册返回点和JNI initializer的返回点，
不跳过任何getter、Long或cleanup body；Python用相同初始fixture顺序调用对应owner。

两份va_list及参数在JNI**实际消费时**验证：static call比较两份32字节结构和五个GP参数，
Long call比较两份结构及其冗余object spill。JNI事件及这些参数与Python一致。
`()J`未消费的四个GP word、SIMD、canary、FP/LR和全部物理栈仍不比较。

初始组合验证发现：缺Long method时，后续retention/lookup函数会覆盖先前query的临时
variadic栈区。将函数结束后的这一区域当成仍有效输出，会制造错误差异。因此没有屏蔽
live参数的差异，而是把比较点放在实际JNI消费处，终态只比较仍有效的caller pair。

先观察到原生组合caller返回、Python缺少`initialize_cold_java_switch`报AttributeError；
实现后14个对照通过。4个负控制均保持guest页不变。晚期DeleteLocalRef服务拒绝时，
包括已写switch word的父事务回滚，已经记录的外部JNI效果仍保留；页面事务不能撤销
真实provider的分配、引用或OS效果。

## 4. 原生cold once已完成，仍未执行startup VM body

四条额外观察在同一次native execution中自然完成ctor、原始JNI_OnLoad中的publication/
JNI初始化、cold call_once、getter、Long和object清理。ctor→JNI_OnLoad之间有**一个显式
host driver continuation**；不能将它当成完整Android loader或全部.init_array自然执行。
JNI_OnLoad定义符号的`+0x375010` GLOB_DAT绑定来自实际ELF，而非旧getter oracle。

每种基址分别给Long服务返回0和`0x200`：

| 受控Long word | once`+0x3D1570`终态 | switch word | 停在入口前 |
|---|---|---|---|
| `0` | `0xFFFFFFFFFFFFFFFF` | `0` | `+0x28040C` |
| `0x200` | `0xFFFFFFFFFFFFFFFF` | `0x200` | `+0x2A0028` |

同次执行有四次GetEnv，七次分配大小`[48,128,16,39,16,24,23]`；第一个48字节为cache mutex。
其指针由实际constructor发布，class/Long method也由实际lookup/caching发布。
最后一次JNI事件为DeleteLocalRef(outer env, returned object)。没有预设once为完成态，
也没有用snapshot或old dispatcher stub制造返回。

初次探针在`+0x3485A0`的broadcast边界明确拒绝；恢复后重定向到matching-libc的实际
pthread_cond_broadcast body。它更新`+0x3E2EE0`的u32 condition counter为4，再执行
syscall98、`FUTEX_WAKE_PRIVATE=129`、count=`0x7FFFFFFF`。OS wake provider明确提供
“无等待者，返回0”边界；没有把整个broadcast当成不改内存的成功stub，也没有证明宿主
并发或真实等待者调度。

136/320 references、emulated-TLS全局和OS keys仍为显式warm输入；当前线程TLS slot从空开始。
allocator、JavaVM/JNI、OS key、exit registration、clock/decimal等服务仍为fixture。
**此处证明原生cold once前缀完成，不证明完整Python JNI_OnLoad、真实全局OS/arena冷启动、
Android JVM或fresh请求签名。**两个startup VM body均未执行。

## 5. 复现、证据与关键用途

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cold_once_fresh_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_cold_once_fresh_20261008.json
```

`--probes-only`只运行四条native启动观察，生成的证据caller对照/负控制数均为0；
不要把该模式的输出当成14/4验证证据。受影响回归通过：cache constructor8/6、
Long34/11、dispatcher54/10、JNI initializer56/9另6入口观察。

- [新验证器](python/verify_vm9_jni_cold_once_fresh_20261008.py)
- [14/4及四条前缀机器证据](evidence/vm9_jni_cold_once_fresh_20261008.json)
- [Python JNI owner](python/vm9_jni_environment.py)
- [此前dispatcher/Long/constructor报告](REQUEST_JNI_DISPATCH.md)

这份证据可以用来定位switch word的来源、区分NULL对象与零Long结果、证明object ownership
清理和两个env的消费关系、确认call_once终态及bit0x200的实际startup分支。引用时保留
样本hash、fixture、driver continuation、比较窗口和计数类别。它不能证明16/24“神”的
数量、新签名、服务器接受度或可用下载器。

## 6. 下一处执行边界

下一步恢复/组合Python once wrapper与完整JNI_OnLoad控制，再生成startup caller/VM输入：

- A分支`+0x28040C`创建`0x3E0`栈区，经`+0x168324`进入VM，bytecode起点`+0xA7050`。
- B分支`+0x2A0028`先构造约`0x62E0`栈区的state（`+0x2A02D4`），再进入后续执行链。

这些位置来自本样本的实际反汇编，尚未构成startup VM成功执行证据。后续fixture还须将
永久JNI table放到独立区域：当前`GUEST+0xA000`在B分支大栈区范围内，不可直接沿用来
判定B分支的真实失败原因。完整ELF/global TLS/arena/OS启动、真实请求URL/headers/JNI、
fresh Medusa、新线上全头矩阵、无JVM Rust、搜索非空/分页、抖音/起点及最终下载产品仍待完成。
