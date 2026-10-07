# TLS／JavaVM 环境获取与 Java 栈检查调用边界

后续发布组件及原始JNI_OnLoad探针见
[REQUEST_JNI_PUBLICATION.md](REQUEST_JNI_PUBLICATION.md)。本报告40/14组件证据
范围保持；完整bootstrap、实际JNI服务与fresh签名仍未完成。

2026-10-07。本阶段恢复 `+0x26EDC4`、`+0x17CAAC`、`+0x26EEEC` 和
`+0x26EF2C` 的有界组件行为，以及 attach 成功分支。新增 **40 个原生对照、
14 个负控制**。原生 oracle 显式启用 `real_jni_acquisition=True`，关闭旧的
`env` 写入 stub，并执行原始 TLS 获取和本地线程析构注册函数。

本阶段没有 Android JVM、真实请求转换、Medusa 签名或服务器请求。JavaVM、
pthread OS 和分配结果是显式测试服务。完整独立 signer 尚未完成。

## 1. 原生调用与恢复结果

| 路径 | 已恢复行为 | 证据限制 |
| --- | --- | --- |
| `+0x26EDC4` | 清零输出 pair，读取 TLS guard，冷构造与析构注册，刷新 env，临时 fallback | 输出 pair 等价；不比较该 void 函数偶然保留的 X0 |
| `+0x34377C` | 既有 emulated TLS owner，索引、变量分配与初始化 | 原生 body 执行；本阶段 OS key/once 服务显式提供 |
| `+0x34265C` | 既有本地析构 owner，注册节点、key 与 atexit | 原生 fallback 执行；不覆盖导入的 thread-atexit 实现 |
| `+0x26EEEC` | 24 字节对象的 vtable、ownership byte、env word 初始化 | 只写原生实际写入的字段，保留 padding |
| `+0x17CAAC` | `GetEnv(vm, output_slot, 0x10006)`，先清零 output slot | 原生忽略 GetEnv status；服务输出必须显式提供 |
| `+0x26EF7C` | 两组 lazy 消息解码，attach 成功后的 ownership 发布 | 失败诊断 `+0x26F054` 仍明确拒绝 |
| `+0x26EF2C` | 任何非零 ownership byte 都调用 detach，随后清零 env 和该 byte | detach 状态未作为业务结果；完整 JNI 未恢复 |
| `+0x28B05C → +0x28B71C` | 九组 lazy 全局、环境获取、环境保存、FindClass 参数准备 | 停在原生 FindClass 调用前，未执行 FindClass |

环境 TLS 的两个控制块是 `image+0x3825E0`（size=1、alignment=1 的 guard）
与 `image+0x3825C0`（size=24、alignment=8 的 owner）。guard 按 bit0 判断是否
构造；JavaVM owner 的字段为 vtable `+0`、ownership byte `+8`、env word `+16`。
vtable 为 `image+0x35D478`。冷构造后注册 `+0x26EF2C`，DSO 为 `+0x34C700`。
注册返回值在本调用路径不作为成功条件。

`image+0x374F90` 是 JavaVM storage 的 GOT 指针。本样本 fresh ELF relocation
指向 `image+0x3DEED8`。通过 JavaVM vtable `+0x30/+0x20/+0x28` 分别取得
GetEnv、AttachCurrentThread 和 DetachCurrentThread 服务。临时 fallback 的
cleanup 从 `+0x3DEED8` 直接读取 JavaVM；普通 destructor 经 GOT 读取，代码保留
这两个访问方式。

原生 attach 失败条件是 **uint32 status 等于 -1，或 env 输出为零**。不能把它
改为“所有非零 status 都失败”；本阶段有返回 -2 但 env 非零的原生控制。
临时对象 attach 后，原生把 `+8..+23` 的16字节复制回 TLS owner，随后 detach
临时附件；本阶段保留这个实际顺序和最终 bytes，没有修正原生的行为。

## 2. 对照方式与覆盖

私有样本：

- libmetasec SHA-256：`712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c`
- matching libc SHA-256：`d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db`
- ASLR 基址：`0x122C0000`、`0x775C205000`。

从 fresh ELF、relative relocations 和独立 guest fixture 开始，不使用 native
输入快照，不把 native 输出注入 Python。原始 body 的执行入口由 instruction
observer 记录；matching libc 实际执行 uncontended normal mutex。

40 个控制分为：

- 26 个自然返回的 acquisition 控制：warm guard、bit0 变化、冷 TLS owner、
  全新 TLS slots、冷析构 key、GetEnv status、临时 GetEnv、attach/detach。
- 8 个自然返回的 destructor 控制：ownership byte 为0、1、2、0x80。
- 6 个 evaluator 组合控制：两基址各 warm、全新 TLS slots 和临时 attach，
  原生与 Python 都到达 `+0x28B71C` 调用前。X0/X1 参数在原生前一条 LDR 处
  观察，并与 Python 的 env/class-name 参数比较；该 LDR 到调用点不改变 X0/X1。

比较 guest payload 前 `0xA000`、全部主 ELF 页、分配及服务顺序。evaluator
组合另比较保存输入、环境 pair/slot 的有界栈窗口。没有 padding mask。
不比较完整物理栈、canary、saved-register ABI、Android JVM 或全线程／OS 行为。

14 个负控制覆盖缺少 VM/provider、attach -1／NULL、无效 SP、输出 alias、NULL
vtable/function 和 TLS once 非可用状态。失败时调用者 guest pages 回滚；显式
分配、pthread 和 JavaVM provider 的外部记录或副作用可能保留，不声称整体事务
可逆。未恢复的调用路径仍拒绝，不返回假环境或假 JNI 结果。

## 3. 同次启动组合与当前缺口

同次 owning allocator/session 组合仍使用合成请求：

- 低基址仍为957步、`+0xFFB78` 返回，logger 两条 record，33次请求分配／18次
  free，页提交回 owning session。输出为配置树引用，没有 Medusa 签名。
- 高基址仍为965步、`+0xF8FD0`。其 callback 已调用恢复的 Python acquisition，
  TLS guard／owner 分配由同一真实 allocator 模型处理，申请大小为16和39字节。
  `+0x3DEED8` 的 JavaVM 指针为0，GetEnv 无服务可用，冷构造进入
  `+0x26EF7C` attach 后拒绝：`JavaVM unavailable for AttachCurrentThread +0x26ef7c`。
  acquisition 与父 callback 均未完成，父 request 页事务未提交。

`+0x26EDC4` 的原始 body 对照已经由组件证据通过；**同次启动组合没有执行全
native request/JVM**。40 控制中的 JavaVM 服务是测试输入，不能填入组合来
制造“真实请求通过”。下一步应定位并恢复实际 JavaVM 初始化／发布和 JNI
接口行为，再恢复 `FindClass +0x28B71C` 后的调用链及真实 URL/headers 转换。
attach 失败诊断、完整 callback 返回、fresh signature 与线上全头矩阵仍待通过。

## 4. 代码、复现与证据使用

实现 owner：

- [vm9_jni_environment.py](python/vm9_jni_environment.py)：get、construct、destroy、acquire。
- [vm9_request_leaf_prefixes.py](python/vm9_request_leaf_prefixes.py)：可选的 acquisition
  provider，继续到未恢复的 FindClass 边界；没有 provider 时保持旧前导验证。
- [原生组件验证器](python/verify_vm9_jni_environment_fresh_20261007.py)。

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_environment_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_environment_fresh_20261007.json
python -B platforms/bytedance/tomato/python/verify_vm9_request_diagnostic_continuation_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_diagnostic_continuation_20261007.json
```

`acquire_thread_environment` 需要 owning `get_tls`、`register_destructor` 和显式
`invoke_javavm(pages, function_address, argument_words)`。后者负责写入 GetEnv／
Attach 的输出槽并返回真实或明确声明的测试 status。成功结果包含 environment、
owner、cold/temporary/detach 标记；不提供 HTTP 签名 API。

[组件证据](evidence/vm9_jni_environment_fresh_20261007.json) 可支撑 TLS 对象布局、
ownership 判断、GetEnv/attach/detach 参数与顺序、原始 body 执行和 JNI 调用前
状态等逆向结论。引用时应附样本 hash、fixture、比较窗口及显式服务边界。
[同次组合证据](evidence/vm9_request_diagnostic_continuation_20261007.json) 可支撑
JavaVM 缺失的位置和 owning TLS allocator 的接入，不能支撑独立 Medusa、线上
校验、搜索结果或正文下载。无 JVM Rust、非空搜索/分页、抖音/起点闭环和最终
Pages/Actions 下载产品仍待完成。
