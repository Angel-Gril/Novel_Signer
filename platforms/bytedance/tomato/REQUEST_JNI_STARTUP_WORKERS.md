# 原始 JNI 返回、同次默认 worker 与 B descriptor 查找

记录日期：2026-10-07 UTC。文件名沿用本机试验标签 `20261008`；标签不是新增的 UTC 日期。

本检查点验证了 **A 分支原始 JNI_OnLoad 返回，以及同次生成的第一个 queue worker
执行全部六个默认初始化 caller 并返回任务调用点**。另恢复了 B 分支短 selector
哈希和 descriptor 查找的纯 Python 组件。完整独立 Medusa、fresh 请求签名及线上矩阵仍未完成。

## 1. 正式证据与计数

| 证据 | 数量 | 已验证行为 |
|---|---:|---|
| A 原始 JNI_OnLoad 返回 | 2 | 两个基址，原始入口自然返回 `0x10006` |
| 同次 JNI → 默认 worker 入口 | 2 | 使用同次 thread-create 发布的 argument，到达 `+0x280554` 前 |
| memset 导入单变量控制 | 4 | 两个基址 × 未绑定/绑定，在相同 wrapper 停止点核对 callback 目标 |
| 同次 worker 的完整默认任务 | 2 | 每次六个 caller、48 次嵌套 VM 返回、六块 arena、六次完成 broadcast |
| 同次任务清理/worker wait 边界 | 2 | 实际 task cleanup 执行后到达 condition wait PLT 前 |
| 同次 worker wait/stop/return/free | 2 | 实际 libc wait 后由显式 EINTR/stop 服务驱动，正常返回并释放 argument |
| allocator 区域碰撞控制 | 1 | 原 pool 覆盖 TLS 后 canary 失配；停止于 fail 分支调用前 |
| B 短输入哈希 native/Python 差分 | 20 | 两个基址 × 0..8 字节及高位移位控制 |
| B 短 selector lookup 差分 | 30 | 桶/碰撞/空返回、short/long stored key、实际 ELF selector |
| B Python 拒绝与回滚控制 | 6 | 长 query、坏栈、缺页、循环、超限等 |
| 完整 Python bootstrap 对照 | **0** | 尚未验证全部构造器、全局/TLS/allocator/JNI/worker 的独立生成 |

A 证据：[vm9_jni_A_default_worker_20261008.json](evidence/vm9_jni_A_default_worker_20261008.json)。
worker stop 证据：[vm9_jni_A_worker_stop_20261008.json](evidence/vm9_jni_A_worker_stop_20261008.json)。
B 证据：[vm9_alternative_short_descriptor_20261008.json](evidence/vm9_alternative_short_descriptor_20261008.json)。
这些计数不与此前 34 组 once/mask 组件对照相加为完整 signer 对照。

## 2. A 原始返回与同次默认任务

实际执行链为：

```text
.init_array component +0x271940
  → explicit ctor-exit driver
  → original JNI_OnLoad +0x27B41C
  → cold once / JNI / Long / cleanup
  → A startup +0x28040C / VM +0xA7050
  → queue creation and task submission
  → JNI_OnLoad returns 0x10006
  → explicit virtual worker driver
  → same-run argument → +0x3260A4 → +0x326578
  → default task +0x280554
  → six actual default callers +0x280590 .. +0x280810
  → task returns to +0x326620
```

`pthread_create` 采用显式服务，发布三个延后执行的 guest handle：executor
`+0x326A2C` 和两个 queue worker `+0x3260A4`。JNI 返回后只调度第一个 queue worker。
两个 queue submission 的 matching-libc signal 实际执行，syscall 98 的 operation 129、
count 1、无等待者返回 0 为显式 OS 结果。

原始 JNI 返回观察只有一个 driver：ctor exit → JNI。worker 观察再增加一个 driver：
JNI 返回 → 虚拟 worker。主 TP 为 guest+0x3000，worker TP 为 +0x7000；worker pthread/TLS
状态由 fixture 显式初始化，并清空 legacy emulated-TLS OS slot。main 与 worker 顺序复用
SP=guest+0xEF00；没有真实 OS 线程或并发。JNI table 保留在 guest+0x6000。

完整任务观察不从任务正文另起 CPU，也不替换六个 caller。每次验证：

- 六个实际 caller 依序进入，每个含 8 次嵌套 VM 返回；总计 48 次。
- 六个 once control `image+0x3E09E8+i*0x48` 均成为 `0xFFFFFFFFFFFFFFFF`。
- matching-libc broadcast 实际执行六次；无等待者 futex 返回为显式服务。
- 六块 16 KiB arena 由受控服务提供，所有观测到的 caller canary 对均保持一致。
- 最终到达实际任务返回点 `+0x326620`；另两条延伸观察执行后续 task cleanup，停在 wait PLT `+0x3485B0` 前。

默认任务及其清理/wait 观察均为原生执行观察，尚无完整 Python 启动的对应生成链。
清理/wait 边界观察只执行一次任务返回后的 `+0x167310`，停在 wait PLT 前。
后续两个完整 worker 观察继续执行 matching-libc `pthread_cond_wait`：在其 mutex 已释放时，
显式 futex 服务核对 syscall 98、operation 128、expected 4、NULL timeout，并将 queue+0x88
的 active byte 清零，返回 -4（EINTR）。实际 wait 返回后重新进入 queue 控制，worker
自然返回 0。argument 恰好一次进入受控 free 服务，所属 block 被填入 0xD7 并从受控
allocator 的 live blocks 移除；native terminal guest memory 核对该效果。

这里主动发布 stop 的是显式 OS 服务，不证明真实线程并发或 kernel wait。worker support
wrapper 仍保留在实际 TLS key slot；TLS key 析构、guest pthread_exit 和真实 OS 线程终止
均未执行。任务清理只在 task return 与首次 wait 之间计数，后续 argument 的清理不能
混作第二次 task cleanup。

allocator、JavaVM、JNI、clock、exit、OS 服务，以及 warm reference、TLS subsystem globals/OS keys 仍为显式输入。

## 3. memset 导入与 allocator 碰撞的归因

基础 loader 未解析所有 undefined ABS64 导入。按实际 ELF symbol/relocation 提取
`memcpy` 和 `memset` slot，分别绑定到已有显式服务的 PLT `+0x347F60/+0x347F20`。
`memcpy` 的 16 项继承此前控制，`memset` 项由 ELF 解析，未将全部导入默认为成功。

首个默认任务的实际路径为 `+0x280590 → VM +0xEDCF0 → nested VM +0xEE3B0`
→ callback wrapper `+0x281610`。wrapper 从 packet 读取 target、destination、**一字节** fill
和 length；不能要求 fill 所在整个 64 位 word 为零。四条单变量控制在 `+0x281620` 的
branch 前停止，核对未绑定 target=0 或绑定 target=memset PLT，均未执行该 callback。
完整任务观察进一步实际执行了 callback 及后续 VM。

继续执行暴露了 fixture 的区域碰撞：原小块 allocator 把 16 KiB arena 放到 permanent
JNI/TLS 范围，VM 后续写入改变 worker canary。碰撞控制保留原分配，观察到第六个嵌套
返回处 canary 失配，并在 `+0x280A70` 调用 stack-check fail 前停止。不能将该现象归因为
App 崩溃或无限循环，也不能忽略 canary 检查来让验证通过。

正控制只将 16 KiB 分配交给独立区域服务：guest+0x10000，六块区域总长 0x18000。
小块分配、TLS、JNI 和任务输入保持同一生成流程。隔离后两基址均执行全部六个 caller。
真实 libc allocator/arena 启动和 OS region 生命周期尚未在此组合中贯通。

## 4. B descriptor 的发布来源与短 selector 组件

静态追踪定位 `.init_array` 成员 `+0x29ECAC`：`+0x29F2C8` 调 factory wrapper
`+0x2A95E0`，实际 factory 为 `+0x2CBDC8`。`+0x29F2D8` 将 root 写入 `+0x3E1EB0`，
随后 `+0x29F2E8` 调 `+0x2A9620`，`+0x29F2F4` 将选择结果写入 `+0x3E1EB8`。
这是发布来源的静态定位，尚未执行完整 factory/constructor 来产生实际 root。

后续私有单基址 native 探针已经从实际 constructor 进入 factory 解析，逐项接入
matching-libc memcmp/normal mutex，以及显式 gettid/exit 注册服务。原 64 KiB guest
范围在 `+0x32A9C8` 的栈写入遇到未映射边界；改用独立 2 MiB 栈后，在 2000 万条
指令预算内未再观察到未映射访问，但仍未观察 factory 返回或 descriptor 发布。
这是继续分析的位置，不纳入上述正式 Python 对照计数，也不能用预算结束证明无限循环。


新 owner：[vm9_alternative_startup.py](python/vm9_alternative_startup.py)。

```python
hash_short_descriptor_name(payload)  # 支持 raw bytes 的长度 0..8
lookup_short_descriptor(
    pages, root_address=root, name_address=name,
    entry_stack_address=stack, max_nodes=4096,
)
```

对应 `+0x2AA744` 的短输入哈希，以及 `+0x2A9620 → +0x2AA528` 的桶 lookup：
root[0] 为 descriptor array，root+0x20 为 bucket array，root+0x28 为 bucket count。
bucket 指向 predecessor，其 next 指向 node；node 保存 next、cached hash、libc++ string
和 descriptor index。恢复了 power/non-power bucket、相同 hash 的 key mismatch、链推进
及另一 bucket 边界；stored key 的 short/long 形式均对照。

4..8 字节哈希中的 `first_u32 << 3` 先做 **uint32 截断**再加 length，高位控制可识别
错误的 uint64/unbounded shift。actual constructor selector 的两个字节直接从 ELF 读取。
验证 root/bucket/node 为合成数据，不是初始化完成的 native module，也不从 native 输出
制作 Python 输入。query 长度超过 8、循环、超限或缺页明确拒绝并回滚 guest 页。

## 5. 复现与使用边界

私有 `.so` 不纳入仓库。验证器先核对样本摘要；从仓库根目录运行：

```text
python -B platforms/bytedance/tomato/python/verify_vm9_jni_A_default_worker_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <A-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_jni_A_worker_stop_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <worker-stop-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_short_descriptor_20261008.py --library <private-metasec.so> --libc <matching-libc.so> --output <B-evidence.json>
```

A 验证器的 native hook observation ranges 跳过 dispatcher 热点，只保留实际服务、启动、
caller 和 callback 边界。VM 指令仍由原生执行，不因减少观测 hook 而替换 VM 结果。
脚本逐项恢复 monkeypatch，要求串行运行；输出只导出合成状态、偏移、数量和比较结果。

这些证据可用于证明导入绑定和内存区域依赖、JNI 到默认任务的控制流、once 发布顺序，
以及 B 短 selector 算法/数据布局。它们不能证明 fresh Medusa 输出、服务器认可、全部 OS
析构或独立 Python/Rust signer。完整无 JVM Rust、非空搜索/分页、抖音/起点闭环、最终
Pages/Actions 搜索下载产品仍待完成。

后续优先接回 worker TLS key 清理与 guest pthread_exit，再继续完整
Python 启动与 B `+0x2CBDC8` factory；真实 allocator/arena/OS 输入和 fresh 请求签名仍是
独立 signer 的必要验收项。
