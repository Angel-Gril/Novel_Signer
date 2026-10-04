# 共享引用、环境依赖与 owner/state/root 观察路径闭环

截止：2026-10-04。`+0x25ee84 → +0x26cd0c → +0x26cdc4` 默认路径、环境 getter 和格式化已经恢复；state VM、Python 生成的 state caller、完整 48-byte owner 观察路径已接回 root。

**完整 fresh-input Medusa 尚未完成。** root 组合仍从同次 native 的较早 VM 输入前导开始。不能把“局部观察路径退出”升级为“独立初始化、当前线上签名或最终下载产品完成”。

## 当前验证结果

| 路径 | steps / 终止 bytecode | allocations / frees | 已证明的范围 |
| --- | --- | --- | --- |
| `state_vm` | 363 / `+0xa54bc` | 28 / 21 | VM 退出，全部 32 个终止虚拟槽匹配 |
| `state_caller` `+0x269988` | 同一 state VM | 28 / 21 | Python 生成 caller 前导；owner 字段、32 个虚拟槽和副作用匹配 |
| `state_owner_full` `+0x2698f0` | 构造前缀 + 同一 state VM | 32 / 21 | 从 owner 输入入口组合 clone/count/mutex、caller 和 VM |
| `root_advanced` | 716 / `+0x99f04` | 171 / 93 | 接回 owner/state；root VM 退出，全部 32 个终止虚拟槽匹配 |
| `parser` / `parser_caller` | 3318 / `+0x9c95c` | 119 / 47 | 既有 parser 结果继续匹配 |

[共享／环境 helper 证据](evidence/vm9_shared_reference_native_20261004.json) 为 **106 组 fresh native 差分 / 15 个拒绝与页面回滚案例**；[同次组合证据](evidence/vm9_root_vm_prefix_native_20261004.json) 为 **4 个 fresh controls / 16 段 VM / 68 条完整子树**。两个 image bases × SDK 缺失/30；另有 **7 个 state caller 前置拒绝案例**。保留 root 第 513 步的旧前缀作为回归，而此前第 605 步与 state 第 173 步的停止点已被本次闭环取代。

## 共享 factory 与 getter

生产模型位于 [vm9_configuration_init.py](python/vm9_configuration_init.py)。所有字符串仍从 caller 提供的 guest ELF 页解码，模型和公开证据均不嵌入解码后的配置、路径或 payload。

`construct_default_shared_reference` 对应 `+0x26cdc4`，恢复三组 lazy decode，检查 `+0x3deed8` 的 JNI 环境指针。当前 no-JNI 路径按实际次序执行：临时 string → 日志初始化 → 临时 string 清理 → 24-byte string → payload → 4-byte count → inline reference `+0x3dee28`。匹配 ELF 默认输入的有序效果为 `allocate(8) → free → allocate(24) → allocate(21) → allocate(4)`。JNI 环境非 NULL 时明确拒绝，不能改成空引用捷径。

`get_inline_shared_reference` 对应 `+0x26cd0c`：cold guard `+0x3dee20` acquire，构造 inline reference，注册 destructor `+0x15e1a8`／object `+0x3dee28`／DSO `+0x34c700`，release，最后调用实际的 zero-before-source-read 引用复制语义。这个 inline cache 不分配额外的 16-byte wrapper，不能直接套用已有 lazy-wrapper singleton 的分配布局。

引用复制会先清 destination，再重新读取 source 和 count。差分覆盖 separate、self、前后 8-byte 重叠，以及计数 0/1/2、signed 极值和 uint32 回绕。注册回调可以改变 guest reference，复制必须消费改变后的状态；native 不检查 `__cxa_atexit` 的返回值，该行为也已验证。页面回滚不撤销已经发生的 allocator/syscall/registration 外部效果。

## 日志、SDK 和 TLS 依赖

factory 的 `+0x26e9e0 → +0x271ec8 → +0x271ddc` 日志调用会改变全局初始化状态，即使日志端点不可用也不能整段省略。

`get_cached_sdk` 从 guest 解码属性名，通过显式环境回调取得 synthetic property bytes，恢复正整数缓存及非正数／无属性行为。字符串转换的已测分支需要已经初始化的 singleton136；冷 singleton 或 instrumentation 分支明确拒绝。独立 helper 的 fixture 显式提供 synthetic warm singleton，不宣称它证明完整 cold 启动。

`initialize_unavailable_logger` 覆盖与当前 controls 相同的两条路线：SDK<21 的四个日志文件 open 失败及 close 清理；SDK>=21 的 fallback open 和 socket 失败。恢复 lazy flags、dispatch pointer、正常无竞争 mutex 和 TLS errno。成功打开端点、EINTR 重试及真实日志写入未恢复，均保持拒绝。模型本身不打开宿主文件或网络连接。

`get_environment_service_reference` 对应 `+0x172d40`，cold 分配 16-byte wrapper、**未写入的 1-byte payload** 和 4-byte count。`get_environment_constant` 对应 `+0x2562dc/+0x256330`，只做 lazy guest CString decode；当前路径不消费传入的 X0 内容。cold/warm getter 均有独立对照。

## 格式化和目录行为

`format_string_object` 恢复 `+0x248908` 的非 NULL `%s/%%` 分支：16-byte 临时字段、初始 buffer、严格容量 rounding、截断写入、扩容重试、结果复制和临时结构清理。每次实际格式化重新读取 guest 参数，输出由 Python 计算，不能使用 native 格式化输出充当模型输入。未知转换、缺少／NULL `%s` 参数、容量边界和未恢复的 allocation failure fallback 会拒绝并回滚页面。

`construct_environment_reference` 对应 `+0x25ee84`，组合共享引用、结果 string/count、两次环境 service getter、两组常量、三段 CString 格式化、`faccessat(R_OK)`、递归目录 probe/mkdir 和临时引用释放。所用文件／属性／mkdir／errno／注册均是显式环境边界。本次验证是虚拟不可用文件／socket、mkdir EEXIST 的控制环境，未新增线上接口成功结论。

native bionic `vsnprintf` 还调用 `uselocale(0)`，触发 once、pthread key/generation 和一次 futex wake。可选 `prepare_bionic_format_locale` 用既有 Python pthread 模型生成这些状态，再通过显式 no-waiter wake 边界核对次序；pure Python 格式化本身不需要 libc。忽略这项依赖会让 heap/image 匹配但 ordered wake／TLS generation 对照失败。

## State caller、owner 与 root

[vm9_state.py](python/vm9_state.py) 提供 `StateCallbacks`、`construct_state_caller` 和 `construct_initialized_state_owner`。`StateCallbacks` 恢复当前控制经过的 lazy decode、scoped writer 获取、环境引用、string 生命周期、SHA1 reference、第二次格式化、路径检查、64-byte empty container 和 scoped writer/TLS node 释放；其它 wrapper/target 保持拒绝。

`+0x24a4d8 → +0x2493e8` 读取 guest 的 default malloc table，分配并清零 64 bytes，再写 container+0x18=64。自定义 allocator table 未恢复。容器指针由真实 VM 指令发布到 owner。

`construct_state_caller` 从 `+0x269988` 输入生成 entrySP-0x6d0 的 argument block、descriptor、return word、TLS canary 和 register backing，然后执行 `VM +0xa46a0`。它不读取后续 native VM 入口快照。上界、alignment、PAC-tagged return、未映射 stack/TLS、缺少 bytecode 和无效 word 均有拒绝与页面回滚检查；VM 全局 image base 在退出／拒绝后恢复。

完整 owner 的构造会在 tail caller 的 register backing 留下七个仍可见的 stack words，来源于 `+0x1625a4/operator-new` 和 `+0x17d7e0` 的物理 spill。生产组合按当前 entrySP、ELF return offsets、TLS canary 和 Python clone 地址推导这些 word；不导入稍后的 native 前导来填空。否则 heap 可能匹配而七个 terminal virtual slots 不匹配。这里只恢复可观察 ABI 字段，不声称模拟了全部物理寄存器与调用栈。

root 的 `+0x258500 → +0x2698f0` 组合从更早的同次 root VM 输入开始，不消费后续 configuration constructor、parser、state owner、state caller 或 state VM 的入口快照。随后退出于第 716 步。子树 verifier 仍各自使用同次 native 的函数输入入口进行独立对照；两类输入边界在证据中分别记录。

## 复现与研究使用

从番茄目录运行，matching ELF/libc 保存在私有路径：

```text
python -B python/verify_vm9_shared_reference.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/shared-reference.json
python -B python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-parser-state.json
python -B python/verify_vm9_state_owner.py --library /private/libmetasec_ml_71332.so --output /private/state-owner-prefix.json
```

verifier 强制核对 ELF SHA256。Native 只在 Unicorn oracle 侧执行，生产模型不执行 native constructor 或 JVM。调用研究 API 时，需要 mapped pages、relocated guest ELF、entry SP／thread pointer／return ABI、VM interpreter、allocator 和明确环境回调。它们目前是研究组件，尚不是可直接调用当前线上接口的 signer。

这批证据可以用于排除“共享引用为空即可跳过”“日志无副作用”“环境 getter 读取 payload”“复制引用没有别名问题”“caller 未使用的栈值都可清零”等错误假设。证据同时绑定分配／释放前内容、全 image、TLS/generation、注册／wake 次序和终止虚拟槽；单独的静态反汇编或输出长度不能替代这些对照。

## 剩余工作

后续 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md) 已完成默认 root caller 和更早的 `+0x257578` factory，并以8组fresh ELF/TLS输入消除本报告原有的root VM前导快照依赖。此更新仍使用受控allocator与虚拟OS，尚需接入外层signer/handle，独立补齐实际全局boot／TLS／arena／OS状态，再验证fresh-input Medusa请求输出和线上矩阵。

无 JVM Rust signer/download、当前非空搜索及分页、抖音／起点线上闭环和最终 Pages/Actions 搜索下载产品仍待后续完成。上述 component/VM 结果不代表这些任务已经完成。
