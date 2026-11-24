# Checkpoint log

2026-11-21：**Sample verified**：同一 Unicorn CPU 执行已解析的
`+0x32a444` 共享读锁回调。原版锁/解锁 helper 正常返回，接收对象 `+0x88`
的四字节读者数 0→1，观察的 `0x90` 字节对象内其余字节完全保留。
核对原生 canary 保存、SP 与 X19-X29 恢复及原版 `ret`，回到
`+0x16aa4c` 并停在本次 caller 指令执行之前；分配、服务、JNI 与 SVC
账本相对旧解析边界不变。23 项损坏证据拒绝通过，捕获与 fresh 原生重放
逐字段完全一致。未把原生内存作为 Python
模型输入，也未新增 provider；既有共享读锁模型仍由 `vm9_objects` 持有。
本次仅覆盖无竞争分支，等待/写者分支、物理 PAC 验证、后续 VM 执行、完整
suffix 返回、完整 signer、Android 实机与线上接受均未验证。见
[回调返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_shared_reader_return_dynamic_20261121.json)
及[验证器](../platforms/bytedance/tomato/python/verify_vm9_native_171_shared_reader_return_dynamic_20261121.py)。

2026-11-21：**Sample verified**：随机 getter 包装器返回后，当前原生 VM 从
`+0x16aa4c` 恢复，857 次指令观察到达下一 `+0x16aa48 blr x8`，目标为
`+0x2885e0`。续跑该三指令跳板，在 `+0x2885e8 br x1` 前解析出
descriptor 首字为 `+0x32a444`，第二字与实际 X0 参数一致；尚未执行该目标。
两份冻结证据分别拒绝 6/8 项篡改，解析边界的 fresh 原生重放与旧证据完全相同。
该边界仍使用既有 OS/JNI 控制，不证明 suffix 返回、完整 signer、普通 Cronet
六头、Android 实机或线上接受。见[下一调用证据](../platforms/bytedance/tomato/evidence/vm9_native_171_next_vm_indirect_call_dynamic_20261121.json)、
[回调解析证据](../platforms/bytedance/tomato/evidence/vm9_native_171_resolve_next_vm_callback_dynamic_20261121.json)
及[解析验证器](../platforms/bytedance/tomato/python/verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121.py)。

2026-11-21：**Sample verified**：当前原生 `+0x288648` 回调目标为
`+0x26cc8c` 随机 getter，warm guard 为 1。同一 Unicorn CPU 动态执行
原生 getter和匹配 Bionic `rand` PLT `+0x348020`；原包装器随后在
`+0x28864c` 将返回 `W0` 写入对象 `+8`，填充保持不变。canary 在
`+0x26cca4` 保存后于 `+0x26cca8` 核验。续跑执行包装器 `ldp/ret`
（`+0x288650/+0x288654`），到达 VM dispatch 恢复点 `+0x16aa4c`，并停在
该 caller 指令之前。两份证据分别拒绝 5 项和 6 项篡改；捕获与 replay 完全一致；
无新增时钟/随机 provider，原生内存未作 Python 模型输入。caller body、下一 AST
callback、清理、suffix 返回、普通 Cronet 六头、完整 signer、Android 实机和线上
接受仍未验证。见[callback 证据](../platforms/bytedance/tomato/evidence/vm9_native_171_random_callback_dynamic_20261121.json)、
[VM 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_random_wrapper_return_dynamic_20261121.json)
及[验证器](../platforms/bytedance/tomato/python/verify_vm9_native_171_random_wrapper_return_dynamic_20261121.py)。

2026-11-20：当前 suffix 常量字符串、原始 MD5、引用赋值/临时释放通过。
原版 scratch/header 参数和 16 字节字符串/摘要，引用计数 1→2→1、
五次 17/24/17/48/4 字节分配、诊断表单槽/新锁对象及八次平衡锁操作
全部核对；其余旧状态保留，无新服务/JNI/SVC。停在 `+0x286e10`。
两基址八种声明输入的 16 组原版/现有源码前缀对照、四组新旧 CLI、
四种错误 CLI、13 条指令及 156 项损坏证据拒绝通过。当前原生字节
仅核对原生契约，不输入 Python 模型。普通六头与完整 signer 尚未闭合。
见[摘要证据](../platforms/bytedance/tomato/evidence/vm9_native_171_suffix_digest_20261120.json)。

2026-11-20：当前 suffix 实际入口与三组 lazy constant 初始化通过。
原版 wrapper/body、selector、三次 decoder 调用及 release store 连接到
现有 owner 的独立 ELF 结果，输入帧与旧状态/分配账本保留，无新服务。
停在 `+0x286ce8`、字符串构造之前；完整返回尚未验证。两基址全部
八种 warm flag 组合的 16 组原版/现有源码前缀对照、四组新旧 CLI、
四种错误 CLI、13 条指令及 126 项损坏证据拒绝通过。原上限 400000/2/4
保留，未将原生快照用作模型输入。普通六头与完整 signer 仍未闭合。
见[常量证据](../platforms/bytedance/tomato/evidence/vm9_native_171_suffix_constants_20261120.json)。

2026-11-20：suffix 调用准备及独立完整返回对照通过。当前请求原版七条
字节码将 frame+2088 头部和实际 helper/wrapper 准备到 frame+2752 参数块，
停在进入 wrapper 前。旧复制完整指令/代码/分配前缀一致，头部、padding、
TLS/heap/表和计数引用保留，无服务/JNI/SVC 增量，原观察上限 400000/2/4
保留。四组新声明 VM 执行真实 callback，复用现有 suffix owner 完整返回；
四组原版 helper 与其语义 guest/image、输出、分配清理顺序及释放前字节
一致，分配器/SDK/atoi0 为显式 fixture 输入，未采用原生快照，排除 physical
stack/void X0。四组原生、新旧 CLI、四组独立 VM/原版 helper 及 CLI
重放、四种错误 CLI、七条指令、七个 ELF 字及 166 项损坏证据拒绝通过。
当前请求完整 suffix 返回、整请求等价、普通六头和完整 signer 仍未验证。
见[suffix 证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_suffix_call_20261120.json)。

2026-11-20：配置头部准备及原版 56 字节复制通过验收。原版 27 条字节码
构造标量/字符串/seed/输出槽指针及 mode0 头部，保留最后四字节 padding，
经原版 wrapper/import ABI 及已有 memcpy PLT provider 复制到 frame+2088，
返回目标指针。源、目标相邻
八字节、全部允许区间之外的 frame、旧 TLS/hash/clone/表和两个 count1
引用保留；完整旧 setter 指令/代码/分配前缀一致，无新分配或服务/JNI/SVC。
四组原生、四组新 CLI、四组旧 setter CLI、四组独立声明 VM 及 CLI 重放、
四种错误 CLI、13 条指令、27 个复制 ELF 字、一个 frame 分配字、两个重定位及 213 项损坏
证据拒绝通过。独立模型使用新声明页面，未采用当前原生快照，上限 2/4
保留。下一字节码 `+0xfd698`；suffix、普通六头、整请求等价、在线接受和
完整 signer 仍未验证。
见[复制证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_copy56_20261120.json)。

2026-11-20：TLS 读取后的算术与原版写回已验证。原版 16 条字节码的
输入读取、XOR、右旋 60、32 位符号扩展及四字节参数写入通过指令检查；
原版 setter/warm emutls 将实际值写回同一槽，返回已有指针，相邻字节及
旧 hash/clone/表/两个计数 1 引用保留。无分配或服务/JNI/SVC 增量。
独立声明三种 getter 值及不同输入，两基址六组新 VM/真实 callback，
另六组原版 setter 对照和 CLI 重放通过，未使用原生快照，不声称当前
请求数值与模型相等。四组原生、四组新 CLI、四组旧 getter CLI、四种
错误 CLI、17 条指令、16 个 ELF 字、一个重定位及 201 项损坏
证据拒绝通过。完整旧前缀一致，上限 2/4 保留。下一字节码 `+0xfd62c`；
普通六头、整请求数值等价、在线接受及完整 signer 仍未验证。
见[TLS 写回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_tls_store_20261119.json)。

2026-11-19：暖线程数组中的 TLS 冷变量读取已验证。原版 flags OR256、
旧 hash 参数保留、getter/emutls 实际执行，index 0→5，新增一次 19
字节分配，四字节零值返回及相邻字节保留均通过。独立声明 index 0→8
的 Python VM/真实 callback 与两组原版组件分别验证，未使用原生快照，
不混同当前请求输入。修正旧夹具对 pthread key 状态页的选择，14 组
旧 TLS 控制通过。四组原生、四组新 CLI、四组旧 hash CLI、两组声明
输入原生 TLS 重放、四种错误 CLI、32 条指令、12 个 ELF 字、一个
重定位及 261 项损坏证据拒绝通过。完整旧前缀一致，服务/JNI/
SVC 账本不变，上限 2/4；下一字节码 `+0xfd5ec`。六头、整请求数值
等价、在线接受和完整 signer 仍未验证。
见[TLS 冷变量证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_tls_20261119.json)。

2026-11-19：暖注册表分支与配置 clone 散列已验证。原版 guard bit0=1，
跳过初始化，核对注册表指针读取关系并将 clone 传给 `+0x258be0`。
实际十轮 ELF 表散列及八字节返回值写入通过指令契约检查；clone、表
和两个计数 1 保留。独立新 VM 页面与两组声明输入原生 helper 复用
既有 Python 散列 owner，数值和 guest 字节匹配；其输入/合成表与
当前请求分别独立，未声称当前请求数值与 Python 相同。四组原生、
四组独立 CLI、四组旧清理回归、两组独立 helper 重放、四种错误
CLI、30 条指令、21 个 ELF 字、一个新增重定位及 265 项
损坏证据拒绝通过。完整旧前缀和分配/服务/JNI/SVC 账本保留，上限
2/4 不变。下一字节码 `+0xfd5bc`；配置来源、六头和完整 signer
仍未验证。
见[配置 clone 散列证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_hash64_20261119.json)。

2026-11-19：配置对象保留引用清理已验证。核对 R17/R18 与配置对象
`+160/+168` 字段对应，在暖递归锁内把另一处计数 2 减为 1，仅写
四字节、保留相邻十二字节，正数分支跳过删除。原版通过 frame+1872
提供的 GOT slot 间接取得退出函数，将 scope 读入 R20 后实际解锁，
X0=0；配置对象、指针对、源对象和 clone/payload 保留，两处计数
均为 1。新声明 Python VM/scoped-reference 页面核对选定语义，未
使用原生快照或声称物理栈等价。四组原生、四组独立 CLI、四组旧
清理回归、四种错误 CLI、17 条指令、22 个 ELF 字、两个重定位和
247 项损坏证据拒绝通过。完整旧前缀保留，分配、服务、
JNI/SVC 账本不变，上限 2/4 不变。下一字节码 `+0xfd428`；删除
分支、完整配置来源、六头、在线接受和完整 signer 仍未验证。
见[配置对象保留引用清理证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_owner_cleanup_20261119.json)。

2026-11-19：配置临时引用清理已验证。原版在已有递归锁保护下将临时
引用计数 2 减为 1，仅写四字节，相邻十二字节保留；重读正数后跳过
删除路径，实际退出 scope，锁恢复初始状态、X0=0。clone 对象和
payload 保留，分配/释放、服务、JNI 和 SVC 账本均无增量。完整旧
前缀核对后结束已完成的观察窗口，原版诊断函数继续执行。独立 VM
与 scoped-reference owner 使用新声明页面核对选定语义，不使用原生
快照，不宣称物理栈相同。四组原生、四组独立 CLI、四组旧 clone
回归、四种错误 CLI、17 条指令、25 个 ELF 字、两个重定位及
221 项损坏证据拒绝通过，读取/SVC 上限 2/4 不变。
下一字节码 `+0xfd390`，清理返回尚未消费；删除路径、配置值完整
来源、六头、在线接受和完整 signer 仍未验证。
见[配置临时引用清理证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_cleanup_20261119.json)。

2026-11-19：配置字符串长度复制已验证。原版通过刚复制引用取得源对象，
九条参数字节码准备目标 frame+5016，实际调用 `+0x2483e0`，读取
长度 10，分配 11 字节，复制后补零并返回新 payload；源对象、引用计数、
锁表及目标相邻字节保持原值。独立 Python VM 使用新声明页面，既有
字符串模型使用另外声明的含内部零内容，对照选定复制语义，不把原生
内存或真实业务身份作为模型输入。四组原生、四组独立 CLI、四组旧引用
回归、四种错误 CLI、22 条指令、十个 ELF 字和 181 项损坏
证据拒绝通过。保留完整旧前缀，系统服务/JNI/SVC 账本不变，读取/SVC
上限为 2/4。停止在消费 clone 返回值前。配置值完整来源、NULL 业务
分支、六头、在线接受与完整 signer 仍未验证。
见[配置字符串复制证据](../platforms/bytedance/tomato/evidence/vm9_native_171_configuration_clone_20261119.json)。

2026-11-19：配置内引用复制与锁清理已验证。原版 getter 从接收对象
+24 复制双字引用到 frame+2088，先清零目标，在锁内重新读取源并把
源四字节计数 1 增至 2，相邻字节与源对象保持原值。已有表的空槽新增
一次 48 字节锁对象，返回前解锁；独立 Python VM 和引用作用域模型
从新声明页面对照。四组原生及四组独立 CLI、四组旧退出回归、四种
错误 CLI、25 条指令、九个 ELF 字和 205 项损坏证据拒绝通过。
保留旧指令/代码/分配前缀，服务和 JNI/SVC 账本不变，读取/SVC
限制仍为 2/4。停止在消费 getter 返回值之前。源引用完整构造及业务
身份、真实业务状态、六头输出、在线接受和完整 signer 仍未验证。
见[配置引用复制证据](../platforms/bytedance/tomato/evidence/vm9_native_171_contained_reference_20261119.json)。

2026-11-19：原版配置计数指针的非零分支已继续到四字节计数 1→2，
随后实际退出刚才的诊断作用域，调用匹配 Bionic 的 unlock 并返回零。
24 字节作用域与 2048 字节表保持原值，递归锁释放；独立 Python VM
及 enter/leave 模型使用声明的新输入核对。冷作用域的指令/代码前缀
与全部分配、服务、JNI/SVC 记录保持一致。四组原生及四组独立 CLI、
四组旧冷作用域回归、四种错误 CLI、23 条指令、14 个 ELF 字和
138 项损坏证据拒绝通过。计数地址的历史复用不等于唯一对象来源。
保存的 KMSV NULL 尚未进入业务分支，普通六头与 signer 仍未完成。
见[计数保留与作用域退出证据](../platforms/bytedance/tomato/evidence/vm9_native_171_kmsv_scope_exit_20261119.json)。

2026-11-19：原版 KMSV 缺失结果已保存到 frame+1536，随后从配置对象
的 `+0xa0` 成员取得诊断作用域输入。十一条参数字节码与两基址独立
Python VM 对照一致；原版冷诊断函数、guard、锁表和递归锁与既有
Python 模型核对。只在选定入口启用既有诊断执行选项，新增三次
48/2048/48 字节分配，KMSV 前缀与服务/JNI/SVC 记录保持一致。
四组原生及四组独立 CLI 重放、四组旧 KMSV 回归、四种错误 CLI、
21 条指令绑定、12 个 ELF 字和 150 项损坏证据拒绝通过。
返回值为零，观察在解释器消费它前停止；递归锁仍持有，尚未退出作用域。
完整配置成员构造、真实业务状态、KMSV 值、普通六头与 signer 仍未验证。
见[KMSV 诊断作用域证据](../platforms/bytedance/tomato/evidence/vm9_native_171_kmsv_scope_20261119.json)。

2026-11-19：下一静态名称 `X-BD-KMSV` 的原版解码、独立 guard 获取、
字符串构造、析构登记、发布及缺失键查询已连接。名称来自已绑定 ELF 常量，
实际写入九字节、分配十字节；独立新页面上的既有 Python 模型逐项对照。
原版登记记录唯一出现，两次保护请求绑定到同一页及权限 3/1；当前合成
请求树仅有 `X-TEST: value`，KMSV 查询实际返回 NULL。四组原生及四组
独立公开 CLI 重放、四组旧结果回归、四种错误 CLI、36 条指令、六个
字节码字和 118 项损坏证据拒绝通过。上一结果的指令/代码/分配前缀相同，
新增分配一次十字节、libc SVC 226 两次，读取/main-SVC 限制仍为 2/4。
此检查点没有生成 KMSV 值，没有恢复真实业务状态或完成普通六头与 signer。
见[KMSV 名称查询证据](../platforms/bytedance/tomato/evidence/vm9_native_171_kmsv_lookup_20261119.json)。

2026-11-19：已连接缺失 client-key 查询后的 NULL 落槽与下一静态 guard
预检查。原版保存 NULL 到 frame+1552；紧随其后的分支实际消费另一个
guard 的低位，冷 guard 为零，继续准备其获取调用。函数指针绑定 ELF
相对重定位，停止在下一调用字节码执行前。独立新页面上的既有 Python VM
复现 15 条字节码，未使用原生内存输入。四组原生和四组独立公开 CLI 重放、
四组旧查询入口回归、四种错误 CLI、18 条原生指令、16 个字节码字以及
108 项损坏证据拒绝通过。上一查询证据行完整复现，分配、服务、JNI/SVC
账本均不变，读取/SVC 限制保持 2/4。保存的 NULL 的后续消费、签名值、
真实业务状态、普通六头和完整 signer 仍未验证。
见[client-key 结果续接证据](../platforms/bytedance/tomato/evidence/vm9_native_171_client_key_result_20261119.json)。

2026-11-19：client-key 名称构造后的析构登记、guard 发布与缺失键查询已连接。
原版通过匹配 Bionic 的 `__cxa_atexit` 导出登记名称对象的析构函数，返回
u32 零；对应析构函数、对象和 DSO 三个字实际写入登记页。原版发出两次
精确绑定的内存保护请求后，释放同一个静态 guard，再用名称查询当前合成
请求头树。树中仅有声明的 `X-TEST: value`，实际查询返回 NULL，参数块
其余字节不变。独立 Python 模型使用新页面和相同声明输入，无原生快照。
四组原生、公开 CLI 四组独立重放、四组旧名称入口回归、四种错误 CLI 和
101 项损坏证据检查通过。原名称控制流与分配账本前缀一致，完整分配账本
不变，服务仅增加两次已绑定的 libc SVC 226；handler/main-SVC 上限仍为
2/4。本段没有 client-key 值、真实业务状态、六头输出或完整 signer。
见[client-key 缺失键查询证据](../platforms/bytedance/tomato/evidence/vm9_native_171_client_key_lookup_20261119.json)。

2026-11-19：已连接 `X-BD-CLIENT-KEY` 名称的原版解码、静态 guard 获取和
StringObject 构造。原版从 `+0xf2724` / `+0xf27c0` 解码到 `+0x3e0f14`，
实际写入 15 个字节，结尾零保留自初始零页面；独立 ELF 解码结果一致。
外层 `+0xfd064` 从 R29+1048 读取 guard 地址到 R17。原版 guard 获取
返回 1，包装器将 u32 结果写到参数块 +16，其他 20 字节不变；随后结果
与零不相等，进入名称初始化。原版构造静态对象 `+0x3e0c98`，分配 16
字节，capacity=16、length=15，完整数据为名称加结束零，实际返回到
`+0x16aa4c`。guard 此时仍在初始化中，尚未释放。
既有 Python guard、mutex、字符串模型在独立新页面上对照相同声明输入；
未使用原生内存作为模型输入。四组原生及公开 CLI 四组独立重放一致，八组
旧原生输出、四种错误 CLI 调用、20 条新增指令、四条字节码和 127 项损坏
证据拒绝通过。上个检查点的完整控制流和分配账本前缀一致；新增段仅增加
一次 16 字节分配，系统服务、JNI、libc SVC 保持相同，读取/SVC 限制仍为
2/4。此次证明的是请求头名称；签名值、键值插入、普通六头、整请求等价、
在线接受及完整 signer 均未验证。
见[client-key 名称初始化证据](../platforms/bytedance/tomato/evidence/vm9_native_171_client_key_name_20261119.json)。

2026-11-19：缓存缺失后的第二次 handler 读取及零值相等分支已连接。
独立读取配置仅允许 `+0x16f96c` 在外层 `+0xfcd04` 读取构造 handler
的 +8，大小 8 字节、目的虚拟寄存器 R2、构造值 0；最多两次 handler
读取，旧配置仍只允许首次 +0x50 读取。原版 `+0x15de64` 的构造写入已
观察并绑定，随后实际 LDR 和虚拟寄存器写回得到 R2=0。外层 `+0xfcd08`
实际比较 R2 与 R0（均为零），取相等分支，位移 214 个字；原版将下一
字节码游标写为 `+0xfd064`。观察器停在 `+0x16ee38` 执行前，下一条
字节码已取指，但其 handler 尚未执行；没有 callback 或普通包装器 RET。
既有 `vm_full.VM` 使用声明的字节码、全新合成 handler 和寄存器执行两条
指令，两基址与该投影一致；没有使用原生内存作为模型输入。
四组原生及四组独立公开 CLI 重放一致；八组旧原生输出、四项实际旧配置
拒绝、四项无效读取配置、四种错误 CLI 调用、13 条新增指令与三条字节码
绑定、110 项损坏证据拒绝通过。新增段的完整系统服务、JNI、libc SVC、
分配计数及分配账本均与上个检查点相同，guard=1、errno=2，handler、
空状态根、64 字节空容器及源目录字符串不变。真实业务状态恢复、真实
JVM、普通六头、整请求等价、在线接受和完整 signer 仍未验证。
见[NULL payload 分支证据](../platforms/bytedance/tomato/evidence/vm9_native_171_null_payload_20261118.json)。

2026-11-18：缓存文件检查的 ENOENT 返回与空状态初始化已闭合到下一次
handler 读取前。独立配置仅增加生成文件路径的一次 faccessat，四次主镜像
SVC 均按顺序、调用点、外层字节码、路径和参数绑定；新增调用还核对 LR。
既有离线服务返回 -2，原版将 errno 从 17 改为 2，返回 -1，再生成 false；
包装器实际把 0 写入参数块 +16 字节，其他 31 字节保持原值。原版随后创建
64 字节空容器（+0x18 类型字为 64，其余字节为零），经结果块发布并设为
状态根，状态初始化函数返回到 `+0x26a498`。独立页面上的既有 Python
StateCallbacks 对照 false、errno、单字节写回及完整空容器内容；未使用
原生内存作为模型输入，也未声称完整状态 VM 或物理栈等价。
观察器在外层 `+0xfcd04` 对应的 `+0x16f96c` 执行前停止；下一次读取指向
handler +8、目的虚拟寄存器 2，该读取尚未执行。两基址、两种 NULL JNI
四组及公开 CLI 四组独立原生重放逐项一致；八组旧原生结果、三项旧配置
拒绝控制、四种错误 CLI 调用、18 条新增指令和一条字节码绑定、125 项损坏
证据拒绝通过。JNI 行保持一致；新增既有服务调用明确限定为 faccessat
一次、futex 两次、内存保护两次和 clock 一次，没有新增 provider。
真实文件状态、业务缓存恢复、真实 JVM、普通六头和完整 signer 仍未验证。
见[文件检查及空状态初始化证据](../platforms/bytedance/tomato/evidence/vm9_native_171_file_check_20261118.json)。

2026-11-18：普通合成 aid 请求的默认缓存文件名链已闭合到文件检查调用前。
原版从 ELF 常量解码 `def`，构造并复制 StringObject，再以 flag=1 调用
SHA-1 helper。40 字节十六进制结果与独立 hashlib 一致，实际结果指针继续
传入 `%s/%s%s`，组合目录、`.msp_` 和摘要。原版保留目录尾斜线，因此
最终路径含双斜线、长 76 字节；格式化结果对象及其 CString 指针均连接到
可读性检查参数，mode=4。目录创建失败后环境 helper 已实际返回；观察器
在 `+0x25de04` 的 BL 执行前停止，尚无第四次主镜像 SVC 或文件检查结果。
两基址、两种 NULL JNI 共四组，以及公开 CLI 四组独立原生重放逐项一致；
23 条新增指令绑定、独立 ELF 默认值解码、101 项损坏证据拒绝、三组旧入口
检查和四种错误 CLI 调用通过。四组完整环境服务计数及 libc SVC 行与旧目录
结果一致，原有三次主镜像 SVC 绑定未变，未新增 provider。仅比较声明默认
值、独立 SHA-1/路径公式和选定原生传递关系，没有以原生内存作为公式输入。
其他身份/路径、文件状态与检查返回、业务状态恢复、真实 JVM、普通六头、
完整请求等价和完整 signer 仍未验证。
见[默认缓存文件名证据](../platforms/bytedance/tomato/evidence/vm9_native_171_cache_path_20261118.json)。

2026-11-18：普通合成 aid 请求已继续经过两次目录查询、一次既有 mkdir 服务和
目录 helper 的原版 RET。新增配置只按顺序允许原有 faccessat 和两次精确绑定的
fstatat；查询路径依次为去掉尾斜线的缓存目录与 `/data`，错误返回均为 -2。
原版实际写 errno=2 并返回 -1；两次 128 字节 stat 缓冲区均保持原值。
mkdir 以 0755 请求 `/data`，既有服务设置 errno=17、返回 32 位 -1；原版
helper 返回 false，调用方仍继续。观察器在 `+0x25ef7c` 前停止，不是请求返回。
现有 Python `ensure_environment_directory` 以独立页面和声明的静态路径运行，
两次查询、mkdir、false、errno=17 及 31 字节临时路径投影与原生一致；未把
原生快照用作模型输入，也未比较完整物理栈或整请求。两个基址、两种 NULL JNI
共四组，30 条指令绑定、四组公开 CLI 重放、八组旧控制整行一致、164 项损坏
证据拒绝、两项原生配置拒绝控制及四种错误 CLI 调用通过。guard 保持 1，
handler 和源字符串不变，没有新增 provider。真实文件状态、目录创建成功、
业务状态恢复、真实 JVM、普通六头和完整 signer 仍未验证。
见[目录错误路径与 Python 局部对照证据](../platforms/bytedance/tomato/evidence/vm9_native_171_directory_20261118.json)。

2026-11-18：新增独立的合成 `aid=1` / 缓存缺失配置。两基址、两种 NULL JNI
共四组均由原版搜索取得 aid，局部长度变为 1，`+0xfc240` 走向 `+0xfc244`，
停止前没有触发首次 `-8` 分支或诊断格式化。只允许原版 `+0x271dbc` 在
`+0xfca40` 执行一次、路径和参数精确匹配的 `faccessat(48)`；旧服务返回
`-2`，原版代码实际写入 errno=2、返回 -1，readability helper 返回 false，
调用方进入目录处理分支。观察器在 `+0x25ef6c` 前停止，没有 callback/普通
包装器返回。guard 保持 1，128 字节 handler 不变；复用旧服务，额外调用
一次文件检查和两次时钟。24 条指令、1 个新增字节码字绑定，四组公开 CLI
独立重放、八组旧控制逐项复现、177 项损坏证据拒绝、四种错误 CLI 调用及
一次默认配置主镜像 SVC 拒绝控制通过。默认 libc-only 边界仍有效。
缓存缺失是离线服务设定，真实 Android 缓存、后续目录处理、业务状态、真实
JVM、普通六头、整请求差分和完整 signer 仍未验证。
见[aid 与缓存错误处理证据](../platforms/bytedance/tomato/evidence/vm9_native_171_aid_cache_20261118.json)。

2026-11-18：普通 `0x171` 的 `-8/-11` 直接分支条件已原生观察。合成 URL 没有
query；原版两次 `&aid=`/`aid=` 搜索的源串为空，均返回未找到。局部字符串
长度为 0，使 `+0xfc240` 跳到实际 `-8` 起点 `+0xfc5cc/0x7f01fafb`，将
R0-8 写入 R21，随后跳回 `+0xfc258`。
后续读取 `image+0x3d1558` 的低字节 1，掩码后为 1，`+0xfee14` 跳到
`+0xfef5c`，继而在既有位置写入 `-11`。两处实际存储完成、三处比较和跳转
目标均核对。四组控制的上游整行输出保持一致；13 条指令、11 个字节码字、
独立字段解码、四组公开 CLI 原生重放、117 项损坏证据拒绝及四种错误 CLI
调用通过。输入、guard 和旧 provider 保持原值，仍只有单个诊断头，没有
Android 操作或生产 signer 修改。完整缺头原因、真实业务状态、真实 JVM、
整请求差分、普通六头和完整 signer 仍未验证。
见[诊断分支输入证据](../platforms/bytedance/tomato/evidence/vm9_native_171_diagnostic_gates_20261118.json)。

2026-11-18：同一 CPU 上原版构造出的普通 `0x171` 路径，已从成员读取继续到
callback 返回、输出序列化和普通包装器 RET；扩展观察器没有改写停止 PC。
四组、两个基址的合成 NULL JNI 控制各观察 357865/357898 条 continuation
指令（含 provider 边界）。同一 `X-Neptune` 先插入 `-8`，后插入 `-11`；
原版容器保留第一次 key、替换 value，并释放重复 key/旧 value。最终 `-11`
在 `+0xfef94/0x7ea0f97b` 从源 R0=0 形成。四个丢弃分配在 callback 返回前
释放，十个最终树分配在 RET 前释放；生命周期按 allocation epoch 核对。
25 字节序列化与最终单节点树一致，原生返回指针一致，返回缓冲区仍存活。
14 条指令、8 个字节码字绑定，213 项损坏证据拒绝、四组公开 CLI 原生重放及
四种实际错误 CLI 调用通过；旧默认四组重放和 63 项损坏证据检查仍通过。
沿用旧 OS/JNI/Bionic、虚拟线程和诊断 helper 服务，没有新增 provider 或
Android 操作。诊断头不等于签名成功，也未解释六头缺失的完整原因；真实 JVM、
完整 service/context、整请求差分、普通六头和完整 signer 仍未验证。
见[诊断返回与清理证据](../platforms/bytedance/tomato/evidence/vm9_native_171_output_20261118.json)。

2026-11-18：原版 outer 构造已在同一 CPU 上继续经过普通 `0x171` VM 的栈
检查器，首次读取构造出的 handler 的 `+0x50` 成员并写入 R2。四组控制覆盖
两个基址及显式 NULL class / NULL static ID 输入；复用既有 JNI Services，
原版 evaluator 返回 0。读取位于 `+0xfae4c/0x10820418` 和原生 `+0x16f96c`，
成员引用计数保持 2，128 字节 handler 不变。185881/185914 个指令观察点
包括 provider 边界；既有 libc 系统调用被显式记录。9 条指令、1 个字节码字
绑定及 63 项损坏证据拒绝通过。观察器在 `+0x16f978` 停止并设置结束哨兵，
没有发生 callback 返回；现有 outer continuation 最终检查通过。合成 JNI
场景、旧 OS/诊断服务和匹配 Bionic 的限制均保留。真实 JVM、完整 service
语义、packed context 首次读取、序列化/成功清理、六头和完整 signer 仍未
验证；生产 signer 和 Android 状态未修改。
见[context 成员读取证据](../platforms/bytedance/tomato/evidence/vm9_native_171_context_load_20261118.json)。

2026-11-18：既有原版 outer 构造输出已在同一 CPU 上接到普通 `0x171` 回调选择，
停在 `+0x2830c4` 首指令之前。四组控制覆盖两个基址和 absent/sdk_30 属性；
空普通缓存由原版 getter/引用复制填入同一 root，共享计数 1→2，guard 随后释放。
选择的 context 是该次构造的 service_refs handler，四个引用成员有效且 128 字节
摘要保持不变；URL/头树计数均为 3。continuation 未预置对象或缓存。
8 条指令绑定、42 项损坏证据拒绝及双 ELF CLI 重放受到新验证器约束。
上游仅增加显式私有 runner，默认执行和最终返回检查保留。本批继承旧 outer 的
OS/JNI、虚拟线程及诊断 helper 服务，不能与无内部 helper 替换的 tag-only
模式读取控制混同。普通 callback/请求 VM、context 消费、业务语义、六头与
完整 signer 仍未验证，没有 Android 操作。
见[构造图交接证据](../platforms/bytedance/tomato/evidence/vm9_native_171_constructed_graph_20261118.json)。

2026-11-18：普通 `0x171` 路径已进入请求字节码，并闭合首次模式读取：
`+0xf7e08/0x03024001` 解码为 R1 = s32[R4+24]，原版 `+0x170308`
读取打包块 `+0x18` 的 4 字节，`+0x17030c` 写入 R1=`0x171`，在下一次
字节码获取前停止。四组、两个基址控制各执行 34029 条 VM 入口后原版指令，
保留 443 次 cursor 状态记录和轨迹/代码摘要；非零 mode padding 未混入读取。
5 条指令、1 个字节码字及 50 项损坏证据拒绝通过，公开 CLI 支持双 ELF 重放。
没有增加 OS/JNI provider，生产 signer 未修改。context 槽和两个 tag-only
对象区域均受读取检查保护，尚未被读取；真实业务参数、完整 context、callback
返回/成功清理、六头与完整 signer 仍未验证。私有的更长探索停在运行时初始化
`pthread_create`，该边界尚未闭合，不计作通过结果。
见[首次模式读取证据](../platforms/bytedance/tomato/evidence/vm9_native_171_mode_read_20261118.json)。

2026-11-18：普通 `0x171` 路径已在四组合成控制上继续执行通用 VM 初始化的
115 条连续原版指令，停在 `+0x1684f0` 之前。两个基址、registry/fallback、空
context 和已有 reader 状态下，32 个虚拟寄存器槽及 PC 槽均匹配现有模型，
对应前缀/分配/锁摘要保持一致。新增代码段绑定和 34 项损坏证据拒绝通过，公开
CLI 支持固定双 ELF 重放。显式观察 harness 只延长测试停止位置，上游默认
控制保持原边界；生产 signer 未修改。模型输入仍为局部原版 callback 状态，
请求字节码、完整 context、返回/成功清理、真实六头和完整 signer 仍未验证。
见[通用 VM 初始化证据](../platforms/bytedance/tomato/evidence/vm9_native_171_vm_prelude_20261118.json)。

2026-11-18：普通包装器经原版输入转换、`0x171` child 分发与 `+0x2830c4`
包装器，已在 12 组合成控制上到达 VM `+0x168324` 首条指令之前。
registry/fallback、空目标跳过、空 context 与已有 reader 路径均保留正确 context、
模式及引用计数。包装器定义的打包/保存区域与五个 VM 参数寄存器匹配既有 Python
caller；模式槽高 32 位保留预置字节。context 在打包块 `+0x20`，不能与 VM
直接 `x3=image+0x35e690` 混用。新增 28 条指令、3 段代码、1 个 handler 虚表
重定位绑定和 54 项损坏证据拒绝通过；公开 CLI 已逐项重建 12 组冻结结果。
上游 fixture 仅提取共享构造。全部对象/输入仍是合成控制，wrapper 比较以已观察的
局部边界状态为模型输入；未执行 VM prelude/字节码、callback 返回及成功清理。
没有 Android 操作或新增 hook；真实六头、整请求差分和完整 signer 仍未完成。
见[VM 入口交接证据](../platforms/bytedance/tomato/evidence/vm9_native_171_vm_handoff_20261118.json)。

2026-11-18：普通包装器 `+0x27ed14` 的 32 组原版代码回放，经 `+0x27f84c` 构造
URL/头树，再以 `0x171` 经 child 虚调用到达 `+0x27dd04` 入口。19 组在该入口
之前停下，13 组返回零且临时分配全释放；URL/树引用计数为 2，输出槽为 FP-0x48，
没有假定其初始内容。CRLF 交替键值、尾分隔符、奇偶片段、空键值、重复键、大小写、
空格、二进制字节及 NUL 边界已验证；单行冒号格式不自动拆成键值。
21 条指令、3 段代码、1 段数据、11 个导入、1 个重定位及 91 项损坏证据拒绝通过。
公开 CLI 可用固定 Metasec/Bionic 重新回放全部冻结结果。合成 warm root/child、
TLS 和诊断状态；匹配 Bionic 执行无竞争 mutex/比较，内存服务使用显式 provider。
没有 Android 实验，没有内部 helper stub；child/VM、成功返回清理、整请求差分、
真实业务执行、六头与完整 signer 仍未验证，`0x171` 仍不能替代成 Java 的 `0x138`。
见[原生输入转换证据](../platforms/bytedance/tomato/evidence/vm9_native_171_inputs_20261118.json)。

2026-11-18：已将实际注册入口 `libmetasec_ml.so+0x27d288` 的原版代码接到现有
`+0x271998` 适配器。受测 `ws` 前缀（忽略 ASCII 大小写）构造第二输入 +
`\r\nURL\r\n` + 第一输入的文本，以单参数块到达 `+0x27ecbc`；其余受测输入以
原始两输入字到达 `+0x27ed14`。原版字符串解码得到 `5256` 并还原两个目标。
70 组隔离仿真逐项匹配查询串查表校验、context/TLS 更新、参数块及现有 Python
适配器的保留帧和寄存器；52 条指令、16 段代码、3 段数据、3 个导入和 1 个重定位已绑定，
87 项损坏证据拒绝检查通过，公开 CLI 可用原版 ELF 重新回放。
对象、TLS、输入及三个 libc provider 均为合成控制；回调函数体和前缀分支后续未执行，
没有 Android 实验。包装器到 `+0x27ed9c`/`+0x27f84c` 的调用仅静态绑定。
真实业务执行、六头及完整 signer 仍未验证。
下游静态连接显示 `+0x27f84c` 使用外层 singleton 的 child `+0x18` 和虚表 `+0x20`，
传入 `0x171`；若符合既有构造图类型，该槽重定位到 `+0x27dd04`。实际对象/调用尚未
观察。Java facade 模型的模式为 `0x138`，不能据共享 dispatcher 假定两种模式等价。
见[注册入口交接证据](../platforms/bytedance/tomato/evidence/vm9_registered_security_handoff_20261118.json)。

2026-11-18：原版 Cronet 派发在请求标志为零时优先选择非空原生回调，槽为空才进入
JNI 桥；请求 `+0x530` delegate 字段的构造写入与转发读取已静态绑定。两个独立只读
窗口共 4 次确认原生槽指向 `libmetasec_ml.so+0x27d288`，其中两次入口前 64 字节与
原版 APK 完全一致。身份/正/null/不可读控制、8 个 Cronet 代码窗口绑定、源码重建、
完整清理及各窗口进程存活检查通过；没有 hook、签名调用、注册或页面操作。
32 组原版派发块隔离仿真、45 条指令、5 段代码摘要、2 个重定位及 57 项损坏证据
拒绝检查通过，原生回调/JNI 执行数零。实际请求标志、分支执行、六头及完整 signer
仍未验证；下一步优先追踪已注册的原生入口。
见[原生安全派发证据](../platforms/bytedance/tomato/evidence/vm9_cronet_native_security_selector_20261118.json)。

2026-11-18：原版 `+0x389368 -> +0x38ed48` 的直接尾调用将入口 x2 经 x5 传递，
条件虚表路径选中已知尾包装器时转为安全桥 x4；绑定布局/trampoline 仅静态定位。
24 组合成对象仿真执行 7 段原版代码，每组走三个辅助函数的受控路径；12 组转向另一
分支，4 组停在初始化调用前，8 组到达安全桥，范围外调用执行数零。轨迹逐项重建，
39 条指令、7 段代码摘要、2 个重定位及 44 项损坏证据拒绝检查通过。
实际 caller 类型、虚表身份、业务参数值及六头/signer 仍未验证；没有新增 Android 实验。
见[条件候选路径证据](../platforms/bytedance/tomato/evidence/vm9_cronet_candidate_security_route_20261118.json)。

2026-11-18：原版请求级安全桥先检查第五参数 x4，空值在进入 JNI 前直接返回。
静态尾包装器经 owner `+8` 与 delegate `+0x28` 槽转发，保留 x1..x4；owner 表
`+0x38` 槽的重定位绑定成立，但其业务执行未观察。17 条指令、3 个相对重定位、
原版 APK/ELF 字节、12 组原版前缀隔离仿真逐项重建及 29 项损坏证据拒绝检查通过。
3 个空值返回，9 个非空停在首外部调用前，外部调用执行数零；没有 Android 实验。
Ghidra 六函数批次超时，3 份部分结果不计完整成功，分析进程已清理并复核。
真实业务 x4、未触发原因、初始 110 根因与完整六头/signer 仍未验证。
见[安全桥条件证据](../platforms/bytedance/tomato/evidence/vm9_cronet_security_bridge_guard_20261118.json)。

2026-11-18：确认应用 provider 继承 `AbsCronetDependAdapter` 的安全方法，经
`NetworkParams.tryAddSecurityFactor` 转调静态回调字段；父类及 NetworkParams 的
DEX 与原版相同，应用类所在的整份 DEX 则不同。独立 3 秒只读快照确认下游已注册
`ms.bd.c.r4`，身份/类型、正/null 控制、源码绑定、完整清理和进程存活检查通过。
该快照不连接此前业务响应，也不证明回调执行；普通 Cronet 六头与 signer 仍未闭合。
见[下游回调证据](../platforms/bytedance/tomato/evidence/vm9_cronet_downstream_callback_20261118.json)。

2026-11-18：后续同响应 Java 窗口确认现有 manager 单例、接口 provider 和反射
adapter 均存在，当前 false 优化标志选中反射路径；所选对象类型可解析返回 Map 的
公开安全方法。仅直接读字段，没有调用单例 accessor、注册或签名方法。
45 秒、710 行、65 次创建/启动，164 项损坏记录拒绝、原版 DEX 绑定、源码与完整
清理通过；同一正文 110 链保持，安全阶段计数仍为零。采样后为第三本书封面。
结论限于响应时的注册快照，六头与完整 signer 仍未完成。见
[manager 快照证据](../platforms/bytedance/tomato/evidence/vm9_cronet_manager_registration_20261118.json)。

2026-11-18：稳定 JNI 入口确认实际 delegate 的函数表，读取／安全槽分别指向
`+0x201f30`／`+0x202698`，owner 和 Java receiver 身份关联成立。45 秒、683 行、
62 次创建/启动，13 条原版指令、4 段运行时代码摘要与 152 项损坏记录拒绝检查通过。
恢复后的独立 Java 窗口确认同一响应请求的 `context.E` 为 `org.chromium.c`，原版／
测试包相同的 `classes17.dex` 显示它直接转调安全 manager；45 秒、708 行、65 次
创建/启动，133 项拒绝检查通过。两窗口分别保留正文 110 身份链并完整清理，不能跨
进程关联对象；安全回调计数仍为零。异常与无目标响应窗口排除，signal 11 原因未知，
数据保留、恢复健康检查通过。下一步定位安全派发条件和内部 provider 注册；六头和
完整 signer 仍未完成。见[派发／provider 证据](../platforms/bytedance/tomato/evidence/vm9_cronet_dispatch_provider_20261118.json)。

2026-11-18：继续在稳定 JNI 入口只读观察，保存返回值经低 48 位屏蔽后得到 8 个可执行
模块候选，前一条原版 ELF 指令均为调用；首个对应此前定位的回调 helper 调用点。
45 秒、701 行、64 次创建/启动，135 项损坏捕获拒绝、源码绑定与完整清理通过。
静态定位一个 `.data.rel.ro` 相对重定位引用，未证明实时虚表；地址屏蔽也不验证 PAC
或完整栈。采样后为推荐首页，六头及完整 signer 仍未闭合。见
[返回地址候选证据](../platforms/bytedance/tomato/evidence/vm9_cronet_saved_return_candidates_20261118.json)。

2026-11-18：两次完整窗口连接了实际 `CallVoidMethodV` receiver 与既有正文 110
身份链，通用 helper 返回位置为 `libsscronet.so+0x1f009c`。两次各 45 秒，602／740
行、54／68 次创建/启动，123 项损坏捕获拒绝、源码绑定及完整清理通过。
独立只读窗口定位方法缓存槽 `+0x5ef8a0`；候选回调函数仅静态定位，深入的清理超时和
signal 11 窗口均排除。恢复后身份、原始指令与正常卸载/detach 已复核，应用数据保留。
最早 native 生产、拒绝根因、六头和 signer 仍未闭合。见
[JNI/native 边界证据](../platforms/bytedance/tomato/evidence/vm9_cronet_native_boundary_20261118.json)。

2026-11-18：后续窗口把同一个具体响应对象连接到读取完成 buffer 与 adapter，
原版 DEX 语义和 true/false 对照确认 `k()` 为 `wasCached`，本次值为 false。
HTTP 200、HTTPS，同一 buffer/流/RPC/Gson/正文链仍为 110；截图仍显示不安全版本。
45 秒、1,382 行、132 次创建/启动，109 项损坏捕获拒绝检查及完整清理通过。
该标志不能排除更早缓存或 native 拦截，也不证明服务端根因；六头和 signer 仍未闭合。
见[响应元数据证据](../platforms/bytedance/tomato/evidence/vm9_cronet_response_metadata_20261118.json)。

2026-11-18：在原始 Cronet `onReadCompleted` 执行前，其 ByteBuffer 副本已有 110，
随后实际流返回的完整数据块与副本逐字节一致，并连接到既有 RPC/Gson/正文对象链。
request、connection、buffer 和 adapter 身份关联跨线程成立，HTTP 状态为 200。
45 秒、612 行、55 次创建/启动；源码绑定、90 项损坏捕获拒绝与完整清理通过。
采样后截图为推荐首页，不新增拒绝 UI 声明。更早 native/缓存/传输来源仍待定位，
六头、完整 signer 和线上验签未闭合。见
[缓冲区来源证据](../platforms/bytedance/tomato/evidence/vm9_cronet_read_buffer_provenance_20261118.json)。

2026-11-17：两次被动窗口连接了实际 Cronet `inputStream`、StreamParser、
`m90.b`、RPC 包装流、`c.m`、Gson 和正文 F0。parser 返回同一流，流与包装对象
身份链成立；转换后的 110 JSON 与 Gson 输入逐字符一致，解码结果仍是同一正文对象。
两次各 45 秒，46／76 次 Cronet 创建和启动，完整清理；源码绑定及 65 项损坏捕获
拒绝检查通过。没有额外消费业务流或公开正文。原始 HTTP 字节、最早响应生产点和
初始拒绝根因仍未证明，六头、整请求差分、完整 signer 与线上验签仍未闭合。
见[响应流证据](../platforms/bytedance/tomato/evidence/vm9_reader_stream_provenance_20261117.json)。

2026-11-17：被动观察到目标 FullResponse 的 JSON 在原始 Gson 反序列化前已带 `code=110`，
解码结果及 F0 输入保持 110，并用 Android IdentityHashMap 的正反控制连接到同一 Java 对象。
45 秒窗口完成，62 次 Cronet 创建/启动，操作前核对前台包，脚本/session 清理完成。
该结果把拒绝定位到 JSON 解码前；更早响应流、拦截器、原始 HTTP 响应及最初拒绝根因未证明，
正文对象身份不能外推为六头签名回调身份。见
[JSON 来源证据](../platforms/bytedance/tomato/evidence/vm9_reader_json_provenance_20261117.json)。

2026-11-17：新增可复用的被动 reader 观察模式，实际 CLI 在云手机完成 45 秒窗口：
69 次 Cronet 创建/启动；缓存未命中后 `F0` 收到响应码 110，同线程 `y0` 前后
缓存由未命中变为命中，随后查询命中。字段反射修复了同名方法可能遮蔽字段时的漏记，
host 回归及实际窗口通过，卸载/detach 完成。该结果定位本地二次拒绝缓存，尚不证明
最初 110 的网络来源、根因或跨调用对象身份；六头、完整 signer 与线上验签仍未闭合。
见[脱敏证据](../platforms/bytedance/tomato/evidence/vm9_reader_response_cache_20261117.json)。

2026-11-17：当前隧道已恢复云手机 ADB，确认 Android 13/arm64、原版番茄
7.2.5.32 的 APK 摘要与既有记录一致，并成功启动。现有 `27042` 属于其他应用的
16.7.19 Gadget，已通过实际 Java 包名/UID 核对并完成脚本卸载和 detach；临时
forward 已移除。该连接不是番茄捕获入口。原版未开放调试/备份且设备无可用 root，
番茄测试包需独立端口及明确卸载的数据影响；本轮尚未替换应用，所有完整链声明仍未闭合。

2026-11-17：新增有完整操作超时的 Cronet 分层捕获入口，观察客户端选择、请求创建及
安全回调。实际旧 Frida 端点在枚举阶段按 5 秒限时取消，退出码 1，未安装 hook，
清理完成。6 类 host 生命周期、实际 Cancellable 取消、JavaScript 行为/脱敏、完整
bridge 语法、6 项非法 CLI 参数、输出文件保护及既有 capture lifecycle 回归通过。
本轮复查时 ADB 设备与 forward 列表均为空，本机旧 Frida 端口无监听；新探针的 Android
hook 安装和业务窗口仍未验证，普通 Cronet 六头、独立 signer、整请求差分及线上验签
保持未闭合。详见 [捕获入口](../platforms/bytedance/tomato/python/capture_vm9_cronet_route_android_20261117.py)
及 [host 校验器](../platforms/bytedance/tomato/python/verify_vm9_cronet_route_capture_20261117.py)。

2026-11-04：单次固定合成 JNI 初始化样本把三个四字节 JSON parser 读段接到各自
4/4 个先前写事件，写入地址和时序相符；源操作数不匹配，寄存器组无连续四字节
来源，native copy/clone 入口和 JNI string provider 返回均未观察到，来源账本仍为
`copy_chain=none`。更正 probe12/13 的旧计数：165/263 是 `+0x2482cc` 填充调用，
返回 `+0x2482d0`；`+0x248254`/`+0x248430` 的 copy/clone 入口计数为零。签名调用
正常退出，结果长度 10。该结论限于合成样本，不证明原始 Android provider、完整
signer 或 Cronet 六头链。未保留原始指针、操作数或明文。见
[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_copy_writer_join_20261104.json)
和[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_copy_writer_join_20261104.py)。

2026-11-04：**Sample verified**，两轮独立新 rootfs、8 次固定输入调用中，Python
从当前探针使用的合成 JNI 初始化 JSON 第 0 项生成四字节摘要字、第 3 项生成
368 字节编码配置；两份捕获值只用于比较，生成配置 8 次均与原生输入相等，且
完整旧有摘要、解密、RC4、材料、原生密文与关系账本保持。新校验器验证 8 项关系；
37 项错误证据、6 项畸形日志和畸形 CLI 被拒绝。JNI provider 对象到真实 Android
输入内存的指针/返回关系仍未接通；本结果不外推至其他应用 ID、配置值或长度。
查询键、归约叶字节、Android allocator/singleton 等价、完整 signer 和普通
Cronet 六头线上验签仍未验证。未公开初始化配置、操作数、密钥/IV、明文、指针
或操作数摘要。见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_initializer_fields_20261104.json)
和[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_initializer_fields_20261104.py)。

2026-11-04：**Sample verified**，Python 从初始化 JSON 的第 0 项（应用 ID）实际
生成四字节共享字，捕获摘要输入及共享字仅作比较。未过滤的观察器确认实际 VM
目标是 descriptor wrapper `+0x17d2e0`，接到 C 字符串构造器 `+0x248344`；
对象和源指针、包含终止零的五字节复制、四次 JSON 解析器字节读取均通过实际
writer 身份、快照和时间顺序连接。字段相等尚未证明原始 JNI provider 输入
内存归属。两轮全新 rootfs、8 次调用保留全部旧有生成链和最终原生密文对照；
200 项新关系、18 条 ELF 指令、固定 libc 工件及真实 CLI 通过；59 项错误证据、
6 项畸形日志、畸形 CLI 和 15 项非法私有桥输入被拒绝。其他应用 ID/长度、
编码配置更早来源、剩余输入、Android 等价、完整 signer 与六头线上验签仍开放。
未公开初始化内容、操作数、材料、指针或操作数摘要。见
[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_initializer_word_20261104.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_initializer_word_20261104.py)。

2026-11-04：**Sample verified**，两轮全新 rootfs、8 次调用将共享四字节值追到
初始化 tag `0x4000001` 的实际写入；低四字节操作数与三处摘要消费者快照一致。
通过 `+0x24841c` header store、逐字节 writer 身份、源快照和时间顺序接通四字节
clone 来源，其 libc writer 返回 `+0x248434`；更早源 writer 返回 VM 调用位置
`+0x16aa4c`，该次调用的实际目标、复制参数和源值生成仍未恢复。旧的缺失 writer
观察保留其原业务调用窗口范围，不代表初始化阶段没有写入。96 项新关系、5 条
ELF 指令、完整旧有对照和真实 CLI 通过；120 项错误证据、6 项畸形日志及畸形 CLI
被拒绝。已有 Python 私有桥逐字节不变。完整 signer、Android/其他输入等价及
普通 Cronet 六头线上验签仍未验证，未公开操作数、指针或操作数摘要。见
[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_setup_word_20261104.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_setup_word_20261104.py)。

2026-11-04：**Sample verified**，两轮全新 rootfs、8 次调用通过实际 LOAD32、
标量写入及复制的逐字节 writer 身份、快照和时间顺序，将 MD5 中间段及 SHA-1
首末段接到解码/解密前缀；MD5 中间段经过更早 BCP `+0x9aabc` 标量写入和
`+0x9aab8` LOAD32。共享四字节片段来自同一可读写、不可执行映射地址，位于
所观察原生栈和当前 VM 寄存器区之外，但其初始化、生命周期和分配归属仍未证明。
232 项新关系、8 条 ELF 指令、完整旧有对照和真实 CLI 通过；244 项错误证据、
6 项畸形日志及畸形 CLI 被拒绝。既有 Python 私有桥逐字节不变，完整配置生成链
保持。完整 signer、Android/其他输入等价及普通 Cronet 六头线上验签仍未验证，
未公开操作数、指针或操作数摘要。见
[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_prefix_sources_20261104.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_prefix_sources_20261104.py)。

2026-11-04：**Sample verified**，两轮全新 rootfs、8 次调用将配置链收敛到编码
配置、一个四字节观察值及原有归约/查询输入。令 `D` 为 Python 解码结果前四字节、
`W` 为观察值、`P` 为生成明文前四字节，实际构造 MD5 输入 `W || D || W` 和 SHA-1
输入 `P || W || D`；生成密钥、解码结果 `[4:276]` 和明文 `[4:267]` 实际驱动解密、
RC4、Protobuf、选择与 AES 材料链，全部原生比较及完整旧有对照保持。除 `W` 片段
外，捕获摘要输入、配置密文和密钥仅作比较。每个输入环节的独立中间探针均保留。
MD5 中间段追到 VM 标量写入 `+0x17208c` / BCP `+0x9ab2c`，值相等不证明直接
decoder 地址来源或共同原生生命周期。176 项新增关系、7 条 ELF 指令及真实 CLI
通过；183 项错误证据、4 项畸形日志、畸形 CLI 和 17 项非法私有桥输入被拒绝。
共享四字节值和编码配置的更早来源仍开放。完整 signer、Android/其他输入
等价及普通 Cronet 六头线上验签仍未验证，未公开操作数、材料、指针或操作数摘要。
见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_operands_20261104.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_operands_20261104.py)。

2026-11-04：**Sample verified**，配置 AES 密钥推进至实际 12 字节 MD5 输入。
两轮全新 rootfs、8 次调用中，复用已有 digest-reference 模型生成 16 字节原始
MD5 密钥，并实际驱动配置解密、RC4、Protobuf、字段选择和 AES 材料链；捕获密钥
仅作比较。原生 MD5 返回值与解密入口的数据指针、写入事件身份、快照及时间顺序
均匹配。MD5 与 SHA-1 输入三个对应四字节分段均不同；改变/反转输入、十六进制
摘要、仅对解码前四字节或 SHA-1 输入求 MD5 的候选均失败。56 项新增关系、12 条
ELF 指令、完整旧有对照及真实 CLI 通过；167 项错误证据、4 项畸形日志、畸形 CLI
和 16 项非法私有桥输入被拒绝。MD5 的 12 字节输入来源仍开放；四字节 memcpy
与八字节 memmove 的 writer 形状不构成更早来源证明。完整 signer、Android 等价
及普通 Cronet 六头线上验签仍未验证。未公开操作数、密钥、明文、指针或操作数摘要。
见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_md5_20261104.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_md5_20261104.py)。

2026-11-04：**Sample verified**，配置解密推进至实际驱动下游 RC4。两轮全新
rootfs、8 次调用中，复用已有配置 ECB callback 模型，从显式 272 字节密文和
16 字节密钥生成原生 271 字节明文，独立 AES 一致；生成结果的 `[4:267]` 实际
进入 Python RC4，捕获 RC4 输入仅作比较。配置解析、字段选择、AES 材料与原生
密文及完整旧有对照保持。逐字节实际 writer 身份和时间顺序将密文接到早期解码
`[4:276]`，将 RC4 来源接到解密输出；避免用复用地址归因。SHA-1 输入确认是
三段四字节，首末两段分别等于解密和解码前缀；末段仍只追到 VM 标量写入，
中间段来源未闭合。352 项新增关系、23 条 ELF 指令及真实 CLI 验证通过；
233 项错误证据、4 项畸形日志、畸形 CLI 和 12 项非法私有桥输入被拒绝。
配置 AES 密钥与完整 SHA-1 输入仍为观察输入；明确 fixture 不构成 Android
分配器或 singleton 等价，完整 signer 和普通 Cronet 六头线上验签仍未验证。
未公开操作数、密钥、明文、运行时指针或操作数摘要。见
[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_decrypt_20261104.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_decrypt_20261104.py)。

2026-11-03：**Sample verified**，配置 RC4 密钥推进至实际 12 字节 SHA-1 前置数据。
两轮全新 rootfs、8 次调用中，复用已有 Python digest-reference 模型生成的 20 字节
密钥与原生及独立 SHA-1 相等，并实际驱动下游 RC4、配置解析和 AES 材料生成；
捕获密钥仅用于比较。SHA-1 前置数据与归约字节在正序、反序、多重集及 XOR 上
均不相等，直接代换不能生成实际消息。56 项新关系、27 条 ELF 指令及完整旧有
对照通过；126 项错误证据、畸形 CLI、4 项畸形日志及 9 项非法私有桥请求被拒绝。
成功运行是 `run1` 和 `run3`；420 秒超时的 `run2` 被排除，校准 runner 仅将计时器
改为 1200 秒，分别记录两轮 runner 身份与上限。前置数据可见四字节复制加八字节
追加，但更早生成仍未闭合；完整 signer、Android 等价及普通 Cronet 六头线上验签
仍未验证。未公开前置数据、密钥或操作数摘要。见
[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_key_20261103.json)和
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_key_20261103.py)。

2026-11-03：**Sample verified**，配置 RC4 到 AES 材料链完成配对验证。两轮全新
rootfs、8 次调用中，已有 Python RC4 使用实际 263 字节输入、20 字节密钥及零 drop，
逐字节匹配原生及独立 ARC4 输出；全部 263 次加载按地址连续递减。12 个观察字节
从实际捕获的零操作数开始异或归约，保留的反序/异或模型生成实际 Protobuf 消息，
再经已有解析、选择和解码模型派生 AES 材料，独立 Java AES 复现原生密文。
48 项新关系、24 条 ELF 指令、152 项前批材料关系及完整旧有对照保持；93 项错误
证据、9 项非法模型输入、实际畸形 CLI 和 3 项畸形日志均被拒绝。正式两轮均在
420 秒有界运行内正常退出；早期 240 秒超时探索未计入证据。RC4 输入/密钥、归约
字节及查询键仍是运行时输入，完整独立 signer、Android 等价和普通 Cronet 六头线上
验签仍未验证。未公开操作数、材料、key/IV 或其摘要。
见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_configuration_stream_20261103.json)、
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_configuration_stream_20261103.py)
和[模型](../platforms/bytedance/tomato/python/vm9_framesign_configuration.py)。

2026-11-03：**Sample verified**，修正配置比较回归中 `equality_bound` 的过期夹具：
长度上限负例改用不同 payload，另增加两个基址的同对象/共享 payload 原生对照。
170 项差分、5 项回滚检查通过；原有 166 项结果与旧证据逐项一致，模型行为未修改。
见[回归脚本](../platforms/bytedance/tomato/python/verify_vm9_configuration_init.py)。

2026-11-03：**Sample verified**，两轮全新 rootfs 共 8 次调用闭合 FrameSign AES 材料的
配置选择、Base64 解码、substring 拆分和实际加密关系。已有 Python Protobuf 模型
使用 fresh ELF 描述符及实际查询键，从 263 字节消息的两个配置项中选出唯一匹配的
44 字节字段；另一同长度字段不同。已有解码器把自行选择的字段解为 32 字节，
前后各 16 字节对应实际 key/IV，交换角色均失败；独立 Java AES 使用 Python 派生材料
复现全部原生密文。152 项新关系、24 条 ELF 指令和之前完整对照通过；115 项错误证据、
实际畸形 CLI 与 3 项畸形日志被拒绝。更早的 368 字节输入解码为 276 字节，但两条
44 字节字段均不是该结果的直接切片；263 字节消息的 VM 写入位置已观察，上游转换
尚未闭合。旧对象地址上的 C-string 构造记录已经过期，不能据此归因当前 AES 材料。
未公开任何编码/解码材料、key/IV 或其摘要。配置消息及查询键仍为观察输入；
76 字节组件、剩余 seed 操作数、Android 等价、完整 signer 和普通 Cronet 六头线上验签
仍未完成。见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_aes_material_20261103.json)
及[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_aes_material_20261103.py)。

2026-11-03：**Sample verified**，另两轮全新 rootfs、8 次调用把 FrameSign 块密钥
及反馈尾部接到已有 Python ELF 配置构造器。`+0x3dec74` 的 20 字节 BSS 与
fresh ELF 构造结果相等；前 16 字节逐字反转成为 XTEA 密钥，后 4 字节成为反馈
尾部，反馈前半段来自缓冲区指针低四字节。使用独立构造结果实际加密的 Python
桥仍逐字节复现全部 93 字节原生 AES 输入；旧有对照保持，新增 96 项关系，
41 项错误证据、畸形 CLI 和 2 项畸形日志被拒绝。原生配置构造器本次未直接追踪，
块前数据、地址、前缀立即数、AES key/IV、独立 signer 与线上验签仍有边界。
见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_block_inputs_20261103.json)
及[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_block_inputs_20261103.py)。

2026-11-03：**Sample verified**，FrameSign 块阶段已恢复为 32 轮 XTEA-CBC，
数据字大端、密钥字小端；两轮全新 rootfs 共 8 次调用的 88 个块逐字节相等，
四组错误轮数/字节序/反馈候选均不匹配。最终前缀由块密文首字节经 VM 立即数
XOR 得到；后缀是初始反馈缓冲区地址的小端低四字节，亦为初始反馈的前四字节。
显式传入本次观察参数的 Python 模型，经私有内存管道重建全部 93 字节，均与
原生构造和 AES data 相等。此前完整对照保持；292 项关系、29 条 ELF 指令、
63 项错误证据、12 项模型无效输入、两个实际 CLI 负例与 3 项畸形日志通过。
密钥/反馈完整生成、Android、其他输入、独立 signer 和普通 Cronet 六头线上验签
仍未闭合。见[证据](../platforms/bytedance/tomato/evidence/vm9_framesign_block_cipher_20261103.json)、
[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_block_cipher_20261103.py)
与[显式参数模型](../platforms/bytedance/tomato/python/vm9_framesign_block_cipher.py)。

2026-11-03：后续 allocator 回调只读追踪修正恢复实验的对象归因。两轮独立运行、
共 8 次调用中，`+0x25438c` 每次返回请求长度 `0x70`、位于 `handle+0x70` 的新
对象；同地址进入 `+0x2550cc` 清理函数。监视区间是新对象的前 16 字节，
不支持此前“manager 持久状态”的假设；恢复写入干扰临时对象，不能闭合动态
签名来源。8 次输出均与原 A-B-A-B 对照相同。原 ELF 的 allocator 参数/返回
路径另核对 7 条指令，最终释放和 manager 完整边界仍未验证。见
[归属证据](../platforms/bytedance/tomato/evidence/vm9_framesign_watched_region_ownership_20261103.json)
和[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_watched_region_ownership_20261103.py)。

2026-11-03：FrameSign 状态区边界恢复实验完成同构建配对验证。相同 49 字符输入、
handle2、一轮 setup 和每实例四次调用下，控制组保持既有 A-B-A-B；恢复组出现
有效/空/有效/有效，后两次动态摘要偏离对照。此前四次独立实验复现同一序列。
第二次调用观测到 4 个目标区间写事件、2 次边界恢复，返回时 16 字节与保存值相同；
恢复器没有逐条覆盖 libc 指令，不能宣称完全冻结。`+0x255110` 的零写位于递归
对象清理路径，15 条静态指令通过原 ELF 字节及 PT_LOAD 映射核对；manager 长度、
该区间的对象归属和直接动态来源仍未知。生产 signer 未引入恢复操作。见
[脱敏证据](../platforms/bytedance/tomato/evidence/vm9_framesign_state_boundary_restore_20261103.json)
和[校验器](../platforms/bytedance/tomato/python/verify_vm9_framesign_state_boundary_restore_20261103.py)。
完整 signer、整请求 native/Python 差分和线上验签仍未完成。

2026-10-26：同一 probe 进一步记录 child ABI 与 facade cleanup。两基址的 child
入口均为 `x0=receiver`、`x1/x2=转换后的栈引用`、`x3=0x138`、`x8=栈上的 output
reference`；owning VM 返回后执行 `+0x17baa0/+0x17bac0` facade epilogue，最终到
oracle STOP，仍为 7,751 条 native 指令、5 次真实 memcpy、无 runtime-table 读写和
无 unmapped。target/tree/provider/input 仍是显式 fixture，不能把该返回当作 signer
输出或 normal target 证据。见 [same-CPU facade child evidence](../platforms/bytedance/tomato/evidence/vm9_native_bootstrap_java_facade_child_20261026.json)。

2026-10-26：记录 normal facade fixture 的 receiver/vtable/target 读取 provenance。
未改写 synthetic receiver 虚表的 fresh native facade 在两个 image base 都依次读取
`facade+0x18 → receiver+0 → vtable+0x20`，PC 偏移为 `+0x17b9e4`、`+0x17ba24`、
`+0x17ba38`，随后调用显式 request service；调用期间没有 native 写入这三个 chain
field，它们来自 `facade.fixture` provider。该结果只闭合 fixture-path 的 native
读取链；receiver、vtable、JNI/provider 和 request service 仍是 synthetic，normal
child handoff、whole-request differential、standalone signer 与线上接受保持未验证。
见 [facade target provenance evidence](../platforms/bytedance/tomato/evidence/vm9_java_facade_target_provenance_20261026.json)。

2026-10-26：在同一 fresh native bootstrap CPU 上继续 Java facade 到 owning VM。
两个 image base 均执行 facade `+0x17b8f8`、人工安装的 child `+0x27dd04`、owning
VM `+0x2830c4` 和 VM `+0x168324`。修正为已接受的一节点树布局并复用
bootstrap-owned mapped stack 后，各执行 7,751 条 native 指令并返回 oracle STOP；
callback object 进入真实 `+0x347f60` memcpy PLT 五次，runtime-table canary 无读写、
无 unmapped。receiver/tree、child target、JNI provider 和 URL/header 仍是显式 probe
输入；oracle STOP 与 x0=0 只证明 continuation 返回，因此不计为 normal target、
whole-request differential 或 signer 输出。见 [same-CPU facade child evidence](../platforms/bytedance/tomato/evidence/vm9_native_bootstrap_java_facade_child_20261026.json)。

2026-10-26：人工 facade child continuation 执行到 native return。
在 synthetic receiver 上补齐有限 mutex/tree 字段后，两个基址的注入 `+0x27dd04`
各执行 11,617 条 native 指令，在 `+0x17bac0` 返回 `x0=0`，没有 unmapped
访问。target、输入对象和 provider 均为 verifier fixture；零返回不是 signer 输出，
不计作 normal facade handoff 或 whole-request differential。见
[child continuation evidence](../platforms/bytedance/tomato/evidence/vm9_java_facade_injected_child_continuation_20261026.json)。


2026-10-26：补齐 native facade→child 的人工 target ABI 观察。
独立 fresh ELF probe 在 `+0x17b8f8` 执行期间将 synthetic receiver 的虚表 `+0x20`
改为 `image+0x27dd04`，两个基址均在 child 第一条指令前到达目标；入口寄存器为
`x0` receiver、`x1` URL reference、`x2` header reference、`x3=0x138`、`x8` output
reference，stack delta 为 `0xb0`。child 未执行，故不计作 normal facade handoff、
whole-request differential 或 signer 成功；JNI/allocator/input 仍为显式 fixture。见
[injected child-entry evidence](../platforms/bytedance/tomato/evidence/vm9_java_facade_injected_child_entry_20261026.json)。


2026-10-26：完成 registry guard reset 的独立观察分支。
在两个 fresh native bootstrap 返回后，仅将 `image+0x3d1558` 从 native 写入后的
`01010000…` 清为零，再进入真实 `+0x27dd04`；request 观察到 source low bit 为 0，
但仍到达 `+0xf8554`，`+0xf858c` 仍产生 -5，最后仍返回一节点 `X-Neptune`
诊断树（value `-5|`）。两基址均完整返回；callback ledger 为 37，较正常 guard=1
continuation 的 29 项增加 8 项，故不能作正常路径等价或 signer 成功证据。实验只改写
一个 guard，未合成 table/vtable/snapshot，也未产生七神 header；guard 业务含义、
whole-request Python 差分、fresh signer 与线上验签仍未完成。见
[guard-reset evidence](../platforms/bytedance/tomato/evidence/vm9_request_output_reference_guard_reset_20261026.json)。


Chronological record of the Tomato / ByteDance signer work. Each entry states what was
reproduced, how many controls / negatives / rollback checks passed, and links the detailed
report. Moved verbatim out of the README; wording, numbers and links are unchanged.

2026-10-26：验证 bootstrap/request 的 output reference 实际内容。
两个基址各 1 次 fresh native continuation 返回合法 owning configuration tree、
counter 1，但树中只有 X-Neptune；原始 formatter 使用 signed status -5 和空 C string，
并非完整签名输出。native guard 从零经 `+0x32d514`（caller `+0x15e714`）置一，
request bytecode `+0xf8404` 因 `+0x3d1558` 低位为 1 跳至 `+0xf8554`，
`+0xf858c` 产生 -5。格式化、树插入与最终 pair 写入的对象/长度/hash 均闭合；
每次记录 29 个完整 VM callbacks。两组 continuation metadata 与上一份 dispatch-table
evidence 一致。无生产 owner、guard、callback/table 或 snapshot 输入改动；guard 的
业务含义、whole-request Python 差分、fresh signer 与线上验签仍未完成。见
[output-reference evidence](../platforms/bytedance/tomato/evidence/vm9_request_output_reference_fresh_20261026.json)。

2026-10-26：纠正五个 dispatch relocation slot 的 external-owner 推断。
真实原生地址修正 `-0x106e988` 把编码 addend 指向 `.data.rel.ro` 的五张表，
共 234 项 ELF relative relocation；handler word 减去 live `0x33dc5` bias。
两基址 **468 项 native selector controls** 与 **4 次 bootstrap/request runs**
通过；每次完整观察 1,191 次 table load/BR，有无外部 canary 页时，ledger、返回和
其余 6,168 个物理页的完整地址/字节流 SHA-256 一致。正式观察在新增 hook 后清理 Unicorn translation cache，
避免漏记 bootstrap 已翻译的 block。现有生产 dispatcher/nested owner 已有同类
运算，无生产代码修改、native snapshot 或 table/vtable 合成。这移除这些表的
“缺少外部 owner/writer”阻塞，未完成 whole-request 差分、fresh signer、live JVM
或线上验收。见 [dispatch encoding evidence](../platforms/bytedance/tomato/evidence/vm9_dispatch_table_encoding_fresh_20261026.json)。

2026-10-24：重跑 fresh ELF outer signer native 边界。两个 image base、四种 SDK
property profile、重定位 stack/mapping 共 **10 项 native controls** 通过；root flag、
singleton/configuration、child/handler callback pair、recursive publication mutex、warm
getter reuse 和 JNI/destructor publication ledger 均符合原生。该运行没有使用 native
输入快照、JVM 或真实 OS 线程，allocator/property/clock/virtual-thread 仍是显式服务，
因此只记为 **Sample verified** 边界，不计入 fresh Python signer、完整 Medusa 或线上
验签。见 [VM9 progress checkpoint](../platforms/bytedance/tomato/VM9_PROGRESS.md)。

同日复核 `cv-cat/DouYin_Spider` 上游 HEAD `d151f9c`。新增的浏览器 dtrait/指纹、
Cookie wire 顺序、creator `msToken`、passport 二次验证和直播 protobuf 仍是
**Static only** Web 会话/传输证据；源码没有发现六/七神 App header 生成器，
Douyin `verified_live_requests` 仍为空。见 [DouYin_Spider review](../platforms/bytedance/douyin/DOUYIN_SPIDER_REVIEW_20261015.md)。
2026-10-26：callback-object continuation 的 writer 观察升级为 source-slot provenance。
修订探针在 VM handler 入口先捕获 register-file backing，再记录 `+0x171268` 的
store。两个 image base 都确认 backing `0x7000ec58` 的 slot 3 经过多次 VM 写入，
目标对象 field 0 的 store 使用 `x14&0x1f=3`，读取值与写入值逐项一致，并在
slot-3 历史中找到最终的 `image+0x347f60` memcpy PLT target。该结果闭合了当前
continuation 内的 VM slot 来源，不等同于完整 runtime-table owner、whole-request
差分、fresh signer 或线上验收。见 [callback-object trace](../platforms/bytedance/tomato/evidence/vm9_bootstrap_request_callback_object_trace_fresh_20261026.json)。
2026-10-24：新增显式 provider-effect rollback journal。`EffectJournal` 为
allocator/JNI/OS provider 提供可嵌套 checkpoint、逆序 undo 和外层提交边界；native
service bridge 可选恢复 provider undo 与 live CPU 页面，owning request VM 可在异常时
回滚当前请求 checkpoint，并由 child dispatcher 和 Java facade 向下传递；signer-handle
发布、request state elapsed getter、second VM realtime wrappers、request-environment
acquisition/StringObject/logger callbacks、JNI availability wrapper、second-VM
allocation callback、formatter、consumer free tail、StringObject assignment 与两个
configuration reference getters、cached JNI reference callback、JSON string 与
StringObject fill、empty JSON reference、token string transform、token digest、token
cipher、token append tail、Base64 tail 与 allocated-printf paths 也可回滚
JNI/clock/allocator provider 效果。31 项 Python controls 与 31 项 rollback
controls 通过，默认
page-only 行为保持；该批不计入 native 差分，不声称 live JVM、真实 mapping 拓扑或完整
signer。见 [provider-effect report](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6255-explicit-provider-effect-rollback-journal2026-10-24-asiashanghai)。

同日 `GuestOS` 高层 map/unmap/name/protect 与 `register_os_region` 接入同一 opt-in
journal，4 项 Python controls、3 项 rollback controls 通过；mapping owner 的页面、
metadata 与游标可按 checkpoint 恢复。该批不计入 native 差分，不声称真实内核拓扑或
完整 allocator rollback。见 [GuestOS effect report](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6256-guestos-mapping-owner-effect-rollback2026-10-24-asiashanghai)。

`register_os_region` 同步接入 owner journal；2 项 captured-checkpoint controls 与 2 项
rollback controls 通过，恢复 region pages、arena metadata、mapping list 和游标，并覆盖
lifecycle malloc owner。该批
不计入 native 差分，不声称 fresh allocator 或真实内核拓扑。见 [region effect report](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6257-allocator-region-registration-effect-rollback2026-10-24-asiashanghai)。

The latest bounded root factory/caller runs from fresh ELF/TLS/reference
inputs without native entry snapshots. Eight controls match all32 terminal
slots and ordered effects (206 allocations/93 frees for the full factory).
Real allocator boot, outer signer/handle and fresh request signing remain
open. See the [root initialization report](platforms/bytedance/tomato/ROOT_INITIALIZATION.md)
for reproducible checks and the exact boundary.

Outer startup now independently reproduces the default main-thread caller and three deferred worker descriptors; worker TLS/support prefixes and executor context initialization are also verified. Condition/queue/executor scheduling now adds 256 native controls, including same-fresh-startup idle worker wait/stop/argument cleanup. All six default initialization callers now pass 24 fresh cold/hot controls. Their serial task composition passes four further controls, including 48 nested returns per cold execution and six distinct mapped regions. The earlier partial-arena once-completion claim is corrected. The same fresh startup now runs its nonempty default queue through all six task bodies, wait/stop, normal return and argument cleanup in four native controls; eight new rollback checks and eight idle-worker regressions pass. A further same-startup control runs the explicit bionic key cleanup phase and releases empty support/wrapper after argument cleanup; 20 key-dispatch and eight support-destructor controls pass. Emulated-TLS array cleanup, fallback chains, nonempty support loops and the actual registry tree destructor now add 62 native controls and 13 rollback checks, including fresh registration/key and actual registry init/exit compositions. Real executor shared/weak release and the matching-libc guest pthread_exit state machine add 70 native controls and 11 rollback checks. A same-fresh-startup nonempty worker now also completes the full guest joinable exit branch after its six default tasks. Detached list removal and owned guest mapping release are verified separately. Explicit allocator/TLS/OS services, unknown callbacks and support-associated state types, real thread creation/termination, real allocator boot and fresh request signing remain unfinished. See the [startup report](platforms/bytedance/tomato/STARTUP_INITIALIZATION.md).

番茄 JNI 后续检查点已验证原始 A JNI_OnLoad 返回、同次六个默认 caller / 48 嵌套
返回、wait-stop 和 argument free。新增 **2 个同次 TLS cleanup、2 个 guest joinable
exit 观察**，实际 support slot 清零并依次释放 argument/payload/wrapper；到达显式 OS
exit 服务。B 在两个基址运行原始 constructor/factory，自然返回并各发布 **121 个
非空 descriptor**；另 242 个 Python lookup 控制消费 native 生成 root，不能作为独立
Python factory 证明。独立 XOR prefix 另有 82 个对照（含两个实际 ELF blob）及 8 个回滚
通过，仍停在 reader 前；另两次 actual reader 在 Python XOR 输入下返回 0；
当时完整 Python reader AST 对照为 0。独立 u32 原语新增 258 个对照/7 个回滚；有符号 i32 原语另通过
1336 个对照/10 个回滚，失败时保留输出。section envelope/排序与
通用 custom/function/export/start/data count 新增 202 个对照/12 个回滚（含 8 项
实际 ELF section 输入）。后续 vector 扩容与 type section 又通过 102 / 372 个对照、
34 个回滚，包含 4 个实际 ELF 输入控制。回调参数/状态/type cells 已核对，返回仍是
受控服务。section 2 的 function/global import 又通过 254 个对照、14 个回滚，
含 6 项实际 ELF 输入；完整 1/2/3/7/12 组合每基址 300 次回调一致。后续 u64 读取通过
1438 个对照/10 个回滚，table/memory import 通过 234 个对照/15 个回滚；其中 6 项
为实际 function/global 输入加合成 table/memory，核对 19 字节 limits，转换临时指针。
section 4/5 定义又通过 **266 个对照、18 个回滚**，复用 limits 解析并独立启用；
数量/条目回调、import 索引偏移和 uint32 回绕一致。样本没有真实 section 4/5，
6 项组合使用实际 function/global 输入加合成定义，完整选取组合每基址 306 次回调。
有符号 i64 又通过 **1480 个对照、10 个回滚**；section 6 与初始化表达式通过
**390 个对照、26 个回滚**，其中 10 项含真实 ELF global 输入。独立 global 开关
与 16 字节显式工作区保留 end-only 的局部高字语义；GOT 操作码表重定位已对照。
真实 section 6 有 22 项，完整 1/2/3/6/7/12 组合每基址 455 次回调一致。
section 10 又通过 **228 个对照、15 个回滚**，包含 6 项真实 code 输入：121 个
函数体、54533 个原始指令字，完整选取组合每基址 55351 次回调。独立启用开关
和回调预算已验证；这里只读取指令字，尚未执行指令或构造实际 AST。
section 9 空元素列表、section 11 data 与独立 expression helper 又通过 **450 个对照、
33 个回滚、16 个 abort 边界检查**，其中 6 项含真实 ELF data；完整选取组合每基址
55369 次回调。两类 section 独立启用；非空元素列表的原生 abort 分支仍拒绝。
section 0 的五类特殊 custom 又通过 **860 个对照、32 个回滚**，含 10 项真实 ELF
custom 输入；全部实际 section 组合每基址匹配 55369 次回调。特殊 custom 默认关闭，
要求独立八字节工作区和每段记录预算。全量 AST 和完整 reader 仍未恢复。
实际 type/start/local group 数量/raw-word 五个 callback 与临时 callback 清理又通过
**308 个原生/Python 对照、54 个回滚**，含 32 项真实 ELF 类型输入。原生实际
vtable 执行，核对节点内容、分配/析构/free 顺序与每个副作用时的容器状态。
随后恢复 slot `+160` 的 176 字节 data record 容量预留、反向搬移和 `+2cc1ec`
非 deleting 析构：新增 **176 个对照、30 个回滚**，合成输入在两个基址均通过。
嵌套 vector 转移、目标 padding、发布和倒序释放一致。
随后 slot `+140` 的 data record 创建与追加通过 **148 个对照、105 个回滚**；
内嵌结果 sentinel、u32 截断、扩容发布和临时释放与原生一致，全部输入合成。
随后 slot `+158` 的 payload 写入与 parser length 参数修复通过 **104 个 AST 对照、
34 个参数对照、30 个回滚**，含 6 项实际 ELF payload 与 2 项实际 section 输入。
零长度保留原 payload；非零写入最后记录，扩容发布和释放顺序与原生一致。
随后 slot `+148/+150` 的 data expression frame、u32 修补和树节点删除通过
**148 个对照、36 个回滚**，全部输入合成。保存原始字节长度、左右旋转、释放顺序
及连续删除与原生一致；树 payload 的检查宽度修正为 4 字节。
随后 slots `+f0/+100/+108/+110/+118` 的零字、element 容量预留/创建/表达式
通过 **282 个对照、159 个回滚**；184 字节记录、144 字节嵌套记录的搬移和
倒序清理与原生一致，全部输入合成。复用同一 frame/raw/tree owner。
随后 slots `+120/+128/+130/+138` 的 element 结果类型、嵌套容量预留和
表达式创建/结束通过 **230 个对照、133 个回滚**；完整 u64 类型值、144 字节
记录的转移/释放和连续创建扩容与原生一致。六组旧回归 JSON 逐字节一致。
随后 slots `+c0/+c8/+d0/+d8/+e0/+e8` 的 instruction predicate、结束和
四种带类型常量通过 **398 个对照、122 个回滚**。返回 0/1、保留最外层 frame、
tag/数值分步扩容与原始浮点位一致；七组旧回归 JSON 逐字节一致。
随后 slots `+b8/+f8` 在已有 144 字节布局上追加 local group、结束并保存长度，
通过 **252 个对照、37 个回滚**。完整 u64 类型、u32 累计回绕、扩容与释放一致；
八组旧回归 JSON 逐字节一致。
随后 `+50` 恢复 function 创建、独立类型缓存与 144 字节记录清理，通过
**188 个对照、136 个回滚**。输出与缓存分别深拷贝类型，扩容、padding 和
析构顺序与原生一致；九组旧回归 JSON 逐字节一致。
随后 `+a8` 恢复 code-begin、双修补树处理和 56 字节 child 追加，通过
**284 个对照、100 个回滚**。logical function 选择、metadata、raw 起点、frame、
padding 与扩容释放一致；十组旧回归 JSON 逐字节一致。
随后 table `+58/+60` 恢复容量预留、48 字节记录与独立缓存，通过
**184 个对照、77 个回滚**。实际入口栈提供被复制的 padding；guest 字节没有
屏蔽，十一组旧回归 JSON 逐字节一致。
随后 memory `+68/+70` 恢复 40 字节记录、完整 descriptor 与独立缓存，通过
**272 个对照、65 个回滚**。两种默认 maximum、目标 padding 和搬移/析构
与原生一致；十二组旧回归 JSON 逐字节一致。
随后 global `+78/+80` 恢复 176 字节记录、24 字节独立缓存与记录析构，通过
**328 个对照、120 个回滚**。完整 type、mutable 低位、vector 转移与清理
顺序一致；十三组旧回归 JSON 逐字节一致。
随后 global expression `+88/+90` 恢复 frame、raw fixup 与完整 64 位 end，
并支持 global 内联 AST 的 local/结束回调，通过 **212 个对照、54 个回滚**；
十四组旧回归 JSON 逐字节一致。
AST 字符串复制基础另通过 **68 个对照、12 个回滚**，供后续 import/export 回调复用。
见 [字符串复制报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#627-ast-字符串复制基础2026-10-10-asiashanghai)。
Export AST 回调、五类节点克隆/删除与仅含 export 的输出清理另通过
**362 个对照、247 个回滚**，16 组旧回归 JSON 逐字节一致。
见 [export 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#628-export-ast-回调与专属输出清理2026-10-10-asiashanghai)。
五类 Import AST 回调与仅含 import 的输出清理另通过 **858 个对照、410 个回滚**；
17 组旧回归 JSON 逐字节一致。
见 [import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#629-import-ast-回调与专属输出清理2026-10-10-asiashanghai)。
完整 output wrapper 清理另通过 **330 个对照、214 个回滚**；旧 import/export 两组回归逐字节一致。
见 [output 清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#630-完整-output-wrapper-清理2026-10-10-asiashanghai)。
已贯通 generic/type/function/start/data-count 与空 export 的 attached parser/AST，
通过 **214 项对照、83 项回滚**；旧 section、AST/cleanup 两组 JSON 逐字节一致。
见 [module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#631-attached-parser-与有界-ast-module2026-10-10-asiashanghai)。
函数 import 的 heap 名称组合另通过 **180 项对照、43 项回滚**；默认关闭，
两名称均需至少 23 字节。旧 module/import 两组（1072/493）JSON 逐字节一致。
见 [函数 import module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#632-heap-名称函数-import-的-attached-ast-组合2026-10-10-asiashanghai)。
短名称/空名称和长短混用另通过 **448 项对照、64 项回滚**，需开启额外 inline
opt-in；恢复真实 caller helper 写入。旧 module/heap 两组（394/126）JSON
逐字节一致。见 [inline import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#633-inline-名称函数-import-与真实-caller-栈写入2026-10-10-asiashanghai)。
Table/memory/global 的长名称 attached import 另通过 **406 项对照、72 项回滚**，
恢复真实 descriptor、ABI 参数、AST 与 cache 清理；新开关默认关闭。旧三组
（842/190）JSON 逐字节一致；短名称的后续恢复见下方。
见 [其他 import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#634-tablememoryglobal-import-的-attached-ast-组合2026-10-10-asiashanghai)。
Table/memory/global 的短名称和空名称组合另通过 **612 项对照、41 项回滚**，
需开启额外 inline other-import 开关；恢复 caller padding，默认关闭。旧四组
（1,248/262）JSON 逐字节一致，完整 signer 仍未完成。
见 [短名称其他 import 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#635-短名称其他-import-与-caller-栈传递2026-10-11-asiashanghai)。
Table/memory definitions 的实际 AST 组合另通过 **470 项对照、32 项回滚**，
新开关默认关闭，含 12 项 SP 移位、12 项高位 guest 和完整 record 检查。
八组旧回归（2,582/463）JSON 逐字节一致。
见 [definitions 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#636-tablememory-definitions-的-attached-ast-组合2026-10-11-asiashanghai)。
Global definitions 与初始化表达式的实际 AST 组合另通过 **398 项对照、37 项回滚**，
含 12 项 SP 移位、12 项高位 guest 与 780 个完整 global record 检查。
五组旧回归（1,614/315）JSON 逐字节一致。
见 [global module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#637-global-definitions-与初始化表达式的-attached-ast-组合2026-10-11-asiashanghai)。
Code definitions 的实际 AST 组合另通过 **256 项对照、42 项回滚**，
含 8 项完整实际 ELF body 对照、12 项 SP 移位、12 项高位 guest；
另有 8 项主动截停的原生观察确认短输入不前进，原始指令字只保存不执行。
四组旧回归（1,124/235）JSON 逐字节一致。
见 [code module 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#638-code-definitions-的-attached-ast-组合2026-10-11-asiashanghai)。
完整实际 ELF 的 reader AST 已在两个基址通过：229328 字节输入、121 个
code bodies、54533 个 raw words、55369 次回调，input/guest/1 MiB heap/
effects/cleanup/globals 全量一致。本阶段共 **406 项对照、36 项回滚**；
前一版本的三组旧回归 **1502/99** JSON 逐字节一致，最终修复对其
实际执行范围的 AST 等价检查通过。见
[完整模块 reader AST 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#641-完整实际-module-的-reader-ast2026-10-11-asiashanghai)。
零条目 type 的 incoming X22 现已恢复，新增 **198 项对照、9 项回滚**；
同一最终版另通过 **36/77** 关联回归，包含两个完整实际 module。见
[零条目 type 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#642-零条目-type-与-incoming-x222026-10-11-asiashanghai)。
parse 指令格式转换已恢复，**434 项对照、10 项拒绝检查**通过。见
[parse codec 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#643-parse-指令格式转换2026-10-11-asiashanghai)。
parse 模块转换通过 **170 项对照、25 项回滚检查**，其中 4 项完整实际 ELF
每次匹配 139 个函数、54533 个 decoded words。见
[parse conversion 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#644-parse-模块转换与-builtin-catalog2026-10-11-asiashanghai)。
converted module 清理通过 **146 项对照、21 项回滚检查**。见
[converted cleanup 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#645-converted-module-清理2026-10-11-asiashanghai)。
instruction builder catalog 初始化通过 **40 项对照、22 项回滚检查**。见
[builder catalog 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#646-instruction-builder-catalog2026-10-11-asiashanghai)。
decoded instruction 构造通过 **116422 次原生对照、24 项回滚检查**，
含两份完整实际模块的全部指令。见
[runtime builder 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#647-decoded-instruction-运行时构造2026-10-11-asiashanghai)。
runtime 二次转换/root linking 通过 **3918 个 descriptor 对照、27 项回滚检查**，
覆盖全部 600 种副表规则。见 [runtime linking 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#648-runtime-descriptor-二次转换与-root-linking2026-10-11-asiashanghai)。
defined descriptor 构造与失败清理通过 **288 个原生对照、35 项回滚检查**，
含两份实际模块全部 109066 条指令。见 [defined descriptor 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#649-defined-descriptor-构造与失败清理2026-10-11-asiashanghai)。
builtin function catalog 通过 **32 个原生对照、198 个哈希对照、34 项检查**，
恢复 73 项名称/函数绑定。见 [builtin catalog 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#650-builtin-function-catalog-与名称哈希2026-10-11-asiashanghai)。
imported descriptor 通过 **106 个原生对照、36 项回滚检查**，
含两份 fresh 模块的全部 36 项函数导入。见 [imported descriptor 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#651-imported-descriptor-解析与构造2026-10-11-asiashanghai)。
root 构造通过 **62 个原生对照、34 项回滚检查**，
含两份实际模块的 278 个描述符、109066 条指令。见 [root 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#652-root-构造全局数据搬移与运行时链接2026-10-11-asiashanghai)。
factory 独立组合通过 **26 个原生对照、38 项回滚检查**。见 [factory 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#653-factory-独立组合与两层清理2026-10-11-asiashanghai)。
构造器通过 **2 份完整原生对照、22 项回滚检查**，242 个描述符发布槽一致。见 [构造器报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#654-构造器输入生成与描述符发布2026-10-11-asiashanghai)。
B 有界运行时通过 **48 项执行、6 项初始化、27 项回滚检查**。见 [运行时报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#655-b-运行状态与有界描述符执行2026-10-11-asiashanghai)。
共享 B callable 通过 **84 项原生对照、12 项回滚检查**，含52项A/queue回归。见 [callable 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#656-b-callable-的共享移动与清理2026-10-11-asiashanghai)。
B 主线程 startup 与两类真实导入回调通过 **28 项原生对照、41 项回滚检查**；每次19次分发、3个延后执行的线程请求、22项有序效果匹配。见 [startup 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#657-b-主线程-startup-与真实导入回调2026-10-11-asiashanghai)。
B worker 调用程序的指令扩展通过 **112 项 runtime 对照、4 项 startup 回归、40 项回滚检查**；实际 worker descriptor 使用显式导入 provider。见 [worker runtime 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#658-b-worker-的分支与组合指令2026-10-11-asiashanghai)。
B worker 完整算术与 CAS/memset 通过 **310 项 runtime 对照、30 项 builtin 对照、4 项 startup 回归、69 项回滚检查**；24项实际嵌套程序执行真实 memset 回调。见 [worker arithmetic 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#659-b-worker-完整算术与内存内置函数2026-10-11-asiashanghai)。
共享 once 已接入 B 六个控制字，**60 项原生对照、22 项回滚检查**通过；含24项A回归。见 [共享 once 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#660-b-复用共享-once-状态机2026-10-11-asiashanghai)。
B完整callable已恢复六个外层及48个嵌套程序，**18 项原生对照、36 项回滚检查**通过；每次cold任务120847次分发、6分配、6唤醒。见 [完整 callable 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#661-b-完整-worker-callable-与嵌套初始化2026-10-11-asiashanghai)。
B同次startup队列worker、TLS key清理及完整guest pthread_exit通过 **12 项原生对照、24 项回滚检查**。见 [队列与清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#662-b-同次-startup-的队列-worker-与清理2026-10-11-asiashanghai)。
另外四个ELF module constructor通过 **8 项原生对照、2 项原B回归、77 项回滚检查**，复用同一factory。见 [constructor报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#663-另外四个-elf-module-constructors2026-10-11-asiashanghai)。
六个ELF support constructor通过 **48 项原生对照、51 项回滚检查**，累计覆盖11/13个init_array入口。见 [ELF支持报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#664-六个-elf-support-constructors2026-10-11-asiashanghai)。
ELF guarded string constructor通过 **18 项原生对照、25 项回滚、12 项既有入口回归**，累计覆盖12/13个init_array成员。见 [guard报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#665-elf-guarded-string-constructor2026-10-11-asiashanghai)。
ELF configuration constructor通过 **16 项原生对照、72 项回滚**，既有 registry **38/14** 结果逐字节一致；13/13个init_array成员已有独立实现，完整顺序加载待验。见 [配置报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#666-elf-configuration-constructor2026-10-11-asiashanghai)。
完整13项init_array顺序组合通过 **4项原生对照、40项回滚**；共享堆/TLS/全局状态和全部存活页面匹配。完整二进制加载/链接待验。见 [顺序组合报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#667-elf-init_array-完整顺序组合2026-10-11-asiashanghai)。
完整样本ELF映射/符号链接通过 **10项映射对照、2项完整构造序列、42项拒绝**；990页与18481项重定位一致。见 [ELF加载报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#668-elf-映射与完整符号链接2026-10-11-asiashanghai)。
完整ELF构造→JNI→条件主线程startup通过 **4项原生对照、38项回滚**；finalizer callable另有32/9项检查。见 [完整JNI报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#669-完整-jni-与两条主线程-startup-组合2026-10-11-asiashanghai)。
同次executor/初始化queue与guest退出通过 **4项对照、28项回滚**。见 [完整worker报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#670-完整-jni-后的两条-worker-与-guest-退出清理2026-10-11-asiashanghai)。
Finalizer延时提交通过 **8项对照、24项callable、25项回滚**。见 [延时报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#671-jni-finalizer-的首条延时任务提交2026-10-11-asiashanghai)。
三条worker及完整guest退出通过 **4项完整对照、4项copied probe、47项回滚**。见 [finalizer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#672-jni-finalizer-完整-worker-与-guest-退出2026-10-11-asiashanghai)。
实际延时callback与两段image VM通过 **4项完整对照、22项页面回滚**。见 [延时回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#673-实际延时-jni-callable-与两段-image-vm2026-10-11-asiashanghai)。
实际timed poll、转交与queue清理通过 **4项完整对照、20项页面回滚**。见 [timed转交报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#674-实际-timed-poll转交与-queue-清理2026-10-11-asiashanghai)。
三条worker协作等待、到期转交与完整退出通过 **4项完整对照、23项页面回滚**。见 [协作worker报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#675-三条-worker-协作等待转交与完整退出2026-10-11-asiashanghai)。
Java byte array转引用通过 **52项原生/Python对照、19项回滚**，见 [byte array报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#676-java-byte-array-转引用与实际诊断锁2026-10-11-asiashanghai)。
JNI引用字段、无参数方法和清理通过 **74项对照、18项回滚**，见 [JNI引用报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#677-jni-引用字段无参数方法与引用清理2026-10-11-asiashanghai)。
实际reference作用域与MD5生命周期通过 **80项对照、16项回滚**，见 [作用域报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#678-实际-reference-作用域与-md5-生命周期2026-10-11-asiashanghai)。
已初始化对象的live lookup通过 **48项对照、11项回滚**，见 [live lookup报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#679-已初始化对象的实际-live-java-lookup2026-10-11-asiashanghai)。
cold encoded SDK及其live lookup组合通过 **62项对照、13项回滚**，见 [cold SDK报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#680-cold-encoded-sdk-getter-与实际-live-lookup2026-10-11-asiashanghai)。
带整型/引用参数的JNI方法和静态字段通过 **140项对照、11项回滚**，见 [JNI member报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#681-带整型引用参数的-jni-方法与静态字段2026-10-11-asiashanghai)。
实际UTF构造及Java service查找通过 **42项对照、9项回滚**，见 [Java service报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#682-实际-utf-构造与-java-service-查找2026-10-12-asiashanghai)。
实际live initializer及cold lookup通过 **92项对照、6项回滚**，见 [initializer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#683-实际-live-initializer-与-cold-lookup2026-10-12-asiashanghai)。
VM/callable/worker live服务接线通过 **6项原生对照、2项worker入口检查、16项回滚**，见 [provider报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#684-delayed-vmcallableworker-的-live-provider-接线2026-10-12-asiashanghai)。
实际request stack evaluator通过 **78项对照、1项请求VM入口检查、20项回滚**，见 [evaluator报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#685-实际-request-stack-evaluator-与请求-vm-接线2026-10-12-asiashanghai)。
实际boolean scope清理通过 **46项对照、1项请求VM入口检查、28项回滚**，见 [scope报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#686-实际-boolean-scope-清理与-elapsed-event2026-10-12-asiashanghai)。
实际JNI发布器与byte gate通过 **44项对照、1项请求入口检查、20项回滚**；请求到1019步，见 [发布器报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#687-实际-jni-发布器与请求-byte-gate2026-10-12-asiashanghai)。
实际请求对象构造通过 **60项对照、1项请求入口检查、34项回滚**；请求到1419步，见 [请求对象报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#688-实际请求对象构造与临时引用生命周期2026-10-12-asiashanghai)。
实际registry计数通过 **40项对照、1项请求入口检查、36项回滚**；请求到1444步，见 [计数报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#689-实际-registry-计数回调与拥有者-tls-接线2026-10-12-asiashanghai)。
实际树与iterator ABI通过 **24项对照、1项请求入口检查、13项回滚**；请求到1539步，见 [iterator报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#690-实际请求树构造与-iterator-abi2026-10-12-asiashanghai)。
进程析构导入与注册通过 **16项对照、1项请求入口检查、17项回滚**；请求到1558步，见 [注册报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#691-实际进程析构导入与注册2026-10-12-asiashanghai)。
填充字符串与wrapper通过 **40项对照、1项请求入口检查、20项回滚**；请求到1567步，见 [填充报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#692-实际填充字符串构造与-wrapper-字节参数2026-10-12-asiashanghai)。
树查询与C-string wrapper通过 **28项对照、1项请求入口检查、20项回滚**；请求到1812步，见 [collection报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#693-实际树查询与-c-字符串长度-wrapper2026-10-12-asiashanghai)。
guest table比较通过 **48项对照、1项请求入口检查、26项回滚**；请求到1995步，见 [比较报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#694-实际-guest-table-折叠比较与-singleton-接线2026-10-12-asiashanghai)。
树计数、value清理与iterator遍历通过 **128项对照、1项请求入口检查、40项回滚**；请求到2321步，见 [树遍历报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#695-请求树计数与-value-清理和-iterator-遍历2026-10-12-asiashanghai)。
局部树析构通过 **32项对照、1项请求入口检查、27项回滚**；请求到2329步，见 [局部树析构报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#696-请求局部树析构2026-10-12-asiashanghai)。
请求后续清理通过 **78项对照、1项入口检查、36项回滚**；空header/NULL JNI输入的VM在2475步返回，见 [请求清理与VM返回报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#697-请求对象与树删除清理和-vm-返回2026-10-12-asiashanghai)。
请求scoped tree构造通过 **24项对照、1项入口、31项回滚**，见 [scoped tree报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#698-请求-scoped-tree-reference-构造2026-10-12-asiashanghai)。
VM load/compare-store修复通过 **114项对照、1项入口、21项拒绝/回滚**，见 [VM load/store报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#699-vm-load-与串行-comparestore2026-10-12-asiashanghai)。
caller物理返回恢复通过 **16项原生对照、1项入口、26项拒绝**；25项全部页面不变，canary入口的新增分配映射保留。见 [caller返回报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6100-request-caller-物理返回2026-10-12-asiashanghai)。
NULL raw cleanup修复通过 **16项新增对照、6项回滚**；构造请求的105次有效packed输入、10次服务与物理返回一致。见 [整链有效字段报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6101-null-raw-cleanup-与整链有效字段2026-10-12-asiashanghai)。
ASCII case与request byte flag通过 **92项新增对照、8项回滚**；构造非空请求推进到2174步，尚未完成JNI输入转换。见 [ASCII/byte flag报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6102-ascii-case-与-request-byte-flag2026-10-12-asiashanghai)。
Byte search通过 **80项新增对照、12项回滚、8项扫描上限检查**；构造非空请求推进到2224步。见 [byte search报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6103-request-byte-search2026-10-12-asiashanghai)。
定长字符串请求分发通过 **18项新增对照、10项回滚**；构造非空入口推进到2243步，拒绝时保留64个新增allocator OS页。见 [sized dispatch报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6104-request-sized-string-dispatch2026-10-12-asiashanghai)。
二进制相等判断通过 **48项新增对照、8项回滚**，含16项actual libc memcmp；构造非空入口推进到2395步。见 [binary equality报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6105-request-binary-equality2026-10-12-asiashanghai)。
构造非空请求2395步的 **98次回调路径与有效packed输入** 与原native全部一致；substring body与完整非空等价仍未完成。见 [非空ABI报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6106-constructed-nonempty-request-effective-abi2026-10-12-asiashanghai)。
Field clone/substring通过 **74项新增对照、20项回滚**；构造非空入口推进到2510步。见 [substring报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6107-field-clone-与-substring2026-10-12-asiashanghai)。
CString/StringObject拼接与清理通过 **84项新增对照、28项回滚**；构造非空入口推进到2520步。见 [组合报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6108-cstringstringobject-拼接2026-10-12-asiashanghai)。
StringObject/CString构造通过 **68项新增对照、24项回滚**；非空入口在2520步遇到未恢复的matching-libc realloc。见 [对象/CString报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6109-stringobjectcstring-构造2026-10-12-asiashanghai)。
Matching-libc同类别realloc通过 **18项新增对照、28项回滚**；非空入口推进到2538步，下一StringObject搜索回调待恢复。见 [同类别realloc报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6110-matching-libc-同类别-realloc2026-10-12-asiashanghai)。
StringObject ASCII casefold搜索通过 **72项新增对照、20项回滚**；非空入口推进到2590步。见 [casefold搜索报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6111-stringobject-ascii-casefold-搜索2026-10-12-asiashanghai)。
StringObject ASCII CString pattern搜索通过 **76项新增对照、24项回滚**；非空入口推进到2761步。见 [CString搜索报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6112-cstring-pattern-搜索2026-10-12-asiashanghai)。
VM signed64乘法与低半部读取通过 **238项新增对照**；非空入口推进到2850步。见 [signed product报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6113-vm-signed-product-与-low-copy2026-10-12-asiashanghai)。
状态numeric member读取通过 **60项新增对照、18项回滚**；request state callback仍待接入。见 [state numeric报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6114-state-numeric-member-读取2026-10-12-asiashanghai)。
Lazy state service通过 **8项新增对照、7项回滚**，前置singleton136已初始化。见 [state service报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6115-lazy-state-service2026-10-12-asiashanghai)。
实际request state构造通过 **16项新增对照、7项回滚**；非空入口推进2911步。见 [request state报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6116-request-state-构造与清理2026-10-12-asiashanghai)。
实际request elapsed getter通过 **36项新增对照、12项回滚**；非空入口推进3167步。见 [request elapsed报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6117-request-elapsed-seconds2026-10-12-asiashanghai)。
实际request reference copy/hash64通过 **84项新增对照、6项回滚**；非空入口推进3257步。见 [request reference/hash报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6119-request-stringobject-table-hash642026-10-12-asiashanghai)。
实际request TLS读写通过 **34项新增对照**；非空入口推进3307步。见 [request TLS报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6120-request-tls-uint32-读写2026-10-12-asiashanghai)。
实际request binary transform组件通过 **24项新增对照、10项回滚**，外层caller仍待恢复。见 [transform报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6121-request-binary-transform2026-10-12-asiashanghai)。
实际request hex reference通过 **20项新增对照、8项回滚**；外层caller继续恢复。见 [hex报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6122-request-hexadecimal-reference2026-10-12-asiashanghai)。
原始MD5与scoped reference assignment通过 **54项新增对照、12项回滚**；外层getter和格式化继续恢复。见 [raw MD5报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6123-request-raw-md5-and-reference-assignment2026-10-12-asiashanghai)。
版本word getter通过 **40项新增对照、10项回滚**；外层两遍格式化继续恢复。见 [version报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6124-request-version-word2026-10-13-asiashanghai)。
两遍allocated printf通过 **36项新增对照、9项回滚**；外层组合与cleanup继续恢复。见 [allocated printf报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6125-request-allocated-printf2026-10-13-asiashanghai)。
外层suffix及raw free通过 **32项新增对照、11项回滚**；非空入口推进至3405步，继续恢复287168。见 [suffix报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6126-request-outer-suffix-and-raw-free2026-10-13-asiashanghai)。
metadata与unsigned printf通过 **46项新增对照、12项回滚**；非空入口推进至3520步。见 [metadata报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6127-request-metadata-formatting2026-10-13-asiashanghai)。
Base64 encode通过 **68项新增对照、10项回滚**；非空入口推进至3538步。见 [Base64报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6128-request-base64-encoder2026-10-13-asiashanghai)。
单byte StringObject通过 **30项新增对照、7项回滚**；入口推进至3550步。见 [character报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6129-request-character-string2026-10-13-asiashanghai)。
右端character-set trim通过 **64项新增对照、9项回滚**；入口推进至3559步。见 [right-set报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6130-request-right-character-set-trim2026-10-13-asiashanghai)。
左端character-set trim通过 **94项新增对照、11项回滚**；入口推进至3767步。见 [left-set报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6131-request-left-character-set-trim2026-10-13-asiashanghai)。
嵌套token VM caller与两次decode通过 **20项新增对照、8项回滚**，内层179步，下一random getter。见 [token VM报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6132-request-token-vm-caller-and-prefix2026-10-13-asiashanghai)。
random state、getter和actual consumer通过 **98项新增对照、15项回滚**。见 [random报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6133-request-random-state-and-getter2026-10-13-asiashanghai)。
嵌套random与actual外层consumer接线通过 **12项新增对照、5项回滚**，下一shared reader。见 [nested random报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6134-request-nested-random-continuation2026-10-13-asiashanghai)。
嵌套shared-reader consumer通过 **28项新增对照、7项回滚**，下一diagnostic scope。见 [nested readers报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6135-request-nested-shared-readers2026-10-13-asiashanghai)。
嵌套diagnostic consumers通过 **16项新增对照、5项回滚**，内层推进至231步。见 [nested scopes报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6136-request-nested-diagnostic-scopes2026-10-13-asiashanghai)。
嵌套string生命周期通过 **36项新增对照、8项回滚**，内层推进至287步。见 [nested lifecycle报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6137-request-nested-string-lifecycle2026-10-13-asiashanghai)。
嵌套string transforms通过 **46项新增对照、10项回滚**，内层推进至321步。见 [nested strings报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6138-request-nested-string-transforms2026-10-13-asiashanghai)。
嵌套scoped MD5通过 **32项新增对照、8项回滚**，内层推进至422步。见 [nested MD5报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6139-request-nested-scoped-md52026-10-13-asiashanghai)。
request轮密钥/分组helper通过 **32项新增对照、8项回滚**；caller待恢复。见 [round/block报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6140-request-round-schedule-and-block-helpers2026-10-13-asiashanghai)。
request cipher caller通过 **48项新增对照、10项回滚**；owning cross-bin realloc待恢复。见 [cipher caller报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6141-request-allocated-and-string-cipher-callers2026-10-13-asiashanghai)。
cross-bin realloc通过 **18项新增对照、9项回滚**，owning内层推进至430步。见 [cross-bin报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6142-matching-libc-cross-bin-small-realloc2026-10-13-asiashanghai)。
append/Base64 reference通过 **34项新增对照、8项回滚**，内层推进至505步。见 [append/Base64报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6143-request-nested-append-and-base64-reference2026-10-13-asiashanghai)。
nested printf通过 **36项新增对照、10项回滚**，内层推进至574步的return。见 [nested printf报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6144-request-nested-allocated-printf2026-10-13-asiashanghai)。
nested caller return通过 **32项新增对照、10项回滚**，owning外层推进至3879步。见 [nested return报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6145-request-nested-caller-return2026-10-13-asiashanghai)。
URL条件通过 **40项新增对照、7项回滚**，外层推进至3900步。见 [URL条件报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6146-request-url-condition2026-10-13-asiashanghai)。
第二VM caller/prefix通过 **20项新增对照、8项回滚**，owning内层推进至617步。见 [第二VM报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6147-request-second-vm-caller-and-prefix2026-10-13-asiashanghai)。
第二VM consumers通过 **153项新增原生对照、12项回滚**，owning第二VM推进至8184步。见 [second consumer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6148-request-second-vm-consumers2026-10-13-asiashanghai)。
child VM caller/prefix通过 **26项新增原生对照、10项回滚**，owning child推进至290步。见 [child VM报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6149-request-child-vm-caller-and-prefix2026-10-13-asiashanghai)。
child VM四个实际consumer通过 **83项新增原生对照、13项回滚**，owning child推进至19295步并完成有界原生差分。见 [child consumer报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6150-request-child-vm-consumers2026-10-13-asiashanghai)。
environment helper caller/prefix通过 **33项新增原生对照、11项回滚**，owning helper推进至134步并完成有界原生差分。见 [environment helper报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6151-request-environment-helper-vm-callers-and-prefixes2026-10-14-asiashanghai)。
实际environment acquisition callback通过 **17项新增原生对照、6项回滚**，owning helper推进至214步。见 [environment acquisition报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6152-request-environment-acquisition-callback2026-10-14-asiashanghai)。
实际environment StringObject callbacks通过 **39项新增原生对照、9项回滚**，owning helper推进至226步。见 [StringObject报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6153-request-environment-stringobject-callbacks2026-10-14-asiashanghai)。
实际environment logger通过 **13项新增原生对照、9项回滚**，owning helper完成日志与清理并到262步VM退出边界。见 [logger报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6154-request-environment-logger-and-cleanup2026-10-14-asiashanghai)。
environment helper return通过 **53项新增原生对照、8项回滚**，child推进至19302步、下一204B80 JNI。见 [helper return报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6155-request-environment-helper-return2026-10-15-asiashanghai)。
204B80共享JNI语义通过 **32项新增原生对照、10项回滚**，保留finalizer既有行为。见 [availability报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6156-jni-static-method-availability2026-10-15-asiashanghai)。
实际availability wrapper通过 **26项新增原生对照、9项回滚**，返回值/声明保存帧/packed一致。见 [wrapper报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6157-jni-availability-wrapper2026-10-15-asiashanghai)。
child availability接线通过 **1项新增原生对照、6项入口拒绝**，child推进至19470步、下一2814E4环境获取。见 [child callback报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6158-child-jni-availability-callback2026-10-15-asiashanghai)。
child environment新增 **17项原生对照**，推进至19533步、下一28155C字符串构造。见 [child environment报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6159-child-environment-acquisition2026-10-15-asiashanghai)。
child字符串构造通过 **23项新增原生对照、8项回滚**，推进至19541步、下一256A18配置读取。见 [child strings报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6160-child-stringobject-construction2026-10-15-asiashanghai)。
child配置读取新增 **41项原生对照、12项回滚**，推进至19549步、下一28158C字符串析构。见 [child registry read报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6161-child-configuration-u32-read2026-10-15-asiashanghai)。
child析构新增 **17项原生对照、7项回滚**，19566步观察VM exit，物理返回仍待恢复。见 [child cleanup报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6162-child-stringobject-cleanup-and-vm-exit2026-10-15-asiashanghai)。
child物理返回新增 **23项原生对照、16项回滚**，second推进至8251步、下一2885D0字符串构造。见 [child return报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6163-child-physical-caller-and-wrapper-return2026-10-15-asiashanghai)。
second字符串构造新增 **23项原生对照、8项回滚**，推进至8261步、下一32A444共享读锁。见 [second strings报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6164-second-vm-stringobject-construction2026-10-15-asiashanghai)。
second共享读锁新增 **19项原生对照、11项回滚**，推进至8279步、下一26C858诊断scope。见 [second reader报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6165-second-vm-shared-reader-acquisition2026-10-15-asiashanghai)。
second诊断scope新增 **13项原生对照、7项回滚**，推进至8298步、下一26C9D0清理。见 [second diagnostic报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6166-second-vm-diagnostic-scope-entry2026-10-15-asiashanghai)。
second诊断scope清理新增 **21项原生对照、9项回滚**，推进至8309步、下一32A4FC释放。见 [second diagnostic cleanup报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6167-second-vm-diagnostic-scope-cleanup2026-10-15-asiashanghai)。
second共享读锁释放新增 **19项原生对照、12项回滚**，推进至8355步、下一24880C比较。见 [second reader release报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6168-second-vm-shared-reader-release2026-10-15-asiashanghai)。
second字符串比较新增 **27项原生对照、9项回滚**，推进至8405步、下一2485A4赋值。见 [second equality报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6169-second-vm-string-equality2026-10-15-asiashanghai)。
second字符串赋值新增 **37项原生对照、13项回滚**，推进至8416步、下一26CC8C随机数。见 [second assignment报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6170-second-vm-string-assignment2026-10-15-asiashanghai)。
second random新增 **17项原生对照、11项回滚**，推进至8532步、下一288658→257804。见 [second random报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6171-second-vm-random-callback2026-10-15-asiashanghai)。
second reference getter新增 **33项原生对照、13项回滚**，推进至8539步、下一288670→257880。见 [second reference getter报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6172-second-vm-reference-getter2026-10-15-asiashanghai)。
second cached u32新增 **27项原生对照、13项回滚**，推进至8760步、下一28868C→2633A4。见 [second cached u32报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6173-second-vm-cached-u32-getter2026-10-15-asiashanghai)。
second pair getter新增 **29项原生对照、10项回滚**，推进至8809步、下一2886B0→1CF55C。见 [second pair getter报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6174-second-vm-pair-reference-getter2026-10-15-asiashanghai)。
Java object bytes组合新增 **28项原生对照、12项回滚**，补齐26FE2C child；request边界仍为8809步。见 [Java object bytes报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6175-java-object-byte-reference-composition2026-10-15-asiashanghai)。
cached dispatch producer新增 **26项原生对照、13项回滚**，补齐1CF688组合；request边界仍为8809步。见 [cached dispatch bytes报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6176-cached-dispatch-byte-producer2026-10-15-asiashanghai)。
缓存初始化/刷新新增 **44项原生对照、18项回滚**，恢复1CF55C；request边界仍为8809步。见 [cached reference报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6177-cached-reference-initialization-and-refresh2026-10-15-asiashanghai)。
second缓存回调新增 **17项原生对照、8项回滚**，实际入口推进至8844步。见 [second cached reference报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6178-second-vm-cached-reference-callback2026-10-15-asiashanghai)。
second 独立 guard acquire 新增 **33 项原生对照、14 项回滚**，实际入口推进至 8902 步。见 [guard acquire 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6179-second-vm-static-guard-acquire2026-10-15-asiashanghai)。
second 环境常量回调新增 **21 项原生对照、8 项回滚**，实际入口推进至 8938 步。见 [环境常量报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6180-second-vm-environment-constant-callback2026-10-15-asiashanghai)。
second 字符串格式化新增 **27 项原生对照、12 项回滚**，实际入口推进至 8951 步。见 [格式化报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6181-second-vm-c-string-format-callback2026-10-15-asiashanghai)。
second guard release 新增 **25 项原生对照、12 项回滚**，实际入口推进至 9050 步。见 [release 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6182-second-vm-static-guard-release2026-10-15-asiashanghai)。
second 配置读取新增 **22 项原生对照**，复用 12 项既有回滚证据，实际入口推进至 9374 步。见 [配置读取报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6183-second-vm-configuration-u32-read2026-10-15-asiashanghai)。
second 时钟回调新增 **15 项原生对照、10 项回滚**，实际入口推进至 9557 步，下一 NULL target 待排查。见 [时钟报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6184-second-vm-realtime-unsigned-seconds2026-10-15-asiashanghai)。
second PID 回调新增 **26 项原生对照、12 项回滚**，真实导入来源已确认，实际入口推进至 9729 步。见 [PID 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6185-second-vm-process-id-callbacks2026-10-15-asiashanghai)。
second 线程指针缓存新增 **15 项原生对照、7 项回滚**，实际入口推进至 9752 步。见 [线程指针报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6186-second-vm-cached-thread-pointer2026-10-15-asiashanghai)。
second JNI环境获取新增 **17 项原生对照**，复用旧回滚6项，入口推进至9780步。见 [环境报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6187-second-vm-environment-acquisition2026-10-15-asiashanghai)。
second加锁字段读取新增 **19项原生对照、13项回滚**，入口推进至9813步。见 [加锁读取报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6188-second-vm-locked-pointer-getter2026-10-15-asiashanghai)。
second树指针读取新增 **41项原生对照、18项回滚**，入口推进至9940步。见 [树指针读取报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6189-second-vm-tree-pointer-getter2026-10-15-asiashanghai)。
second冷缓存标识符新增 **45项原生对照、19项回滚**，入口推进至9950步。见 [标识符工厂报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6190-second-vm-cold-cached-identifier2026-10-15-asiashanghai)。
second分配回调新增 **22项原生对照、9项回滚**，入口推进至9998步。见 [分配回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6191-second-vm-allocation-callback2026-10-15-asiashanghai)。
second字符串格式回调新增 **21项原生对照、12项回滚**，入口推进至10009步。见 [字符串格式回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6192-second-vm-string-format-callback2026-10-15-asiashanghai)。
second字符串拼接新增 **17项原生对照、8项回滚**，入口推进至10021步。见 [字符串拼接回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6193-second-vm-string-pair-callback2026-10-15-asiashanghai)。
second摘要引用新增 **33项原生对照**，保留旧8项回滚，入口推进至10030步。见 [摘要引用回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6194-second-vm-digest-reference-callback2026-10-15-asiashanghai)。
second CRC新增 **33项原生对照、18项回滚**，入口推进至10059步。见 [CRC回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6195-second-vm-crc-callback2026-10-15-asiashanghai)。
second释放新增 **17项原生对照、12项回滚**，入口推进至10070步。见 [释放回调报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6196-second-vm-deallocation-callback2026-10-15-asiashanghai)。
second删除析构新增 **17项原生对照、12项回滚**，入口推进至10101步。见 [删除析构报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6197-second-vm-deleting-destructor2026-10-15-asiashanghai)。
second空JSON引用新增 **25项原生对照、16项回滚**，入口推进至10110步。见 [empty JSON报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6198-second-vm-empty-json-reference2026-10-16-asiashanghai)。
second全局u32读取新增 **17项原生对照、10项回滚**；入口在10118步遇到未实现opcode34。见 [global u32报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6199-second-vm-global-unsigned-word2026-10-16-asiashanghai)。
VM uint32转double新增 **32项原生对照、6项拒绝检查**，second prefix恢复返回至10124步。见 [转换报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6200-vm-uint32-to-double2026-10-16-asiashanghai)。
JSON数值写入新增 **69项原生对照、16项拒绝或回滚检查**，second prefix推进到10131步。见 [数值写入报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6201-json-number2026-10-16-asiashanghai)。
第二global getter新增 **17项原生对照、10项拒绝或回滚检查**，second prefix推进到10150步。见 [getter报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6202-second-global-u32-b2026-10-16-asiashanghai)。
第二environment helper新增 **27项原生对照、14项拒绝或回滚检查**，second prefix推进到10169步。见 [helper报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6203-second-environment-helper2026-10-16-asiashanghai)。
第三global getter新增 **17项原生对照、10项拒绝或回滚检查**，second prefix推进到10208步。见 [第三getter报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6204-second-global-u32-c2026-10-16-asiashanghai)。
对象原子字段读取新增 **19项原生对照、14项拒绝或回滚检查**，执行到10266步/未恢复指令边界。见 [原子读取报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6205-second-atomic-u322026-10-16-asiashanghai)。
VM int32转double新增 **32项原生对照、6项拒绝检查**，second prefix恢复返回至10294步。见 [有符号转换报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6206-vm-int32-to-double2026-10-16-asiashanghai)。
second TLS getter新增 **15项原生对照、15项拒绝或回滚检查**，prefix到10320步。见 [TLS读取报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6207-second-tls-u322026-10-16-asiashanghai)。
五参数64位unsigned格式化新增 **17项原生对照、16项拒绝或回滚检查**，prefix到10332步。见 [格式化报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6208-second-five-argument-format2026-10-16-asiashanghai)。
JSON字符串插入新增 **53项原生对照、24项拒绝或回滚检查**，prefix到10341步。见 [字符串报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6209-second-json-string2026-10-16-asiashanghai)。
数字字符串构造新增 **31项原生对照、34项拒绝或回滚检查**，prefix到10403步。见 [数字字符串报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6210-second-numeric-string2026-10-16-asiashanghai)。
配置字符串查询新增 **29项原生对照、24项拒绝或回滚检查**，prefix到10471步。见 [配置字符串报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6211-second-configuration-string2026-10-18-asiashanghai)。
JSON布尔插入新增 **41项原生对照、22项拒绝或回滚检查**，prefix到10481步。见 [JSON布尔报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6212-second-json-bool2026-10-18-asiashanghai)。
JSON序列化与引用构造新增 **49项原生对照、36项拒绝或回滚检查**，prefix到10494步。见 [JSON序列化报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6213-second-json-print2026-10-18-asiashanghai)。
普通锁导入与回调新增 **15项原生对照、24项拒绝或回滚检查**，prefix到10599步。见 [普通锁报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6214-second-mutex-lock2026-10-18-asiashanghai)。
实时毫秒回调新增 **15项原生对照、14项拒绝或回滚检查**，prefix到10651步。见 [实时毫秒报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6215-second-realtime-milliseconds2026-10-18-asiashanghai)。
Protobuf长度回调新增 **53项原生对照、35项拒绝或回滚检查**，prefix到10662步。见 [Protobuf长度报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6216-second-protobuf-packed-size2026-10-18-asiashanghai)。
字符串填充新增 **29项原生对照、26项拒绝或回滚检查**，prefix到10671步。见 [填充报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6217-second-string-fill2026-10-18-asiashanghai)。
Protobuf编码新增 **57项原生对照、32项拒绝或回滚检查**，706字节输出一致，prefix到10680步。见 [编码报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6218-second-protobuf-pack2026-10-18-asiashanghai)。
显式解锁新增 **15项原生对照、24项拒绝或回滚检查**，prefix到10788步。见 [解锁报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6219-second-mutex-unlock2026-10-18-asiashanghai)。
JSON清理新增 **53项原生对照、30项拒绝或回滚检查**，prefix到11108步。见 [清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6220-second-json-delete2026-10-18-asiashanghai)。
配置查找与嵌套引用新增 **19项原生对照、33项拒绝或回滚检查**，prefix到11118步。见 [配置查找报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6221-second-configuration-lookup2026-10-18-asiashanghai)。
解码引用新增 **31项原生对照、33项拒绝或回滚检查**，prefix到11128步。见 [解码引用报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6222-second-decoded-reference2026-10-18-asiashanghai)。
二进制字符串复制新增 **31项原生对照、29项拒绝或回滚检查**，prefix到11263步。见 [复制报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6223-second-string-clone2026-10-18-asiashanghai)。
显式长度字符串构造新增 **35项原生对照、28项拒绝或回滚检查**，prefix到86800步。见 [构造报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6224-second-sized-string2026-10-18-asiashanghai)。
内存填充新增 **50项原生对照、20项拒绝或回滚检查**，prefix到93021步。见 [填充报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6225-second-memory-fill2026-10-18-asiashanghai)。
条件字符串清理新增 **34项原生对照、19项拒绝或回滚检查**，prefix到96519步。见 [清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6226-second-flagged-cleanup2026-10-18-asiashanghai)。
Base64引用构造新增 **31项原生对照、33项拒绝或回滚检查**，prefix到96588步。见 [Base64报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6227-second-base64-reference2026-10-18-asiashanghai)。
格式化分配新增 **50项原生对照、39项拒绝或回滚**，second到96740步的未恢复返回边界。见 [格式化报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6228-second-allocated-printf2026-10-19-asiashanghai)。
Second返回新增 **21项原生对照、15项拒绝检查**，outer推进至4000步。见 [second返回报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6229-second-vm-return2026-10-19-asiashanghai)。
外层配置写入新增 **39项原生对照、64项拒绝检查**，构造request在5182步返回（second使用私有预算）。见 [配置写入报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6230-outer-configuration-set2026-10-20-asiashanghai)。
公共服务传入与执行预算恢复，构造request在公共调用参数下5182步返回，新增30项拒绝检查。见 [公共服务报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6231-public-second-services2026-10-20-asiashanghai)。
JNI header输出数组组件已恢复，新增42项双基址原生对照和42项回滚检查。见 [JNI数组报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6232-cached-class-jni-header-array2026-10-20-asiashanghai)。
JNI String class冷分支恢复，新增24项原生对照和16项回滚检查；构造request的7项结果成功转为14个Java元素。见 [冷class报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6233-cold-string-class-and-constructed-output2026-10-20-asiashanghai)。
JNI header输入和树引用释放恢复，新增72项原生对照、32项回滚；synthetic输入输出及树清理通过。见 [header输入报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6234-jni-header-input-and-tree-reference-release2026-10-20-asiashanghai)。
child请求分发及结果所有权恢复，新增36项原生对照、18项回滚；fresh Java输入到owning VM到14元素输出及清理的构造链通过，JNI/OS仍为显式服务。见 [分发器报告](../platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6236-signer-child-request-dispatch2026-10-20-asiashanghai)。
完整signer仍未完成。见
[AST/清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#612-实际-ast-callback-与临时清理2026-10-09-asiashanghai)。
[Data reserve/析构报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#613-data-record-容量预留搬移与析构2026-10-09-asiashanghai)。
[Data 创建报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#614-data-record-创建与追加2026-10-09-asiashanghai)。
[Data payload 与 length 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#615-data-payload-写入与-parser-length-参数修复2026-10-09-asiashanghai)。
[Data expression 与树删除报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#616-data-expression-frameu32-修补与树节点删除2026-10-09-asiashanghai)。
[Element 回调与清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#617-element-回调与嵌套记录清理2026-10-09-asiashanghai)。
[Element 嵌套表达式报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#618-element-结果类型与嵌套表达式2026-10-09-asiashanghai)。
[Instruction 与常量报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#619-instruction-predicate-与带类型常量2026-10-09-asiashanghai)。
[Local group 与结束报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#620-local-group-与函数结束回调2026-10-09-asiashanghai)。
[Function 创建与清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#621-function-创建类型缓存与清理2026-10-09-asiashanghai)。
[Code-begin 与修补树报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#622-code-begin双修补树与-child-追加2026-10-09-asiashanghai)。
[Table 与栈 padding 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#623-table-预留创建与显式栈-padding2026-10-09-asiashanghai)。
[Memory 与独立缓存报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#624-memory-预留创建与独立缓存2026-10-09-asiashanghai)。
[Global 与记录清理报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#625-global-预留创建与记录清理2026-10-09-asiashanghai)。
[Global expression 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#626-global-expression-与内联-ast-回调2026-10-10-asiashanghai)。
真实 OS 线程/allocator、独立 Medusa 与 fresh 签名仍未完成，
完整 Python bootstrap 对照仍为 **0**。详见
[原始 JNI 与同次 worker 报告](platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md)。

Owning request VM execution now lives in a production module with strict callback and Java facade adapters. Two Python prefix checks and25 refusal/rollback checks pass; the constructed chain returns14 Java elements with complete scoped cleanup. No historical native groups replayed; complete signing remains unfinished. See the [owning entry report](../platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6237-reusable-owning-request-vm-entry2026-10-20-asiashanghai).


## 2026-10-20：VM9 live native provider bridge

公开CPU页面/provider桥与opt-in输入页映射新增2项native GetEnv对照和13项拒绝检查。
实际original287474完整返回，391回调与七项返回值一致；1432/1439页一致，7页libc/栈
差异保留为未完成，整段探索不计入已验收native数量。累计3559native/1650checks。
未重跑历史native组，完整signer仍未完成。
见 [6.238报告](../platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6238-live-native-provider-bridge2026-10-20-asiashanghai)。

## 2026-10-20：VM9 matching libc clock cache

共享时钟provider前恢复匹配bionic guard/cache，新增8项native对照、14项拒绝。
整段original287474保持391回调与七项返回值一致；1433/1439页相同，剩余2页dtoa和4页栈。
最后写入探针将dtoa定位到JSON打印回调223；完整内存等价和完整signer仍未通过。
累计3567native/1664checks；未重跑历史native组。见
[6.239报告](../platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6239-matching-libc-clock-cache2026-10-20-asiashanghai)。

## 2026-10-20：VM9 matching libc integer dtoa

显式数值服务恢复已观察整数double的dtoa静态池与free链，经公开owning入口完成9次实际调用。
新增16项原始对照、29项拒绝/页面回滚；默认17位路径保留。整段391回调及七项返回值一致，
1435/1439页相同，全部libc页一致，剩余4页栈残留。通用float、完整内存等价与完整signer仍未完成。
累计3583native/1693checks，未重跑历史native组。见
[6.240报告](../platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6240-matching-libc-integer-dtoa2026-10-20-asiashanghai)。

## 2026-10-24：VM9 request-environment provider rollback

`apply_request_environment_acquisition_callback` 现在接受可选
`EffectJournal`；second VM 向 helper/child 继续传递同一 journal。新增失败
acquire-environment provider 控制同时恢复 guest page transaction 与外部 ledger，
默认 page-only 行为保持不变。provider evidence 更新为 31 Python / 31 rollback
controls；Python compile、public scan、diff check 和既有 Rust tests 继续按当前
工作区验证，live JVM、完整 signer 与完整 second/request 物理内存等价仍未验证。
见 [provider rollback 报告](../platforms/bytedance/tomato/REQUEST_JNI_STARTUP_WORKERS.md#6255-explicit-provider-effect-rollback-journal2026-10-24-asiashanghai)。

同一批继续覆盖 request-environment `StringObject` 构造/析构 wrapper；显式
allocation/free provider 失败时，object/payload guest 页面与外部 ledger 一起回滚，
默认 page-only 路径不变。

环境 logger callback 也加入同一 opt-in 边界；logger provider 失败时其 staged
guest 页面和外部 ledger 一起回滚。

JNI availability wrapper 也加入同一 opt-in 边界；provider 失败时 wrapper 的 staged
guest 页面和外部 ledger 一起回滚，默认 page-only 调用保持兼容。

second-VM allocation callback 也加入同一 opt-in 边界；allocator provider 失败时 packed
guest 页面和外部 allocation ledger 一起回滚。

second-VM formatter callback 也加入同一 opt-in 边界；formatter provider 失败时 staged
guest 页面和外部 formatter allocation ledger 一起回滚。

second-VM consumer free tail 也加入同一 opt-in 边界；free provider 失败时 staged guest
页面和外部 free ledger 一起回滚。

second-VM StringObject assignment 也加入同一 opt-in 边界；assignment provider 失败时
staged guest 页面和外部 assignment ledger 一起回滚。

second-VM configuration reference/pair getters 也加入同一 opt-in 边界；reference provider
失败时各自的 staged guest 页面和外部 reference ledger 一起回滚。

second-VM cached JNI reference callback 也加入同一 opt-in 边界；JNI/reference provider
失败时 staged guest 页面和外部 ledger 一起回滚。

second-VM JSON string 与 StringObject fill callbacks 也加入同一 opt-in 边界；provider
失败时各自的 staged guest 页面和外部 allocator ledger 一起回滚。

second-VM empty JSON reference callback 也加入同一 opt-in 边界；provider 失败时 staged
guest 页面和外部 reference ledger 一起回滚。

second-VM token string transform 与 token digest callbacks 也加入同一 opt-in 边界；
provider 失败时各自的 staged guest 页面和外部 ledger 一起回滚。

second-VM token cipher callback 也加入同一 opt-in 边界；provider 失败时 staged guest
页面和外部 cipher allocation ledger 一起回滚。

second-VM token append tail 与 Base64 tail callbacks 也加入同一 opt-in 边界；provider
失败时各自的 staged guest 页面和外部 ledger 一起回滚。

second-VM allocated-printf callback 也加入同一 opt-in 边界；provider 失败时 staged
guest 页面和外部 allocator ledger 一起回滚。



## 2026-10-26：request continuation evidence redaction and callback target correction

The fresh same-CPU continuation probes now publish only bounded summaries rather than
raw import, callback, tail, or unmapped traces. The summary retains import-name counts,
the first `memcpy` argument shape, callback target offsets, stop state, output-reference
nonzero status, and runtime-page read/write counts. Re-running both image bases preserved
the prior observations: the memcpy probe reaches the oracle STOP after 99,927 native
instructions and 194 imports; the URL-only probe reaches the real `image+0x347f60`
memcpy PLT and then records one unserviced unmapped stop. This remains a native
continuation boundary, not a whole-request differential, fresh standalone signer, or
online acceptance result.

## 2026-10-26：outer loader candidate opcode closure

The static owner inventory now asserts 24 decoded instructions in the candidate
`+0x18a314 → +0x184ad4` loader path. The bytes confirm `x0=path`, `dlopen(path, 2)`,
the loaded span `[x22, x8)` and `x20=x8-x22`, anonymous syscall 222, old mapping
`munmap`, `MAP_FIXED` replacement `mmap`, two segment copies, temporary `munmap`, and
`dlclose`. The scan still finds no direct writer for the five runtime relocation slots;
this closes the candidate's static contract only and does not prove execution, table
ownership, handler contents, or signer output.

## 2026-10-27：APK Java-to-native loader handoff provenance

The APK-side init chain is now checked through `MSManagerUtils.init -> g.c -> n3.a -> p3.a`.
`p3` first uses `System.loadLibrary(name)` and, on failure, the `h` extractor scans
`ApplicationInfo.sourceDir` and `splitSourceDirs` for the ABI-qualified entry before
calling `System.load` on the private `lib` path. The pinned DSO remains byte-identical
to `lib/arm64-v8a/libmetasec_ml.so` in the fixed APK.

This closes Java library provenance and the handoff into the native loader. It does not
show native `+0x184ad4` execution, populate the `0x13700000` descriptor mapping, or
identify the callback/runtime-table owner. The fresh child continuation therefore still
stops at `+0x2859dc` with `x3=0`; whole-request differential, standalone signer, and
online acceptance remain open. See [APK Java loader handoff](../platforms/bytedance/tomato/evidence/vm9_dso_java_loader_provenance_fresh_20261027.json).

2026-11-05：新增官方 OkHttp/r4 运行时栈的脱敏证据。真实回调栈以
`OkHttp3SecurityFactorInterceptor -> okhttp3.RealCall -> ms.bd.c.r4` 为前段，
窗口内返回六个七神键。Java bridge 的 identity 字段在冷启动与热进程表现不稳定，
因此记录为“入口/返回字段配对”，不记录为 Java 对象身份闭合；Cronet、standalone
signer、整请求差分和线上验签仍未完成。

2026-11-05：新增官方阅读窗口的 r4 多请求复核。30 秒 attach 中观察到 19 次
`ms.bd.c.r4.onCallToAddSecurityFactor`：18 次为完整六头，`X-Medusa` 长度为
1272 或 1276；另 1 次为单独的 `X-Neptune` 结果并单独计数。Cronet 两个
`addSecurityFactor` 入口和 `CronetUrlRequestContext.o0` 均已安装但事件数为 0。
证据只保留长度、名称和摘要，未建立 Cronet 对象身份或线上验签；详见
`platforms/bytedance/tomato/evidence/vm9_networkparams_runtime_window_20261105.json`。
2026-11-06：重新执行 outer graph fresh differential 四项 controls，并把 allocation
308 的旧 padding attribution 固化为 verifier 约束。两个 image base、`absent`/
`sdk_30` 均保持核心对象图和默认 logger 语义一致；四个 96 字节临时向量的全部
差异都落在四个 24 字节 C-string 槽的 NUL 后未使用尾部。该项只标记语义字节相等，
不提升为完整 native state、独立 signer、整请求差分或线上验签。详见
`platforms/bytedance/tomato/evidence/vm9_outer_graph_fresh_20261106.json`。

2026-11-06：新增 `vm9_claim_matrix_20261106` 交叉证据门禁，复核 12 份 Cronet、
OkHttp、NetworkParams 和 outer graph 记录中的所有未闭合标志均仍为 `false`。
设备上的最小原生 hook 虽安装了 r4、NetworkParams、Cronet manager 与 `o0`，但目标
进程随后进入 ANR，未产生新的回调事件；因此没有新增 Cronet 或完整 signer 结论。

2026-11-06：将官方进程的一份未跟踪多请求捕获转成脱敏摘要。130 次 r4 回调中，126 次
返回六个标准七神键，4 次返回 `X-Neptune`；130 个栈都包含 OkHttp3 安全因子拦截器和
`okhttp3.RealCall`，没有 Cronet 栈帧。受限栈前缀中 31 次保留 NetworkParams；所有
URL、header 值和不稳定 identity 字段均未作为证据。该结果加强当前窗口的 OkHttp 路径
覆盖，不改变 Cronet、完整 signer、整请求差分或线上验签的未闭合状态。

2026-11-06：重新执行 request VM 五组 dispatch table fresh continuation。两个 image base、
外部 canary 存在/缺失共 4 项 controls，均观察到 1191 次 table load；两基址各完成 234
项 selector controls。加载 word 与 pinned ELF `.data.rel.ro` 的相对 relocation 一致，
没有 relocation slot 或 table 写入，外部 dispatch mapping 对该 continuation 不是必需的。
父 probe 仍使用显式 JNI/OS/import services，因此 whole-request native differential、
standalone signer 和线上 header acceptance 继续未完成。详见
`platforms/bytedance/tomato/evidence/vm9_dispatch_table_encoding_fresh_20261106.json`。

2026-11-07：在设备恢复到 2 GB 内存并切换匹配的 Frida 17.24.3 服务后，官方未修改
7.2.5.32/72532 主页/推荐页做了新的 120 秒 attach。捕获到 21 次 `r4` 安全因子回调，
全部返回六个七神键，`X-Medusa` 长度为 1288 或 1292；17 次响应反序列化均为 HTTP 200，
业务码为 0 的 14 次、-2002 的 3 次。所有回调栈均进入 OkHttp 拦截器和 `okhttp3.RealCall`，
没有 Cronet 栈帧或 Cronet 入口事件。该窗口继续只闭合 OkHttp 路径覆盖，不提升为
Cronet 六头链、standalone signer、整请求差分或线上验签。详见
`platforms/bytedance/tomato/evidence/vm9_networkparams_runtime_fresh_20261107.json`。

2026-11-20：在当前原版 `0x171` suffix digest continuation 上继续到第五个
main-image SVC 前，保持 400000 指令窗、2 次 handler read、4 个 main-image
SVC 的既有上限。捕获停于 `+0x271dbc`，syscall 169；现场 `x0=sp+8`、
`x1=NULL`、`x8=0xa9`、`LR=image+0x272924`。pinned ELF 静态绑定验证了
`+0x271d9c..+0x271dcc` 的 syscall thunk 和 `+0x272920..+0x272954` 的
调用/返回路径，确认 169 是 `gettimeofday`，并解析成功时读取 timeval 秒、
失败时选择 `-1` 及可选输出写回。真实 ELF/Bionic 新捕获、replay 和 10 项
篡改证据拒绝通过。证据只闭合 SVC 前现场与静态返回路径关系；handler 和
动态返回、suffix 返回、完整配置、普通 Cronet 六头、完整 signer 与线上验签
仍未验证。详见
`platforms/bytedance/tomato/evidence/vm9_native_171_gettimeofday_return_20261120.json`。

2026-11-21：从 `+0x16aa4c` 的 VM 恢复点继续执行诊断回调 wrapper
`+0x288530` 和目标 `+0x26c858`。24 字节 descriptor 将目标、对象和输入字
`0x136d9140` 绑定；61 个目标指令观察点后回到 `+0x16aa4c`，停止在恢复指令
之前。24 字节对象仅计数字段从 `0x40906d13` 变为 `0x40916d13`，malloc 增量
为 1，显式 service、JNI、libc SVC 和 main-image SVC 账本不变。冻结 evidence、
16 项篡改拒绝及 fresh replay 已通过。该边界未覆盖后续清理和 suffix 返回；
完整 standalone signer、普通 Cronet 六头、Android 与线上验收仍未验证。详见
`platforms/bytedance/tomato/evidence/vm9_native_171_diagnostic_scope_entry_dynamic_20261121.json`。

同一原生回放从 `+0x16aa4c` 继续观察 1168 个 VM 指令，在 `+0x16aa48`
执行 `blr x8 -> +0x288540`，descriptor 三条指令解析到 diagnostic cleanup
目标 `+0x26c9d0`。目标参数与前一 scope-entry callback 更新的对象一致；记录停在
清理 body 之前。此 continuation 未增加 malloc、explicit service、JNI 或 libc/main
SVC 账本，冻结 evidence 和 18 项篡改拒绝通过。清理 body 和之后的 VM continuation
仍未闭合，完整 signer、普通 Cronet 六头和线上验收仍未验证。详见
`platforms/bytedance/tomato/evidence/vm9_native_171_diagnostic_cleanup_entry_dynamic_20261121.json`。

继续执行同一 scope 的原生 cleanup body `+0x26c9d0`，记录 50 条目标与匹配
Bionic 指令以及 `+0x16aa4c` 的返回边界；该恢复指令执行前停止。mutex 在 `+0x347f10` 执行
pthread unlock，状态/owner 从 `0x4001/137` 恢复到 `0x4000/0`；24 字节 scope
对象及其摘要保持不变，X0 返回零。allocator、explicit service、JNI、libc SVC
及 main-image SVC 账本均无增量；冻结 evidence、16 项篡改拒绝和 fresh replay 通过。
恢复后的 VM 指令、suffix 返回及完整 standalone signer 仍未验证。详见
`platforms/bytedance/tomato/evidence/vm9_native_171_diagnostic_cleanup_return_dynamic_20261121.json`。

2026-11-22：沿用 20261121 捕获批次，从诊断 cleanup 返回继续，通过
`+0x16aa48 -> +0x2885e0 -> +0x32a4fc` 执行共享读锁释放。descriptor 选择的
receiver 与先前 acquire 相同；`+0x88` 的 reader count 从 1 减为 0，观察的
`0x90` 字节对象除计数字段外保持不变，释放后完整字节恢复到 acquire 之前。
原版 lock/unlock helpers 执行，mutex、SP 与 X19-X29 恢复，X0=0 返回
`+0x16aa4c`，观察在该恢复指令执行前停止。allocator、explicit service、JNI、
libc/main-image SVC 账本无增量。冻结验证和 27 项篡改拒绝通过，fresh replay
与冻结 evidence 完全一致。证据覆盖当前单一 class0 control；未将原生
快照输入 Python 模型。writer/signal/wait、physical PAC、后续 VM、suffix 返回、
完整 signer、普通 Cronet 六头及线上验收仍未验证。见
[共享读锁释放证据](../platforms/bytedance/tomato/evidence/vm9_native_171_shared_reader_release_dynamic_20261121.json)。

2026-11-22：共享读锁释放后的同一原生 continuation 已完成八次 callback：
`+0x32a444 → +0x26c858 → +0x26c9d0 → +0x32a4fc → +0x257804 →
+0x257880 → +0x248344 → +0x26c858`。该实际顺序由原版 VM 调度确定，
没有套用既有独立 second-VM fixture 的下一目标。reader count 再次 `0→1→0`，
两次 getter 的 X0 均为零；六种 wrapper 字节、32 字节 descriptor 观察窗、
目标参数、输出及相邻 padding、SP/X19-X29 恢复均受到 verifier 约束。
该段记录 8566 个指令观察点，包含最终尚未执行的 `+0x16aa4c` 返回边界；
trace/code 摘要和八次调用/返回索引已冻结。新增 48、1 字节的两次 malloc，
没有 free、explicit service、JNI（含 late JNI）、Java dispatch 或 libc/main-image
SVC 增量。冻结 capture、113 项篡改拒绝及三种错误 CLI 调用检查通过；独立
fresh ELF/Bionic replay 与冻结 JSON 完全一致，649 个 Python 文件编译、公共
扫描及 diff 空白检查通过。
最后一个 scope 的 cleanup、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、
Android 和线上验收仍未覆盖；仍为单一合成 class0 control，原生快照未作为
Python 模型输入。见
[后续八次 callback 证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_reader_callbacks_dynamic_20261122.json)。

2026-11-22：在前八次 callback 的调用记录、trace/code 摘要及分配前缀完全一致后，
同一 CPU 继续完成 16 次 callback：先退出上一边界留下的 scope，再完成七组
scope 进入/退出，并执行一次 `+0x2633a4` getter。getter 的 X0=0，同时 16 字节
输出写入两个非零 word；未据此提升为实际业务值或完整构造来源。VM 调用游标从
`+0x1070a4` 推进到 `+0x10766c`，记录 18689 个指令观察点，包含最终未执行的
`+0x16aa4c` 返回边界。全部调用恢复 SP/X19-X29；scope 的选中 mutex 状态/owner
按 `0x4000/0 → 0x4001/137 → 0x4000/0` 配对，scope padding、表项其他字节和
2048 字节 diagnostic table 保持预期。allocator（含完整事件序列）、explicit
service、JNI（含 late JNI）、Java dispatch、libc/main-image SVC 账本无增量。
冻结 capture、207 项篡改拒绝和三种错误 CLI 调用通过；独立 fresh ELF/Bionic
replay 与冻结 JSON 完全一致。650 个 Python 文件编译、公共扫描和 diff 检查通过。
该观察 scope 在最终停点已关闭；后续 VM、suffix 返回、完整 signer、普通 Cronet
六头、Android 与线上验收仍未覆盖。继续使用单一合成 class0 control，原生快照
未作为 Python 模型输入。见
[后续 scope 配对证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_reader_scope_cycles_dynamic_20261122.json)。

2026-11-22：从已关闭的 scope-cycle 边界继续，原版 VM 的 32 次后续 callback
完整返回，游标从 `+0x10769c` 推进到 `+0x108bb8`。观察到 guard 获取/释放、
格式化、五次复制、StringObject 构造/析构和配置读取。十种 wrapper 的代码字节、
descriptor、目标参数、输出字段及 padding、调用/返回索引均绑定；每次返回恢复
SP/X19-X29，reader count 为 0。新增段包含 45352 个指令观察点，最后停在
`+0x16aa4c` 恢复指令执行前。malloc 增加 12 次、free 增加 7 次，完整新增
分配/释放事件受摘要约束；explicit service 仅析构注册增加 1 次。
Java-dispatch 入口观察到一次 `0x01000011` 调用，沿用既有显式 NULL-result
provider，未执行真实 ART/JVM；early/late JNI、libc/main-image SVC 账本无增量。
五次 memcpy 的长度为 16/16/16/48/192 字节，源/目标摘要及源字节保留通过；
该导入由既有内存 provider 处理，不计作 native Bionic memcpy body 验证。
冻结 capture、350 项篡改拒绝和三种错误 CLI 参数检查通过；独立 fresh ELF/Bionic
replay 与冻结 JSON 逐字段一致。651 个 Python 文件编译、公共扫描及 diff 空白
检查通过。未新增 provider，原生快照未作为 Python 模型输入；单一合成 class0
control、完整业务/heap 等价、suffix 返回、完整 signer、普通 Cronet 六头、Android
及线上验收的限制均保留。见
[后续配置读取与清理证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_scope_configuration_dynamic_20261122.json)。

2026-11-22：从配置阶段的 `+0x16aa4c` 继续，同一原生执行完成 26 次后续
callback，随后在 `+0x288648 blr x8` 前停止。新增段有 28561 个指令观察点，
包含未执行的最终 BLR；实际 VM 调用游标为 `+0x108bdc..+0x10963c`。
七种 wrapper 字节、32 字节 descriptor、目标参数、输出与 padding、调用/
返回索引受约束，26 次返回均恢复 SP/X19-X29。两组共享读锁完成 `0→1→0`，
接收对象其余字节保留。原版时间 helper 将既有显式 clock provider 的
timespec 转换为微秒、毫秒、无符号秒 `1791023800`，中间值已核对。
malloc/free 各增加 5 次，新增分配大小为 `33/33/33/33/48`；explicit service
仅 clock 增加 1 次，JNI、late JNI、Java dispatch、libc/main-image SVC
账本不变。上一配置段的 callback、指令/代码摘要、PC 窗与完整新增分配
事件必须逐项匹配冻结证据后才允许进入新段。

末次 VM 调用选择 `+0x28863c` wrapper，但当前合成 class0 control 的
descriptor 首字与 X8 均为零。前三条 wrapper 指令执行后，保存的 caller
frame、`SP-16`、X0/X19 与 descriptor 关系、descriptor 保留均核对；在
第四条 BLR 执行前沿用既有拒绝策略停止。未执行回调目标、`+0x28864c`
结果写入或回调返回，未为 NULL 填造目标。早期独立 second-VM fixture 在
同一字节码游标通过 ELF ABS64 元数据绑定过 getpid/getppid（既有报告
6.185 节）；这是追踪当前 descriptor 首字来源的线索，不能直接替代本次
执行的导入来源证据，也不能据此宣称真实 Android app 存在空回调或崩溃。
冻结 capture、254 项篡改拒绝、三种错误 CLI 参数与冻结证据覆盖拒绝通过。
独立 fresh ELF/Bionic replay 与冻结 JSON 逐字段一致，652 个 Python 文件
编译、包含新增证据的公共扫描及 diff 空白检查通过。
未新增 provider，未将原生快照输入 Python 模型；physical PAC、当前 suffix
返回、完整 signer、普通 Cronet 六头、Android 与线上验收仍未验证。见
[配置后回调边界证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_configuration_callback_boundary_dynamic_20261122.json)。

2026-11-22：已将上一 NULL 回调现场绑定到当前执行的 getpid 导入来源。
原 ELF `.rela.dyn` 的符号 20、ABS64 类型 257、零 addend 将 `+0x3833b0`
指向匹配 Bionic 的 getpid `+0x1fe6c`。原版 VM 在字节码 `+0x109628` 经
`+0x16f96c` 读取该槽，`+0x16f974` 写入虚拟寄存器 1；字节码 `+0x10962c`
经 `+0x171240` 读取同一寄存器，再由 `+0x171268` 写入 descriptor 首字。
后一个双字节码操作的现场游标已前进到 `+0x109630`；verifier 分别记录
逻辑字节码起点与现场游标，避免漏记写入。两次读取/两次写入的指令字节、
地址、寄存器值与观察索引均受约束。

本次 control 在先前 26 次回调返回后，仅绑定该八字节 ABS64 槽；相邻
getppid 槽仍为零，公共 ELF loader 保持原样。descriptor 完全由原版 VM
构造。此前 26 个 callback 记录与直到旧间接调用前的 28561 个指令观察点、
代码摘要均与冻结前缀相同，末次 descriptor 仅解析后的函数首字不同。
匹配 Bionic getpid 读取零 PID 缓存后走 libc `+0x6b030` 的 syscall 172，
使用明确的合成返回值 `919`。原版 wrapper 将 W0 写入 descriptor+8，
`+12` 起的 padding 与其余字节保留，SP/X19-X29 恢复后回到 `+0x16aa4c`，
停在恢复指令执行之前。新增回调段共 16 个观察点，包含该未执行的最终
VM 边界；观察的 48 字节 TLS 与零 PID 缓存保留。分配、继承的 service、
JNI 与 SVC 账本不变，新增的一次 libc SVC 172 在独立账本明确记录；
不代表总 SVC 数不变，也没有读取宿主 PID。

独立 fresh ELF/Bionic replay 与冻结 JSON 逐字段一致；三种错误 CLI 参数、
冻结证据覆盖拒绝、653 个 Python 文件编译、包含新增证据的公共扫描和
diff 空白检查通过。

冻结 capture 和 52 项篡改拒绝通过；独立组件的原始 wrapper/Bionic 冷
getpid 路径与 16 点 continuation 检查通过。未将原生快照输入 Python 模型。
getppid、完整动态链接、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、
Android、physical PAC 与线上验收仍未验证。见
[getpid 导入与返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_getpid_import_return_dynamic_20261122.json)。

2026-11-22：从 getpid 的 `+0x16aa4c` 返回边界续跑，十二次后续 callback
返回后，确认下一空回调来自 getppid 的 ABS64 槽 `+0x3833b8`。ELF
`.rela.dyn` 符号 59、类型 257、零 addend 绑定匹配 Bionic `+0x6a36c`。
新 control 在核对 getpid 前缀的指令路径、trace/code 摘要、binding、两次
读取/两次写入、syscall 172 和返回字段后，只绑定 getppid；已有 getpid
绑定保持不变。原版 VM 在字节码 `+0x109b2c` 读取该导入，经虚拟寄存器
1，由逻辑字节码 `+0x109b30` 写入 descriptor，现场游标为 `+0x109b34`。
这条当前执行的来源链受到指令字节、地址、值与观察索引约束，未直接
改写 descriptor，也未改公共 loader。

新增段完整返回十三次 callback，包含两组 reader `0→1→0` 与四组
diagnostic entry/exit；每次调用核对 wrapper、descriptor 参数、输出及
padding 和 SP/X19-X29 恢复。getppid 原生主体执行 libc `+0x6a370` 的
syscall 173，使用显式合成 parent PID `17`；原版 wrapper 将先前测试
PID `919` 的四字节结果字段改为 `17`，相邻 padding 保留。该段共 13291
个指令观察点，包含最终未执行的 `+0x16aa4c` 恢复指令；reader count 为 0。
新增 48 字节 malloc 一次、无 free，新增分配事件受精确约束。继承的
service/JNI/SVC 账本不变，syscall 172 与新增的 173 分别入账；未读取
宿主进程信息，未把原生快照输入 Python 模型。

冻结 capture、143 项篡改拒绝、三种错误 CLI 参数与冻结证据覆盖拒绝通过。
独立 fresh ELF/Bionic replay 与冻结 JSON 逐字段一致；654 个 Python 文件
编译、包含新增证据的公共扫描与 diff 空白检查通过。本次仍覆盖一个合成
class0 control。后续 VM/suffix 返回、完整 signer、
普通 Cronet 六头、Android、physical PAC 和线上验收仍未验证。见
[getppid 导入与返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_getppid_import_return_dynamic_20261122.json)。

2026-11-22：从 getppid 返回边界继续，原版 VM 在游标 `+0x109b60` 调用
`+0x28876c -> +0x204f58`。当前 cold cache `+0x3da090` 从零变为合成
TPIDR_EL0 值 `0x7000a000`；原版 MRS 和 `+0x205020` 八字节 store 实际
执行，相邻八字节保留。wrapper 将完整 X64 写入 descriptor+8，输出之外
的 descriptor 字节、SP 与 X19-X29 均核对。原版 `+0x20513c` helper 两次
将 LR 增加 12/20 字节，分别到 `+0x204f88/+0x20501c`；应被跳过的伪造
栈指令没有执行。getppid 前缀的 13 个 callback、指令/code 摘要、binding、
descriptor 来源、syscall 172/173 及新增分配事件必须先匹配冻结证据。

新增段含 2269 个指令观察点，停在下一次 `+0x16aa48 blr x8` 执行前，
该时刻 VM 游标为 `+0x109bbc`，wrapper 为 `+0x288788`，目标为 JNI
environment acquisition `+0x26edc4`。descriptor 和 wrapper 字节已绑定，
16 字节输出 pair 已映射；目标参数只按 wrapper 静态解释，未宣称动态
调用成立。该 VM call、wrapper、目标主体与 JNI provider 均未执行。
分配、service、JNI、SVC 及显式 syscall 172/173 账本无增量；未新增
provider 或导入绑定，未把原生快照作为 Python 模型输入。

冻结 capture 与 46 项篡改拒绝通过；独立 fresh 原生 fixture 也核对了
helper 的 LR 调整、跳过路径、cold cache 与 X64 结果。单一合成 class0
control、后续 JNI 获取、VM/suffix 返回、完整 signer、普通 Cronet 六头、
Android、physical PAC 与线上验收的限制保留。见
[线程指针与 JNI 前边界证据](../platforms/bytedance/tomato/evidence/vm9_native_171_thread_pointer_before_jni_dynamic_20261122.json)。

本阶段独立 fresh ELF/Bionic replay 与冻结 JSON 逐字段一致。655 个 Python
文件编译、包含新增证据的公共扫描、三种错误 CLI 参数、冻结证据覆盖拒绝与
diff 空白检查通过。

2026-11-22：从线程指针阶段的 JNI 调用前边界继续，先核对前缀的 2269 点
trace/code 摘要、getppid receipt、线程指针 callback、cache store、helper
返回和未执行 JNI descriptor。原版 VM BLR 与 `+0x288788` 三条 tail wrapper
指令执行；两次八字节 descriptor 读取与实际目标入口参数 `X0=0x7004d1d8`
均核对。沿用现有 `verify_vm9_signer_objects.native` 的 acquisition provider：
它把合成环境 `0x70007800` 写到输出 pair 前八字节，返回 X0=0 并转向 LR。
原生 `+0x26edc4` 主体未执行，也没有真实 ART/JVM；入口 hook 观察点不能
作为主体执行证据。输出 pair 后八字节仍为 `0xffffff2300000000`，未将它
解释为有效 TLS owner。descriptor、SP 和 X19-X29 保持原值。

该段共 1887 个观察点，含共享起始 BLR、被 provider 替代的目标入口和最后
未执行的 VM BLR。保存完整 PC 路径与 observed code，离线重新构造 trace
摘要。下一游标 `+0x109c44` 选择 `+0x288794 -> +0x282b84`，descriptor
`0x7004caf8`；该调用未执行，下一 X0 只作静态解释。线程 cache 和输出 pair
在下一边界仍保留；无新增 allocation，继承的 service、JNI、SVC、显式
syscall 172/173 账本不变，本次 acquisition provider 单独入账。未新增
provider、导入绑定或原生快照驱动的 Python 语义模型。

8 项独立原版 wrapper/provider 对照覆盖两基址、跨页 pair、零和非零环境值，
核对完整 payload 内存及后八字节保留。本次仍是合成 class0 control，原生
acquisition、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、Android、
physical PAC 与线上验收仍未验证。见
[JNI provider 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_jni_provider_return_dynamic_20261122.json)。

冻结 capture、48 项篡改拒绝和独立 fresh ELF/Bionic replay 通过，重放与冻结
JSON 逐字段一致。656 个 Python 文件编译、公共扫描、三种错误 CLI 参数、
冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从 JNI provider 返回阶段的调用前边界继续，先核对其 1887 点
完整 observation path、code/trace 摘要、wrapper 两次读取、provider event
和下一 descriptor。原版 `+0x288794 -> +0x282b84` 执行，receiver 为
`0x136f3000`，在 +0x98 取出 owner `0x136d38d0`，scope 位于调用前
SP-0x50。匹配 Bionic 的原版 pthread_mutex_lock/unlock 主体执行；原版
两次 16 位 atomic store 使 `owner+8` 从 `0→1→0`，观察的全部 16 字节
最终恢复。`+0x282bc4` 的八字节读取发生在 mutex state=1 时；原版
`+0x15f778` 从 scope+8 读取保存的 owner 后解锁。

当前字段和返回结果为零，wrapper 在 `+0x2887a4` 将完整 X64 写入
`descriptor+16`，相邻字节、scope padding、SP 和 X19-X29 均核对。
callback 在观察点 88 返回；本段 1804 点在下一 VM BLR 前停止，实际
游标 `+0x109de8` 选择 `+0x2885d0 -> +0x248344` 字符串构造，descriptor
为 `0x7004ccc0`。该调用、wrapper、目标均未执行；下一参数只作静态解释。
无新增分配，继承的 service、JNI、SVC 与显式 syscall 172/173 账本不变，
本次两项 mutex call/body entry 及两次 store 单独记录。未新增 provider、
导入绑定或原生快照驱动的 Python 语义模型。

8 项独立原版代码对照覆盖两基址、高 64 位结果、value/mutex 别名，以及
mutex 改变 receiver+0x98 时仍使用保存 owner 解锁；核对持锁读取、完整结果、
padding 和寄存器恢复。前缀 JNI acquisition 仍为显式合成 provider，原生
获取主体、真实 JVM、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、
Android、physical PAC 和线上验收仍未验证。见
[加锁指针返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_locked_pointer_return_dynamic_20261122.json)。

冻结 capture、54 项篡改拒绝、无参数离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。657 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从原版加锁 getter 后的字符串构造边界继续，先核对其 1804 点
完整路径、code/trace 摘要、原生 lock/unlock、持锁读取、scope owner 读取、
两次 mutex store 与下一 descriptor。原版 `+0x2885d0 -> +0x248344` 执行，
实际参数为 object `0x7004d1d8`、source `0x126a12f0`。输入长 32 字节，
原版构造器写入 vtable、capacity=33、length=32；匹配 Bionic 的 malloc
入口执行并返回 `0x136d4020`，原版八字节 store 写入 payload pointer。
继承的 strlen/memcpy 是显式 host provider，未宣称执行其 Bionic 主体；
memcpy 复制包含结尾 NUL 的 33 字节，after-write observer 的时序单独记录。

callback 在第 157 个观察点返回，源和 payload 的含 NUL 摘要一致，object
之后八字节、descriptor、SP 与 X19-X29 保留。新增段共 771 点，在游标
`+0x109e08` 的 VM BLR 前停止；下一 `+0x2887b0 -> +0x256b84` 树指针查询
尚未执行，receiver/query 参数仅作静态解释。新增一次 33 字节分配，原因位置
`+0x248388`；malloc 计数增一，free/GC/flush 与继承的 service、JNI、SVC、
显式 syscall 172/173 账本不变。未新增 provider、导入绑定或原生快照驱动
的 Python 语义模型。

12 项独立原版代码对照覆盖两基址、空字符串、NULL source、分配失败、跨页
object 和 embedded NUL，核对完整 payload 内存、padding 与寄存器恢复；
独立用例的合成 allocator 已明确标注。前缀 JNI acquisition 仍为合成
provider；原生获取主体、真实 JVM、后续 VM/suffix 返回、完整 signer、
普通 Cronet 六头、Android、physical PAC 和线上验收仍未验证。见
[字符串构造返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_string_constructor_return_dynamic_20261122.json)。

冻结 capture、53 项篡改拒绝、默认离线校验和独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。658 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从字符串构造返回后的树查询边界继续，先核对前缀 771 点完整
路径、code/trace 摘要、原版对象写入、Bionic 33 字节分配和显式 strlen/
memcpy provider。原版 `+0x2887b0 -> +0x256b84` 接收 receiver `0x136e0000`
和 query `0x7004d1d8`，在 shared-reader 保护下调用 `+0x25c168` 查找。
当前 lookup 返回 NULL，走原版零结果分支，未执行 found-value X64 load；
没有把未执行分支写成当前 control 的动态结果。

reader count 经 `0→1→0` 恢复，read-mode flag 原值为 1，原版 store 再写 1。
四次匹配 Bionic 的原版 mutex 调用及四次 16 位 atomic store 保护计数更新；
查找期间逻辑 reader 保持活动，mutex 已释放。scope 从保存的 reader 指针
释放后，wrapper 在 `+0x2887c4` 把完整八字节零写入 descriptor+24。query
对象/payload、树 header、reader 相邻字节、scope padding、SP 和 X19-X29
均核对，callback 在第 323 个观察点返回。

新增段共 987 点，在下一 VM BLR 前停止；游标 `+0x109e30` 选择
`+0x2884cc -> +0x2484b8` 字符串析构，参数只作静态解释，该调用、wrapper
及目标均未执行。分配、service、JNI、SVC 与显式 syscall 172/173 账本无
增量，新增 reader/mutex/store 事件另行记录。未新增 provider、导入绑定或
原生快照驱动的 Python 语义模型。

16 项独立原版代码对照覆盖两基址、空/缺失查询、NULL value、零/高 X64、
既有 readers、reader-count/value 别名与跨页 value，核对 reader 活动期间
读取、释放之后写回。前缀合成 JNI acquisition、真实 JVM、后续 VM/suffix
返回、完整 signer、普通 Cronet 六头、Android、physical PAC 和线上验收
的限制保留。见
[树指针返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_tree_pointer_return_dynamic_20261122.json)。

冻结 capture、58 项篡改拒绝、默认离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。659 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从树查询返回后的字符串析构边界继续，先核对前缀 987 点完整
路径、code/trace 摘要、NULL lookup、reader/mutex 写入、scope 释放及下一
描述符。原版 `+0x2884cc -> +0x2484b8` 接收 `0x7004d1d8`，确认对象仍
持有此前 malloc(33) 返回的 `0x136d4020`，payload 摘要也与原构造记录一致。
继承的 free 导入路由进入匹配 Bionic 原版入口 `+0x1bac0`，返回后新增一次
free 账本事件。原版指令重写 vtable、清零 payload 指针，再由 D0 写入 ELF
空描述符的原始八字节 `0000000023ffffff`；未把该 opaque 状态解释成普通
零长度字符串。对象相邻字节、descriptor、SP 与 X19-X29 保留。

callback 在观察点 154 返回；void 析构器的 X0 只记录现场值，不解释为成功
状态。本段共 2374 点，在游标 `+0x109ea8` 的下一 VM BLR 前停止，选择
`+0x2884cc -> +0x2481ac` 默认 StringObject 构造，下一参数只作静态解释。
该调用、wrapper 和目标主体均未执行。free 计数增一，malloc/GC/flush、
继承的 service、JNI、SVC 与显式 syscall 172/173 账本不变。未新增 provider、
导入绑定或原生快照驱动的 Python 语义模型。

12 项独立原版代码对照覆盖两基址、NULL payload、跨页 object、free 期间
修改对象、非默认空描述符及 payload/object 别名，核对完整 guest payload
与寄存器恢复；独立用例的合成 free observer 已单独声明。前缀合成 JNI
acquisition、真实 JVM、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、
Android、physical PAC 和线上验收的限制保留。见
[字符串析构返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_string_destructor_return_dynamic_20261122.json)。

冻结 capture、49 项篡改拒绝、默认离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。660 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从析构返回边界继续，先核对前缀 2374 点完整路径、code/trace
摘要、原版 free、payload 指针清零和 ELF 原始描述符恢复。原版
`+0x2884cc -> +0x2481ac` 默认构造接收对象 `0x7004d118`，先写 vtable 与
ELF 初始描述符 `0800000000000000`，再沿继承的 malloc 导入路由进入匹配
Bionic 原版主体。malloc(8) 返回 `0x136d82c0`，原版八字节 store 写入指针，
单字节 store 写入 NUL，其余七字节保留。首字节原本即为零，写入事实仍由
原版指令轨迹与 store observer 核对，没有仅凭相同内存内容推断写入。

callback 在观察点 148 返回，X0 保留分配结果，不另解释为成功状态；对象
相邻八字节、descriptor、SP 与 X19-X29 保留。新增段共 804 点，在游标
`+0x109ecc` 的下一 VM BLR 前停止；下一次仍选择同一默认构造器，对象为
`0x7004d130`。下一参数仅作静态解释，该次调用尚未执行。malloc 计数增一，
free/GC/flush 与继承的 service、JNI、SVC、显式 syscall 172/173 账本不变。
未新增 provider、导入绑定或原生快照驱动的 Python 语义模型。

18 项独立原版代码对照覆盖两基址、分配失败、跨页 object/payload、
descriptor/object/payload 别名与自定义初始描述符，核对声明的 0xa000 字节
guest payload 范围、写入顺序/宽度与寄存器恢复；该内存比较不含原生栈和
合成线程指针区域。失败分支只清零 32 位 capacity，保留自定义
length；对照使用的合成 malloc provider 单独声明。前缀合成 JNI acquisition、
真实 JVM、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、Android、
physical PAC 和线上验收的限制保留。见
[默认字符串构造返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_default_string_constructor_return_dynamic_20261122.json)。

冻结 capture、56 项篡改拒绝、默认离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。661 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从 `+0x109ecc` 的第二次默认字符串构造继续，先核对前缀
804 点完整路径、code/trace 摘要、原版 malloc 事件、对象写入及下一描述符。
复用已冻结 owner 的 read/store/return 观察逻辑，原版
`+0x2884cc -> +0x2481ac` 再次执行，目标对象为 `0x7004d130`。匹配 Bionic
malloc(8) 返回 `0x136d82d0`；原版指令写 vtable、初始描述符、payload
指针与单字节 NUL。分配返回时八字节原本均为零，单字节写入仍单独记录；
没有把该现场描述成构造器清零整个分配区。相邻字节、descriptor、SP 与
X19-X29 保留，X0 只记录分配结果。

首对象 `0x7004d118` 的 24 字节有效区域及其 `0x136d82c0` 的八字节
payload，在第二段开始、返回和停止时均与前证据一致；新段持续拒绝任何
覆盖这两个区域的写入。该对象的后继对象已进入初始化，保护范围按有效
对象宽度明确记录。

新段同为 804 点，callback 在观察点 148 返回。游标 `+0x109ef0` 选择
第三次默认构造，对象 `0x7004d148`；下一参数仅作静态解释，该次调用
尚未执行。malloc 计数从 580 增至 581；free/GC/flush、继承的 service、
JNI、SVC 与显式 syscall 172/173 账本不变。未新增 provider、导入绑定或
原生快照驱动的 Python 语义模型。

22 项独立原版代码对照包含继承的 18 项 fresh 用例，以及两基址上的四项
相邻首对象保护/第二次分配失败检查；合成 malloc provider 单独声明。
内存比较覆盖声明的 0xa000 字节 guest payload，不含原生栈与合成线程
指针区域。前缀合成 JNI acquisition、真实 JVM、后续 VM/suffix 返回、
完整 signer、普通 Cronet 六头、Android、physical PAC 和线上验收的限制
保留。见
[第二次默认字符串构造返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_second_default_string_constructor_return_dynamic_20261122.json)。

冻结 capture、65 项篡改拒绝、默认离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。662 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从 `+0x109ef0` 的第三次默认字符串构造继续，先核对前缀
804 点路径、code/trace 摘要、原版分配、对象写入、首对象保护记录与下一
descriptor。复用冻结 owner 的 read/store/return 观察逻辑，原版
`+0x2884cc -> +0x2481ac` 接收 `0x7004d148`，匹配 Bionic malloc(8) 返回
`0x136d82d8`。vtable、初始描述符、payload 指针和单字节 NUL 写入均记录；
分配返回时八字节已为零，未把现场解释成构造器清零整个分配区。callback
在观察点 148 返回，object 相邻字节、descriptor、SP 与 X19-X29 保留，
X0 只记录分配结果。

前两个对象 `0x7004d118`、`0x7004d130` 的各 24 字节有效区域，以及
`0x136d82c0`、`0x136d82d0` 的各八字节 payload，在新段开始、返回和停止
时均与前证据一致。整个新段持续拒绝覆盖这四个范围的写入。旧阶段观察
状态在完成原样核对后退役，当前构造的读取、写入和返回观察复用冻结实现。

新增段共 3232 点，在游标 `+0x10a178` 的下一 VM BLR 前停止；下一调用
切换为 `+0x2885d0 -> +0x248344` 带 source 参数的构造器。下一 descriptor
为 `0x7004ccc0`，X0=`0x7004d1d8`、X1=`0x126a1330` 只作静态解释；
该次调用、wrapper 和目标均未执行，16 字节 wrapper 与 156 字节原版
constructor 另行固定。malloc 计数从 581 增至 582，free/GC/flush、继承
service、JNI、SVC 与显式 syscall 172/173 账本不变。未新增 provider、
导入绑定或原生快照驱动的 Python 语义模型。

26 项独立原版代码对照包含继承的 22 项 fresh 用例和两基址上的四项
双对象保护/分配失败检查；合成 malloc provider 单独声明。内存比较覆盖
声明的 0xa000 字节 guest payload，不含原生栈与合成线程指针区域。
前缀合成 JNI acquisition、真实 JVM、后续 VM/suffix 返回、完整 signer、
普通 Cronet 六头、Android、physical PAC 和线上验收的限制保留。见
[第三次默认字符串构造返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_third_default_string_constructor_return_dynamic_20261122.json)。

冻结 capture、73 项篡改拒绝、默认离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。663 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从 `+0x10a178` 的带 source 参数构造继续，先核对前缀 3232
点路径、code/trace 摘要、原版分配、对象写入、前两对象保护记录及下一
descriptor。原版 `+0x2885d0 -> +0x248344` 接收对象 `0x7004d1d8` 与
source `0x126a1330`，NUL 前长度为 32。匹配 Bionic malloc(33) 返回
`0x136d4020`，复用此前释放地址；分配返回时的 33 字节摘要仍为旧 payload
摘要。继承的 host memcpy 复制含 NUL 的新源，after-write observer 记录
新 source/payload 摘要一致；原版 Bionic strlen/memcpy 主体仍未执行。

复用冻结 source-constructor owner 的对象写入、服务、copy-effect 与返回
观察逻辑。vtable、capacity=33、length=32、payload 指针四次 store、
对象相邻八字节、source、SP 与 X19-X29 均核对；新增完整 48 字节
descriptor 写保护及返回比较，覆盖 `0x7004ccc0` 全块。前三个对象各 24
字节有效区域和各八字节 payload，在开始、返回与停止时均与前证据一致；
整个新段持续拒绝覆盖这六个范围的写入。未向 Python 语义模型提供原生
内存快照，也未新增 provider 或导入绑定。

callback 在观察点 157 返回，新段共 783 点，在游标 `+0x10a198` 的下一
VM BLR 前停止。下一选择 `+0x28874c -> +0x256a18` u32 树查询，descriptor
为 `0x7004cb30`；receiver=`0x136e0000`、query=`0x7004d1d8` 仅作静态
解释，该次调用尚未执行。32 字节 wrapper 与 152 字节 getter 范围另行
固定。malloc 从 582 增至 583；free/GC/flush、继承 service、JNI、SVC、
显式 syscall 172/173 与 late-JNI/Java-dispatch 账本不变。

16 项独立原版代码对照包含原带参构造 owner 的 12 项 fresh 用例和两基址
上的四项三对象保护/分配失败检查；合成 malloc 及 host strlen/memcpy 边界
均明确声明。内存比较限于声明的 0xa000 字节 guest payload，不含原生栈和
合成线程指针区域。前缀合成 JNI acquisition、真实 JVM、后续 VM/suffix
返回、完整 signer、普通 Cronet 六头、Android、physical PAC 和线上验收
的限制保留。见
[默认构造后带参字符串构造返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_defaults_string_constructor_return_dynamic_20261122.json)。

冻结 capture、68 项篡改拒绝、默认离线校验与独立 fresh ELF/Bionic replay
通过，重放与冻结 JSON 逐字段一致。664 个 Python 文件编译、公共扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）和 diff 空白检查通过。

2026-11-22：从 `+0x10a198` 的 u32 树查询继续，先核对前缀 783 点路径、
code/trace 摘要、原版对象写入、显式 host strlen/memcpy 效果、完整
descriptor 与三对象保护记录。原版 `+0x28874c -> +0x256a18` 接收
receiver=`0x136e0000`、query=`0x7004d1d8`，在 receiver+8 的配置树中查找。
当前 lookup 返回 NULL，原版 getter 选择 `0xa985f`，未执行 found-value
W32 load；没有将该结果解释成空树或声称读取了 found 分支。

reader count 经 `0→1→0` 恢复，既有 read-mode flag 再写 1。四次匹配
Bionic 的原版 mutex 调用保护 count 更新；查找时逻辑 reader 活动，mutex
已释放。scope 的 vtable/reader/status 写入、释放期间 retained-reader
读取与 mutex 半字写入分别记录。观察点 513 完成 reader 释放，523 才在
descriptor+24 写入四字节 W0，保留其后高四字节与其余 padding。低字原本
即为 `0xa985f`，store 事实仍由原版指令及写事件单独确认。

query 的 24 字节有效对象和含 NUL 的 33 字节 payload，以及前三个对象
各 24 字节与各八字节 payload，在新段持续写保护下保持不变。返回时还
核对 query 相邻字节、40 字节 tree header、0x98 字节 reader、scope
padding、SP 和 X19-X29。callback 在观察点 526 返回，新段共 1190 点。
游标 `+0x10a1c0` 的下一次 query 析构 `+0x2884cc -> +0x2484b8` 尚未
执行，X0=`0x7004d1d8` 仅作静态解释。

新段只到达继承的 mutex PLT 路由，原版对应 Bionic 主体已观察。allocator、
继承 service、JNI、SVC、显式 syscall 172/173 与 late-JNI/Java-dispatch
账本不变；未新增 provider、导入绑定或原生快照驱动的 Python 语义模型。
24 项独立原版代码对照覆盖两基址、NULL lookup/value、零/最大/高位 W32、
既有 readers、跨页 value、packed output 别名与 reader-count/scope 字段
别名，核对 reader 活动期间四字节读取、释放后写回及 padding 保留。
声明的 0xa000 字节 guest payload 与额外 24 字节 scope 完整比较，其他
原生栈和合成线程指针区域不在比较范围。前缀合成 JNI acquisition、真实
JVM、后续 VM/suffix 返回、完整 signer、普通 Cronet 六头、Android、
physical PAC 和线上验收的限制保留。见
[默认构造后 u32 树查询证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_defaults_u32_lookup_return_dynamic_20261122.json)。

冻结 capture、24 项独立原版代码对照、74 项篡改拒绝、默认离线校验与
独立 fresh ELF/Bionic replay 通过，重放与冻结 JSON 逐字段一致。665 个
Python 文件编译、公共扫描、三种错误 CLI 参数、冻结覆盖拒绝（证据 hash
不变）、源码指纹匹配与空白检查通过。



2026-11-22：从 `+0x10a1c0` 的 query 析构继续，先逐项重验冻结 u32
lookup 的 1190 点路径、code/trace 摘要、reader 读写、四次匹配 Bionic
mutex 调用、W32 descriptor 写入及四个字符串保护记录。原版
`+0x2884cc -> +0x2484b8` 接收对象 `0x7004d1d8`，释放原 33 字节
payload `0x136d4020`。观察点 15 进入继承的 free PLT，16 进入匹配
Bionic free，147 返回；allocator ledger 仅新增一次 free，计数变为
268，其余 malloc/gc/flush 不变。

三次原版八字节写入依次恢复 vtable、在 free 返回后清零指针，并从
ELF `+0x6e208` 恢复空描述符。两次原版读取、三个 store、query 相邻
八字节、完整 48 字节当前 descriptor、SP 与 X19-X29 均核对；此前
u32 结果的完整 48 字节 descriptor 在析构返回前保持不变。前三个默认
字符串的各 24 字节对象及各八字节 payload 在本段持续写保护下保持
完整，直到下一调用边界。void 析构返回的 X0 仅记录为附带寄存器值。

callback 在观察点 154 返回，新段共 734 点。下一次 VM 调用停在
`+0x10a1e0`，选择 `+0x2886b0 -> +0x25bd8c`；尚未执行的包装器保留
X0=`0x7004cbe8` descriptor，并将输出对象 `0x7004d178` 放入 X8。
完整 20 字节 wrapper 与目标入口 16 字节已固定，未执行该调用。

复用既有析构 owner 的 12 项独立原版代码对照，覆盖两基址、NULL
payload、跨页对象、free 时改写对象、定制空描述符及 payload/object
别名，完整比较声明的 0xa000 字节 guest payload，明确使用合成 free
observer。其他原生栈和合成线程指针区域不在比较范围。主路径只到达
继承的 free PLT，未新增 provider、导入绑定或原生快照驱动的 Python
语义模型；service/JNI/SVC、显式 syscall 172/173 与 late-JNI/Java-dispatch
账本不变。前缀合成 JNI acquisition、真实 JVM、后续 VM/suffix 返回、
完整 signer、普通 Cronet 六头、Android、physical PAC 与线上验收仍
未验证。见
[u32 查询后 query 析构证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_u32_query_destructor_return_dynamic_20261122.json)。

冻结 capture、12 项独立原版代码对照、56 项篡改拒绝、默认离线校验与
独立 fresh ELF/Bionic replay 通过，重放与冻结 JSON 逐字段一致。666 个
Python 文件编译、公共扫描、三种错误 CLI 参数、冻结覆盖拒绝（证据 hash
不变）、源码指纹匹配与空白检查通过。

2026-11-22：从 `+0x10a1e0` 继续进入 identifier 缓存 getter
`+0x2886b0 -> +0x25bd8c`，先重验冻结 query 析构的 734 点路径、
code/trace 摘要、free 调用与原版对象写入、descriptor 完整性及三个
默认字符串保护记录。wrapper 的 X0 保留 packed descriptor
`0x7004cbe8`，X8 接收输出引用 `0x7004d178`。

当前为冷缓存路径。原版匹配 Bionic 的两次分配分别为 48 和 16 字节，
得到普通互斥量 `0x136d4020` 与空 cache pair `0x136d73a0`；前者复用
刚释放的 query payload 地址。两个缓存初始化 guard 已发布，输出引用
由原版指令清零。新段共 1147 点，在 `+0x255d38` 调用 fopen 的 BL 前
停止，尚未执行 PLT `+0x348460` 或任何 fopen/fread/fclose 主体。解码
path/mode 的长度为 12/2，公开记录只保留含 NUL 摘要。

停止时 output 与 cache pair 均为空，当前 cache mutex 仍持有，seed
guard 仍 pending；未声称 identifier 已生成、发布、callback 已返回、
scope 已释放或寄存器已恢复。完整 48 字节 descriptor、cache globals
与原版写宽核对，前三个默认字符串各 24 字节对象与各八字节 payload
在本段持续写保护下保持完整。allocator 仅新增两次 malloc，计数变为
585，free/gc/flush 不变；继承 service/JNI/SVC、显式 syscall 172/173、
late-JNI/Java-dispatch 账本保持。未新增 provider 或导入绑定。停点选在
caller 的 BL，避免继承的 PLT 路由覆盖观察器设置的停止 PC。

既有 identifier owner 的 44 项 fresh 原版/Python 对照覆盖两基址的
32 项 cache 与 12 项 formatter 场景；固定显式 seed 文件服务只用于
这些独立组件对照。另有 19 项页回滚检查，范围不含外部 provider 效果。
比较声明的 image pages、guest payload 与明确的 outer-scope/formatter
scratch，不比较其他 physical spills 与 PAC；不向模型灌入 native
快照。serialized guard、继承 gettid/OS/JNI provider 仍为显式边界；
真实 JVM、本前缀完整 identifier 生成、后续 VM/suffix 返回、完整 signer、
Android、physical PAC 与线上接受仍未验证。见
[identifier seed-open 边界证据](../platforms/bytedance/tomato/evidence/vm9_native_171_identifier_seed_open_boundary_dynamic_20261122.json)。

冻结 capture、44 项 fresh 原版/Python 对照、19 项组件页回滚检查及
44 项篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，
重放与冻结 JSON 逐字段一致。667 个 Python 文件编译、公共扫描、三种
错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与空白
检查通过。当前 fopen 调用、identifier 生成及完整 signer 的边界保持。

2026-11-22：从 `+0x255d38` 原版 fopen BL 继续，先逐项重验冻结的
1147 点 seed-open 路径、code/trace 摘要、缓存对象、guard、descriptor
与三个默认字符串保护记录。继承的导入路由进入匹配 Bionic 原版
fopen `+0x57cd8`。`libc+0x6a6a0` 的 openat SVC 使用原 pathname、
AT_FDCWD、flags=0、mode=0；既有虚拟 OS 对非 `/proc/stat` 路径返回
-2。原版 errno 四字节写入变为 2，已选 static FILE 的 acquired flag
以四字节清零，观察点 303 返回 NULL；没有新增文件或熵 provider。

FILE 为 `0x510e5bb8`，extension 为 `0x510e54d0`，分别核对 0x98 与
0x68 字节。seed initializer 在观察点 308 返回 W0=`0xffffffff`
（signed32 -1），但 caller 随后仍以两次原版单字节 store 发布 seed
guard。16 字节 seed 保持全零并受持续写保护；完整 descriptor、此前
三个默认对象及 payload、空 output/cache pair 和持有中的 cache mutex
分别核对。当前主镜像 allocator ledger/counts 不变，服务计数只新增
一次 syscall-56，libc SVC ledger 只追加该原版 SVC；其余 JNI、main
SVC、syscall 172/173、late-JNI/Java-dispatch 账本保持。

新段共 381 点，停在 `+0x25bd1c` 调用 formatter `+0x255d84` 的 BL 前。
本路径没有执行 fread/fclose 或 formatter；已核对 fopen 与 seed
initializer 的栈返回，外层 identifier callback 仍在进行。

16 项 fresh 原版/Python readonly FILE 对照覆盖两基址的打开/重复打开、
失败、fd 零值/边界/溢出、binary 与非法 mode；另有 27 项组件拒绝检查，
仅回滚 guest pages、mapping records 与 cursor，不回滚外部 provider
效果。对照使用独立构造的输入与既有 FILE owner，比较声明的 stdio、
global/TLS/guest/mapping 字节及有序 OS 效果，不将原生快照送入 Python
语义模型。继承 virtual OS/TLS/JNI 与 serialized guard 的限制保留；
成功的熵访问、本次 identifier 生成、完整 VM 返回、独立 signer、
Android/PAC 与线上接受仍未验证。见
[seed-open 失败证据](../platforms/bytedance/tomato/evidence/vm9_native_171_identifier_seed_open_failure_dynamic_20261122.json)。

冻结 capture、16 项原版/Python FILE 对照、27 项组件回滚检查及 43 项
篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放
与冻结 JSON 逐字段一致。668 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与空白检查
通过。当前 formatter 调用和完整 signer 的未验证边界保留。

2026-11-22：从 `+0x25bd1c` 的 formatter BL 继续，先重验冻结 seed-open
失败段的 381 点路径、code/trace、fopen/seed return、errno/FILE/guard
写入与保护记录。原版 `+0x255d84` 完成 template/alphabet lazy 解码，
两次进入 `+0x255ec0`。四次八字节 state store 后状态仍全零；两次
八字节 scratch store 也保留零。37 次原版单字节 store 生成 36 字符与
结尾 NUL，核对长度、含 NUL 的摘要及完整 64 字节窗口的剩余区域；
不公开 identifier 或 seed 原始字节，写事件只保留位置/宽度/观察点。

formatter 在观察点 1139 返回，SP 与 X19-X29 恢复。X0 只作为附带
寄存器值观察，不解释为成功码。新段共 1140 点，停在 `+0x25bd24`
调用 `+0x32a1f0` 的 BL 前，X0=24；该分配未执行。三个默认对象与
payload、完整 descriptor、cache 对象/guard、输出引用与 errno 持续
写保护，allocator ledger/counts、继承 service/JNI/SVC/late dispatch
账本保持；未新增 provider 或导入绑定。外层 identifier callback 与
cache 发布仍未完成。

14 项 fresh 原版/Python formatter 对照覆盖两基址上的六组既有
template/alphabet/seed/output 场景与显式全零 seed 场景；核对声明的
guest image/payload 与 scratch 内存。另有 19 项既有组件页回滚检查，
外部 provider 效果不在回滚范围。未把原生快照用作 Python 语义模型
输入。成功熵读取、当前 identifier 对象构造/发布、完整 VM 返回、
独立 signer、真实 JVM/Android/PAC 与线上接受仍未验证。见
[identifier formatter 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_identifier_formatter_return_dynamic_20261122.json)。

冻结 capture、14 项原版/Python formatter 对照、19 项组件页回滚检查与
35 项篡改拒绝通过；默认离线校验和独立 fresh ELF/Bionic replay 通过，
重放与冻结 JSON 逐字段一致。669 个 Python 文件编译、公共工作树扫描、
三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与
空白检查通过；4 项 Rust 单元测试通过。扫描器回归测试因沙箱禁止创建
临时 `.git` fixture 未能完成，本轮该测试集保持未验证。当前下一次分配、
identifier 对象构造/发布和完整 signer 的未验证边界保留。

2026-11-23：从 `+0x25bd24` 的 operator new BL 继续，先重验冻结
formatter 段的 1140 点路径、code/trace、两次 state advance、输出摘要、
写入位置/宽度与保护记录。原版 operator new 经匹配 Bionic malloc 分配
24 字节字符串对象 `0x136d9640`；原版 `+0x248344` 构造函数再分配
37 字节 payload `0x136d4050`。四次原版对象写入的宽度依次为 8/4/4/8，
核对 vtable、capacity=37、length=36 和 payload 指针。继承的 host
strlen/memcpy provider 测量并复制含 NUL 的 formatter 输出，逐字节相等；
原版 Bionic strlen/memcpy 主体未执行。不公开 identifier/seed 原始字节
或写事件的字节值，公开证据只保留位置、长度与摘要。

构造函数在观察点 293 返回，SP 与 X19-X29 恢复。新段共 295 点，停在
`+0x25bd3c` 调用 `+0x1625a4` 的 BL 前，X0 指向 temporary reference
`0x7004b8c0`，X1 指向新字符串；该引用构造调用尚未执行。三个默认
对象及 payload、完整 descriptor、cache globals/mutex/pair、输出引用、
完整 64 字节 formatter 源窗口和 errno 持续写保护。allocator 只新增
24/37 字节两次 malloc，malloc 总计 587；free/gc/flush 与继承的
service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch 账本保持。
未新增 provider 或导入绑定，外层 identifier callback 与 cache 发布
仍未完成。

14 项 fresh 原版/Python 对照覆盖两基址的六组既有字符串构造场景与
operator new 成功场景，组件分配器明确为合成 provider；9 项既有
string-wrapper 拒绝检查核对 guest-page 回滚，外部 provider 效果不在
回滚范围。未将原生快照送入 Python 语义模型。引用构造、cache 发布、
成功熵访问、完整 VM 返回、独立 signer、真实 JVM/Android/PAC 与线上
接受仍未验证。见
[identifier 字符串构造返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_identifier_string_constructor_return_dynamic_20261123.json)。

冻结 capture、14 项原版/Python 对照、9 项组件页回滚检查及 42 项篡改
拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放与
冻结 JSON 逐字段一致。670 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与空白检查
通过。此前冻结证据和语义 owner 的基线 hash 保持不变。当前引用构造
调用、cache 发布和完整 signer 的未验证边界保留。

2026-11-23：从 `+0x25bd3c` 的引用构造 BL 继续，先逐项重验冻结
字符串构造段的 295 点路径、code/trace、两次分配、原版对象写入、
继承 memcpy 效果、栈返回与保护记录。原版 `+0x1625a4` 清空临时
pair，进入诊断 scope，写入字符串指针并创建四字节引用计数。诊断
table 的槽 100 起初为空，原版 48 字节分配创建递归互斥量
`0x136d4080`；scope 进入时 state=0x4001、owner=137，退出后恢复
state=0x4000、owner=0。既有 guard、global lock 与 table 保留，仅
该 table 槽被写入；global lock 前后摘要相同。

引用构造在观察点 1474 返回，identifier factory 在 1483 返回；前者
核对 SP 与 X19-X29，后者依据其真实保存帧及未改寄存器核对完整
恢复，SP 从 `0x7004b850` 恢复为 `0x7004b8b0`。临时引用
`0x7004b8c0` 指向字符串 `0x136d9640`，计数块 `0x136d82e0` 为 1。
新段共 1485 点，停在 `+0x25be18` 调用输出赋值 `+0x162620` 的 BL
前。该赋值、temporary release 和 cache 发布均未执行；output/cache
pair 仍为空，cache mutex 仍持有，外层 getter 尚未返回。X0 为附带
寄存器值，不解释为字符串或计数结果。

前三个默认对象及 payload、完整 descriptor、新字符串对象与含 NUL
payload、formatter 源窗口、cache 状态和 errno 持续写保护。仅新增
48/4 字节两次 malloc，总计 589；free/gc/flush 和继承 service/JNI/SVC、
syscall 172/173、late-JNI/Java-dispatch 账本不变。未新增 provider 或
导入绑定；不公开 identifier/seed 原始字节、初始化前的引用/计数值
或写事件值。

8 项 fresh 原版/Python 对照覆盖两基址、冷/热诊断锁与普通/NULL
字符串输入，比较声明的 image pages、guest payload、scope 字节及
有序分配/锁效果；分配器和线程 id 服务为显式组件 provider。4 项
既有引用构造拒绝检查核对 guest-page 回滚，外部 provider 效果不在
回滚范围。未将原生快照送入 Python 语义模型。输出赋值、临时引用
释放、cache 发布、完整 getter/VM 返回、独立 signer、真实 JVM/
Android/PAC 与线上接受仍未验证。见
[identifier 引用与工厂返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_identifier_reference_factory_return_dynamic_20261123.json)。

冻结 capture、8 项原版/Python 对照、4 项组件页回滚检查及 45 项篡改
拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放与
冻结 JSON 逐字段一致。671 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与空白检查
通过。此前冻结证据和语义 owner 的基线 hash 保持不变。当前外层输出
赋值、cache 发布和完整 signer 的未验证边界保留。

2026-11-23：从 `+0x25be18` 继续，先重验冻结 reference/factory 段的
1485 点路径、code/trace、引用与计数写入、诊断锁、工厂返回及保护记录。
原版 `+0x162620` 将临时引用赋给输出，计数由 1 增至 2；`+0x15e1a8`
释放临时拥有权，计数降回 1，但 temporary pair 的字节不清零。原版
`+0x1633b0` 将输出 pair 发布到 cache，计数再增至 2。输出与 cache
同指字符串 `0x136d9640` 和 counter `0x136d82e0`；临时引用生命周期
已经结束，不能因其残留 pair 字节而继续算作一个拥有者。

cache mutex 在观察点 622 解锁，getter `+0x25bd8c` 在 631 返回，
wrapper `+0x2886b0` 在 633 返回。对照原版保存的 caller frame 与未变
寄存器，SP、X19-X29 均恢复。新段共 633 点，停在 VM continuation
`+0x16aa4c` 指令之前，尚未恢复执行 VM。X0 是附带寄存器值，实际
对象结果通过输出引用核对。三个诊断锁进出循环复用既有 entry；未新增
分配或释放，allocator、service/JNI/SVC、syscall 172/173、late-JNI/
Java-dispatch 账本保持，未新增 provider 或导入绑定。

前三个默认对象与 payload、完整 descriptor、新字符串对象及含 NUL
payload、identifier globals 和 errno 持续写保护。后续函数合法复用
formatter 旧栈窗口，因此该窗口仅记录摘要，不再作为存活 payload
写保护；不公开 identifier/seed 原始字节或写事件值。

16 项 fresh 原版/Python cache 对照覆盖两基址上的八组既有场景，包括
冷/热缓存、seed-open 失败、零 seed、输出别名和跨页输出；19 项既有
拒绝检查核对 guest-page 回滚，外部 provider 效果不在回滚范围。文件、
分配及线程服务为显式组件 provider，未将原生快照送入 Python 语义
模型。后续 VM 执行、成功熵访问、完整独立 signer、真实 JVM/Android/
PAC 与线上接受仍未验证。见
[identifier 缓存发布证据](../platforms/bytedance/tomato/evidence/vm9_native_171_identifier_cache_publication_dynamic_20261123.json)。

冻结 capture、16 项原版/Python 对照、19 项组件页回滚检查及 43 项篡改
拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放与
冻结 JSON 逐字段一致。672 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与空白检查
通过。此前冻结证据和语义 owner 的基线 hash 保持不变。本次 identifier
缓存发布与 callback 返回已闭合；后续 VM 指令、完整独立 signer 与
线上验收仍未验证。

2026-11-23：从 `+0x16aa4c` 恢复原版 VM，先重验冻结 identifier
publication 段的 633 点路径、code/trace、三次计数变更、输出/cache pair、
锁释放、callback 返回与保护记录。新段共 686 点，VM cursor 从
`+0x10a1e0` 前进至 `+0x10a208`，停在下一次 `+0x16aa48` 调用前。
两个边界的 SP 与 X19-X29 摘要相同。三个默认字符串及 payload、新
identifier 对象及 payload、输出/cache pair、counter、cache mutex、
相关 globals 与 errno 持续写保护；输出与 cache 仍共享同一 pair，
计数为 2，cache mutex 保持未持有，errno 为 2。allocator、继承的
service/JNI/SVC、syscall 172/173 与 late-JNI/Java-dispatch 账本不变。
未新增 provider 或导入绑定。

下一份 48 字节 packed descriptor 位于 `0x7004cda8`，与旧调用区不同。
原版 wrapper `+0x288508` 的完整 28 字节表明：从 descriptor 读取
target `+0x32a1f0` 和 X64 size=24，再把返回指针写入 descriptor+16
（`0x7004cdb8`）。wrapper 与 target 入口代码均已固定；该 VM 调用、
wrapper、分配和结果写回尚未执行。公开记录只保留 descriptor 摘要与
已定义的参数/地址，不公开原始 descriptor、identifier/seed 或写事件值。
VM 的参数区写入按位置和宽度记录，仍存活的字符串与缓存持续受保护。

复用现有分配 wrapper owner，20 项 fresh 原版/Python 组件对照覆盖
两基址上的十组场景：零/一/24/4097/uint64 最大 size、高指针、跨页
输入/结果、provider 改写和 packed alias。组件 malloc 为显式合成
provider；9 项既有拒绝检查核对 guest-page 回滚，外部 provider 效果
不在回滚范围。组件独立执行不代表本次主路径分配已经执行；未将原生
快照送入 Python 语义模型。独立 Python VM continuation、成功熵读取、
后续 VM 返回、完整独立 signer、原生 NULL/new-handler/throw、真实
JVM/Android/PAC 与线上接受仍未验证。见
[identifier 后 VM 边界证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_identifier_vm_boundary_dynamic_20261123.json)。

冻结 capture、20 项原版/Python 分配对照、9 项组件页回滚检查及 42 项
篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放
与冻结 JSON 逐字段一致。673 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹匹配与空白检查
通过。此前冻结证据和语义 owner 的基线 hash 保持不变。当前下一次
分配、后续 VM 返回、完整独立 signer 和线上验收的未验证边界保留。

2026-11-23：重验 identifier 后冻结的 686 点 VM 路径，在现有仿真输入下
继续执行 `+0x16aa48` 分配调用。原版 wrapper `+0x288508` 从 packed
descriptor 读取 operator new `+0x32a1f0` 与 size=24；观察点 14 经
PLT `+0x347fd0`，15 进入匹配 Bionic 的原始 malloc `libc+0x1bb08`。
138 返回指针 `0x136d9660`，143 在 `+0x288518` 写入 descriptor+16
（`0x7004cdb8`），144 核对写回完成。146 返回 VM continuation
`+0x16aa4c`，对照调用前 SP 与 X19-X29 摘要均恢复，输入与 descriptor
尾部摘要保持。本次主路径使用继承的真实 Bionic 分配器，没有新增
malloc provider 或导入绑定。

新段共 681 点，VM cursor 从 `+0x10a208` 前进到 `+0x10a228`，停在
下一次 `+0x16aa48` 调用前。新的 48 字节 descriptor 在 `0x7004cdf8`；
完整 12 字节 wrapper `+0x2884cc` 将 target `+0x2481ac` 与对象地址
`0x136d9660` 取出，然后尾调用。该次 VM 调用、wrapper 与 target
均未执行。新分配内容仅保留摘要，未将未初始化内存解释成有效字段。

三个默认字符串及 payload、identifier 对象及含 NUL payload、输出/
cache pair、counter、cache mutex、相关 globals 与 errno 持续写保护，
没有重叠写入；引用计数保持 2，cache mutex 未持有，errno 保持 2。
只新增一次 24 字节 alloc 事件，malloc 589→590，free/gc/flush 不变；
service/JNI/SVC、syscall 172/173 与 late-JNI/Java-dispatch 账本不变。
公开记录只包含摘要、长度、已定义指针/标量及写入位置/宽度，不公开
identifier/seed、descriptor 或分配原始字节，不将原生快照送入 Python
语义模型。

复用现有 allocation callback owner，20 项两基址 fresh 原版/Python
组件对照使用显式合成 malloc；9 项拒绝检查核对 guest-page 回滚，外部
provider 效果仍不在回滚范围。这些组件对照未建立独立 owning allocator
一致性。原生 NULL/new-handler/throw、独立 Python VM continuation、
成功熵读取、剩余 VM 返回、完整 signer、真实 JVM/Android/PAC 与线上
接受仍未验证。见
[identifier 后分配返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_identifier_allocation_return_dynamic_20261123.json)。

冻结 capture、20 项原版/Python 分配对照、9 项组件页回滚检查及 50 项
篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放
与冻结 JSON 逐字段一致。674 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹、LF/属性规则与
空白检查通过。11 个前序冻结证据和语义 owner 的基线 hash 保持不变。
当前闭合到 24 字节分配结果写回、callback 返回及下一次 VM 调用前；
下一 target `+0x2481ac`、剩余 VM、完整独立 signer 与线上接受仍未验证。

2026-11-23：先重验冻结的 681 点 identifier 后分配段，再执行
`+0x2884cc -> +0x2481ac` 默认 StringObject 构造，目标是刚分配的
24 字节堆对象 `0x136d9660`。原版构造器读取 ELF `+0x6e168` 的
初始 descriptor，写入 vtable `+0x34f5f8`、capacity=8、length=0，
经继承的真实匹配 Bionic malloc 申请 8 字节 payload。观察点 141
返回地址 `0x136d82e8`，随后写入对象的 payload 指针，并只写一字节
NUL；其余七字节保持写入前摘要。147 在 `+0x2481f8` 返回，148 到达
VM `+0x16aa4c`，SP 与 X19-X29 摘要均恢复，packed descriptor 保持。
X0 只作为观察到的 payload 指针记录，不解释为独立构造成功状态。

新段共 858 点，VM cursor 从 `+0x10a228` 前进至 `+0x10a250`，停在
下一次 `+0x16aa48` 调用前。48 字节 descriptor 在 `0x7004cd80`；
完整 16 字节 wrapper `+0x288530` 将 scope 地址 `0x7004d1d8` 放入
X0，新 StringObject 地址 `0x136d9660` 放入 X1，再尾调用诊断入口
`+0x26c858`。此调用、wrapper 与 target 均未执行，参数只作静态投影。

此前三个默认字符串及 payload、identifier 对象及含 NUL payload、
输出/cache pair、counter、cache mutex、相关 globals 与 errno 持续
写保护，没有重叠写入；callback 返回后将新堆对象及完整八字节 payload
加入保护范围。计数仍为 2、cache mutex 未持有、errno 为 2。只新增
一次八字节 alloc 事件，malloc 590→591，free/gc/flush 与继承的
service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch 账本不变。
未新增 provider 或导入绑定。公开记录只包含摘要、长度、已定义字段
和写入位置/宽度，不公开 identifier/seed、packed descriptor 或分配
原始内容，不把未初始化内存解释成有效字段。

复用既有默认构造观察 owner 的 18 项原版布局/写宽/SP 检查，以及
consumer 语义 owner 的 8 项两基址 fresh 原版/Python 对照，覆盖正常、
NULL 分配、跨页对象及 packed alias；这些组件使用显式合成 malloc。
12 项既有 consumer-family 拒绝检查核对 guest-page 回滚，外部 provider
效果不在回滚范围。原生快照未作为 Python 语义模型输入。独立 owning
allocator 一致性、真实 Bionic NULL 分支、独立 Python VM、成功熵读取、
剩余 VM 返回、完整 signer、真实 JVM/Android/PAC 与线上接受仍未验证。
见 [identifier 后堆字符串构造证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_identifier_heap_string_constructor_return_dynamic_20261123.json)。

冻结 capture、18 项原版布局检查、8 项原版/Python 对照、12 项组件页
回滚检查与 54 项篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic
replay 通过，重放与冻结 JSON 逐字段一致。675 个 Python 文件编译、
公共扫描、三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码
指纹、LF/属性规则与空白检查通过。15 个前序证据和 owner 的基线 hash
保持不变。本次闭合到堆字符串默认构造返回及下一 VM 调用前；诊断
scope `+0x26c858`、剩余 VM、完整独立 signer 与线上接受仍未验证。

2026-11-23：重验冻结的 858 点堆字符串构造段，继续执行
`+0x288530 -> +0x26c858` 诊断入口，输入为新 StringObject 地址
`0x136d9660`，scope 在 `0x7004d1d8`。地址选出 bucket 102，table slot
`0x136f8330` 原为空。原版全局 mutex 加锁后，经匹配 Bionic malloc
分配 48 字节 entry `0x136d40b0`，构造递归 mutex 并发布到该槽。
global mutex 随后恢复未持有状态，再经原版 Bionic pthread_mutex_lock
持有新 entry；状态为 `0x4001`、owner=137，scope 的 W32 lock result
从初始化值 -233 更新为 0。scope+12 的四字节 padding 摘要保持。

390 在 `+0x26c98c` 返回，391 到达 VM continuation `+0x16aa4c`，
SP 与 X19-X29 恢复，packed descriptor 保持。新段共 947 点，VM cursor
从 `+0x10a250` 前进到 `+0x10a270`，停在下一次 `+0x16aa48` 调用前。
下一 descriptor 位于 `0x7004cda8`，完整 28 字节 wrapper `+0x288508`
选择 operator new `+0x32a1f0`、size=4，预期结果槽为 `0x7004cdb8`。
该次调用、wrapper、分配与结果写回均未执行。新诊断 mutex 在停止点
仍持有，尚未执行该 entry 的解锁，scope 的完整生命周期仍未闭合。

既有三个默认字符串、identifier 字符串、新堆字符串及各 payload、
输出/cache pair、counter、cache mutex、相关 globals 和 errno 持续
写保护；另外保护 identifier 的旧 100 号 entry 及已初始化 guard。
table 除 102 号槽外摘要保持，只记录该槽的一次八字节发布。callback
返回后将 active scope 和 held entry 加入保护范围。引用计数仍为 2，
cache mutex 未持有，errno 为 2。只增加一次 48 字节 alloc 事件，malloc
591→592，其他 allocator、service/JNI/SVC、syscall 172/173 及 late-JNI/
Java-dispatch 账本不变，未新增 provider 或导入绑定。公开记录只保留
摘要、长度、已定义字段及写位置/宽度，不公开原始 identifier/seed、
packed descriptor、padding 或分配内容。

14 项两基址 fresh 原版/Python 对照覆盖七组场景，在既有六组之外补入
全局表已初始化而目标槽为空的路径；组件 allocation 为显式合成 provider，
原版匹配 Bionic mutex body 执行。7 项既有拒绝检查核对 guest-page 回滚，
外部 allocator 效果不在回滚范围；原生快照不作为 Python 语义模型输入。
完整 scope 生命周期、竞争/宿主并发、独立 owning allocator 一致性、
独立 Python VM、剩余 VM 返回、完整 signer、真实 JVM/Android/PAC 与
线上接受仍未验证。见
[identifier 后诊断入口证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_identifier_diagnostic_scope_entry_dynamic_20261123.json)。

冻结 capture、14 项原版/Python 对照、7 项组件页回滚检查及 62 项篡改
拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放与
冻结 JSON 逐字段一致。676 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹、静态范围唯一性、
LF/属性规则与空白检查通过。23 个前序证据和 owner 的基线 hash 保持。
本次闭合诊断入口返回及下一次 VM 调用前；停止点仍持有 102 号递归锁，
下一次四字节分配、该 scope 的完整生命周期、剩余 VM、完整独立 signer
与线上接受仍未验证。

2026-11-23：重验冻结的 947 点诊断入口段，在持有 102 号递归 mutex
的状态下执行下一次 `+0x288508 -> +0x32a1f0`，size=4。继承的原版
匹配 Bionic malloc 返回 `0x136d82f0`；观察点 143 在 `+0x288518`
写入 packed descriptor+16（`0x7004cdb8`），144 核对写回完成。146
返回 VM continuation `+0x16aa4c`，SP 与 X19-X29 恢复，输入 16 字节
与 descriptor 尾部摘要保持。

观察点 584 的 `+0x17208c: str w11, [x12, x10]` 对新分配执行一次
四字节写入。585 在 `+0x172090` 核对写入完成，初始化值为 1，随后
把该四字节区域加入写保护。该 VM 内部观察点不导出 GP 寄存器，只保留
已验证的初始化谓词、位置/宽度和摘要；未初始化的分配内容仅记录摘要。
新段共 1009 点，VM cursor 从 `+0x10a270` 经 `+0x10a284` 前进至
`+0x10a29c`，停在下一次 VM 调用前。新的 48 字节 descriptor 位于
`0x7004cd70`，完整 12 字节 wrapper `+0x288540` 将 scope 地址
`0x7004d1d8` 作为 X0 传给 `+0x26c9d0`。该解锁调用、wrapper 与
target 尚未执行，诊断 scope 的完整生命周期仍未闭合。

既有字符串及 payload、输出/cache pair、identifier counter、cache
mutex、相关 globals 与 errno 持续保护；另外保护 active scope、held
entry、完整诊断表、global lock 及两个全局指针字段。102 号 entry 保持
`0x4001`、owner=137，scope result=0，100 号 identifier entry 保持。
旧 packed 调用区为可复用参数存储，不作为存活对象保护。只增加一次
四字节 alloc 事件，malloc 592→593，其他 allocator 与继承的
service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch 账本不变。
没有新增 provider 或导入绑定，不公开原始 identifier/seed、packed
descriptor、未初始化内容或每次写入的寄存器值。

复用既有 20 项分配 wrapper 原版/Python 对照，新增两基址明确 size=4
的对照，共 22 项；组件 malloc 为显式合成 provider。9 项既有拒绝检查
核对 guest-page 回滚，外部 provider 效果不在回滚范围；不将原生快照
作为 Python 语义模型输入。后续解锁、完整 scope 生命周期、独立 owning
allocator 一致性、原生 NULL/new-handler/throw、独立 Python VM、剩余
VM 返回、完整 signer、真实 JVM/Android/PAC 与线上接受仍未验证。见
[诊断后四字节分配证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_diagnostic_small_allocation_return_dynamic_20261123.json)。

冻结 capture、22 项原版/Python 分配对照、9 项组件页回滚检查及 62 项
篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放
与冻结 JSON 逐字段一致。677 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹、内部寄存器过滤、
静态范围唯一性、LF/属性规则和空白检查通过。25 个前序证据和 owner
的基线 hash 保持。本次闭合四字节分配、结果写回和 VM W32 初始化；
停止点仍持有诊断锁，下一 scope 解锁、完整生命周期、剩余 VM、完整
独立 signer 与线上接受仍未验证。

2026-11-23：重验冻结的 1009 点四字节分配/初始化段，执行
`+0x288540 -> +0x26c9d0` 清理当前诊断 scope。scope result=0，原版
tail branch 进入匹配 Bionic `pthread_mutex_unlock`。观察点 41 在
`libc+0x68e48` 通过四字节 store 清除 owner，44 在 `libc+0x68e54`
通过半字 release store 将状态从 `0x4001` 改为 `0x4000`。42 和 45
分别核对两个步骤，内部 GP 寄存器不导出。55 返回 VM continuation
`+0x16aa4c`，SP 与 X19-X29 恢复，packed descriptor 保持。

scope storage 与四字节 padding 摘要在返回前保持；返回时结束该 scope
生命周期，后续不再解码其对象字段，只保留栈存储的地址和摘要，允许
VM 合法复用。bucket 102 的 entry `0x136d40b0` 仍保留在进程表中，
mutex owner=0、state=`0x4000`。entry 的 vtable/tail 在解锁过程中保护，
返回后将已释放的 header 也加入保护。这闭合当前样本的诊断进入/离开
配对，不表示进程拥有的诊断 entry 被析构或释放。

既有字符串及 payload、输出/cache pair、identifier counter、cache
mutex、globals、errno、完整诊断表、global lock、其他 entry 和新四字节
word 持续保护。word 保持为 1。没有新增分配或释放，allocator 与继承的
service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch 账本不变，未
增加 provider 或导入绑定。新段共 921 点，VM cursor 从 `+0x10a29c`
前进至 `+0x10a2c8`，停在下一次调用前。

下一 descriptor 位于 `0x7004ca78`，完整 20 字节 wrapper `+0x28880c`
选择 formatter `+0x248908`，目标为新堆 StringObject；记录 format 指针，
packed W2 只保留宽度和摘要，标注其向 X2 零扩展，不公开实际格式串、
变参值、identifier/seed、packed descriptor 或写入值。该调用、wrapper
与 formatter 均未执行，静态参数投影不代表格式化行为已验证。

16 项两基址 fresh 原版/Python leave 对照覆盖零/高位 input、跨页 scope、
正常释放、递归计数、非零 saved result、空 entry 和 owner 不匹配。使用
独立 Python 构造的组件状态，实际 leave wrapper 执行；leave 不分配或
释放。6 项拒绝检查核对 guest-page 回滚，外部 observer 效果不在回滚
范围，原生快照不作为 Python 语义输入。竞争/宿主并发、完整物理 stack/
返回 ABI、独立 Python VM、剩余 VM 返回、完整 signer、真实 JVM/Android/
PAC 与线上接受仍未验证。见
[诊断 scope 离开返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_diagnostic_scope_leave_return_dynamic_20261123.json)。

冻结 capture、16 项原版/Python leave 对照、6 项组件页回滚检查及 60 项
篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，重放
与冻结 JSON 逐字段一致。678 个 Python 文件编译、公共扫描、三种错误
CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码指纹、scope 生命周期
字段与内部解锁寄存器过滤、静态范围唯一性、LF/属性规则和空白检查通过。
27 个前序证据和 owner 的基线 hash 保持。本次闭合诊断 scope 解锁及
返回 VM；停止点位于 formatter `+0x248908` 调用前，后续格式化、剩余
VM 返回、完整独立 signer、真实 JVM/Android/PAC 与线上接受仍未验证。

2026-11-23：重验冻结的 921 点诊断 scope 离开段，执行完整 20 字节
wrapper `+0x28880c -> +0x248908`。实际 W2 在 formatter 入口保持四字节
操作数并零扩展；原版匹配 Bionic `vsnprintf` 经 `+0x347f70` 执行一次。
观察点 2276 返回 VM continuation `+0x16aa4c`，SP 与 X19-X29 恢复，
48 字节 packed descriptor 在返回前保持。新堆 StringObject `0x136d9660`
的长度从 0 变为 6，容量保持 8，payload 仍为 `0x136d82e8`，包含终止
NUL。校验器要求同次运行的 W2 十进制转换与目标长度和 payload 摘要一致，
不导出实际 W2、格式串或明文。该关系检查不表示完整 GP/FP 变参帧或
清理后的物理 X0 返回 ABI 已有原版/Python 等价证明。

新增 16、8、32 字节三次分配，随后释放这三个临时块；主路径仍走继承的
原版匹配 Bionic allocator。malloc 593→596、free 268→271，gc/flush
保持。继承的 service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch
账本均不变，没有增加 provider 或导入绑定。既有字符串、payload、输出/
cache pair、counter、已初始化 word、诊断表和 locks/entries 持续保护，
target vtable 没有写入。callback 返回后把已格式化对象及完整 payload
capacity 加入保护。已结束生命周期的诊断 scope 不再解码，packed 参数
存储在返回后允许合法复用。

新段共 3156 点，VM cursor 从 `+0x10a2c8` 前进到 `+0x10a2f4`，停在
下一次调用前。下一 descriptor 位于 `0x7004ca98`；完整 28 字节 wrapper
`+0x2887f0` 选择 `+0x248780`，该 VM call、wrapper 与 target 均未执行。
只保留 descriptor 摘要和静态路由，不推断下一次 clone/append 已完成。
不公开原始 identifier/seed、packed descriptor、分配内容、padding、
每次写入值或寄存器转储。

20 项两基址 fresh 原版/Python 对照覆盖 signed/unsigned、W2 截断、
percent/literal/empty 格式、长字符串、跨页 packed 输入和 format/output
alias。组件采用显式合成 allocator 效果，匹配 Bionic printf 实际执行；
12 项拒绝检查核对 guest-page 回滚，外部 provider 效果不在回滚范围。
原生快照不作为语义模型输入。独立 owning allocator 一致性、原生失败/
throw 路径、完整物理 stack/GP/FP/PAC ABI、竞争/宿主并发、独立 Python VM、
剩余 VM 返回、完整 signer、真实 JVM/Android 与线上接受仍未验证。见
[诊断后 formatter 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_diagnostic_formatter_return_dynamic_20261123.json)。

冻结 capture、20 项原版/Python formatter 对照、12 项组件页回滚检查及
62 项篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，
重放与冻结 JSON 逐字段一致，同次运行的 W2 转换与目标 payload 关系
断言通过。679 个 Python 文件编译、公共扫描、三种错误 CLI 参数、冻结
覆盖拒绝（证据 hash 不变）、源码指纹、退休 scope 与原始格式/变参/
寄存器过滤、静态范围唯一性、LF/属性规则和空白检查通过。34 个前序
证据和 owner 的基线 hash 保持。本次闭合 formatter 调用、Bionic printf、
临时块清理和返回 VM；下一次 `+0x2887f0 -> +0x248780` clone/append
尚未执行，剩余 VM 返回、完整独立 signer 与线上接受仍未验证。

2026-11-23：重验冻结的 3156 点 formatter 段，执行完整 28 字节
hidden-X8 wrapper `+0x2887f0 -> +0x248780`。X0 选择 36 字节 identifier，
X1 选择六字节格式化 StringObject，X8 指定目标 `0x7004d1d8`。这正是已
结束生命周期的诊断 scope 栈存储；新对象构造前只记录其地址、宽度和
存储摘要，不再解释旧 scope 字段，也不解码尚未构造的目标字段。

原版 `+0x2483e0` 在观察点 166 返回后，新 StringObject 的 length=36、
capacity=37、payload=`0x136d40e0`，payload 含 NUL 的摘要与第一个输入
一致。随后 tail branch 进入 `+0x246ba0` 追加第二个输入。629 返回
wrapper `+0x288804`，status W0=0，目标 length=42、capacity=64，
payload=`0x136df280`，包含终止 NUL；同次运行的关系断言要求其内容严格
等于第一个输入后接第二个输入。631 返回 VM continuation `+0x16aa4c`，
SP 与 X19-X29 恢复，packed descriptor 在 callback 返回前保持。

clone 增加一次显式 37 字节 malloc。追加时观察到 `+0x348320` 请求将
该 payload realloc 为 64 字节，实际进入匹配 Bionic `libc+0x1bb88`。
校验器分别核对 `+0x2469c4` 的返回指针、`+0x2469ec` 的八字节 pointer
写回和 `+0x2469f0` 的四字节 capacity 写回；这些过渡点不解码已退休的
旧 payload。继承的事件账本只增加那一次显式 malloc，malloc 596→597、
free 仍为 271，gc/flush 保持；该账本不枚举 realloc 内部分配/释放，
不能据此声称独立 owning allocator 等价。realloc 的移动与字段写回另行
记录。service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch 账本
不变，没有新增 provider 或导入绑定。

两个源对象及其 payload、其余既有字符串、输出/cache pair、counter、
已初始化 word、诊断表和 locks/entries 持续保护；callback 返回后把新
目标及当前完整 payload capacity 加入保护。新段共 1624 点，VM cursor
从 `+0x10a2f4` 前进到 `+0x10a324`，停在下一次 VM 调用前。下一 descriptor
为 `0x7004cab8`，完整 32 字节 wrapper `+0x2887d0` 选择 MD5 reference
helper `+0x25874c`；该 VM call、wrapper 与 target 尚未执行，不推断其
输入消费或摘要结果。原始字符串、identifier/seed、packed descriptor、
分配内容、padding、逐次写值和寄存器转储均不公开。

复用 16 项原版/Python 两基址对照，增加两个独立构造的 36＋6 字节
场景，共 18 项，覆盖 binary/empty、输入输出 alias、合成分配/增长失败
和跨页输出。8 项拒绝检查核对 guest-page 回滚，外部 provider 效果不在
回滚范围；组件 allocator 为显式合成服务，原生快照不进入语义模型。
完整物理 stack/GP/FP/PAC ABI、独立 owning allocator、原生失败/throw、
竞争/宿主并发、独立 Python VM、剩余 VM 返回、完整 signer、真实
JVM/Android 与线上接受仍未验证。见
[formatter 后 clone/append 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_formatter_pair_return_dynamic_20261123.json)。

冻结 capture、18 项原版/Python clone/append 对照、8 项组件页回滚检查及
81 项篡改拒绝通过；默认离线校验与独立 fresh ELF/Bionic replay 通过，
重放与冻结 JSON 逐字段一致，包含第 594 点的 realloc 返回指针，以及
第 599、600 点的 pointer/capacity 写回核对。680 个 Python 文件编译、
公共扫描、三种错误 CLI 参数、冻结覆盖拒绝（证据 hash 不变）、源码
指纹、目标构造生命周期与退休 scope 检查、原始字符串/寄存器过滤、
静态范围唯一性、LF/属性规则和空白检查通过。37 个前序证据和 owner
的基线 hash 保持。本次闭合 36＋6 字节的顺序拼接、realloc 移动及
返回 VM；下一次 MD5 reference helper `+0x25874c` 尚未执行，剩余 VM
返回、完整独立 signer 与线上接受仍未验证。

2026-11-23：重验冻结的 1624 点 clone/append 段，执行完整 32 字节
hidden-X8 wrapper `+0x2887d0 -> +0x25874c`。实际来源仍为前一步的
42 字节 StringObject `0x7004d1d8`；wrapper 读取一个字节 flag 并零扩展，
本样本选择十六进制分支。观察点 74 进入真正的 MD5 计算入口 `+0x243c34`，
871 在 `+0x258608` 返回，16 字节结果与同次运行输入的独立 MD5 计算一致。
`+0x243bdc` 是计算内部的结果字节写入点，不是函数入口。原始输入、
raw digest 和最终摘要文本不导出，只记录长度、摘要及关系谓词。

临时引用位于 `0x7004b8c8`，construct 返回时 count=1；输出 pair
`0x7004c560` 在观察点 5175 赋值返回时 count=2，5369 临时引用释放
返回后输出 count=1。临时引用生命周期结束后只保留其存储地址和摘要，
不再解码其字段。输出在实际发布前不作为有效引用解码。结果 StringObject
为 `0x136d9680`，counter 为 `0x136d8300`，payload 为 `0x136df180`，
length=32、capacity=64，含终止 NUL。5392 返回 VM continuation
`+0x16aa4c`，SP 与 X19-X29 恢复，不把物理 X0 偶然值当作模型返回 ABI。

构造、赋值和释放均通过实际 scope 入口 `+0x26c858` 及离开
`+0x26c9d0`。正式校验器分别读取入口返回、活跃 leave 入口及已退休
leave 返回的状态，后者不再解码 scope 字段。诊断表只发布 bucket 104
的一次八字节槽写入，新 entry `0x136d40e0` 在三组 scope 配对之后仍保留，
状态为 `0x4000`、owner=0。该地址是先前 realloc 后已退休的旧 clone
payload 存储，不能继续按旧 payload 解释。global lock header 的合法
瞬态写入被允许，其 vtable/tail、已发布 entry 的 vtable/tail 及其他
存活区域持续保护；callback 返回后进一步保护输出 pair、结果对象、
counter/payload、完整表和完成后的诊断状态。

新增 24、8、48、4、64 字节五次 malloc 请求，只释放结果对象最初的
八字节 payload；继承计数 malloc 597→602、free 271→272，gc/flush
保持。service/JNI/SVC、syscall 172/173、late-JNI/Java-dispatch 账本
不变，没有新增 provider 或导入绑定。原有字符串、42 字节来源、输出/
cache pair、counter 和初始化 word 保持保护。新段共 6014 点，VM cursor
从 `+0x10a324` 前进到 `+0x10a348`，停在下一次调用前。下一 descriptor
为 `0x7004ca60`，完整 28 字节 wrapper `+0x288820` 选择 CRC helper
`+0x258bac`，该 VM call、wrapper 与 target 均未执行，不推断 CRC 结果。

复用 32 项两基址原版/Python 对照，新增四项独立 42 字节 raw/hex 场景，
覆盖全局表已初始化但目标槽为空的路径，共 36 项；匹配 Bionic 递归锁
实际执行，组件 allocator 效果为显式合成服务。8 项拒绝检查核对
guest-page 回滚，外部 provider 效果不在回滚范围。原生快照不进入语义
模型，同次运行来源字节仅用于关系断言。完整物理 stack/GP/FP/PAC ABI、
独立 owning allocator、原生失败/throw、竞争/宿主并发、独立 Python VM、
剩余 VM 返回、完整 signer、真实 JVM/Android 与线上接受仍未验证。见
[拼接后 MD5 reference 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_pair_md5_return_dynamic_20261123.json)。

正式 capture 与默认离线校验均通过：6014 个观察点、36 项原版/Python
对照、8 项组件回滚检查及 90 项损坏证据拒绝检查。独立进程通过公开
`run()` 与 `validate()` 重新执行完整 ELF/Bionic 路径，所得 JSON 与冻结
证据逐字段一致。全部 681 个 Python 文件编译通过；公共扫描、三种错误
CLI 参数组合、冻结证据覆盖拒绝及拒绝前后 hash 不变、源码指纹、未发布
输出与已退休 scope/reference 的生命周期过滤、原始输入/digest/寄存器
省略、静态范围唯一性、LF/属性规则与空白检查均通过。44 个前序证据和
owner 文件保持基线 hash；下一 CRC 调用和完整独立 signer 仍未验证。

2026-11-23：完整重验冻结的 6014 点 MD5 reference 返回结果，并执行
28 字节 wrapper `+0x288820 -> +0x258bac`。CRC 的实际来源是上一检查点
保留的 32 字节十六进制 MD5 StringObject `0x136d9680`，payload 为
`0x136df180`。观察点 12 进入 buffer CRC `+0x24b298`，244 返回
`+0x258bc4`。guest ELF 的 `+0x96144` 表共 256 项、1024 字节，与独立
生成的 reflected CRC32 表一致；原版返回 W0 同时满足 guest 表计算和
同次运行输入的 `binascii.crc32` 关系。实际输入及 CRC 值不公开。

wrapper 在观察点 246 的 `+0x288830` 仅写四字节到 `0x7004ca70`，
247 在下一条指令检查写回结果。packed descriptor 的前 16 与后 28 字节
保持，249 返回 VM continuation `+0x16aa4c`，SP 和 X19-X29 恢复。
写回前只记录输出存储摘要，实际 store 后才检查其值。原来源、所有保留
的 MD5/reference/诊断区域及 CRC 表持续写保护。没有新增分配、释放、JNI
或服务效果，malloc/free/gc/flush 仍为 602/272/3/4；全部继承账本与前序
case result 逐字段相等，没有新增 provider 或导入绑定。

新段共 1206 点，VM cursor 从 `+0x10a348` 前进到 `+0x10a37c`。
下一 descriptor `0x7004cd80` 通过完整 16 字节 tail wrapper `+0x288530`
选择诊断 scope 入口 `+0x26c858`；该 VM call、wrapper 和 target 均未执行，
不推断下一 scope 的结果。原始输入、identifier/seed、CRC 数值、packed
descriptor、分配内容、padding、逐次写值和寄存器转储均不导出。

32 项既有原版/Python 对照加四项独立构造的 32/42 字节场景，共 36 项，
覆盖两个 image base、signed 非正长度、binary/NUL、跨页、alias、声明
长度边界和变更后的 guest 表；18 项拒绝检查确认全部 guest 页保持。
外部 provider 效果不在回滚范围，原生快照不进入语义模型。完整物理
stack/GP/FP/PAC ABI、独立 Python VM、剩余 VM 返回、完整 signer、真实
JVM/Android 与线上接受仍未验证。见
[MD5 文本 CRC 返回证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_md5_crc_return_dynamic_20261123.json)。

正式 capture 与默认离线验证均通过：1206 个观察点、36 项原版/Python
对照、18 项组件回滚检查和 69 项损坏证据拒绝检查。独立进程通过公开
`run()` 与 `validate()` 重新执行完整 ELF/Bionic 路径，所得 JSON 与冻结
证据逐字段一致。685 个仓库 Python 文件编译通过；公共扫描、三种错误
CLI 参数组合、冻结证据覆盖拒绝及拒绝前后 hash 不变、源码指纹、完整
前序结果相等、未写回输出过滤、原始输入/CRC/寄存器省略、静态范围
唯一性、LF/属性规则和空白检查均通过。46 个前序证据和 owner 文件保持
基线 hash；下一诊断 scope 调用和完整独立 signer 仍未验证。

2026-11-23：完整重验冻结的 1206 点 CRC 返回结果，执行完整 16 字节
tail wrapper `+0x288530 -> +0x26c858`。scope 存储为 `0x7004c660`，
输入对应保留的 MD5 对象 `0x136d9680`，复用 bucket 104 的既有 entry
`0x136d40e0`。没有新增 table publication；完整表和 global lock 保持。
观察点 26 完成构造字段写入后才解码 scope，保留四字节 padding；实际
Bionic 递归锁经 39 的 PLT 和 40 的 libc 入口执行，101 返回后 entry
由 `0x4000`/owner=0 变为 `0x4001`/owner=137。102 写回 lock result=0，
此前 sentinel 为 -233。112 返回 VM continuation，SP 与 X19-X29 恢复，
packed descriptor 保持。scope 和 entry 一直持锁到本检查点边界。

callback 后 VM 在第 522 点 `+0x17208c` 对 MD5 counter `0x136d8300`
执行一次四字节写入，计数从 1 减到 0；523 在 `+0x172090` 读取并核对
实际写回，随后重新保护该计数存储。只允许这一处已观察的计数更新，
其余存活区域持续保护。零计数后的存储仍未释放，不再将旧 pair 解码为
活跃拥有引用。初次私有 probe 将这次续段写入报告为保护冲突；补充原生
重跑独立读取写入前后值及下一调用参数，正式校验器据此限定写入与生命周期。

本段共 1249 个观察点，VM cursor 从 `+0x10a37c` 前进到 `+0x10a3bc`。
下一 descriptor `0x7004cc80` 经完整 12 字节 tail wrapper `+0x288610`
选择 `+0x32a264`，参数对应该零计数存储。静态代码表明目标转向 free
路由；该 VM call、wrapper 和 target 均未执行，没有实际 free。新增
分配/释放为零，malloc/free/gc/flush 保持 602/272/3/4；全部继承 JNI、
SVC 和显式服务账本保持，没有新增 provider 或导入绑定。前序 serializer
结果逐字段等于冻结 CRC case；allocator 前缀计数由最终原生计数减去
实际新增分配/释放事件得出，本样本增量为空。

18 项原版/Python 双基址对照覆盖 cold/warm、递归/saturated、跨页、
alias、已存在/缺失槽，以及独立构造的 bucket 104 former StringObject
存储重用；7 项拒绝检查核对 guest-page 回滚，外部 provider 效果不在
回滚范围。组件 allocator 为显式合成服务；原生快照不进入语义模型。
只公开哈希、已定义字段、关系及写入位置/宽度，不公开原始 word/CRC、
输入、identifier/seed、descriptor、分配内容、padding 或寄存器转储。
scope leave、计数/对象清理、完整物理 stack/GP/FP/PAC ABI、独立 owning
allocator、独立 Python VM、剩余 VM 返回、完整 signer、真实 JVM/Android
与线上接受仍未验证。见
[CRC 后诊断 scope 证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_crc_diagnostic_scope_entry_dynamic_20261123.json)。

正式 capture 与默认离线校验均通过：1249 个观察点、18 项原版/Python
对照、7 项组件回滚检查和 79 项损坏证据拒绝检查。独立进程通过公开
`run()` 与 `validate()` 重新执行完整 ELF/Bionic 路径，所得 JSON 与冻结
证据逐字段一致，包括持续持有的 scope 和 522/523 的引用计数转换。
686 个仓库 Python 文件编译、公共扫描、三种错误 CLI 参数组合、冻结
证据覆盖拒绝及拒绝前后 hash 不变、源码指纹、完整前序结果相等、scope/
counter 生命周期过滤、原始 word/CRC/寄存器省略、静态范围唯一性、LF/
属性规则和空白检查均通过。48 个前序证据和 owner 文件保持基线 hash；
下一计数存储释放、scope leave 和完整独立 signer 仍未验证。

2026-11-23：完整重验冻结的 1249 点 held-scope 前缀，执行完整 12 字节
tail wrapper `+0x288610 -> +0x32a264`。实际 free 参数是上一检查点已归零
的 counter 存储 `0x136d8300`；观察点 7 到达 `+0x347fa0`，8 进入匹配
Bionic `libc+0x1bac0`。从此入口起不再读取或解释该计数字段，snapshot
保留地址/宽度与生命周期标记，`counter_fields={}`。139 返回 VM
continuation `+0x16aa4c`，SP 和 X19-X29 恢复，packed descriptor 保持。
void free 不产生 packed 结果，不比较或公开物理返回 X0。

随后原版 VM 在 263 的 `+0x171268`，通过 `STR X15` 将旧 pair 的计数
指针槽 `0x7004c568` 写为 NULL；此前槽内容与已退休 counter 地址一致。
264 在 `+0x17126c` 读取实际写回并确认八字节全零，随后重新保护该槽。
该读取只针对仍有效的指针存储，不解引用已释放的 counter，也不把旧
pair 解释为活跃拥有引用。最初私有 probe 将这一处续段写入报告为保护
冲突；补充重跑实际核对前后字节和 NULL 关系，正式校验器仅允许这一
已确认位置/宽度/值的写入窗口。MD5 对象 `0x136d9680`、payload、scope
与 entry 仍完整；bucket 104 保持 `0x4001`/owner=137，表及 global lock
保持。新增分配为零、free 一次，malloc/free/gc/flush 为 602/273/3/4。
继承 JNI、SVC 和显式服务账本不变，没有新增 provider 或导入绑定。

本段共 966 点，VM cursor 从 `+0x10a3bc` 前进到 `+0x10a3e8`。下一
descriptor `0x7004cdf8` 经完整 12 字节 wrapper `+0x2884cc` 选择 MD5
StringObject 的 deleting destructor `+0x2484fc`；参数对应保留的对象，
该 VM call、wrapper 和 target 均未执行。对象/payload 删除和 scope
leave 尚未闭合。完整前序 serializer 结果与冻结 scope case 逐字段相等，
allocator 前缀计数由最终原生计数减去新增 free 事件得出。

20 项原版/Python 双基址对照覆盖 NULL/high/unaligned pointer、跨页、
alias 及显式 free provider 写入效果；新增四项独立四字节零计数场景，
含 packed-tail alias，比较 bookkeeping 移除与覆写字节。12 项拒绝检查
核对 guest-page 回滚，外部 provider 效果不在回滚范围。组件 free 为
显式合成服务，不声称独立 owning allocator 等价；原生快照不进入语义
模型。只公开哈希、已定义字段、关系及写入位置/宽度，不导出原始输入、
word/CRC、identifier/seed、descriptor、分配内容、padding 或寄存器
转储。完整物理 stack/GP/FP/PAC ABI、独立 Python VM、剩余 VM 返回、
完整 signer、真实 JVM/Android 与线上接受仍未验证。见
[CRC 后计数存储释放证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_crc_counter_free_return_dynamic_20261123.json)。

正式 capture 与默认离线校验均通过：966 个观察点、20 项原版/Python
对照、12 项组件回滚检查和 70 项损坏证据拒绝检查。独立进程通过公开
`run()` 与 `validate()` 重新执行完整 ELF/Bionic 路径，所得 JSON 与冻结
证据逐字段一致，包括 8/139 的 Bionic free 入口/返回及 263/264 的指针
清空写回。687 个仓库 Python 文件编译、公共扫描、三种错误 CLI 参数、
冻结覆盖拒绝及拒绝前后 hash 不变、源码指纹、完整前序结果相等、已退休
counter 与指针槽生命周期过滤、原始输入/CRC/寄存器省略、静态范围
唯一性、LF/属性规则及空白检查均通过。50 个前序证据和 owner 文件保持
基线 hash；MD5 对象删除、scope leave 和完整独立 signer 仍未验证。

2026-11-23：完整重验冻结的 966 点 counter-free 前缀，执行完整 12 字节
tail wrapper `+0x2884cc -> +0x2484fc`。deleting destructor 在观察点 10
调用 base destructor `+0x2484b8`，先释放 `0x136df180` 的 64 字节 payload，
再释放 `0x136d9680` 的 24 字节对象。实际匹配 Bionic free 入口分别为
21、166，返回分别为 152 的 `+0x2484e0` 和 297 的 VM continuation。
从各自 free 入口起，payload/object 的 fields 与内容摘要均停止读取，
后续 snapshot 对应字典为空；更早退休的 counter 字段始终不解码。

对象存储仍分配时，只允许析构代码的三次已定义字段写入：17 的 vtable
store、152 的 payload pointer clear、155 的八字节 scalar reset。153/156
分别核对实际写回；capacity 变为 0，原 length 字段写入 signed sentinel
-221，与 ELF `+0x6e208` 常量一致，不把该值作为可读 payload 长度使用。
payload free 返回到指针清空之间，只读取仍分配对象的字段位，不解引用
旧 payload 指针。166 进入对象 free 后也不再读取对象布局。297 返回时
SP 与 X19-X29 恢复、packed descriptor 保持；void 返回 X0 不导出或比较。

随后 VM 在 421 的 `+0x171268` 将旧 pair 的对象指针槽 `0x7004c560`
置为 NULL；观察器按实际指令解码源寄存器。422 在 `+0x17126c` 核对
实际八字节写回及整个 16 字节 pair 存储全零，随后重新保护该槽，不把
已释放 pair 解释为活跃拥有引用。scope 与 bucket 104 entry 保持持锁
`0x4001`/owner=137，表及 global lock 保持。新增 free 两次，无新增分配、
GC/flush 或 SVC；malloc/free/gc/flush 为 602/275/3/4。继承 JNI 和显式
服务账本保持，没有新增 provider 或导入绑定。完整前序 serializer 与
冻结 counter-free case 逐字段相等；前缀计数由最终原生计数减实际新增
事件重建，SVC proof 保留并核对实际前缀。

本段共 1181 点，VM cursor 从 `+0x10a3e8` 前进到 `+0x10a41c`。
下一 descriptor `0x7004cd70` 经完整 12 字节 wrapper `+0x288540`
选择 scope leave `+0x26c9d0`，参数对应该 active scope。该 VM call、
wrapper 和 target 均未执行；MD5 对象/payload 删除已闭合，scope leave
和剩余 VM 返回尚未验证。

20 项原版/Python 双基址对照覆盖 NULL/negative length、跨页、alias 和
显式 provider mutation；新增四项独立 length=32/capacity=64 场景，覆写
已退休 payload/object 字节并核对对象 free 前的重置状态。12 项拒绝检查
核对 guest-page 回滚，外部 provider 效果不在回滚范围。组件 free 为
显式合成服务，不声称独立 owning allocator 等价；原生快照不进入语义
模型。原始输入、word/CRC、identifier/seed、descriptor、分配内容、
padding 和寄存器转储不公开。完整物理 stack/GP/FP/PAC ABI、独立 Python
VM、完整 signer、真实 JVM/Android 与线上接受仍未验证。见
[CRC 后 MD5 对象删除证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_crc_md5_delete_return_dynamic_20261123.json)。

正式 capture 与默认离线校验均通过：1181 个观察点、20 项原版/Python
对照、12 项组件回滚检查及 76 项损坏证据拒绝检查。独立进程通过公开
`run()` 与 `validate()` 重新执行完整 ELF/Bionic 路径，所得 JSON 与冻结
证据逐字段一致，包括 payload/object 释放顺序及 421/422 的对象指针
清空。688 个仓库 Python 文件编译、公共扫描、三种错误 CLI 参数、冻结
覆盖拒绝及拒绝前后 hash 不变、源码指纹、完整前序结果相等、已退休
payload/object/counter 生命周期过滤、store 源寄存器解码与 NULL 写回、
原始输入/CRC/寄存器省略、静态范围唯一性、LF/属性规则及空白检查均
通过。52 个前序证据和 owner 文件保持基线 hash；scope leave、剩余 VM
返回及完整独立 signer 仍未验证。

### 2026-11-23：CRC/MD5 清理后的诊断锁释放

**Sample verified**：当前请求经 `+0x288540 -> +0x26c9d0` 进入匹配 Bionic
`pthread_mutex_unlock`。42 的观察显示 owner 137 清为零而状态仍为 `0x4001`，
45 显示状态改为 `0x4000`；55 返回到 VM，SP、X19-X29 和 packed descriptor
保持。从返回开始不再解码 scope 字段，释放后的 entry header 重新受写保护。
完整 MD5-delete 前序 serializer 逐字段一致，无新增分配、释放、SVC、JNI 或
显式服务效果。沿用既有锁模型和对照夹具，16 项双基址原版/Python 对照、
6 项 guest-page 回滚检查及 22 项损坏证据拒绝检查通过；未增加语义模型。

本段 635 个观察点将 VM cursor 从 `+0x10a41c` 推进至 `+0x10a43c`。下一处
descriptor 使用相同的 `+0x2884cc` 包装器，但目标为基础 StringObject 析构
`+0x2484b8`，此前 MD5 删除的目标则为 `+0x2484fc`。静态代码确认前者清理
payload/字段后返回，后者还会尾调用 object operator delete。不能仅凭包装器
地址推断对象所有权；下一参数的所有权及下一调用均未验证或执行。

新增验证器的状态和辅助方法以独立前缀命名，经 66 个前序类检查，无意外重名；
原有 owner 和冻结证据不改写。正式 capture、默认离线验证和完整 `--replay`
CLI 均通过，第二次 ELF/Bionic 执行所得完整 JSON 与冻结证据逐字段相等。
完整 VM 返回、独立 Python/Rust signer、真实 Android 和线上接受仍未验证。见
[诊断锁释放证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_crc_scope_leave_return_dynamic_20261123.json)。

### 2026-11-23：拼接临时字符串的基础析构与 JSON 边界

**Sample verified**：下一基础析构参数与早先拼接构造的 destination 完全一致，
是栈上 `0x7004d1d8` 的 42 字节临时字符串，payload 位于 `0x136df280`，
capacity 为 64。原版 `+0x2884cc -> +0x2484b8` 只释放 payload，未进入删除
析构 `+0x2484fc` 或 object operator delete。匹配 Bionic free 在 16 进入、
147 返回，随后清空 payload pointer；150 重置 scalar storage，151 核对
capacity=0、原 length 字段为析构 sentinel -221。154 返回 VM，SP、X19-X29
和 packed descriptor 保持。对象存储未被 free，生命周期结束后不再解码字段；
后续 storage hash 仅描述未类型化存储。payload 内容和内容摘要始终不导出。

本段 888 个观察点将 cursor 从 `+0x10a43c` 推进到 `+0x10a464`。新增一次
payload free，无新增 malloc、GC/flush 或 SVC；前序完整 scope-leave serializer
仍逐字段相等，其他被保留对象、缓存和已释放诊断锁保持。基础语义沿用既有
`destroy_string_object(delete_object=False)`，没有新建算法 owner。

下一 wrapper `+0x28883c` 的目标是 `+0x261404`，即 JSON 引用构造／解析入口，
并非 `+0x261350` 的数值追加。既有 empty-JSON 模型只覆盖 NULL source 和空对象
前缀；本次尚未证明实际 source、hidden-X8 output 或 parser 分支，调用保持未执行。
完整 VM 返回、独立 signer、真实 Android 和线上接受仍未验证。见
[临时字符串基础析构证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_crc_base_string_destructor_return_dynamic_20261123.json)。

规范 `--capture --compare-case` 与独立 ELF/Bionic 探针的完整 case 逐字段相等，
默认离线校验、16 项双基址原版／模型对照和 15 项损坏证据拒绝检查通过。前序
源码与冻结证据字节保持不变；4 种错误 CLI 参数、冻结覆盖拒绝和拒绝前后 hash
不变检查通过。687 个平台 Python 文件编译、工作区公共扫描通过。本检查点未
执行完整 `--replay` CLI；不把两次原生 case 对照扩大为完整独立 signer 验收。

### 2026-11-24：JSON 构造、全局整数与数值字段的连续原生窗口

**Sample verified**：一个有界窗口连续执行三个原版 VM 回调，共 4027 个观察点。
`+0x28883c -> +0x261404` 在 1605 返回：实际 source 是长度为 2 的空对象前缀，
descriptor +8 投影到 hidden X8 输出，+16 投影到 X0 source；两者均在实际入口核对。
输出包含新分配的 wrapper、计数为 1 的 counter，以及 type=64、child=NULL 的根节点。
根节点地址复用了已释放的临时字符串 payload 存储；只按新的存活分配账本解码 JSON，
不读取旧字符串字段。source 位于本次 image+0x3e1360，不据此断言它是文件内静态字面量。

`+0x28863c -> +0x1c3018` 在 2180 返回，实际 unsigned X0 等于入口全局
`+0x37a794` 的 word，packed +8 仅写四字节，其余 44 字节和全局值保持。
共享包装器 `+0x288648` 原先触发早期时间探针的无条件断点；本窗口只对这个已核实目标
跳过旧研究断点，并核对实际 X8、descriptor 首字及记录目标相等，没有填入猜测返回值。
五项局部边界检查覆盖已知目标放行、其他目标停止及实参不匹配拒绝，前序保存标记保持。

`+0x288854 -> +0x261350` 的数值字段插入在 3588 返回，接收对象指针等于刚构造的
JSON wrapper。三个回调均恢复 SP 和 X19-X29。本窗口观察到原版数值插入返回；未额外
证明当前全局 word 经中间 VM 浮点转换后与节点 double 的逐值关系。既有数值语义模型
仅由独立组件对照验证，不把本次原生输出用作模型输入。

第四个 descriptor 在 4023 出现，cursor 为 `+0x10a4dc`，仍使用 `+0x28863c`，但
目标变为 `+0x1c3024`。VM call 和 wrapper 已进入；4027 在 `+0x288648` 的 BLR 前
主动停止，target 未执行、未返回。该目标已有读取 `+0x37a790` 的模型，本窗口未放行；
不能把四个观察到的边界计为四个完成回调。

完整临时字符串基础析构前序 serializer 逐字段一致；前缀计数从最终原生账本减实际
新增事件重建。新增 7 次分配、1 次释放，malloc/free/gc/flush 为 609/277/3/4；
没有新增 SVC、JNI 或实际导入绑定。`pthread_mutex_init` 与 bounded strlen 沿用已有
provider；预备的匹配 Bionic strncmp bridge 未被调用。诊断表等保留区域的实际写入
按窗口记录，不把前序检查点的状态误当成后续永久不变状态。

空 JSON、全局 u32 和选定数值插入路径共 52 项双基址原版／模型对照、42 项拒绝及
guest-page 回滚检查通过。组件分配服务为显式合成效果，外部 provider 效果不在
guest-page 回滚范围内；不宣称完整 JSON parser、完整物理 ABI 或独立 owning allocator
已经恢复。只新增一份连续窗口验证器与紧凑证据，不发布原始输入、源内容或其摘要、
word 值或其摘要、packed descriptor 原文、分配内容、寄存器转储及逐指令 trace。
见 [JSON 连续窗口证据](../platforms/bytedance/tomato/evidence/vm9_native_171_json_suffix_window_dynamic_20261124.json)。

完整 VM 后缀返回、独立 Python/Rust signer、真实 Android/JVM 与线上接受仍未验证。

规范 `--capture --compare-case` 和默认离线校验通过；正式公开 case 与独立原生探针的
脱敏投影逐字段一致，52/42 项组件结果也与独立运行一致。14 项损坏证据拒绝、4 种错误
CLI 参数、5 项旧断点边界、6 个组件入口签名及冻结覆盖拒绝检查通过；拒绝覆盖前后
源码和证据 hash 保持。1444 个前序基线文件字节不变，基线内仅追加研究日志和新文件
属性规则。688 个平台 Python 文件编译、Rust 现有 4 项测试通过。本检查点未另行执行
完整 `--replay` CLI；扫描器单元测试仍受已确认的临时 Git 创建权限限制，本轮未重跑，
不记为通过。

### 2026-11-24：两条全局整数到 JSON 数值节点的数据关系

**Sample verified**：补齐上一窗口未验证的数值关系，并连续执行第二个全局 getter
及第二次数值插入。两条路径均在内存中核对 getter 的 unsigned word、VM 转换源、
double 写回、packed +24、实际 callee D0，以及最终 type=8 节点的 +48 字段；数值、
数值内容摘要、字段名及其内容摘要不导出，也不以原生页或当前值初始化独立 Python VM。

第一条来源为 image+0x37a794。前序窗口的 2825 在 `+0x17079c` 执行 `LDR S0`，
2827 的 `+0x1707ac` 执行 `UCVTF D0,D0`，2830 在 `+0x1707f8` 写回 double。
核对转换前 D0 是四字节源值的零扩展，转换后与该 unsigned uint32 的精确 binary64
表示相等；3198 的 packed 参数及实际 callee X0/X1/D0 保持该关系，3588 返回时
节点 `0x136df180` 的 double、int32 饱和字段、owned key 和一字节 success 写回均相符。

保留原窗口在 `+0x288648` 的完整停止记录后，从已进入的包装器 frame 继续执行
`+0x1c3024`，真实读取 image+0x37a790；第 8 个新观察点返回，只有 packed +8 的
四字节结果改变，其余字节和源全局保持。第二次转换在新窗口 578 读取源值，897
进入 `+0x288854 -> +0x261350`，1290 返回并核对第二个节点 `0x136df240`。
根仍为新 JSON 根 `0x136df280`；首节点 64 字节除 next/prev 追加链接外保持，
第二个节点的 double 和饱和 int32 与第二个 getter 对应，字段名副本与入口内容相等。
正式验证器另外要求节点及字段名存储均来自本次插入调用内的分配，并仍在存活账本中。

新后缀共 1725 个观察点、两个返回回调。新增 64/5 字节两次分配，没有新增 free、
GC/flush、SVC、JNI 或导入绑定；malloc/free/gc/flush 为 611/277/3/4。最终计数减去
实际新增事件后，完整前序 JSON 窗口 case 逐字段相等；前序观察记录保留在原边界，
不把后续追加后的对象状态误写回历史证据。新状态经 69 个前序类检查，无意外重名。

1725 在 VM cursor `+0x10a528` 停于下一个 VM call 之前，wrapper 为 `+0x28863c`，
target 为环境辅助入口 `+0x204e50`；VM call、wrapper 和 target 均未执行。该辅助
入口可能进入嵌套 VM，本窗口按两个新回调的预算停止，没有补入任何猜测返回值。
现有 `verify_vm9_second_environment_helper_fresh_20261016.py` 的原生对照从
`+0x204eac` 开始检查返回段；不能仅凭这个夹具把 `+0x204e50` 的整个调用视为已覆盖。

沿用既有整数转换、getter 和 JSON 数值模型；原生当前值仅用于路径内关系断言，
模型对照使用独立声明的合成输入。新证据选取 16 项双基址 abstract/backed 转换
对照、16 项第二 getter 对照及 6/10 项拒绝检查；父证据的 JSON 组件对照按源指纹
复用。另在本地执行完整 32 项转换对照；合成核对逻辑拒绝九类源值、转换、参数、
节点数值、字段复制、生命周期及追加链接损坏。这些检查不等于真实 JVM/Android、
完整浮点指令族、完整物理 ABI 或独立 signer 验收。见
[两条数值数据关系证据](../platforms/bytedance/tomato/evidence/vm9_native_171_json_field_flow_dynamic_20261124.json)。

完整 VM 后缀返回、独立 Python/Rust signer 与线上接受仍未验证。

规范 `--capture --compare-case` 与默认离线校验通过，公开 case 与独立原生探针逐字段
一致；32 项组件对照、16 项拒绝检查也与独立运行的相应结果一致。16 项损坏证据拒绝、
四种错误 CLI 参数、四个组件调用签名及冻结覆盖拒绝检查通过，拒绝前后源码和证据
hash 保持。1447 个前序基线文件字节不变，仅追加研究日志及新文件属性；689 个平台
Python 文件编译和 Rust 现有四项测试通过。本检查点未额外执行完整 `--replay` CLI；
扫描器单元测试的临时 Git 创建权限限制仍存在，本轮未重跑，不记为通过。

### 2026-11-24：环境辅助函数真实入口、嵌套 VM 与外层返回

**Sample verified**：当前受控路径从 `+0x28863c -> +0x204e50` 进入辅助函数，执行
独立嵌套 VM 后返回外层 VM。不能将这一结果扩大为真实 Android/JVM：内部
`+0x205058 -> +0x26edc4` 明确沿用既有受控 JNI 获取服务，仅写 output pair 的
前八字节、保留后八字节并返回声明的 status=0，原始获取函数体未执行。

新窗口 6 到达 helper 入口，SP 为 `0x7004b920`；28 在 `+0x204ea8` 核对调用
`+0x168324` 的实际 X0-X4、三个已定义 descriptor word、`0x500` 字节局部 frame
及 TLS canary。字节码为 `+0x8a040`，callback sentinel 为 `+0x2050e4`。144 在
`+0x1684f0` 核对独立 VM state `0x7004b7d0`、backing `0x7004b7d8` 与七个明确
初始化的槽 0/4/5/6/7/29/31；其他槽和尚未写入的 result word 不填零、不解释或导出。

外层调用内观察到四个内部回调：受控 JNI 获取、`+0x248344` 字符串构造、
`+0x26e9e0` 日志函数，以及 `+0x2484b8` 基础析构。四次均返回，嵌套 callback
SP 为 `0x7004b2a0`；独立 frame 栈避免将内部的共享 VM return PC 误认为外层返回。
本次未观察到 decode-wrapper 调用，不据缓存路径推断其他冷分支已覆盖。

14390 在 `+0x204eac` 回到辅助函数的返回段，此时 result local 仍有效，读取其
四字节结果用于内存中关系核对。14402 回到外层 VM，核对 unsigned X0 与该 word
相等，packed +8 仅写四字节，其他 44 字节、SP 和 X19-X29 保持。不在 helper frame
结束后重新解码 local result。已有 JSON wrapper、counter、根、两个节点及 owned
key 全程受保护，停止时逐字节保持；原生写入观察器未记录对这些存活区域的写入。

共 15291 个观察点，完成一个外层辅助调用及四个内部回调。新增 8 字节分配一次并
匹配释放，没有新增 GC/flush、SVC、JNI 分派或 provider；受控获取服务的再次使用
单独记录。malloc/free/gc/flush 为 612/278/3/4。减去实际新增分配事件后，完整前序
两字段 case 逐字段相等；原有源码、模型和冻结证据未改写，新状态经 70 个前序类
检查无意外重名。解码内容、临时分配内容、辅助结果值及其摘要、寄存器转储不导出。

15291 停在 cursor `+0x10a558` 的下一个外层 VM call 前，目标为
`+0x288854 -> +0x261350`；call、wrapper 和 target 均未执行。辅助结果经转换进入
第三个 JSON 数值节点的逐值关系尚未核对。整个辅助路径的实际返回已在本次受控
样本中观察到，原来的返回段夹具仅用于独立的 epilogue 对照，不再代替入口验证。

8 项双基址完整 caller frame/32 个 backing word/五个 VM 参数对照和 12 项返回段
对照，以及 8/3/14 项 caller、wrapper 和 return 拒绝及回滚检查通过。另有九项
合成分支、provider、SVC 和保留存储边界检查；合成检查不代替原生执行。见
[环境辅助入口证据](../platforms/bytedance/tomato/evidence/vm9_native_171_environment_entry_dynamic_20261124.json)。

完整独立 Python/Rust signer、真实 ART/JVM/Android、完整物理 ABI 与线上接受仍未验证。

规范 `--capture --compare-case` 和默认离线校验通过，公开 case 与独立原生探针逐字段
一致，20 项组件结果及 25 项拒绝检查也与独立运行一致。18 项损坏证据拒绝、九项
边界检查、四种错误 CLI 参数及冻结覆盖拒绝检查通过；拒绝覆盖前后源码和证据 hash
不变。1449 个前序基线文件字节保持，基线内仅追加研究日志和新文件属性规则；690
个平台 Python 文件编译及 Rust 现有四项测试通过。本检查点未额外执行完整
`--replay` CLI；扫描器单元测试仍受已确认的临时 Git 创建权限限制，本轮未重跑，
不记为通过。

### 2026-11-24：辅助结果与第三个全局整数进入第三、第四个 JSON 数值节点

**Sample verified**：在同一窗口连续完成第三次数值追加、`+0x1e53d0` 全局 getter
和第四次数值追加，共 4205 个新观察点。完整环境辅助前序 case 保持逐字段一致；
原始 JNI 获取函数体仍由前序声明的受控服务替代，不据这次数据关系推断真实 ART/JVM。

辅助结果在前序 14390 的 `+0x204eac`、helper frame 仍有效时复制，14402 已核对
实际 W0 和 packed +8 的四字节写回；frame 返回后不再重新读取 local result。
14972 在 `+0x17079c` 核对该值进入转换源，随后核对 D0 零扩展、`UCVTF D0,D0`
的精确 binary64 及 `+0x1707f8` 写回。新窗口 1 的 packed +24 和实际 X0/X1/D0
延续该关系，394 返回时第三个节点 `0x136df2c0` 的 double、int32 饱和字段和 owned
key 均相符，成功结果只写 packed +32 的一个字节，其他 47 字节保持。

829 经 `+0x28863c -> +0x1e53d0` 读取 image+0x3d60d4，840 返回，实际 unsigned
X0、四字节 packed 结果和入口全局值相符，其余 descriptor 字节与全局保持且无分配。
1410 再次核对转换源；1729 经 `+0x288854 -> +0x261350` 追加第四个数值，2509
返回并核对新节点 `0x136df300`。两次追加均恢复 SP、X19-X29；当前值只参与原生
路径内关系断言，不以原生页或当前值初始化独立 Python VM。

追加核对扩展为非空子链：第三次追加前有两个节点，第四次前有三个。首节点仅允许
prev 更新到新尾节点，旧尾仅允许 next 指向新节点，其余旧节点、数值字段和 owned
key 字节保持；root、wrapper、counter 存储保持。新节点和字段名副本必须在本次
调用内产生且仍为存活分配，不能沿用早先已释放或同址复用对象的类型解释。

新增分配顺序为 64/5/64/4 字节，无新增 free、GC/flush、SVC、JNI 效果或 provider；
malloc/free/gc/flush 为 616/278/3/4。第三个字段名副本复用上一窗口已释放的
8 字节临时字符串 payload 地址 `0x136d8310`，按本次 5 字节新分配核对内容及归属，
不再把它解释为旧 StringObject payload。源值、源值摘要、字段名内容及其摘要、
分配内容和寄存器转储不导出。新状态经 71 个前序类检查，无意外重名。

4205 在 VM cursor `+0x10a760` 停于 `+0x28887c -> +0x256f58` 之前，VM call、
wrapper 和 target 均未执行。它是后续串行原子字段读取边界，当前窗口未核对该
receiver 的归属、读取值或后续有符号浮点转换，不把现有组件覆盖扩大为当前路径已验证。

8 项双基址两／三节点、zero／uint32-max 追加对照、16 项第三 getter 对照及 16/10
项拒绝和 guest-page 回滚检查通过。组件分配服务仍为显式合成效果；外部 provider
效果不在 guest-page 回滚范围。另用声明的合成链检查 1/2/3 个已有节点，并拒绝
16 类旧节点、字段名、链接、数值、生命周期、分配代次、counter 或 padding 损坏。
见 [辅助调用后的两条数值关系证据](../platforms/bytedance/tomato/evidence/vm9_native_171_post_environment_fields_dynamic_20261124.json)。

完整独立 Python/Rust signer、真实 ART/JVM/Android、完整物理 ABI 与线上接受仍未验证。

规范 `--capture --compare-case` 与默认离线校验通过，公开 case 与独立原生探针逐字段
一致；24 项组件对照及 26 项拒绝／回滚结果与独立报告一致。18 项损坏证据拒绝、
三个合成链正例及 16 类损坏检查、四种错误 CLI 参数和冻结覆盖拒绝检查通过，
拒绝覆盖前后源码与证据 hash 不变。1451 个前序基线文件字节保持，基线内仅追加
研究日志和新文件属性规则；71 个祖先类状态检查、691 个平台 Python 文件编译和
Rust 现有四项测试通过。本检查点未额外执行完整 `--replay` CLI；扫描器单元测试
仍受已确认的临时 Git 创建权限限制，本轮未重跑，不记为通过。

### 2026-11-24：registry 原子字段经无符号转换进入第五个 JSON 数值节点

**Sample verified**：从保留的四字段检查点继续，原生执行
`+0x28887c -> +0x256f58` 和一次 `+0x288854 -> +0x261350` 数值追加，
共 2845 个新观察点、两个完整回调。完整辅助调用后两字段前序 case 逐字段一致。
原始 JNI 获取函数体仍由前序声明的受控服务替代，不据此推断真实 ART/JVM/Android。

原子入口的 receiver 为 `0x136e0000`，与前序 `hash_registry_root`、树查询及整数查询
的接收对象相同，并属于同址 320 字节存活分配，与 JSON root 有区别。观察点 1 的
cursor 为 `+0x10a760`，实际 X0 和 wrapper 返回地址相符，`+0x256f5c` 的 `LDAR W0`
地址等于 receiver+0x138。12 返回，unsigned X0 和 packed +16 四字节写回等于入口
字段；其余 descriptor 字节、接收对象前 316 字节、JSON wrapper/counter/root、四个
原有节点及 owned key 字节保持，getter 内无分配或释放。此处只证明串行观察结果，
不证明 acquire/release 并发内存语义。

657 在 `+0x17079c` 核对转换源，随后核对零扩展、`+0x1707ac UCVTF D0,D0`
的精确 binary64 及 `+0x1707f8` 写回。1030 的 cursor 为 `+0x10a798`，实际 X0/X1/D0
与 packed 参数及转换结果相符；1858 返回，第五节点 `0x136df340` 的 double、
int32 饱和字段、owned key 和一字节成功写回均相符。旧首节点 prev 与旧尾节点 next
仅更新为新节点，其余旧节点及字段名字节、root/wrapper/counter 保持；新节点与字段名
副本必须来自本次调用内的新分配并仍存活。源值仅用于原生路径内关系断言，不以原生
快照初始化独立 Python VM；源值、源内容摘要、字段名内容及摘要和寄存器转储不导出。

此前根据后续独立组件预判本字段采用 signed int32，首次探针未观察到有符号转换，
在公共浮点 store 前拒绝继续。原生轨迹明确走 UCVTF，因此修正为复用既有无符号
转换和数值追加观察器，不将已通过的独立有符号组件对照当成本字段或下一字段的证明。

新增 64/4 字节分配各一次，无新增 free、GC/flush、SVC、JNI 效果或 provider；
malloc/free/gc/flush 为 618/278/3/4。2845 停在 cursor `+0x10a7d0` 的下一次
`+0x288854 -> +0x261350` 之前，descriptor 为 `0x7004ca20`；该 VM call、wrapper
与 target 均未执行。下一数值字段的来源及其后续转换尚未建立完整关系。

18 项双基址原子 getter 对照、16 项无符号转换对照和 8 项四节点追加对照通过；
14 项 getter 拒绝／guest-page 回滚及六项浮点操作拒绝检查通过。组件输入均为声明的
合成输入，分配服务为显式合成效果；四个转换及四个第五节点合成正例、五类转换损坏
和 16 类节点／字段名／链接／生命周期／分配代次／padding 损坏检查通过。
见 [原子字段与第五数值节点证据](../platforms/bytedance/tomato/evidence/vm9_native_171_atomic_numeric_field_dynamic_20261124.json)。

完整独立 Python/Rust signer、真实 ART/JVM/Android、完整物理 ABI、并发语义与线上接受仍未验证。

### 2026-11-24：延续 VM 标量进入第六个 JSON 数值节点

**Sample verified**：从已验证的原子字段和第五节点检查点继续，三个数值 callback 均返回，
新增 4225 个指令观察点；第五节点之后的 VM 标量经原生转换写入第六节点，完整环境前序
case 逐字段一致。接收字段在 VM 源区域 `+0x17079c` 的观察点 2064 被读取，零扩展后经
`+0x1707ac UCVTF D0,D0` 转成精确 binary64，并在 `+0x1707f8` 写回。callback 参数
在 cursor `+0x10a7d0` 的观察点 2845 与转换结果相符；第六节点 `0x136df380` 在追加前
已有五个子节点，完成观察点为 3238。节点 double、
int32 饱和值、owned key 和一字节成功写回相符；已有节点及 owned key 只发生尾部链
接更新，root/wrapper/counter 保持。新节点和 key 必须是本次调用新分配并仍存活。

当前公开证据只证明这个 VM source word 到第六节点的关系，不把它误称为新的 getter；
其更早的业务来源和含义仍未知。下一次数值追加在观察点 4225、cursor `+0x10a808`
停住，descriptor `0x7004ca20`，wrapper/target `+0x288854 -> +0x261350` 均未执行。

新增分配为 64/4/64/3 字节，无新增 free、GC/flush、SVC、JNI 效果或 provider；
malloc/free/gc/flush 为 620/278/3/4。12 项 getter、16 项无符号转换和 8 项五节点
追加对照，以及 14/6 项拒绝／回滚检查沿用前一公开检查点；本轮另有八项两基址五节点
追加对照，使用 zero、one、signbit、u32max 声明输入。完整 signer、Android、物理 ABI、
并发 acquire/release 语义和线上接受仍未验证。JNI 获取函数体仍由已声明的受控服务替代。

规范 `--capture --compare-case` 和默认离线校验通过，公开 case 与私有原生重放逐字段
相同，42 项前序组件、20 项前序拒绝检查和八项新增五节点追加结果一致；14 项损坏证据
拒绝、四种错误 CLI 参数及冻结覆盖拒绝检查通过，拒绝覆盖前后源码和证据 hash 不变。
1534 个 tracked 基线文件中 1532 个字节保持，基线内仅追加研究日志和新文件属性规则。
73 个祖先类状态检查中新增 `_jan_next_` 状态无冲突；新增源码语法检查通过。本检查点
未额外执行完整 `--replay` CLI、Rust 测试或扫描器单测；扫描器单测仍受已确认的临时 Git
创建权限限制，不记为通过。
见 [第六数值节点证据](../platforms/bytedance/tomato/evidence/vm9_native_171_sixth_numeric_field_dynamic_20261124.json)。

规范 `--capture --compare-case` 及默认离线校验通过，公开 case 与独立原生探针逐字段
一致，42 项组件对照和 20 项拒绝结果也与独立报告一致。22 项损坏证据拒绝、公开版
八个合成正例及 21 项损坏检查、四种错误 CLI 参数与冻结覆盖拒绝检查通过；拒绝覆盖
前后源码与证据 hash 不变。72 个祖先类检查无新状态重名，新增验证器语法检查通过；
1530 个前序基线文件字节保持，基线内仅追加研究日志和新文件属性规则。本检查点
未额外执行完整 `--replay` CLI，Rust 测试未重跑；扫描器单元测试仍受已确认的临时
Git 创建权限限制，本轮未重跑，不记为通过。


### 2026-11-24：保留完整第六检查点，验证第七数值节点

**Sample verified**：在第六字段检查点的停止入口继续一次原生数值追加，使用独立
`_j7_` 观察状态，保留完整第六字段 case 并在结束时逐字段核对相等。前序仍停在其
原有的 4225／`+0x10a808` 边界，前序 callback 的未执行状态也保持；本轮实际执行
单独记录在新窗口，不能通过覆盖前序流或回填 done 状态满足前序检查。

第七字段的四字节 VM 源在前序窗口观察点 3444 的 `+0x17079c` 读取，核对加载后的
D0 零扩展、`+0x1707ac UCVTF D0,D0` 的精确 binary64，以及 `+0x1707f8` 写回。
源字节仅参与原生路径内关系断言，不用于初始化独立 VM，也不导出值或值摘要；其更早
的业务来源及含义仍未知。新窗口 1 在 cursor `+0x10a808` 经
`+0x288854 -> +0x261350` 调用，实际 X0/X1/D0 与 packed 参数及转换结果相符。
390 返回，第七节点 `0x136df3c0` 的 double、int32 饱和值、owned key 和一字节成功
写回均相符，SP、X19-X29 恢复。追加前有六个旧节点，旧首节点 prev 与旧尾节点 next
只更新为新节点，其余旧节点完整字节和 owned key 保持；root/wrapper/counter 保持，
新节点与 key 是本次调用内新分配且仍存活。

新增窗口共 958 个观察点，新增分配 64/4 字节各一次，无新增 free、GC/flush、SVC、
JNI 效果或 provider；malloc/free/gc/flush 为 622/278/3/4。958 停在下一次 VM call
之前：cursor `+0x10a828`，descriptor `0x7004ca60`，
`+0x288820 -> +0x258bac`（CRC 入口）。该 VM call、wrapper 和 target 均未执行；
不能据静态存在的后续有符号转换指令推断当前路径已执行该转换或取得 CRC 返回值。

新增八项双基址六节点追加 native/model 对照覆盖 zero、one、signbit、u32max，
比较完整声明内存和分配效果。另有四个无符号转换、四个七节点追加合成正例，以及五类
转换损坏和 16 类节点／字段名／链接／生命周期／分配代次／padding 损坏拒绝检查。
前序组件证据通过冻结内容摘要引用，本轮不重复执行，也不计为新增测试。新状态经
74 个祖先类检查，无意外重名。

结论仍限于声明受控样本：原始 JNI 获取函数体由前序受控八字节 env 写入服务替代；
真实 ART/JVM/Android、完整物理 ABI、并发 acquire/release、完整独立 signer 和线上
接受仍未验证。
见 [第七数值节点证据](../platforms/bytedance/tomato/evidence/vm9_native_171_seventh_numeric_field_dynamic_20261124.json)。

规范 `--capture --compare-case`、默认离线校验和独立结果一致性检查通过；完整第六字段
case 逐字段相等，八项新增组件结果与独立报告一致。20 项损坏证据、四种错误 CLI、
冻结覆盖拒绝及拒绝前后 hash 保持检查通过；公开版八个合成正例和 21 项损坏检查
通过。1536 个 tracked 基线文件中 1534 个字节保持，仅日志及新文件属性规则变更。
本轮未额外运行完整 `--replay` CLI、Rust 测试或扫描器单元测试；已知临时 Git 创建
权限限制下的扫描器单测未重试、不记为通过。
