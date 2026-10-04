# 番茄（ByteDance Tomato）完整分析与使用报告

> 截止：2026-10-04
> 结论：**本项目整体尚未完成，不能作为当前线上小说搜索下载器发布。**

这份报告把已经获得的接口、签名、解密、运行时和证据边界集中到一处。它是研究归档和后续开发的使用说明，不把桥接实验、旧快照复现或捕获状态回放描述成独立的线上实现。

最新纠正：初始化回调 `0x1000000e` 返回 `MSC.GetABSwitch()`，旧桥接器误传冻结时间。恢复 APK 默认值 `2` 后，三个旧失败时间输入成功，未取整时间的详情请求也被线上接受。Python 已独立恢复这一全局和 bit-5 分支，18 个字节码对照通过；默认 A/B=2 的 publisher 是 `+0x28c268`，两个 child/handler、root 已观测字段装配、callback pair 绑定、引用计数和 JNI 清理已有 92 个新建内存对照。2026-10-04 又恢复了 0x2d0-byte service 配置图、完整无竞争 guard 状态和真实 getter → handler 构造，72 个 native 对照、15 个拒绝/回滚例通过；root 前段的 264-byte 配置及全局启动仍未完成。此前“时间取整稳定”的结论只适用于旧误配桥接器，不能作为 native 时间约束。详见 [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md) 与 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md)。修正后当前搜索在 b/c 两个主机仍为空。

2026-10-04 的后续恢复包括 guest-table cipher（256 组 native 差分 / 11 个回滚例）及完整 mode-0 配置解密 callback（200 / 12）。后续又恢复了流状态和 reference 生命周期（174 / 9）。四次 fresh 控制中的 parser 已在 3318 步 / `+0x9c95c` 退出，165 字节消息成功解包，119 次分配、47 次 free、TLS/generation/有序副作用及 32 个虚拟槽均一致。新增字符串重填为 190 / 5，消息解包/清理为 208 / 6；60 条完整子树对照包括四次 `+0x262608` caller 验证：所需 parser 前导由 Python 生成，7 个拒绝/回滚案例通过；caller 之前的 root/堆/TLS 状态仍由同次 native 输入提供，完整 Python 冷启动和88-byte其它初始化分支仍未完成。接口、用法与证据用途见 [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) 、[STREAM_REFERENCE.md](STREAM_REFERENCE.md) 与 [PARSER_UNPACK.md](PARSER_UNPACK.md)。

较早的恢复完成已观察的 `+0x26194c → +0x261c54 → +0x261cb0` 默认配置构造路径（helper **166 / 5**、流组件回归 **174 / 9**），并将 root 推进到第605步；修正了 -0x340 工作栈、iterator length 与 saved-frame getter 的归属，详见 [CONFIGURATION_INITIALIZATION.md](CONFIGURATION_INITIALIZATION.md)。

最新检查点恢复了 `+0x25ee84 → +0x26cd0c → +0x26cdc4` 冷启动共享引用、日志／SDK／环境 getter、格式化和目录依赖（**106 组 native 差分 / 15 个拒绝回滚案例**）。Python 生成的 state caller 和完整48-byte owner 已接回 root：state VM **363步 / +0xa54bc退出，28次分配 / 21次free**；root **716步 / +0x99f04退出，171 / 93**，二者全部32个终止虚拟槽与guest/image/TLS/generation/有序副作用一致。组合为 **4个controls / 16段VM / 68条子树**，另有7个state caller前置拒绝案例。详见 [STATE_OWNER_INITIALIZATION.md](STATE_OWNER_INITIALIZATION.md)。

本次又独立生成了 `+0x257578 → +0x257084 → +0x257308 → VM +0x991c0` 默认 root factory。**8个 fresh ELF/TLS 控制不使用任何 native 函数／VM 入口快照**，32个终止虚拟槽、全部主 image、guest/TLS/generation 和有序副作用一致；完整factory分配／释放为206/93，另有9个caller拒绝和2个factory失败回滚案例。旧component对照增至4个controls/16段VM/76条子树，仍单独标注native函数入口输入。详见 [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md)。

当前控制仍使用明确的nonreusing malloc/free与虚拟OS；真实allocator全局boot、TLS/arena/OS region贯通、外层signer/handle、fresh请求签名输出和线上新矩阵仍未完成。无JVM Rust、当前非空搜索与分页、其它平台及最终Pages/Actions产品的完成状态没有变化。

外层启动的最新恢复：`+0x28040c → VM +0xa7050` 的 4 个 fresh 控制完成 86 步／16 次分配／3 次 deferred worker 创建；worker TLS support 前段为 16 个冷／热控制。OP45 的第二寄存器 bit 21 和 equality 语义由 308 个 native 控制确认，共用 VM 的 root／state／parser 回归通过。worker dispatch、真实 allocator boot、fresh 请求签名和新线上矩阵仍未验证。详见 [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md)。

## 1. 完成度结论

| 范围 | 当前状态 | 可以据此声称什么 |
| --- | --- | --- |
| `device_register` | 私有桥接试验记录中跑通；公开索引未单独列证据 | 能取得后续请求所需的设备/会话资料；公开报告不包含真实设备标识和票据 |
| `registerkey` | 已跑通并解出会话章节密钥 | 可进入章节解密流程；报告只公开 key version 和摘要 |
| 目录接口 | **桥接线上验证通过** | 当前样本返回 611 个章节条目 |
| `reader/full` | **桥接线上验证通过** | `crypt_status=0`，AES-CBC 解密得到 6,496 字节 HTML；摘要见 `EVIDENCE_INDEX.json` |
| AES-CBC/压缩解码 | 已实现并有向量 | 可验证章节明文长度和 SHA-256 |
| Helios | Python/向量和线上矩阵支持 | 在已测阅读请求中是必需头之一 |
| 旧版 Medusa（225 字节快照） | 纯 Python 可复现 | 只能研究旧快照字段和 VM 语义，不能代表当前线上 VM9 |
| 当前 Medusa VM9 | Java/Unidbg 桥接通过；捕获状态回放通过 | 当前样本可以被桥接器签出并被阅读接口接受；仍未完成独立 fresh-input 参数化 |
| Perseus | 当前时间窗内可加可不加 | 只能说明本次矩阵未发现硬依赖，不等于永久可省略 |
| Gorgon/Ladon/Argus | 有算法/向量或矩阵证据 | 在已测阅读矩阵中可移除；不要把该结论外推到其他产品或接口 |
| 搜索 | 当前 `7.1.3.32` 首阶段仍为空；旧 `6.8.1.32` 配置的外部 Java 服务已返回两页 | 旧服务分别返回 9/10 本书、同一 searchId；不代表当前版本搜索或独立 signer 完成 |
| Python allocator/runtime | TLS、arena、tcache、OS region、空 bin、清理、部分 callback 和受控环境下的 fresh root factory 已独立建模 | 是 VM9 研究组件，不是完整 Medusa signer |
| Rust | scaffold 可编译；明确返回 current Medusa unavailable | 可承载已验证纯 Rust 边界和参数模型，不能独立访问当前阅读接口 |
| 抖音 | 仅静态/社区材料 | 没有当前版本线上签名和正文闭环 |
| 起点 | 证据缺口 | 没有 APK、签名样本、接口矩阵或章节解密向量 |
| GitHub Pages 下载网页 | 尚未开始产品实现 | 当前 `docs/` 是路线说明和研究归档，不是可用下载器 |
| GitHub Actions | 已有检查/构建骨架 | 只能构建研究归档和 Rust scaffold，不能发布完整下载能力 |

### 对“六神/七神/16/24 神”的准确结论

历史里的“神”是请求头名称，不是 VM 层。六个传统名称是 Gorgon、Ladon、Argus、Khronos、Helios、Medusa；Neptune 常被作为第七个软字段描述；Perseus 是另一个独立 VM 头。

当前材料直接证明了 Medusa 中存在等价于 `state & 0x0f` 的选择器，因此只能确认 **16 个 selector 值的 dispatch 空间**。现有样本没有逐一重建 16 个分支，也没有可靠的 24 分支结果。`jadx_out16`、`jadx_out24` 是分析目录名，不能当成 16/24 套算法已完成的证据。

## 2. 已恢复的番茄调用链

以下链路使用当前 Java/Unidbg signer 和同一会话上下文。公开报告隐去设备标识、token、完整请求头和可复用票据。

```text
device_register
  -> registerkey
  -> directory/detail
  -> reader/full/v1
  -> AES-CBC 解密与压缩解码
```

### 2.1 设备注册

```http
POST /service/2/device_register/
```

这是 ByteDance 日志/注册服务。请求体包含应用 profile 和生成的设备指纹；响应提供后续请求使用的会话标识。私有桥接试验记录包含该步骤，但当前公开 `EVIDENCE_INDEX.json` 没有独立的 `device_register` 摘要，因此这里不把它作为可由公开仓库单步复核的线上证据。该请求在已记录流程中不依赖阅读接口的 Medusa 头。

### 2.2 章节密钥注册

```http
POST /reading/crypt/registerkey
```

请求体包含 JSON `content` 和 key-version。`content` 是 AES-CBC 信封：前 16 字节是 IV 文本，后续字节加密小端设备/用户字段。响应 `data.key` 仍是 AES-CBC 信封，解出本次会话的章节密钥。已观察的 key version 是 `598113575`；原始密钥不进入公开仓库。

### 2.3 目录

```http
GET /reading/directory/detail
```

当前桥接请求使用 `X-Helios`、`X-Medusa`、`X-Khronos`。成功样本返回 611 个章节条目。必须同时保存请求时间、响应长度、JSON 结构和会话上下文，单独一个 HTTP 200 不足以证明目录成功。

### 2.4 正文

```http
GET /reading/reader/full/v1/
```

响应是带 base64 章节载荷的 JSON envelope。成功样本的 `crypt_status=0`；用 `registerkey` 返回的会话密钥解密后得到 6,496 字节 HTML。公开证据用明文 SHA-256 证明解密结果：

```text
13e2415e7bef414a197a62aca08ccb11bf9cf436bc3f955b676fa03fac2fa2f7
```

### 2.5 阅读请求头矩阵

| 变量 | 结果 | 证据边界 |
| --- | --- | --- |
| Helios + Medusa + Khronos | HTTP 200，非空响应 | 当前阅读矩阵的基线 |
| 再加 Gorgon/Ladon/Argus | HTTP 200，非空响应 | 这些头在该矩阵可选 |
| 再加 Perseus | HTTP 200，非空响应 | 兼容组合可用 |
| 移除 Perseus | HTTP 200，非空响应 | 当前时间窗内未发现硬依赖 |
| 移除 Medusa | HTTP 200，空响应 | 传输层 200，但业务失败；Medusa 是当前阅读接口硬依赖 |

矩阵必须在时间戳窗口内成对运行。过期时间会把“签名错误”和“时间窗失效”混在一起。

## 3. 签名与解密模块

| 模块 | 当前实现/证据 | 使用限制 |
| --- | --- | --- |
| `X-Khronos` | 秒级时间戳 | 必须与请求 `_rticket`/签名时间一致 |
| `X-Neptune` | 软时间字段；桥接公开路径可移除 | 不作为当前阅读硬依赖 |
| `X-Gorgon` | 当前 0404 形式和 KSA/PRGA 路径 | 只对已分析版本和输入向量负责 |
| `X-Ladon` | 34 轮 Speck-like 变换 | 不将 Tomato 结果外推到抖音 |
| `X-Argus` | Tomato 变体的 SHA-256/AES 细节 | 与常见 Douyin Argus 不混用 |
| `X-Helios` | 34 轮 VM 的 Python 翻译和向量 | 当前阅读矩阵必需 |
| `X-Medusa` | 旧快照纯 Python；当前版本桥接 | 当前 VM9 仍不能独立 fresh-input 生成 |
| `X-Perseus` | 独立 VM 快照/实验辅助 | 当前时间窗可选，未来风控可能重新要求 |
| 章节 AES-CBC | 已实现 | 必须使用同一 registerkey 会话密钥和 IV 规则 |

详细证据分别在 [SIGNATURE.md](SIGNATURE.md)、[API_CALLS.md](API_CALLS.md) 和 [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json)。

## 4. 搜索接口现状

### 4.1 静态恢复的请求模型

搜索 feed 构造 `GetSearchPageRequest`，调用 `u15.c.i0(request)`。已恢复字段包括：

```text
query, searchId, passback, correctedQuery, useCorrect, offset,
bookshelfSearchPlan, searchSource, tabType, tabName, targetMainId,
userIsLogin, bookstoreTab, clickedContent, searchSourceId, sourceBookId,
clientAbInfo, isFirstEnterSearch, fromHalfScreen, reportInfo, clientExtra
```

feed 路径固定写入 `bookshelfSearchPlan=4`；`PlaceUtils.addPlaceColumnParams` 还可能补充字段，补充规则尚未完全验证。

### 4.2 当前路径和实测结果

```text
GET /reading/bookapi/search/tab/v
GET /reading/bookapi/search/page/v/
GET /reading/bookapi/search/page/v1/
```

2026-09-29 的同步时间戳探针对四种路径均得到 HTTP 200、0 字节 body，body SHA-256 是空流摘要 `e3b0...2b855`。APK hook 观察到的 `sinfonlineb`、`query=三体&offset=0&aid=1967` 形状也返回空 body。

这证明了签名和传输可以到达路径，不证明搜索被业务接受，更不证明有书籍列表。Rust 的 `search_params` 只是参数模型；调用者必须把搜索状态显示为“未验证”。

2026-10-03 补充了两个分开的结论：旧 `6.8.1.32` 请求配置的外部 Java 服务返回第一页 9 本、第二页 10 本，第二页沿用同一 `searchId`，两页无重复书籍；服务包含缓存、重试和设备池，尚未捕获原始上游请求。当前 `7.1.3.32` 使用成功详情请求的设备配置、同一 session 对和数字首进入标志，在 b/c 两个域名上仍返回 HTTP 200、空 body，没有取得可进入第二阶段的 `searchId`。详见 [SEARCH.md](SEARCH.md)，不能混用版本或 session 来宣称当前搜索完成。

初始化也获得了新证据：相同 URL 下，某些时间输入未发布 signer handle，原桥接器错误回退到 app manager，随后发生虚表读取错误。私有桥接器已修正为明确失败、保留日志、清空旧签名；新鲜详情请求仍被服务器接受。11 个时间输入只证明这一边界，尚未恢复任意时间下的 native 初始化。详见 [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md)。

## 5. Python 研究 API

代码位于 `python/`。这些 API 用来验证 VM9 初始化和 allocator 边界，不应直接当作线上 signer。

### 5.1 GuestOS 映射和 fresh region

```python
from vm9_allocator import GuestOS, register_os_region

pages = {}
guest_os = GuestOS(pages, next_address=0x13600000)
registration = register_os_region(
    pages,
    guest_os=guest_os,
    arena_address=arena,
    length=0x40000,
)
```

`GuestOS` 只接受当前明确建模的匿名私有映射：页对齐、`PROT=3`、`MAP_PRIVATE|MAP_ANONYMOUS`、非重叠、地址范围受限。失败在提交前回滚，不覆盖原页。

### 5.2 TLS、arena、tcache 和 small allocation

下面是边界 API 的示意调用。`pages`、`arena_zero`、`arena_table`、`arena` 和
`thread_pointer` 必须由调用者从同一次受信采样或自己的 guest 初始化中提供；
它不是一个可以独立启动当前线上 Medusa 的完整脚本。

```python
from vm9_allocator import (
    AllocatorConstants, GlobalBootConfig, initialize_global_boot,
    prepare_thread_allocator, allocate_small_object,
)

def run_allocator_step(
    pages, *, arena_zero, arena_table, thread_pointer, guest_os
):
    # These inputs must come from the same trusted guest initialization.
    constants = AllocatorConstants()
    boot_config = GlobalBootConfig(
        arena_zero=arena_zero,
        arena_table=arena_table,
    )
    initialize_global_boot(pages, config=boot_config)
    thread = prepare_thread_allocator(
        pages, thread_pointer=thread_pointer, constants=constants
    )
    return allocate_small_object(
        pages,
        thread_state_address=thread,
        request_size=24,
        guest_os=guest_os,
        constants=constants,
    )
```

已验证组件包括 pthread TLS generation 检查、stale TLS 清理、base allocation、arena/tcache/thread state 创建、arena 选择、空 bin refill、slab bitmap、free list/tree、清理和 purge。`GLOBAL_BOOT_COMPONENTS` 会明确哪些 boot 仍是 `captured-input` 或 `partial`，不能被误读为完整 `je_*_boot` 重建。

### 5.3 构造器和 callback 边界

```python
from vm9_objects import construct_string_object
from vm9_callbacks import clock_callback, publish_callback_descriptor

payload = construct_string_object(
    pages,
    object_address=obj,
    source_address=source,
    allocate=lambda staged, size: allocate_payload(staged, size),
)
clock = clock_callback(
    pages,
    wrapper_address=wrapper,
    clock_id=1,
    seconds=123456789,
    nanoseconds=0,
)
descriptor = publish_callback_descriptor(
    pages,
    descriptor_address=descriptor_addr,
    branch_target=target,
    object_address=obj,
)
```

`compose_packed_callback_x8` 会显式抛出 `RefillUnsupported`，因为 packed callback x8 的组合写入者尚未被独立参数化。这个拒绝是设计的一部分，不能用一个捕获常量替代。

服务引用型 handler 依赖两个 guarded singleton。`construct_service_reference(kind="flag")` 生成 2-byte zero payload；`kind="service"` 默认用 Python 构造完整已测 0x2d0-byte 图，读取 fresh ELF/GOT 输入。冷 getter 要求显式 `thread_id`，会生成 guard 的 acquire/release 状态与线程 ID；已发布 getter 不重复分配。handler 可以用 `initialize_services=True` 连续构造并复制这两个引用。`verify_vm9_service_singletons.py` 用 72 个真实 native 对照和 15 个拒绝/回滚例验证这些局部组件；完整 root、诊断全局副作用和独立 signer 仍未完成。

### 5.4 配置树和 136/320 字节构造器

`vm9_registry.py` 的 `compare_string_fields`、`lookup_configuration_value` 和 `insert_configuration_pair` 分别用于验证配置 key 比较、查询和所有权转移式插入。比较器遇到双方相同 NUL 会提前判等；重复插入会删除传入 key 和原 value，不能使用普通字典排序或覆盖语义替代 native 行为。

`set_configuration_u32` 包括 scoped writer、缺失 key 克隆、u32 覆盖和清理，返回旧值或 `0x000a985f`。`construct_registry320`、`construct_singleton136` 已恢复完整构造主体；`get_registry320_reference`、`get_singleton136_reference` 完整构造后才发布 lazy reference。调用者需要提供 caller stack、allocator/free、clock、TLS 初始化/解析和广播边界；cold getter 还需要 `thread_id`。复用栈槽位会改变后续 TLS padding，不能清零或注入 native 的结果页。

配置树通过 96 组 native 差分 / 11 个回滚例，完整主体和 getter 通过 38 / 14。四次 fresh native 控制新增 20 条同次入口子树对照，串接实际 Python 冷 TLS/key/析构注册，并比较内存和有序 allocation/free/clock/registration/wake。详细布局、证据和限制见 [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md)。这些结果保留串行 guard/OS 边界和 native 输入前导快照依赖；mode-0 `+0x259dbc` 已贯通，parser 已在第 3318 步 / `+0x9c95c` 退出，其所需 caller/VM 前导已由 Python 生成，但 caller 之前的 root 初始化仍未独立恢复；尚不能直接调用这些组件生成当前线上 Medusa。

### 5.5 验证命令

在仓库根目录运行：

```powershell
python scripts/check_python.py
python platforms/bytedance/tomato/python/verify_vm9_initialization.py `
  --capture-dir <trusted-private-capture-dir> `
  --output <sanitized-output.json>
python platforms/bytedance/tomato/python/verify_vm9_allocator_lifecycle.py `
  --checkpoint <trusted-private-checkpoint.pkl> `
  --output <sanitized-output.json>
python platforms/bytedance/tomato/python/verify_vm9_os_region.py `
  --checkpoint <trusted-private-checkpoint.pkl> `
  --output <sanitized-output.json>
python platforms/bytedance/tomato/python/verify_vm9_callbacks.py `
  --output <sanitized-output.json>
cargo check --manifest-path platforms/bytedance/tomato/rust/Cargo.toml
```

其中前三个脚本需要同次采样的受信任私有 ARM64 capture/checkpoint；这些输入不在 Git 仓库，不能用公开 evidence 文件冒充。输出只应是脱敏 JSON。最近一次记录的研究验证为：初始化差分 85 cases（11 个拒绝）、allocator lifecycle 83 cases（8 个拒绝）、fresh region 对比 4,256 pages、callback 边界 3 个拒绝；这些是组件验收，不是线上 Medusa 验收。

## 6. Rust 当前使用范围

入口在 `rust/`：

```text
rust/src/api.rs       # 路径常量与搜索参数模型
rust/src/signature.rs # 已验证的纯 Rust 辅助头边界
rust/src/status.rs    # capability/unavailable 明确错误
```

默认 crate 可以在 Windows/Linux 上编译，不依赖 JVM、Android artifact 或 dynarmic。`status::current_medusa()` 会返回明确的 `CapabilityError`，理由是当前 VM9 独立参数化尚未完成。这个错误必须保留，不能为了让下载器“看起来可用”而生成猜测头。

当前 Rust 能做的是保存已恢复的接口/参数模型、构建检查和能力边界；它还不能独立完成当前线上 `registerkey -> directory -> reader/full` 下载闭环。

## 7. 逆向分析过程和关键证据

1. 从 APK/JADX 恢复 Java/Kotlin 请求构造、路径、参数和 header 进入点。
2. 从 ELF/native 符号、ARM64 指令和 hook 记录定位 Helios/Medusa/Perseus、构造器、allocator 和 callback 边界。
3. 用 Java/Unidbg 桥接器生成当前版本签名，采用同一时间戳和会话贯穿注册、目录、正文。
4. 对章节做 AES-CBC/压缩解码，用 `crypt_status`、明文长度和明文 hash 证明得到的是解密正文。
5. 对 VM9 做 trace、寄存器、内存页和 native write watch 对比；把 callback 8、clock、string constructor、OS region 和 allocator 生命周期逐个拆成可拒绝的 Python 组件。
6. 对每个结论区分四种证据：静态恢复、离线向量、桥接线上接受、fresh-input 独立实现。只有最后两项同时闭合，才可称为当前线上独立 signer。
7. 对公开证据做脱敏：不提交设备标识、token、完整 headers、原始响应、APK、so 和可复用票据。

### 证据如何在逆向报告中使用

- 证明“头是必需的”：使用同一会话、同一时间窗的单变量 paired matrix；`drop_medusa` 空 body 对比 `drop_perseus` 非空 body，才能支持硬依赖判断。
- 证明“章节确实解密”：同时给出 `registerkey` key version、`crypt_status=0`、解密长度和 SHA-256；只给 HTTP 200 不足够。
- 证明“当前 VM 输入相关”：同一 URL/时间戳/PID 重复得到同一 digest，改变其中一个得到 digest 或分支长度变化；这仍是桥接证据，不替代独立实现。
- 证明“allocator 组件是真实结构”：报告页数、指针、metadata、free node、回滚拒绝和同次采样重放；不要只贴一段捕获内存。
- 证明“callback 写入来源”：使用 instruction-level write watch 和 caller/callee liveness；不能把 callback page 常量当成通用输入。
- 证明“fresh-input 已完成”：必须用未读过的输入从初始化开始生成 Medusa，重新跑目录/正文矩阵，并与已捕获输入分开记录。当前尚未达到此门槛。

主要证据索引：

- [API_CALLS.md](API_CALLS.md)
- [SIGNATURE.md](SIGNATURE.md)
- [SEARCH.md](SEARCH.md)
- [VM9_PROGRESS.md](VM9_PROGRESS.md)
- [RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md)
- [ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md)
- [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json)

## 8. 平台隔离和最终产品路线

平台目录必须保持独立：

```text
platforms/bytedance/tomato/  # 番茄：当前目录
platforms/bytedance/douyin/  # 抖音：单独版本、签名和线上证据
platforms/qidian/            # 起点：独立 APK、接口和解密证据
```

抖音目录当前只有静态/社区算法清单，不能引用番茄线上矩阵。起点目录是证据缺口报告，不能从通用小说项目或其他平台推导接口。

最终产品可以按以下顺序落地：

1. 完成当前 Medusa fresh-input 参数化，或取得可复现、可公开验证的匹配样本。
2. 用同一版本、同一设备策略完成 `device_register -> registerkey -> directory -> reader/full` 的无 JVM Rust 闭环。
3. 让搜索返回非空 JSON，确认字段、分页和书籍 ID；再做下载器的选择书籍/章节流程。
4. 分别完成抖音和起点的独立线上验证，不共享未经证明的 header 或参数。
5. 以平台能力矩阵为输入开发 GitHub Pages 搜索/章节/下载网页；未完成的平台显示“未验证”，不伪装成可用。
6. GitHub Actions 在检查通过后构建 Rust 的 Linux/Windows 构件，并部署 Pages。当前 Actions 仅适合研究归档、检查和 scaffold 构建。

## 9. 当前验收矩阵和下一步

### 已通过

- 当前桥接可生成被阅读接口接受的 Helios + Medusa 请求。
- 注册、目录、正文和章节解密链路有公开脱敏证据。
- 旧 225 字节 Medusa 快照、Helios 和若干辅助头有 Python/向量级复现。
- VM9 的 TLS/arena/tcache/OS region/allocator/callback 子边界有输入驱动验证。
- 配置树、136/320 字节完整构造主体与 getter 在明确边界下通过 native 差分和同次子树验证。
- Rust crate、Python 文件和 JSON evidence 可检查。

### 仅桥接或捕获状态通过

- 当前 VM9 Medusa 的 228 字节和 802–804 字节分支。
- 三段 trace continuation、native callback、clock 和 constructor 交接。
- bridge 性能优化后的同 digest 结果。

### 仍需完成

- 当前版本 Medusa 的独立 fresh-input Python 参数化。
- packed callback x8、lookup cache、callback tables、mutex/ctl boot 和剩余 native object graph。
- 无 JVM Rust signer/download 完整链路及线上复测。
- 当前 `7.1.3.32` 非空搜索响应和分页行为；旧配置外部服务已有两页证据。
- 全头服务器矩阵的更多时间窗/版本复测，特别是 Perseus 的风控变化。
- 抖音当前版本、起点平台完整接口/签名/正文实测。
- GitHub Pages 小说搜索下载网页和最终 Actions 发布流程。

**最终判定：当前项目是有实证的逆向研究归档和实现 scaffold，状态为“可继续开发”，不是“完整下载器”或“可直接发布的最终产品”。** 本报告是分析证据和使用说明，不是授权绕过未完成边界或发布不可验证能力。
