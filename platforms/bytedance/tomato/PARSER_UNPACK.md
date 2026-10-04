# 配置 parser 的字符串重填、消息解包与退出路径

2026-10-04 已恢复 `+0x248dd8 → +0x247a08` 的字符串重填，以及 `+0x256088 → +0x254330` 的配置消息解包。`vm9_parser.py` 已进一步由 Python 生成 `+0x262608` 的所需 caller 前导状态，四次 caller 对照不再读取 native VM 入口快照。四次同次 fresh native 对照中的 parser 在第 **3318 步 / +0x9c95c** 正常退出；165 字节配置解包返回非 NULL。root 仍在第 **513 步 / +0x99b40**，尚未恢复 `+0x261c54` 后续初始化。**完整独立 Medusa 未完成。**

## 接口与调用约定

| Python 接口 | native 入口 | 输入与结果 |
| --- | --- | --- |
| `pad_and_copy_string_fields` | `+0x247a08` | destination fields、W1 position、可选 source fields、填充 byte；返回 0/-1 |
| `fill_string_object` | `+0x248dd8` | string object、W1 length、W2 填充 byte；先清 length，返回 0/-1 |
| `unpack_configuration_message` | `+0x256088 / +0x254330` | allocator、length、data、guest ELF descriptor；返回 message pointer 或 NULL |
| `free_configuration_message` | `+0x2550cc` | 对模型自身产生的 message graph 递归清理；保留 ELF 中的默认值 |

`+0x2635ac` 从 packed argument 的 `+8`、`+0x10`、`+0x14` 读取 string、长度和填充 byte。`+0x2635c0` 从 `+8/+0x10/+0x18` 读取 allocator、length、data，把解包返回值写入 `+0x20`。原生 `+0x256088` 为通用 unpack 添加 `+0x350d68` descriptor；没有 JVM 或网络操作。

## 字符串恢复结果

重填会把 object `+0xc` length 清零，再处理 fields `object+8`。因此负 position、reserve 失败也不能恢复旧 length。capacity=8、requested length=165、fill=0 的当前控制经过 malloc/free reserve 路线扩到 capacity=256；填充 165 个零字节，再写终止 NUL。

通用 padding 校验有符号 position/length/capacity 和 payload。source payload 落在 destination 的 capacity 范围内时，即使没有增长，也先 clone。reserve 的目标为 position+source_length+1；分配和释放后重新读取字段与内容。gap 填充、source 的 memmove 复制、alias clone 清理和最终 NUL 都按 native 次序执行，保留 position 后的既有 suffix。source capacity 不参与直接 source 验证。

[字符串证据](evidence/vm9_padding_native_20261004.json) 为 **190 组 native 差分 / 5 个拒绝与页面回滚案例**。包括无增长 alias、跨页、malloc/realloc 失败、原地 realloc、有符号溢出、无效字段和 allocator 改变读取点。比较完整 guest/image bytes、有序 allocator 状态，以及释放前的内容。

## 消息模型与边界

`vm9_protobuf.py` 读取调用方 relocated guest ELF 中的 descriptor、field table 和不可变生成器初始化模板。没有嵌入解码后的字段名称、真实配置值、密钥、明文或 native 输出。当前支持观察到的三个 message descriptor，其 sizeof_message 分别为 **112 / 56 / 40 bytes**；field descriptor stride 为 72 bytes。

已验证的配置类型包括 SINT32、SINT64、ENUM、STRING、repeated MESSAGE 与 repeated STRING。解析顺序为：分配 message、复制生成器默认模板、扫描 tag/wire/value、计数重复字段、按字段顺序分配数组、分配 unknown-field table、逐项解析并发布。字符串重复出现会释放前值并使用后值；未知字段保留原始 wire value（包含 length prefix），但不会把内容写入证据文件。嵌套消息递归执行相同过程。

malformed wire 在扫描期间仅释放 message；后续 allocation/parse 失败清理已发布字段、数组、unknown fields 和 message。`do_free(NULL)` 不调用 allocator callback，不能在外部账本里多记一次 free。清理先清 message descriptor，再按 field table 次序递归释放；默认 string pointer 不被释放。

这是针对当前配置 descriptor 的有界模型，**不是完整 Protobuf-C 库替代品**。每个 message 最多 16 个 scanned members，未实现 heap scanned-member slabs、singular-message merge、自定义 allocator、packed repeated numeric、oneof 或超过边界的 schema。未知状态拒绝并回滚 guest pages；调用方的 allocator/free 账本是外部副作用，无法由页面事务回滚。原生 heap allocator 的完整语义也不由这里的显式 callback 等价替代。

[解包/清理证据](evidence/vm9_protobuf_native_20261004.json) 为 **208 组 native 差分 / 6 个拒绝与页面回滚案例**。包括两个 image bases、空消息、全部当前标量/字符串字段、重复字符串、重复和嵌套 message/string、1/2/8/16 项数组、未知字段、错误 wire type、截断与超长 tag/varint/length，以及逐项 malloc NULL。清理的 Python 输入来自自身的 unpack 输出；native 输出仅用于独立 cleanup oracle 的对照，不作为 Python 模型输入。

native verifier 为该解包路径设置 200000 条指令上限；旧通用 helper 的 10000 上限在 16 项嵌套样本中不够。这是 oracle 运行预算调整，不是放宽模型比较或删掉测试。行为核对参考 protobuf-c 上游 v1.3.3 的 `protobuf_c_message_unpack`、`parse_member` 和 `protobuf_c_message_free_unpacked`；最终证据以匹配 ELF 的 native 差分为准。

## 同次组合对照

[组合证据](evidence/vm9_root_vm_prefix_native_20261004.json) 包含两个 image bases × SDK 缺失/30，**4 次 fresh controls、8 段 VM 对照、44 条完整子树对照**。

| 检查点 | parser steps | allocations | explicit frees | 状态 |
| --- | ---: | ---: | ---: | --- |
| 先前 stream checkpoint | 725 | 100 | 26 | `+0x248dd8` 前 |
| 本轮重填 checkpoint | 3134 | 101 | 27 | `+0x256088` 前 |
| 当前 parser 路径 | 3318 | 119 | 47 | `+0x9c95c` 正常 VM exit |

165 字节消息在四次控制中都成功解包。新增 `+0x256088` 单独子树每次有 16 次分配、无显式 free，并比较实际返回 pointer。完整 parser 的 guest、所有主 image pages、隔离 TLS、2256-byte bionic generation 表和有序 allocation/free/clock/registration/wake 一致，退出时全部 32 个虚拟寄存器槽也一致。

native VM 只初始化 slots 0、4..7、29、31，其他 slots 保留 caller backing 原有字节。模型从同次入口输入 pages 读取这些字节，不从 native 退出结果初始化。parser 的原生返回点 `+0x26266c` 仅做栈保护校验和返回，没有消费 X0；退出证明以虚拟槽、发布内存与副作用为准。

原有 root/parser VM 组件对照仍从同次 native **VM 入口输入快照**开始。新增四次 caller 对照从更早的 `+0x262608` 调用入口开始，由 Python 生成所需 VM 前导，不读取 `+0x168324` 入口快照。caller 之前的 root/堆/TLS/全局状态仍来自同次 native 控制输入；串行 guard、OS 和 diagnostic 边界仍明确存在。当前尚未验证当前线上 fresh-input Medusa。

## Python 生成 parser caller 前导

`vm9_parser.py` 将已恢复的 parser callbacks 放在一个代码 owner 中，VM 组件和 caller 对照都使用它。生产接口为 `parse_configuration_caller`：输入 caller pages、X0/X1/X2/X8、entry SP、未携带 PAC 的 return address、thread pointer、image base、matching VM interpreter，以及明确的 allocate/reallocate/free/singleton 环境服务。输出 `ParserResult` 包含 steps、终止 offset、32 个虚拟槽和 callback/unpack 计数。

前导工作区起点为 entry SP-0x810。四个输入放在 `+0/+8/+0x10/+0x18`；callback、backing-end 和 exit descriptor 放在 `+0x20/+0x28/+0x30`。读取 TLS guard；寄存器 backing 从工作区 `+0x6c8` 起，只有 native 明确初始化的 slots 被重设，其余保留 caller 工作区内容。native callback 的显式 scratch SP 由工作区地址减 0x190 得到。物理 callee register spills 不属于此 Python 接口的语义输出，也未宣称整个 caller 栈逐字节相等。

四次 `parser_caller` 对照均匹配 **119 allocations / 47 frees**、guest、全部主 image pages、TLS/generation、有序副作用和 32 个虚拟槽。验证包含 **7 个 caller 拒绝/页面回滚案例**：未对齐 stack、PAC return、非法指令预算、unmapped stack/TLS、缺少 bytecode 和非法 u64 输入。异常后 VM image base 恢复，不调用环境服务。VM 模块当前使用共享 image base，调用需串行。

这里已经移除 parser **所需 VM 前导**的快照依赖；并未移除 caller 之前的完整 native root 初始化状态。

## 复现与使用

从番茄目录运行，matching ELF 与 libc 留在私有路径：

```text
python -B python/verify_vm9_padding.py --library /private/libmetasec_ml_71332.so --output /private/padding.json
python -B python/verify_vm9_protobuf.py --library /private/libmetasec_ml_71332.so --output /private/protobuf.json
python -B python/verify_vm9_root_vm_prefix.py --library /private/libmetasec_ml_71332.so --libc /private/libc.so --output /private/root-parser.json
```

直接调用模型需提供已映射的 caller pages、matching relocated ELF 和明确的 allocation/free callbacks：

```python
from vm9_protobuf import unpack_configuration_message, free_configuration_message

message = unpack_configuration_message(
    pages, data_address=data_pointer, length=data_length,
    image_base=image_base, allocate=allocate, free=free,
)
if message:
    # 消费 guest message 布局；这里不是 HTTP 搜索或章节接口。
    free_configuration_message(
        pages, message_address=message, image_base=image_base, free=free,
    )
```

## 作为逆向证据与下一步

这些证据证明重填容量策略、source alias 处理、分配后的实际读取点、unpack ABI、descriptor-driven message 布局、重复值/unknown fields 处理、清理次序，以及当前 parser 路径的退出。可用于定位 ABI、schema、ownership 或初始化状态错误；不能据此把下载失败归因于服务器，也不能证明所有配置输入、所有 native 环境或其他平台已经等价。

下一段是 `+0x261c54 → +0x261cb0` 的完整初始化及 parser 前导。已静态定位 `+0x262608` 会在调用 VM 前生成 caller 工作区、四项输入和 callback/exit descriptor；这些所需前导状态已由 `vm9_parser.py` 生成并通过 caller 对照；下一步须生成该 caller 之前的 root 状态。完整 root/88-byte 初始化、独立当前 Medusa、无 JVM Rust signer/download、搜索非空/分页、抖音/起点及最终 Pages 搜索下载网页与 Actions 工具仍未完成。
