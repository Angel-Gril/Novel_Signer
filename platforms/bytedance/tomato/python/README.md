# Tomato Python material

2026-10-08 B reader components: `vm9_alternative_startup.read_reader_varuint32`
restores +0x324870 (258 fresh controls/seven rollback checks).
`read_reader_varint32` restores signed +0x324e0c (1336 controls/10 rollback
checks). It preserves output on failure and checks every fifth-byte value at
two bases; type vectors and function/global imports are verified separately below. See the
[signed reader report](../REQUEST_JNI_STARTUP_WORKERS.md#63-有符号-i32-读取2026-10-08-utc).
`run_reader_sections` restores +0x324188 envelope/order/partial state and section
0 (generic custom), 3, 7, 8 and 12 (202 controls/12 rollback checks, including
eight actual ELF sections from independent Python XOR). Callbacks are explicit
pure status services; special custom and separate actual AST callbacks are documented below.
Full AST, wrapper cleanup and a complete Python reader/factory remain open. See
[startup/reader report](../REQUEST_JNI_STARTUP_WORKERS.md#62-section-状态与部分-handler2026-10-08-utc).

Subsequent `grow_reader_word_vector` and section 1 type vectors pass 102 / 372
controls and 34 rollback checks, including four fresh ELF input controls. Type
parsing requires the explicit `vector_allocate(size)` service; it returns a
planned pointer into mapped pages. Allocation/free effects and immutable type
cells are returned with parser results/events. Actual allocator/AST construction,
remaining handlers and full reader remain open. See the
[type/vector report](../REQUEST_JNI_STARTUP_WORKERS.md#64-type-vector-与-section-12026-10-08-utc).

Section 2 function/global imports require `enable_function_global_imports=True`
and pass 254 native/Python controls plus 14 rollback checks, including six fresh
ELF inputs. Events snapshot the four import counts before each callback; names
remain opaque guest spans. The global callback's ninth argument is a bool byte
on the native stack. Actual AST callbacks remain open.
See the [import report](../REQUEST_JNI_STARTUP_WORKERS.md#65-section-2-函数与全局变量-import2026-10-08-utc).

`read_reader_varuint64` restores +0x3249b0 with 1438 controls/10 rollback checks:
terminating tenth-byte overflow preserves output; missing termination clears it.
Table/memory imports require `enable_table_memory_imports=True` and a mapped,
aligned, disjoint 32-byte `import_scratch_address`. Their 234 controls/15 rollback
checks compare all 19 descriptor bytes after normalizing only its transient
native stack pointer to model scratch. `event.import_limits` snapshots minimum,
maximum, `has_maximum`, `flag_bit1` and `flag_bit2` values. Six compositions combine
fresh ELF function/global inputs with synthetic table/memory imports; the sample
has no real ELF table/memory import inputs. Actual AST/allocator remain open.
See the [u64/limits report](../REQUEST_JNI_STARTUP_WORKERS.md#66-u64-与-tablememory-import2026-10-08-utc).

Sections 4/5 require the independent `enable_table_memory_sections=True` and
reuse the same mapped 32-byte `import_scratch_address`. Their 266 comparisons/18
rollback checks cover count/entry callbacks, indices offset by imports, uint32
wrap and all 19 descriptor bytes. Definitions do not increment import counts.
The sample contains no real sections 4/5; six compositions add synthetic
definitions to fresh ELF function/global inputs. Full selected composition
matches 306 callbacks per base. Actual AST/allocator remain open. See the
[section 4/5 report](../REQUEST_JNI_STARTUP_WORKERS.md#67-section-45-tablememory-定义2026-10-08-utc).

`read_reader_varint64` restores +0x324f6c with 1480 comparisons/10 rollback
checks. Every tenth byte is checked under two prefixes at two bases; only
0/127 terminators are accepted, and failures preserve unused output.
Section 6 and +0x32365c initializers add 390 comparisons/26 rollback checks.
Use `enable_global_section=True` and a mapped, aligned, disjoint 16-byte
`global_scratch_address`: the first word supplies the explicit caller-local
seed/result, the second is read scratch. End-only preserves the local's high
word; i32/f32 bits zero-extend. `max_initializer_ops` bounds each expression.
Kinds follow the GOT table pointer; relocation and overrides are checked.
Ten controls contain actual ELF globals (22 entries); full 1/2/3/6/7/12
matches 455 callbacks per base. Actual AST remains open. See the
[global/initializer report](../REQUEST_JNI_STARTUP_WORKERS.md#68-有符号-i64-与-section-6-初始化表达式2026-10-08-utc).

Section 10 +0x323ca8 adds 228 comparisons/15 rollback checks, including six actual
ELF code inputs. Enable it with `enable_code_section=True`; body count must match
the function count. Metadata, local groups and raw 32-bit words produce explicit
status callbacks. `max_code_words=65536` bounds the whole section, including native
zero-word retries without cursor progress. All supplied input bytes are compared.
The sample has 121 bodies and 54533 words; full 1/2/3/6/7/12/10 matches 55351
callbacks per base. Words are read, not executed; actual AST remains open. See the
[code report](../REQUEST_JNI_STARTUP_WORKERS.md#69-section-10-元数据局部类型与指令字读取2026-10-08-utc).

Sections 9/11 add 450 comparisons, 33 rollback checks and 16 native abort boundary
checks. Use independent `enable_element_section=True` / `enable_data_section=True`
with mapped, aligned, disjoint eight-byte `expression_scratch_address` and
`max_expression_ops=4096` per expression. Their +0x3215f0 helper emits +0xf0 for
kind zero and produces constant callbacks without a result word. Element vectors
must be empty; native nonempty vectors reach abort and the model rolls back.
Data payloads are opaque spans; +0x158 receives index/pointer/u64 length. The
original status-only controls omitted length; the repair and fresh ABI checks
are documented below. Six controls
contain actual ELF data, including full 1/2/3/6/7/12/10/11 with 55369 callbacks.
See the [segment report](../REQUEST_JNI_STARTUP_WORKERS.md#610-section-911-与独立-expression-helper2026-10-08-utc).

Section 0 special custom metadata adds 860 comparisons and 32 rollback checks,
including ten actual ELF controls. Use `enable_special_custom_sections=True`
with a mapped, aligned, disjoint eight-byte `custom_scratch_address` and
`max_custom_records=4096` per custom section. Dylink, dylink.0, linking,
target_features and reloc prefixes parse fields without AST callbacks. Known
subsections consume their exact size; unknown tags skip opaque content. Temporary
limits and the custom flag are restored on success and parse failure. The work
region also protects decoder storage, the opcode table pointer and active
expression opcode tables.
All actual sections match 55369 callbacks per base. Actual AST, bootstrap and
signing remain open. See the
[custom report](../REQUEST_JNI_STARTUP_WORKERS.md#611-section-0-特殊-custom-元数据2026-10-08-utc).

2026-10-09 actual AST components add 308 comparisons and 54 rollback checks,
including 32 actual ELF type inputs. `run_reader_ast_callback` recovers slots
+0x18/+0x20/+0xa0/+0xb0/+0x168: reserve type capacity, append an owned 64-byte
type node, append u32 start index, write local group count and clear +7c, append a raw
u32 word. `destroy_reader_ast_type_node` frees results then parameters without
deleting the node. `cleanup_reader_callback` destroys five temporary node
lists backwards, releases two trees in left/right postorder, then its buffer.
Each result records logical allocation/destruction/free effects and owner bytes
at that effect. Native functions and vtables execute, with explicit malloc/free
plans; memory stays mapped and unpoisoned. No allocator boot is implemented.

Slot +0x160 adds 176 comparisons and 30 rollback checks for 176-byte data
record capacity reserve at output+f0. It does not increase size. Growth moves
five owned vectors backwards, clears their source pointers, preserves target
padding, publishes the header, then destroys old records and frees the block.
`destroy_reader_ast_data_record` implements +2cc1ec: reverse +98 children
(each owns a +10 u64 vector), child block, +70 locals, inline type
results/params, then byte payload. It retains the record itself. All new
fixtures are synthetic. See the
[data report](../REQUEST_JNI_STARTUP_WORKERS.md#613-data-record-容量预留搬移与析构2026-10-09-asiashanghai).

Slot +0x140 subsequently restores data record creation/append with
`arguments=(index,memory_index,flags)`: index is ignored, the other values
truncate to u32. The classification is 2 when flags&3 equals 3, otherwise
flags&1; +18 packs memory_index in the high word. Inline type results own one
u64 -1, and record +88 is 0x00000000ffffffff. Four sentinel allocations and
three temporary frees follow native order; growth publishes before old record
destruction. Destination padding remains intact. All 148 native/Python controls
and 105 full-page rollback checks pass. Old AST 308/54 and data 176/30 evidence
remains byte-identical. See the
[creation report](../REQUEST_JNI_STARTUP_WORKERS.md#614-data-record-创建与追加2026-10-09-asiashanghai).

Slot +0x158 now restores +0x31e53c with
`arguments=(index,payload_pointer,payload_length)`. Index is ignored; length
uses all 64 bits. Zero length keeps the existing payload and does not read the
source or require an active data record; callback/ownership prechecks still
apply. Nonzero length resizes the last 176-byte record's byte vector, growing
to max(length,capacity*2). It zeroes newly added bytes, copies old contents,
publishes the header, frees the old block and then copies the source payload.
The mapped source must be bounded and disjoint from owned storage; it is
retained through allocation. The parser now includes length in the +158 event.
104 AST comparisons, 34 parser ABI comparisons and 30 rollback checks pass,
including six actual ELF payloads and two actual ELF data-section controls.
Old AST/data/create/segments JSON remains byte-identical; two complete actual
section composition records match. See the
[payload/length report](../REQUEST_JNI_STARTUP_WORKERS.md#615-data-payload-写入与-parser-length-参数修复2026-10-09-asiashanghai).

Slots +0x148/+0x150 restore +0x31e4a4/+0x31e4f4 with one ignored index
argument each. Begin points callback+28 to the last record's inline type,
stores the raw buffer's u32 byte length in record+88, resets callback+38 to
+30 begin and appends a 16-byte frame with its first word read from image+6e188
and two u32 -1 values. End selects the tree key (frame_count-1), reads u32
patch byte offsets and writes the raw buffer's length before each patch.
It grows/zeroes the raw buffer when needed, erases the matched node with the
actual libc++ parent/link/color changes, frees payload then node and pops a
frame. No match still pops a frame. Empty stacks are rejected.
Tree payloads use four-byte elements; the old eight-byte precheck rejected a
valid native cleanup, reproduced RED before repair. End additionally validates
count/begin, parent links, key order, colors and black heights. 148 comparisons
and 36 full-page rollback checks pass; all inputs are synthetic. See the
[expression/tree report](../REQUEST_JNI_STARTUP_WORKERS.md#616-data-expression-frameu32-修补与树节点删除2026-10-09-asiashanghai).

Slots +0xf0/+0x100/+0x108/+0x110/+0x118 add 282 comparisons and 159 full-page
rollback checks. F0 takes zero arguments and appends a u32 zero. Count reserves
184-byte element records; entry ignores index, truncates table index/flags,
copies an image+6e210 constant and appends one -1 type result. Reverse movement
transfers five vectors and preserves padding. Begin/end share the existing
16-byte frame, raw byte-length and u32 fixup/tree owner, storing the starting
length at element+90. `destroy_reader_ast_element_record` restores +2cc2b8;
it frees children/locals/type, then destroys the owned 144-byte nested records
backwards through +2cc470. Nested records own their own type/locals/children.
Actual stack temporary destruction executes; its frees are compared, while
stack-local destroy events and whole stack/TLS bytes are outside the comparison.
All fixtures are synthetic. See the
[element report](../REQUEST_JNI_STARTUP_WORKERS.md#617-element-回调与嵌套记录清理2026-10-09-asiashanghai).

Slots +0x120/+0x128/+0x130/+0x138 pass 230 comparisons and 133 full-page
rollback checks. Result type ignores index and stores the full u64 at the
last element+18. Count ignores index, truncates count to u32 and reserves
144-byte nested records without resizing. Nested begin copies that result
value into an original and temporary type result, transfers the temporary
result into a new record, then frees the original before beginning its frame.
Growth transfers four owned vectors backwards, publishes, destroys old
records backwards and frees the block. Padding +0c/+4c/+74 remains intact.
Begin/end share the existing frame/raw/fixup/tree owner. Both accept one
ignored argument in the bounded API; section 9 never calls them because its
nonempty-vector path aborts. This argument convention is not a verified
parser ABI. All fixtures are synthetic; six old regression files match byte
for byte. See the
[nested expression report](../REQUEST_JNI_STARTUP_WORKERS.md#618-element-结果类型与嵌套表达式2026-10-09-asiashanghai).

Slots +0xc0/+0xc8/+0xd0/+0xd8/+0xe0/+0xe8 pass 398 comparisons and 122
full-page rollback checks. Predicate accepts one ignored kind and returns 1
when active +28 is zero or frames are empty; it never dereferences active.
End accepts no arguments, retains a single frame and reuses existing
fixup/erase/pop for inner frames. Empty end stacks are rejected by the model.
The four constants accept one u64 register value: f32 tag 4/u32 bits,
f64 tag 5/u64 bits, i32 tag 2/u32 bits and i64 tag 3/u64 bits. Floating
values remain raw bits; u32 values truncate high bits. Tag and value each
append through the existing byte-growth owner, with separate allocation,
publication and free effects. All fixtures are synthetic; seven old evidence
files match byte for byte. Parser composition remains open. See the
[instruction report](../REQUEST_JNI_STARTUP_WORKERS.md#619-instruction-predicate-与带类型常量2026-10-09-asiashanghai).

Slots +0xb8/+0xf8 pass 252 comparisons and 37 full-page rollback checks.
Active +28 must exactly select an existing data inline, element inline or
element nested 144-byte layout; unused nested capacity is rejected. Local
group accepts `(ignored_index, count, type_bits)`: append 16 bytes containing
full u64 type, low u32 count and cumulative u32 count after wrapping addition
to callback+7c. Count zero still appends; +b0 resets the declared group count
and cumulative count while preserving existing local storage. Growth copies
old entries, publishes, then frees the old buffer. End accepts
`(ignored_index, length)`, clears active and writes low u32 length at record+70;
frames and trees remain intact. Later data/element destruction owns the local
buffer. All fixtures are synthetic; eight old evidence files match byte for
byte. See the
[local group report](../REQUEST_JNI_STARTUP_WORKERS.md#620-local-group-与函数结束回调2026-10-09-asiashanghai).

Slot +0x50 now recovers +31c7b8 with `(function_index, type_index)`, both
truncated to u32. Type index selects a logical output type. Clone params/results
by their actual lengths into an owned 144-byte function at output+30, then
clone them independently into the 64-byte cache at callback+80. Two full
containers allocate in this order: function params/results, function block,
cache block, cache params/results. Growth transfers old vectors backwards,
publishes, destroys moved records backwards and frees the old block.
`destroy_reader_ast_function_record` implements +2cc470 (native address in X1):
reverse child payloads, child block, locals, type results, then type params.
It resets ends/vtable and retains the record. Existing +b8/+f8 accept a logical
function record as active and reject its spare capacity. All 188 comparisons
and 136 rollback checks pass; nine old evidence files match byte for byte.
Parser composition remains open. +58/+60 are table callbacks;
section 3 emits +50 entries without a separate function reserve/count callback.
See the [function report](../REQUEST_JNI_STARTUP_WORKERS.md#621-function-创建类型缓存与清理2026-10-09-asiashanghai).

Slot +a8 selects a logical function using the low-u32 index minus the
cache/function count difference. It sets active, stores u32 metadata, the raw
length before fixup and u32 cursor offset, ignoring body length. It frees the
frame fixup tree, applies/removes the matching function fixup node, resets
frames and appends one 16-byte frame and one owned 56-byte child. Child fields
retain destination padding and record the raw length after fixup and local
entry count. Growth moves existing child payload vectors backwards, clears
source headers, publishes and frees the old block. Shared `apply_fixup` also
serves expression end. All 284 comparisons and 100 rollback checks pass;
ten old evidence files match byte for byte. Two budget RED controls caught
double-counting existing children; exact budgets 6/10 now pass. Parser, other
production APIs and the shared native driver are unchanged. See the
[code-begin report](../REQUEST_JNI_STARTUP_WORKERS.md#622-code-begin双修补树与-child-追加2026-10-09-asiashanghai).

Slots +58/+60 reserve output+48 and append 48-byte table records to that output
and a separate callback+98 cache. Entry arguments are ignored index, full u64
type and borrowed descriptor pointer. The native callback reads 24 descriptor
bytes and copies 19; a zero maximum flag replaces descriptor+08 with u64
ffffffff. New kind is 1. Growth copies old records backwards, retaining five
destination tail bytes. Output growth frees the old block; cache growth also
calls old destructors backwards after publication. Callback cleanup owns the
cache; full output wrapper cleanup remains open.

For +60, pass `entry_stack_address` as the actual aligned entry SP. The mapped
frame [SP-b0, SP) must be disjoint from owned/input/allocation storage. The
model reads the unwritten temporary word at SP-7c into record+14, where native
code also copies it. Native-only controls with three different stack words
and inspection of the actual +3210d0 clone confirm this dependency; no padding bytes are
masked or invented. Other native stack writes and complete parser composition
remain outside this API. Omitted/invalid stack context fails closed. All 184
comparisons and 77 rollback checks pass; eleven old evidence files match byte
for byte. The shared driver only forwards this optional entry context. See the
[table report](../REQUEST_JNI_STARTUP_WORKERS.md#623-table-预留创建与显式栈-padding2026-10-09-asiashanghai).

Slots +68/+70 reserve output+60 and append independent 40-byte records to
output and callback+b0. Entry arguments are ignored index and a borrowed
24-byte descriptor pointer. All descriptor bytes copy to record+10; four
destination bytes at +0c retain their values. A zero maximum flag selects
u64 10000 or 1000000000000 according to the memory64 flag. Output growth
only frees; cache growth destroys old nodes backwards after publication.
Memory entry requires no explicit stack context. All 272 native/Python
comparisons and 65 rollback checks pass; twelve old evidence files match
byte for byte. See the [memory report](../REQUEST_JNI_STARTUP_WORKERS.md#624-memory-预留创建与独立缓存2026-10-09-asiashanghai).

Slots +78/+80 reserve output+78 and append 176-byte global records and
separate 24-byte callback+c8 cache nodes. Entry takes ignored index, full
u64 type and mutable (only bit 0 is retained). The inline type owns one
result; growth transfers four vectors and destroys old records after
publication. Twelve destination padding bytes are retained. The bounded
`destroy_reader_ast_global_record` API reproduces +2cc3b4 children/locals/
results/params cleanup, retaining the record and scalar/padding bytes.
All 328 comparisons and 120 rollback checks pass; thirteen old evidence
files match byte for byte. See the [global report](../REQUEST_JNI_STARTUP_WORKERS.md#625-global-预留创建与记录清理2026-10-09-asiashanghai).

Slot +88 takes one ignored index, selects the last global inline AST at
+18, stores its u32 raw byte start at +80 and resets/appends a sentinel
frame. Slot +90 takes (ignored index, full u64 end value), writes the
second argument at global+a8, applies frame-index raw fixups and pops
the frame while retaining active. Existing +b8/+f8 also accept owned
global inline layouts. All 212 comparisons and 54 rollback checks pass;
fourteen historical evidence files match byte for byte. Attached global parsing
is covered by the module opt-in below. See the [global expression report](../REQUEST_JNI_STARTUP_WORKERS.md#626-global-expression-与内联-ast-回调2026-10-10-asiashanghai).

`copy_reader_ast_string` constructs a disjoint 24-byte string destination. It copies inline padding, converts heap strings of length <=22 to inline, and clones longer payloads into rounded storage. Its status is the native X0 return address. The source is borrowed; the destination must own no previous heap allocation. All 68 comparisons and 12 rollback checks pass. Import/export callbacks are covered below; parser composition remains open. See the [string report](../REQUEST_JNI_STARTUP_WORKERS.md#627-ast-字符串复制基础2026-10-10-asiashanghai).

`run_reader_ast_callback` slot +98 takes (ignored index, kind, cache index, name pointer, full u64 length). It clones one of five callback node kinds and owns a name/node/index in output+a8 (stride 40). Growth copies names and clones old nodes backwards, then deletes the old records after publication. Short names require `entry_stack_address` for unwritten native padding. `cleanup_reader_ast_export_output` supports output headers containing only export records; it leaves begin/capacity dangling after logical free and must be consumed once. All 362 comparisons and 247 rollback checks pass; sixteen historical evidence files match byte for byte. See the [export report](../REQUEST_JNI_STARTUP_WORKERS.md#628-export-ast-回调与专属输出清理2026-10-10-asiashanghai).

`run_reader_ast_callback` import slots +28/+30/+38/+40/+48 append output+18 records (stride 64) with module/field names and an independently cloned node. Arguments retain full name lengths; function/type indexes truncate to u32. Table/global stack arguments follow ARM64 ABI; every import requires `entry_stack_address` for actual frame padding. Table import defaults to 0x00000000ffffffff, memory uses its existing default rules, and kind4 copies type params. Output growth clones old records; cache growth transfers old vectors after separately copying the new node. `cleanup_reader_ast_import_output` accepts only import-owned output headers and retains dangling begin/capacity after logical free; consume it once. All 858 comparisons and 410 rollback checks pass; seventeen historical evidence files match byte for byte. See the [import report](../REQUEST_JNI_STARTUP_WORKERS.md#629-import-ast-回调与专属输出清理2026-10-10-asiashanghai).

`run_reader_ast_module` composes actual +31b360/+324444 with real AST callbacks for generic/type/function/start/data-count and empty exports. It requires empty output, explicit native `entry_stack_address`, and separate model `varuint_scratch_address`. Prefix bytes are skipped without magic validation. Parse failures/count mismatch commit partial output with status 1; guards roll back all pages. Parser vectors are freed before callback caches; output remains owned. `allocate` must plan distinct mapped aligned blocks without reusing freed addresses. `ReaderAstModuleResult.effects` preserves the interleaved `ReaderVectorEffect`/`ReaderAstEffect` order. Attached callback/cleanup opt-in uses `attached_state_address` and validates the state+8/callback+8 and state+20/callback relationship plus retained input/vectors. The initial attached callback set is extended by the verified opt-ins below. Slot +28 also requires an explicit entry stack and callback frame; the module bridge admits inline names with its additional `enable_inline_function_imports` opt-in. Defaults still reject it. 214 controls and 83 rollback checks pass; old section and AST/cleanup evidence is byte-identical. See the [module report](../REQUEST_JNI_STARTUP_WORKERS.md#631-attached-parser-与有界-ast-module2026-10-10-asiashanghai).

`run_reader_ast_module(..., enable_function_imports=True)` additionally supports function imports whose module and field names are both at least 23 bytes. The default is `False`; short names require the additional inline opt-in below and other import kinds use the bounded opt-in below. The switch requires mapped `[state-0x1e0, state)` caller storage disjoint from input/output/scratch/reservations/allocations; callback entry SP is `state-0x100` with its `0xe0` frame below. Completed import output survives parse errors, while parser temporaries and callback caches are cleaned. 180 comparisons and 43 rollback checks pass; old module/import evidence is byte-identical (1072/493). Whole caller stack/TLS/OS and the complete signer remain unverified. See the [function import module report](../REQUEST_JNI_STARTUP_WORKERS.md#632-heap-名称函数-import-的-attached-ast-组合2026-10-10-asiashanghai).

`enable_inline_function_imports=True` requires `enable_function_imports=True` and additionally permits empty/short/mixed function import names. It models three type-helper save stores retained by inline string padding using current caller frame addresses, image base and type counts; subsequent imports retain earlier untouched bytes. The default is `False`, preserving the existing module and heap-only paths. 448 comparisons and 64 rollback checks pass, including 12 relocated-entry-SP controls and 282 independent full inline-padding controls. Old module/heap JSON files are byte-identical (394/126). Other import kinds have the bounded opt-in below; complete caller stack/TLS/OS remains unverified. See the [inline import report](../REQUEST_JNI_STARTUP_WORKERS.md#633-inline-名称函数-import-与真实-caller-栈写入2026-10-10-asiashanghai).

`enable_table_memory_global_imports=True` independently permits actual table/memory/global imports with both names at least 23 bytes. With the inline other-import opt-in left False, all import kinds in this combined scope require heap names; functions still need `enable_function_imports=True`. The new flag defaults to `False`. Retain the disjoint mapped `[state-0x210, state)` caller region; callback entry SP is `state-0x100`, descriptor is at `state-0xf8`, and global's ninth argument retains the caller word's high bytes. Type/helper saves and global temporary clearing recover bytes consumed by later imports. Imports after a zero-count type section remain unsupported because incoming `X22` is not modeled; empty type vectors are supported. 406 comparisons and 72 rollback checks pass, with 12 relocated SP cases and independent padding/descriptor/ABI checks. The three old module/heap/inline JSON files are byte-identical (842/190). The additional opt-in below enables short names of other imports; code composition is covered below; the complete signer remains unfinished. See the [other import report](../REQUEST_JNI_STARTUP_WORKERS.md#634-tablememoryglobal-import-的-attached-ast-组合2026-10-10-asiashanghai).

`enable_inline_table_memory_global_imports=True` additionally permits empty/short/mixed names in the table/memory/global import scope; it requires `enable_table_memory_global_imports=True` and defaults to `False`. Mixed function imports still require their own permission, and short function names require their inline opt-in. Caller/helper saves and clone clearing preserve the complete inline padding passed between import kinds, without native stack snapshots as input. 612 comparisons and 41 rollback checks pass, including 436 independent entire inline-padding checks and 12 relocated SP controls. All four old module/heap/inline/other evidence files remain byte-identical (1,248/262). Zero-count type caller registers and the complete signer remain unfinished. See the [short other import report](../REQUEST_JNI_STARTUP_WORKERS.md#635-短名称其他-import-与-caller-栈传递2026-10-11-asiashanghai).

`enable_table_memory_definitions=True` independently composes sections 4/5 with real AST effects and cleanup; it defaults to `False` and requires no import option. Actual table/memory descriptors are at `state-0xc0` / `state-0xe0`; caller saves supply descriptor tail bytes and table padding without native snapshots as input. 470 comparisons and 32 rollback checks pass, including 12 moved SP and 12 high guest controls, plus 1142 independent complete records. Eight old module/import/section/table/memory evidence files remain byte-identical (2582/463). Remaining attached handlers, complete reader/factory/bootstrap and the independent signer remain open. See the [definition module report](../REQUEST_JNI_STARTUP_WORKERS.md#636-tablememory-definitions-的-attached-ast-组合2026-10-11-asiashanghai).

`enable_global_definitions=True` independently composes section 6 with actual global and constant-expression AST effects and cleanup; it defaults to `False`. The caller result at `state-0xb0` retains its high four bytes for end-only expressions, including the memory handler saved image pointer; initializer integer reads use `state-0x108`. The mapped `[state-0x2a0,state)` frame stays disjoint from input/output/scratch and allocation plans. 398 comparisons and 37 rollback checks pass, including 12 moved SP, 12 high guest and 780 complete global record checks. Five affected historical JSON files remain byte-identical (1614/315). Remaining attached handlers, complete reader/factory/bootstrap and the independent signer remain open. See the [global module report](../REQUEST_JNI_STARTUP_WORKERS.md#637-global-definitions-与初始化表达式的-attached-ast-组合2026-10-11-asiashanghai).

`enable_code_definitions=True` independently composes section 10 with actual metadata/local/raw-word/begin/end AST effects and cleanup; it defaults to `False`. Code words are stored without execution. All five callbacks enter at `state-0xe0`; retain mapped `[state-0x210,state)` (or the larger global frame). `max_code_words=65536` bounds the whole section, including native zero-word retries without cursor advance. 256 comparisons and 42 rollback checks pass, including 8 selected complete ELF-body controls, 12 moved SP, 12 high guest, 362 entire function records and 340 entire child records. Eight deliberately interrupted native observations separately cover short-input retries. Four affected historical JSON files remain byte-identical (1124/235); the old unsupported-slot guard now uses +100. Remaining attached handlers, complete reader/factory/bootstrap and the independent signer remain open. See the [code module report](../REQUEST_JNI_STARTUP_WORKERS.md#638-code-definitions-的-attached-ast-组合2026-10-11-asiashanghai).

`entry_x22` explicitly supplies the incoming uint64 register for table/memory/global imports after a zero-count type section. Its default `None` preserves the previous rejection boundary. 198 native/Python controls and 9 rollback checks pass, including caller-save observations, 12 moved SP and 6 high guest. On the same final owner, 36 selected historical controls (including both complete actual ELF modules) and all 77 guards from the two affected suites match their historical evidence. The actual ELF reader/AST is verified; parse/root, independent factory/bootstrap, signer and online acceptance remain unfinished. See the [zero-count type report](../REQUEST_JNI_STARTUP_WORKERS.md#642-零条目-type-与-incoming-x222026-10-11-asiashanghai).

`convert_parser_instruction_word` now recovers the native parse codec helper, including scalar/SIMD shift differences and ignored metadata bytes. 434 fresh native/Python controls and 10 rejection checks pass, including 198 actual constructor codec controls, 16 moved SP and 12 high guest. Existing owner code is AST-identical after removing the new function. Complete parse/root, factory/bootstrap and signer remain unfinished. See the [parse codec report](../REQUEST_JNI_STARTUP_WORKERS.md#643-parse-指令格式转换2026-10-11-asiashanghai).

`run_parser_conversion` now transforms the independent reader AST into the native converted-module layout, including cold/warm builtin catalogs, error paths and ordered ownership effects. 170 fresh native/Python controls and 25 rollback checks pass. Four complete actual ELF controls each match 128 allocations, 139 functions and 54533 decoded words across full guest, extra heap and image pages. Prior owner code, including the codec, remains AST-identical. Converted cleanup, root/descriptor, factory/bootstrap and signer remain unfinished. See the [parse conversion report](../REQUEST_JNI_STARTUP_WORKERS.md#644-parse-模块转换与-builtin-catalog2026-10-11-asiashanghai).

`cleanup_parser_conversion` now releases the converted module in native reverse ownership order, retaining native dangling headers. 146 fresh native/Python controls and 21 rollback checks pass, including two complete actual ELF modules generated independently through Python reader/parse. Full guest, extra heap, image pages and every ordered free match. Existing owner code remains AST-identical. Root/descriptor builders, factory/bootstrap and signer remain unfinished. See the [converted cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#645-converted-module-清理2026-10-11-asiashanghai).

`initialize_instruction_builder_catalog` now constructs the native dispatch graph (529 nodes, 99 tables) and secondary catalog (600 nodes), preserving allocation padding and serial guard/finalizer behavior. 40 fresh native/Python controls and 22 rollback checks pass, including cold/warm catalogs, relocated heaps/SP and alternate thread IDs. Metadata comes from static ELF constructor stores; previous owner code remains AST-identical. Executing opcode builders, root/descriptor, factory/bootstrap and signer remain unfinished. See the [builder catalog report](../REQUEST_JNI_STARTUP_WORKERS.md#646-instruction-builder-catalog2026-10-11-asiashanghai).

`build_parser_runtime_instruction` now executes recovered virtual builder semantics, including 187 leaf methods, nested dispatch and fallback. 116422 native/Python instruction calls in 22 driver batches and 24 rollback checks pass; 109066 calls cover every decoded word of two complete actual ELF modules generated by Python reader/parse. Each full 64-byte output slot and all guest/heap/image pages match. Runtime-vector moves, secondary conversion/root linking, descriptor/root, factory/bootstrap and signer remain unfinished. See the [runtime builder report](../REQUEST_JNI_STARTUP_WORKERS.md#647-decoded-instruction-运行时构造2026-10-11-asiashanghai).

`link_parser_runtime_descriptor` now applies root pointers and all 600 secondary instruction rules. 3918 native/Python descriptor controls in 18 batches and 27 rollback checks pass, including two complete actual ELF modules with 109066 instruction records. All guest/heap/image pages match; inputs come from Python reader/parse/builders. Native vector moves, complete descriptor/root, factory/bootstrap and signer remain unfinished. See the [runtime linking report](../REQUEST_JNI_STARTUP_WORKERS.md#648-runtime-descriptor-二次转换与-root-linking2026-10-11-asiashanghai).

`construct_parser_defined_descriptor` now composes decoded builders, native variant moves, name copies and failure cleanup for an empty name filter. 288 native/Python descriptor controls in 48 batches, 113762 runtime instructions and 35 rollback checks pass. Two fresh actual modules contribute 242 functions and 109066 instructions; full guest/heap/image pages, consumed temporary bytes and ordered effects match. Imported descriptors, complete root, factory/bootstrap and signer remain unfinished. See the [defined descriptor report](../REQUEST_JNI_STARTUP_WORKERS.md#649-defined-descriptor-构造与失败清理2026-10-11-asiashanghai).

`initialize_builtin_function_catalog` now constructs 73 owned-name function entries in 128 buckets from ELF source references. 32 native/Python catalog controls, 198 name-hash controls and 34 rollback/type guards pass. Ordered effects, owner publication bytes and consumed temporary storage match; decoded names stay private. Imported descriptors, complete root, factory/bootstrap and signer remain unfinished. See the [builtin catalog report](../REQUEST_JNI_STARTUP_WORKERS.md#650-builtin-function-catalog-与名称哈希2026-10-11-asiashanghai).

`construct_parser_imported_descriptor` now resolves external and builtin functions, initializes the empty registry and constructs kind-0 descriptors. 106 native/Python controls in 72 batches and 36 rollback checks pass. Two fresh actual modules contribute all 36 function imports using ELF constructor callback references. Full pages, consumed name temporaries and ordered publication effects match. Complete root, factory/bootstrap and signer remain unfinished. See the [defined descriptor report](../REQUEST_JNI_STARTUP_WORKERS.md#651-imported-descriptor-解析与构造2026-10-11-asiashanghai).

`construct_parser_root` now composes binding maps, moved global data, imported/defined descriptors, owned name indexes and runtime linking. 62 native/Python root controls and 34 rollback checks pass. Two fresh complete actual modules contribute 278 descriptors and 109066 runtime instructions; each matches 544 allocations, 52 frees and 3 finalizers. Whole pages and consumed root temporaries match. Factory/bootstrap and signer remain unfinished. See the [root report](../REQUEST_JNI_STARTUP_WORKERS.md#652-root-构造全局数据搬移与运行时链接2026-10-11-asiashanghai).

`run_module_factory` now composes ELF blob decoding, reader/AST, parser conversion, root linking and both temporary cleanups. 26 native/Python factory controls and 38 rollback checks pass. Each fresh actual module matches 139 descriptors, 54533 instructions, 2330 allocations, 1836 frees and 4 finalizers. Constructor publication, full bootstrap and signer remain unfinished. See the [factory composition report](../REQUEST_JNI_STARTUP_WORKERS.md#653-factory-独立组合与两层清理2026-10-11-asiashanghai).

`run_module_constructor` now derives its binding/codec inputs from ELF instructions, invokes the independent factory and publishes all 121 descriptors. Two complete native/Python constructor controls and 22 rollback checks pass, including relocated SP, padding and a fault at the last publication. Full pages, 242 publications and ordered effects match. Full JNI/bootstrap, B VM execution and signer remain unfinished. See the [constructor report](../REQUEST_JNI_STARTUP_WORKERS.md#654-构造器输入生成与描述符发布2026-10-11-asiashanghai).

`initialize_runtime_context` and `execute_runtime_descriptor` now cover B context setup and the initialization descriptor with explicit pure imported providers. 48 execution controls, 6 initializer controls and 27 rollback checks pass. Two independently constructed actual descriptors each match 19 dispatches and 2 provider calls, including complete pages, active frames and callback SP. Actual imported bodies, full startup and signer remain unfinished. See the [bounded runtime report](../REQUEST_JNI_STARTUP_WORKERS.md#655-b-运行状态与有界描述符执行2026-10-11-asiashanghai).

The existing shared `vm9_startup` callable owner now supports B vtable +35fc28 for move/destruction, including its GOT-derived clone target. 84 native/Python controls and 12 rollback checks pass: 32 B controls and 52 existing A/queue regressions. Full B startup composition and signer remain unfinished. See the [B callable report](../REQUEST_JNI_STARTUP_WORKERS.md#656-b-callable-的共享移动与清理2026-10-11-asiashanghai).

The B main-thread startup now executes both actual imported callback bodies through the shared queue owner. 28 native/Python controls and 41 rollback checks pass, including four actual startup controls from two independently constructed ELF modules. Each startup matches 19 dispatches, three deferred thread requests and 22 ordered service effects. B worker execution, full JNI/bootstrap and signer remain unfinished. See the [B startup report](../REQUEST_JNI_STARTUP_WORKERS.md#657-b-主线程-startup-与真实导入回调2026-10-11-asiashanghai).

The B executor now supports signed immediate/conditional branch tags and six further fused instructions used by worker callers. 112 runtime controls, four actual startup regressions and 40 rollback checks pass. The 24 actual worker-descriptor controls use explicit pure imported providers; worker callback bodies and nested initializers remain unfinished. See the [B worker runtime report](../REQUEST_JNI_STARTUP_WORKERS.md#658-b-worker-的分支与组合指令2026-10-11-asiashanghai).

The B executor now covers the evidenced worker arithmetic with 28 primary tags and 47 fused tags, plus actual CAS64/memset adapters. 310 runtime controls, 30 builtin controls, four startup regressions and 69 rollback checks pass. The 24 actual nested worker descriptor controls execute the real memset callback. Full once/worker composition and signer remain unfinished. See the [B worker arithmetic report](../REQUEST_JNI_STARTUP_WORKERS.md#659-b-worker-完整算术与内存内置函数2026-10-11-asiashanghai).

The shared once owner now accepts all six B controls. 60 native/Python controls include 36 B cases and 24 A regressions; 22 rollback checks pass. Actual libc broadcast executes, while the initializer remains an explicit provider boundary in this check. Full B worker and signer remain unfinished. See the [B shared once report](../REQUEST_JNI_STARTUP_WORKERS.md#660-b-复用共享-once-状态机2026-10-11-asiashanghai).

The complete B worker callable now composes six outer and 48 nested descriptor programs with the shared once gate and actual CAS64/memset semantics. 18 native/Python controls and 36 rollback checks pass. Each cold task matches 120847 dispatches, six allocations and six wakes from fresh independent ELF inputs. Queue-worker/TLS composition and the full signer remain unfinished. See the [B full callable report](../REQUEST_JNI_STARTUP_WORKERS.md#661-b-完整-worker-callable-与嵌套初始化2026-10-11-asiashanghai).

B now runs the actual startup-generated queue task through normal worker return, TLS key cleanup and the full joinable guest pthread_exit body. 12 native/Python controls and 24 rollback checks pass with fresh independent ELF inputs. Main/task contexts, both TLS regions, all nonstack pages and ordered effects match. Full JNI/bootstrap and the independent signer remain unfinished. See the [B queue worker report](../REQUEST_JNI_STARTUP_WORKERS.md#662-b-同次-startup-的队列-worker-与清理2026-10-11-asiashanghai).





`cleanup_reader_ast_output` consumes the twelve output containers in native descending order. It reuses existing record destructors, accepts nullable import/export nodes, directly resets/frees kind4 vectors, and frees table/memory storage without reading its records. All owned regions must be disjoint; retained caller regions belong in `reserved_regions`. Begin/capacity stay dangling after logical free; consume every effect once. This does not free the output object or callback/parser state. 330 comparisons and 214 rollback checks pass; affected import/export JSON files match byte for byte. See the [output cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#630-完整-output-wrapper-清理2026-10-10-asiashanghai).

The callback has its actual +0x372370 vtable, zero helper pointer at +8, output
at +18 and output+108 at +20. The output is a 0x120-byte vector-header prefix;
only type/import/function/table/memory/global/export/start/element/data/raw-word containers may hold storage. Caller-supplied
`reserved_regions` retain other borrowed memory. `max_nodes=4096` bounds nodes
and new type/function/table/memory/global/cache/element/data capacities (nested records and children also count);
`max_vector_bytes=16*1024*1024` bounds each buffer.
The pure `allocate(size)` service returns an aligned mapped address and must
not mutate pages or perform external allocation. Consume free effects once;
destruction leaves native dangling begin/capacity/tree pointers. Unsupported
slots, attached parser state without the verified opt-in, opaque output ownership, aliasing and bounds
fail closed with full model-page rollback. Nonnull zero-capacity pointers
must also be mapped; that guard was reproduced RED before its fix. These APIs are separate from
`run_reader_sections`, whose callback remains a status service. Full AST,
reader/factory/bootstrap and signer remain open. See the
[AST/cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#612-实际-ast-callback-与临时清理2026-10-09-asiashanghai).
The +158 length ABI is repaired. This checkpoint keeps parser and AST callback
execution separate; remaining AST callbacks and attached parsing remain open.

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_sections_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-section-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varint32_20261008.py --library "$env:TOMATO_LIBMETASEC" --output <reader-i32-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_types_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-type-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_imports_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-import-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varuint64_20261008.py --library "$env:TOMATO_LIBMETASEC" --output <reader-u64-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_import_limits_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-import-limits-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_table_memory_sections_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-table-memory-sections-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_varint64_20261008.py --library "$env:TOMATO_LIBMETASEC" --output <reader-i64-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_globals_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-globals-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_code_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-code-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_segments_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-segments-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_custom_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-custom-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-data-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_create_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-data-create-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_payload_20261009.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-data-payload-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_data_expression_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-data-expression-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_element_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-element-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_element_nested_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-element-nested-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_instruction_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-instruction-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_local_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-local-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_function_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-function-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_code_begin_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-code-begin-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_table_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-table-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_memory_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-memory-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_global_20261009.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-global-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_global_expression_20261010.py --library "$env:TOMATO_LIBMETASEC" --output <reader-ast-global-expression-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_function_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-function-imports-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_inline_function_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-inline-function-imports-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_other_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-other-imports-evidence.json>
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_ast_module_inline_other_imports_20261010.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-ast-module-inline-other-imports-evidence.json>
```

2026-10-07 Additional cold-switch original-entry observations: two native probes,
zero Python-bootstrap comparisons. The original JNI_OnLoad reaches +0x26e70c
before its body/stub after actual TLS acquisition (three GetEnv calls, six
explicit allocator requests). Thread storage starts empty; TLS subsystem/OS
keys and reference fields remain explicit warm fixtures. Once remains 1.
See [JNI initialization report section 6](../REQUEST_JNI_INITIALIZATION.md#6-后续原始-cold-switch-initializer-已经经过-tls-获取).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_cold_switch_tls_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_cold_switch_tls_fresh_20261007.json
```

2026-10-07 JNI dispatch initialization: 56 native/Python controls, 9 negatives
and six separately counted original JNI_OnLoad probes. Recovered +0x26e19c
and +0x26f154 with explicit JNI services; four same-run publication compositions
pass. Warm-switch probes stop at startup entries; cold-switch probes execute
matching-libc mutex and stop before TLS acquisition, with once state still 1.
Full bootstrap/JVM/fresh signing remain open. See
[REQUEST_JNI_INITIALIZATION.md](../REQUEST_JNI_INITIALIZATION.md).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_jni_initialization_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_jni_initialization_fresh_20261007.json
```

2026-10-07 Previous JavaVM publication checkpoint: 54 native/Python controls and 11
negative controls, plus four separately counted original JNI_OnLoad probes.
Recovered +0x271998/+0x27be88 and live X6 spill; six publication-to-acquisition
controls execute consecutively in one native invocation. Bootstrap probes use
explicit warm dependencies/services and stop after publication on success;
full cold/Python JNI_OnLoad remains open. Same-session request still has no VM
input. See [REQUEST_JNI_PUBLICATION.md](../REQUEST_JNI_PUBLICATION.md).

2026-10-07 JNI environment checkpoint: 40 original-body controls and 14
negative controls pass with the legacy acquisition stub disabled. Original
TLS/destructor bodies execute; JavaVM/pthread/allocator service effects are
explicit fixtures. Six evaluator controls reach the unexecuted FindClass
callsite +0x28b71c. Same-session low synthetic request still returns at 957;
high reaches recovered Python acquisition but refuses at attach +0x26ef7c
because the JavaVM global is zero. Fresh signing and real JNI remain open.
See [REQUEST_JNI_ENVIRONMENT.md](../REQUEST_JNI_ENVIRONMENT.md).

`fq_crypto.py`, `helios_vm.py`, and `medusa_f13.py` contain the pure primitives and sample checks extracted during the analysis.

`medusa_body.py` and `medusa_body_legacy_snapshot.py` are deliberately labelled as the old 225-byte snapshot implementation. The current online VM produces different branches and is only available through the Java/Unidbg bridge in the original isolated workspace. Do not import this module into a current downloader and infer online compatibility from a local 225-byte match.

`vm_full.py` is the sanitized current-VM diagnostic interpreter used to replay
captured VM9 traces. It requires the private `libmetasec_ml_71332.so` supplied
outside this repository (`TOMATO_LIBMETASEC` may point to it) and captured
memory/trace inputs for replay. The fresh component models below can also drive
its semantics without captured input. It is not a current online signer; the
complete fresh request and host handoff remain unresolved.

`vm9_request_nested.py` and `vm9_request_or64.py` recover the fresh request
prefix through STORE64, sub-dispatch, OR64, signed MOVhi and normal ORi.
`vm9_request_nested_callbacks.py` composes the caller and the complete bounded
string getter: shared-reader acquire, declared-length StringObject clone and
release, then VM exit at `+0x99150`. Remaining VM semantics reuse `vm_full`
with guest-backed registers, not captured input state. The 28 new native
controls, 7 refusals and 6 outer-prefix frame controls pass; the original 36
nested-prefix controls also pass. Native caller/wrapper return is observed,
while the Python full native caller ABI remains unmodeled.

The same-session outer/request probe uses the constructed receiver and its
own allocator/OS staging chain. C-string equality, signed `%d` formatting,
temporary string cleanup, serial guard acquire and parsed ELF memory imports
now continue through the additional monotonic clock, raw state and guard
release components. The low image case reaches step 945 / `+0xffb48`, stopping
at `+0x28dc38`; the high image case reaches step 965 / `+0xf8fd0`, stopping
at `+0x28bb5c`. Neither entire native request branch is compared, and requests
still use synthetic inputs.

`vm9_configuration_init.format_string_object` supports only `%d/%s/%%` over
raw ABI words. Native successful cleanup returns zero; the helper returns its
destination address for API use. `vm9_startup.acquire_serial_guard` reuses the
startup guard transition with its actual global normal mutex. New evidence
covers 32 equality, 16 formatter and 10 guard differences plus 11 refusals.
The formatter oracle executes real matching-libc vsnprintf with explicit
allocator services; the integration uses the owning allocator model and
performs no real realloc. `session.reallocate` remains unsupported.
`resolve_request_memory_imports` parses 35 ELF symbol relocations to explicit
memset/memcpy PLT services; it is a limited fixture loader contract.

`vm9_callbacks.store_monotonic_start` and `elapsed_monotonic_microseconds`
use the same explicit owning clock provider with clock id 1. Subtraction wraps
at 64 bits and signed division by 1000 truncates toward zero. Fixed-clock zero
elapsed in this probe is not an online timestamp-freeze result.
`vm9_objects.initialize_mutex_storage` clears raw 140-byte state without the
outer constructor's vtable/flag. `vm9_startup.release_serial_guard` supports
the serial no-waiter branch. The new verifier checks 48 clock, 8 raw state,
6 guard release and 20 shared pointer differences, 18 refusals and 4 outer
constructor regressions. `read_shared_state_pointer` acquires a shared reader,
loads receiver+0x90 and releases it; it does not dereference the return word.
See [REQUEST_CLOCK_STATE.md](../REQUEST_CLOCK_STATE.md) for ABI and commands.

See [REQUEST_NESTED_VM.md](../REQUEST_NESTED_VM.md) for the getter and
[REQUEST_STRING_CALLBACKS.md](../REQUEST_STRING_CALLBACKS.md) for callback ABI,
comparison windows, loader dependencies, evidence use and commands. These
results do not implement real URL/headers/JNI conversion, complete Medusa or
online signature output.

`vm9_cpp_strings` models the tagged 24-byte inline/heap C++ layout used by
request event wrappers. `vm9_request_event` and `vm9_request_boolean_gate`
restore bounded outer orchestration; their formatter/evaluator/scope cleanup
leaves require explicit providers. The 52 string, 16 gate and 8 event controls
pass with 10 refusals. Native outer code executes with those leaves intercepted;
this is not proof of the leaf bodies. The same-session probe stages prefixes
and rejects at event formatter +0x28ddd0 / boolean evaluator +0x28b05c without
committing the new callback body transaction. Outer VM steps remain 945/965.
The formatter verifier now resolves realloc at +0x348320 from ELF and includes
two forced realloc controls; the old truncation control used malloc/copy/free
and never exercised realloc. See [REQUEST_EVENT_GATE.md](../REQUEST_EVENT_GATE.md).

The Python files are research fixtures. They do not contain the private device configuration or raw online trial material.

`vm9_callbacks.py` also initializes the A/B global from an explicit
`MSC.GetABSwitch()` value (APK default `2`) and evaluates the bit-5 initialization
gate. `verify_vm9_startup_switch.py --library <matching-private-so> --output <local-json>`
compares 18 fresh-page cases against actual bytecode in the existing VM.
It loads no captured memory and invokes no JVM. Full signer construction and
callback publication remain open; the old bridge's timestamp-valued A/B
callback is not a valid source of default startup state.

`vm9_handoff_rule.py` learns a diagnostic Seg1-to-Seg2 state rule from two paired
captures. Its default byte rule predicted a third homepage capture's `NEXT#1`
exactly, but failed on detail with 34 different bytes and a trace-3 register
divergence. The optional `--allocator-model` derives the object address from the
Seg1 free list, relocates the trained 24-byte constructor state, and applies
shared whole-word counter deltas. A new detail input then completed Seg2 and
Seg3, retaining one unexplained stack byte. The
[sanitized evidence](../evidence/vm9_handoff_holdouts_20261002.json) records the
control, holdout, hashes, and remaining dependencies.

`vm9_allocator.py` now exposes `allocate_small_object`, `free_small_object`
and `cleanup_small_object_bins`, covering empty-bin batches, mapped new slabs,
compact trees, flush, cleanup and slab release. `initialize_slab_bitmap`
generates bitmap words from the class descriptor. `GuestOS` owns explicit
zero-filled anonymous mappings, and `register_os_region` registers the native
`0x40000` region layout before the first fresh slab split. Lifecycle failures
are atomic; purge requires an explicit guest madvise result. The bounded
global boot reader/publisher still requires explicit captured arena/key inputs;
lookup-cache generation, callback tables and standalone current Medusa remain
unsupported.

`vm9_callbacks.py` contains only directly attributed callback effects:
`clock_callback` writes a supplied guest timespec and wrapper result,
`publish_callback_descriptor` writes the two fields consumed by the active
descriptor trampoline, and `dispatch_descriptor_trampoline` models the
observed pre-dispatch/reload/branch sequence with explicit callbacks. The
packed callback-object composition, actual branch bodies and remaining native
object graph are explicit unsupported boundaries.
The module accepts trusted local checkpoint pages. See
[ALLOCATOR_LIFECYCLE.md](../ALLOCATOR_LIFECYCLE.md) for usage, 83 native
differential cases, 360 sequential operations and the same-capture chain.

`vm9_objects.py` also exposes `construct_lazy_reference`,
`construct_configuration_reference`, and
`construct_service_reference`. They parameterize the measured singleton
guard/slot publication and exact allocation order. The `flag` kind creates
the native 2-byte zero payload; the larger `service` kind now defaults to
`construct_service_payload`, generating its 0x2d0-byte graph from loaded ELF
constants/GOT inputs. The configuration helper creates the measured 8-byte
vtable-only payload used by the root constructor. Cold getters require an
explicit `thread_id`; acquired/released guard state and thread ID are modeled,
while recursive/contended guards are rejected. Warm getters allocate nothing.
`construct_signer_handler(kind="service_refs", initialize_services=True)`
initializes both services in native order before copying their references.
Run `verify_vm9_service_singletons.py --library <matching-private-so>
--libc <matching-private-libc> --output <sanitized-output.json>` for 72 native
fresh-memory comparisons and 15 rejection/rollback cases. Native code is used
only by the verifier; the model invokes neither native constructors nor JVM.
Full root configuration, diagnostic/global boot and standalone current Medusa
remain open. See [SIGNER_CONSTRUCTION.md](../SIGNER_CONSTRUCTION.md).

`construct_root_configuration_layout` generates the 264-byte configuration
prefix and 30 nested allocations before the VM initializer. It is separate
from the 8-byte configuration singleton. `decode_masked_bytes` preserves
source/mask aliasing and stops at a zero mask without adding a terminator.
The two uncontended mutex helpers model serialized normal bionic transitions,
including the shared bit, and reject unsupported states. Run
`verify_vm9_configuration_primitives.py` with the same library/libc/output
arguments for 72 native differences and 25 rejection/rollback cases.

`verify_vm9_root_configuration.py` runs 16 native initialization cases in an
explicit virtual environment, with fresh ELF strings and isolated TLS/stack.
Its output contains counts and offsets only. This is a native oracle for
future Python differences; it does not implement the initializer in Python
or establish current online Medusa.

`construct_configuration_object_layout` models the separate 88-byte
+0x26194c prefix through +0x261a1c, with nine allocations, declared-length
string clones and a 48-byte empty container reference. It does not execute
the later parser initializer. `clone_string_object` and the serialized
shared-reader acquire/release helpers are independently native-tested.
Run `verify_vm9_configuration_objects.py` with library/libc/output arguments:
140 differences and 23 rejection/rollback cases.

`decode_configuration_base64`, `construct_sized_string_object` and
`construct_decoded_configuration_reference` recover the parser's +0x258e7c
dependency. Caller supplies explicit allocate/free effects; native whitespace,
padding, buffer queries and partial groups are preserved. Run
`verify_vm9_configuration_decode.py --library <matching-private-so>
--output <sanitized-output.json>`: 200 differences and 11 rollback cases.

`verify_vm9_root_vm_prefix.py` (library/libc/output arguments) compares eight
VM phases from four same-fresh-native runs at two image bases. Root step 513
matches through the 88-byte prefix; parser step 725 matches before +0x248dd8
with 13 allocations, four explicit frees and a 48-byte callback descriptor.
Guest object bytes, allocation sequence and main image pages match.
These are native-prelude snapshots for differential testing, not a
fully Python startup. No trace/branch/opaque hooks or external captured pages
are used. Complete parser, root initialization and current Medusa remain open.

`append_string_object`, `append_string_fields`, `reserve_string_fields` and
the string cleanup helpers preserve native alias, growth, failure and field
reload rules. `verify_vm9_strings.py` (library/output arguments) passes 166
native differences and eight rollback cases under explicit malloc/realloc/free
effects. Allocator ledgers are external to page transactions.

`construct_digest_reference` models the parser's MD5/SHA-1 raw or hex string
references, including SHA-1 padding initialization and guest alphabet/GOT
reads. `verify_vm9_parser_digests.py` (library/output arguments) passes 142
native differences and five rollback cases, including single-byte append.
Only synthetic inputs and sanitized evidence are used; no digest payload or
private ELF alphabet is exported. Diagnostic/native stack effects and the
later 136-byte singleton remain outside these component models.

`construct_singleton_layout136` and `construct_registry_layout320` generate
the next constructor prefixes, with 4 and 7 allocations respectively.
`construct_singleton_helper56` is a full helper constructor.
The table reader follows guest GOT rather than a fixed default pointer;
the realtime clock wrapper preserves signed wrap/truncation rules.
Run `verify_vm9_singleton136.py` (library/libc/output): 78 differences / 13
rollback cases. These prefix tests are retained alongside the complete-body
tests in `verify_vm9_registry_initialization.py`.

`get_emulated_tls_address` uses explicit allocate/reallocate, key-create,
get/set-specific and cold once-wake boundaries. Run
`verify_vm9_emulated_tls.py`: 60 differences / 12 rollback cases.
`vm9_allocator.pthread_key_create` models matching bionic's serialized
141-entry generation-table scan: `verify_vm9_pthread_keys.py` passes 36 / 4.
For the current matching libc explicitly supply libc-base +0xe0200; the
older checkpoint default is not this libc ABI.

`register_emulated_thread_destructor` recovers local cold key/TLS list
registration; `initialize_scoped_tls_registry` initializes its guarded
thread-local tree. Run `verify_vm9_thread_destructors.py`: 32 / 5.
Registration does not execute a process/thread destructor.

`construct_single_scoped_lock`, `destroy_single_scoped_lock` and
`broadcast_condition_no_waiters` cover zero/one live TLS mutex and an idle
writer. The constructor takes original scratch memory because native copies
seven stack padding bytes into its 48-byte node. Run
`verify_vm9_scoped_lock.py`: 42 / 7, including nesting, poisoned free and wake
ordering. Multiple live keys/readers/waiters are rejected. Caller allocator
and registration ledgers are not rolled back by page transactions.

The same-run root verifier additionally compares eight constructor prefixes,
eight TLS calls, four cold TLS-tree initializers and eight scoped locks,
including all 2256 generation-table bytes and allocation/free/registration/
wake sequences. It also compares 36 complete constructor/setter/getter/cipher
subtrees, including ordered clock effects and actual cold Python TLS.
Its native input snapshots remain explicit; the VM parser
crosses mode-0 +0x259dbc and stream +0x2592b8, then stops before +0x248dd8; full Python Medusa is incomplete.

`vm9_registry.py` provides input-driven configuration comparison, lookup,
red-black insertion, `set_configuration_u32`, `construct_registry320`,
`construct_singleton136`, `get_registry320_reference` and
`get_singleton136_reference`. Full constructors include map population and
cleanup; cold getters publish only after construction and reference count.
Supply `entry_stack_address` because reused frame words affect copied TLS
padding. Matching bionic unlock and node-erase stack effects are derived from
that input. This is not a general native stack emulator or concurrent guard.

Run `verify_vm9_registry.py` (library/output): 96 native groups / 11 rollback
cases. Run `verify_vm9_registry_initialization.py` (library/libc/output):
38 / 14, including pre-free bytes, cold/warm getters and rollback of nested
initialization. Keys are synthetic or decoded at runtime from a private ELF;
no decoded key strings are exported. TLS resolution is explicit in component
tests; the same-run subtree checks use recovered Python cold TLS/key models.

`verify_vm9_allocator_lifecycle.py` requires Unicorn and the trusted primary
initialized checkpoint. `verify_vm9_divmod_backing.py` additionally requires
the paired private memory image and `TOMATO_LIBMETASEC`. Both write sanitized
JSON results and load no online device configuration. The latter checks the
explicit native register-backing address, which must never be inferred from
virtual R28.

The `pop_bitmap_slot` helper records one more directly observed refill step:
`RBIT/CLZ` selects the lowest set bit of a slab bitmap, the native path clears
that bit with XOR, and the slab counter decreases by one. It deliberately does
not turn that bit into an object address; the slab base, higher-level bitmap
updates, and allocation history are still required for that calculation.

For trusted local captures only:

```text
python vm9_handoff_rule.py training_a training_b heldout_seg1.pkl predicted_next1.pkl --allocator-model --summary prediction.json
```

Each training directory supplies `mem_after_seg1_offline.pkl` and its captured
`handoff/next_1/` region files. The held-out input is only a Seg1 checkpoint;
this command does not read its `NEXT#1`. Compare with the real handoff afterwards.
The size-class refill path is unsupported and raises an error. Pickle inputs
must be trusted. The predicted checkpoint still contains captured baseline and
trained target bytes; this utility does not generate current Medusa headers.

The held-out detail capture's trace was separately replayed with
`vm9_trace_replay.py`; its 779-byte body matched the final captured
`MEDCOPY` body at every byte. This is an output assembly check for one capture,
not a fresh-input current Medusa implementation. The remaining one-byte
handoff difference is documented in
`evidence/vm9_detail_body_compare_20261002.json`.

`vm9_cipher.py` reads matching guest cipher tables and builds enc/dec schedules,
block encryption/decryption, CBC IV updates and the observed ECB/CBC dispatcher.
Run `verify_vm9_cipher.py` (library/output): 256 native groups / 11 rollback
cases. PyCryptodome AES is used only as a verifier oracle.

`vm9_cipher_callback.py` supplies `initialize_cipher_context`,
`checked_forward_copy` and `decrypt_configuration_reference`. The copy executes
two recovered singleton getters before its forward byte loop. Complete mode-0
callback tests cover last-byte-only trimming, allocator mutation, failed clone
and string payload allocations, poisoned cleanup and indirect guest targets:
`verify_vm9_cipher_callback.py` passes 200 groups / 12 rollback cases. Supply
explicit entry SP and allocator/singleton callbacks. Modes 1/2/3 initialization
and nonzero environment-check branches reject. See
[the cipher callback guide](../CIPHER_CALLBACK.md) for ABI, evidence and limits.

`vm9_stream_cipher.py` restores RC4 state/discard, processing, one-shot
wrapping and +0x258fd8/+0x2592b8 string/shared-reference construction and
cleanup. `verify_vm9_stream_cipher.py` (library/output) passes 174 groups / 9
rollback cases. Independent ARC4 is verifier-only. The one-shot oracle must
load length into X5; its entire 264-byte stack state is explicitly compared.
See [STREAM_REFERENCE.md](../STREAM_REFERENCE.md). The same-run parser now
reaches step 725 with 100 allocations and 26 frees; snapshots and serialized
OS/guard boundaries remain explicit.


### Request leaf prefixes (2026-10-07)

`vm9_request_leaf_prefixes.py` recovers sampling/ABI locals in `+0x28ddd0`,
mode global/input preparation in `+0x28e788`, and nine lazy Java stack names
plus encoded/input slots in `+0x28b05c`. The fresh verifier has 30 original-body
controls and 6 negative controls. Native stops before actual JNI acquisition
`+0x26edc4` or mode builder `+0x28f0f4`; no JNI stub/result is used. Unsampled
event paths return, while sampled/evaluator staged transactions refuse without
commit. Same-session outer steps remain 945/965; full callbacks and fresh signing
remain open. See [REQUEST_LEAF_PREFIXES.md](../REQUEST_LEAF_PREFIXES.md).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_leaf_prefixes_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --output platforms/bytedance/tomato/evidence/vm9_request_leaf_prefixes_fresh_20261007.json
```


### Signed mode format body (2026-10-07)

`vm9_request_format_objects.py` recovers the bounded `+0x28e788` mode path:
token and borrowed parameter vectors, live signed32 rendering, 128-byte inline
conversion, C++ string output and temporary cleanup. The verifier has 12 builder,
22 full mode, 4 late-parameter native controls and 14 negative controls. Builder
comparison excludes only unspecified token padding; full mode compares the full
final payload and objects after cleanup. Explicit allocator/free/copy services
remain component boundaries. Other format grammar/types/growth refuse.

Same-session owning allocator composition produces `{"x0":0}` and stops at
five-argument `+0x28e86c`; high image still stops at real JNI `+0x26edc4`.
Outer steps remain 945/965 and the complete event parent transaction does not
commit. See [REQUEST_MODE_FORMAT.md](../REQUEST_MODE_FORMAT.md).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_mode_format_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_mode_format_fresh_20261007.json
```


### Five-argument event format (2026-10-07)

The existing format owner now builds a 144-byte object with four live uint64
cells and one live signed-int32 cell, indexes 0..4, bounded inline rendering,
heap C++ output and temporary cleanup. Twelve builder controls, six original
event-prefix controls, four late-parameter controls and 19 negatives pass.
Complete prefixes stop before emission +0x28ff44 and compare the full final
payload, bounded locals and two global pages without padding exclusion;
builder-only controls still exclude unspecified token padding.

The same owning-session composition produces the three caller strings, records
17 frees and stops at emission. The high branch still needs actual JNI
+0x26edc4. Outer steps remain 945/965 and the parent callback does not commit.
Shared hex-selector initialization is also restored for the previous signed
mode owner, whose native regressions now compare that global page.
See [REQUEST_EVENT_FORMAT.md](../REQUEST_EVENT_FORMAT.md).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_event_format_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_event_format_fresh_20261007.json
```


### Warm event emission and bounded request VM return (2026-10-07)

`vm9_request_event.execute_event_emission` now models distinct-owner moves,
normal mutex transitions, 96-byte record-vector append/growth, count>=200 drop
and cleanup. `vm9_cpp_strings.move_assign_cpp_string` preserves source tail
bytes, while record move construction clears the full object. Forty native
controls and 14 negatives cover emission, returned formatter/event callers,
heap ownership, nonempty old records and the actual VM return handler.

The low same-session synthetic Python request reaches 957/+0xffb78 with its
caller sentinel matched, commits request pages, and preserves/appends logger
records (33 allocations/18 frees). Its output is a tree reference, not a
signature. The high branch still needs actual JNI +0x26edc4. Cold/alternate
publication and whole-native request/physical caller ABI remain unverified.
See [REQUEST_EVENT_EMISSION.md](../REQUEST_EVENT_EMISSION.md).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_request_event_emission_fresh_20261007.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output platforms/bytedance/tomato/evidence/vm9_request_event_emission_fresh_20261007.json
```


### Actual JNI dispatcher and Long conversion (2026-10-07)

`vm9_jni_environment.invoke_java_dispatch` restores the actual getter,
integer GP va_list and two distinct exception checks (54 controls/10 negatives).
`convert_java_long` restores lazy Long strings, cached lookup/normal lock scope
and the no-argument CallLongMethodV path (34 controls/11 negatives). JNI services
and cache mutex inputs remain explicit; unused GP/SIMD/physical spill ABI is
excluded. Two original JNI_OnLoad observations reach +0x270854 before the cache
mutex is initialized; full once/bootstrap/fresh signer remains open. See
[REQUEST_JNI_DISPATCH.md](../REQUEST_JNI_DISPATCH.md) for API and reproduction.


`initialize_java_cache_mutexes` subsequently restores `.init_array +0x271940`
(8 controls/6 negatives): allocate48/publish cache mutex, inline normal mutex,
and explicit exit registration. Cache fields are preserved. Full ELF init,
actual destructor and same-fresh cold once integration remain open; see
[JNI report section 7](../REQUEST_JNI_DISPATCH.md#7-后续init_array-0x271940-的-mutex-构造已恢复).


### Cold JNI caller composition and native once completion (2026-10-08)

`initialize_cold_java_switch` restores +0x165658 acquisition, independent getter
env, Long/store and returned-object deletion. Fourteen compositions/four negatives
compare fresh payload/image/JNI table/caller pair and live JNI argument windows;
late deletion refusal rolls back guest pages while retaining external JNI events.
Four separate original JNI_OnLoad prefixes complete cold once and stop before
startup VM entries using one explicit constructor driver. Full Python bootstrap
and actual startup VM execution are still open. See
[REQUEST_JNI_COLD_ONCE.md](../REQUEST_JNI_COLD_ONCE.md) for commands and limits.

### Cold once getter/mask and original startup input boundaries

`read_cold_java_switch` and `check_cold_java_switch_mask` add 34 native/Python
controls and nine negatives. They restore normal once/cache/broadcast flow and
the full uint64 predicate, including the fixed startup mask 0x200. Waiting and
C++ unwind remain rejected. Four original startup prefixes and four single-variable
memcpy ABS64 binding observations locate A's next pthread_create boundary and B's
missing descriptor publication. Full Python bootstrap comparisons remain zero.
See [REQUEST_JNI_COLD_MASK.md](../REQUEST_JNI_COLD_MASK.md) for APIs and reproduction.
