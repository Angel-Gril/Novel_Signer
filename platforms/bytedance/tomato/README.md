# Tomato / Fanqie (ByteDance)

Current boundary (2026-10-09 Asia/Shanghai; earlier host trial label `20261008`): original A
JNI_OnLoad returns `0x10006`; its same-run queue worker executes six default
callers / 48 nested returns, cleanup, matching-libc wait, explicit stop and
argument free. Two new TLS cleanup and two guest joinable exit observations
clear the actual support slot and free argument/payload/wrapper in order.
Guest state 0→1 reaches explicit syscall 93 exit. Thread creation/termination,
allocator/OS/JNI/warm TLS and the empty cxa thread list remain explicit inputs.

Two original B constructor/factory observations now return naturally and each
publish 121 nonzero descriptors. 242 Python lookup comparisons consume native
generated roots, distinct from the earlier 50 synthetic-root controls and six
negatives. Independent Python factory, original JNI B composition, B VM and
full Python bootstrap (0 controls) remain open. The independent XOR prefix
adds 82 native/Python controls (including two real ELF blobs) and eight
rollback cases; it stops before the +31b360 reader. Two subsequent native
reader observations accept that Python XOR input and return 0 after 1658
controlled allocations each. The independent u32 helper adds 258 comparisons/seven rollback
checks. The signed i32 helper adds 1336 comparisons/10 rollback checks; failed
reads preserve output. Reader envelope/order and generic-custom/function/export/start/data-count
handlers add 202 comparisons/12 rollback checks, including eight actual ELF
section controls from fresh Python XOR. Callback arguments and state match;
callbacks remain explicit status services. Word-vector grow and section 1 types
add 102 / 372 comparisons and 34 rollback checks, including four fresh ELF
input controls; type cells at each callback and pointer publication match.
Function/global imports in section 2 add 254 comparisons and 14 rollback checks,
including six fresh ELF inputs; the 1/2/3/7/12 composition matches 300 callbacks
per base. Parsing requires explicit `enable_function_global_imports=True`.
The u64 reader adds 1438 comparisons/10 rollback checks; table/memory imports
add 234 comparisons/15 rollback checks. Six compositions combine fresh ELF
function/global inputs with synthetic table/memory imports; actual ELF table/memory
import inputs remain absent. Their 19-byte descriptors match after normalizing
the transient native stack pointer to model scratch. Parsing requires
`enable_table_memory_imports=True` and a mapped 32-byte `import_scratch_address`.
Sections 4/5 add 266 comparisons/18 rollback checks with the independent
`enable_table_memory_sections=True`, reusing that scratch and descriptor parser.
Count/entry callbacks and indices offset by imports match; definitions do not
increment import counts. The sample has no real sections 4/5. Six compositions
add synthetic definitions to fresh ELF function/global input; the full selected
composition matches 306 callbacks per base. See [section 4/5 evidence](evidence/vm9_alternative_reader_table_memory_sections_fresh_20261008.json).
Signed i64 adds 1480 comparisons/10 rollback checks; section 6 and initializers
add 390 comparisons/26 rollback checks, including ten fresh ELF global inputs.
Globals require the independent `enable_global_section=True` and a mapped,
aligned, disjoint 16-byte `global_scratch_address` with an explicit caller-local
seed. End-only retains its high word; i32 results zero-extend; opcode kinds
follow the actual GOT table pointer, with relocation/overrides checked. The
actual section has 22 definitions, and 1/2/3/6/7/12 matches 455 callbacks per base.
See the [global/initializer report](REQUEST_JNI_STARTUP_WORKERS.md#68-有符号-i64-与-section-6-初始化表达式2026-10-08-utc).
Section 10 adds 228 comparisons/15 rollback checks, including six actual ELF code
inputs. Its 121 bodies contain 54533 raw words; the full selected composition
matches 55351 callbacks per base. Use the independent `enable_code_section=True`;
`max_code_words` bounds all word callbacks, including native retries without cursor
progress. This reads words; instruction execution and actual AST remain open. See
the [code report](REQUEST_JNI_STARTUP_WORKERS.md#69-section-10-元数据局部类型与指令字读取2026-10-08-utc).
Sections 9/11 and their distinct +0x3215f0 expression helper add 450 comparisons,
33 rollback checks and 16 native abort boundary checks. Six controls contain
actual ELF data (three segments); full 1/2/3/6/7/12/10/11 matches 55369 callbacks
per base. Each section requires its own opt-in and an eight-byte expression
scratch region. Section 9 supports empty element vectors; nonempty vectors reach
native abort and remain unsupported. See the
[segment report](REQUEST_JNI_STARTUP_WORKERS.md#610-section-911-与独立-expression-helper2026-10-08-utc).
Section 0 special custom handlers add 860 comparisons and 32 rollback checks,
including ten actual ELF custom controls. All actual sections, including three
custom payloads, match 55369 callbacks per base. Enable these metadata parsers
with `enable_special_custom_sections=True`, an independent eight-byte
`custom_scratch_address` and `max_custom_records=4096` per custom section.
Subsection limits and the custom flag are restored on parse failure. See the
[custom report](REQUEST_JNI_STARTUP_WORKERS.md#611-section-0-特殊-custom-元数据2026-10-08-utc).
Actual type/start/local group count/raw-word callbacks and temporary callback cleanup
add 308 native/Python comparisons and 54 rollback checks, including 32 actual
ELF type inputs. Actual vtables run naturally; node bytes, pointer publication,
allocation/destruction/free ordering and owner state at every effect match.
The five callback slots are +18/+20/+a0/+b0/+168; cleanup covers five reverse
node lists, two bounded trees and a byte buffer. These separate APIs require a
detached callback by default and empty unrecovered output containers. A bounded
attached module is now available below; remaining composition stays open. See the
[AST/cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#612-实际-ast-callback-与临时清理2026-10-09-asiashanghai).
Slot +160 subsequently adds 176 comparisons and 30 rollback checks for
176-byte data record reserve/move and the +2cc1ec non-deleting destructor.
All fixtures are synthetic and run at two bases. Nested vectors transfer,
destination padding remains intact, and publication/destruction/free match.
Data storage at output+f0 is now validated in the shared ownership graph;
remaining attached handlers stay open. See the
[data reserve/destructor report](REQUEST_JNI_STARTUP_WORKERS.md#613-data-record-容量预留搬移与析构2026-10-09-asiashanghai).
Slot +140 data record creation/append adds 148 comparisons and 105 rollback
checks, all synthetic at two bases. Flag classification, u32 truncation,
owned result sentinel, growth/padding and temporary cleanup match native.
Old AST 308/54 and data reserve/destructor 176/30 regressions pass with
byte-identical evidence. See the
[data creation report](REQUEST_JNI_STARTUP_WORKERS.md#614-data-record-创建与追加2026-10-09-asiashanghai).
Slot +158 payload writes and the parser's missing length argument now pass
104 AST comparisons, 34 parser ABI comparisons and 30 rollback checks.
Six AST controls use actual ELF payloads; two ABI controls use the actual data
section. Zero length preserves existing payload; nonzero length resizes and
writes the last record. AST/data/create/segments regressions and two complete
actual section compositions remain unchanged. Parser/AST composition remains
open. See the
[payload/length report](REQUEST_JNI_STARTUP_WORKERS.md#615-data-payload-写入与-parser-length-参数修复2026-10-09-asiashanghai).
Slots +148/+150 now pass 148 comparisons and 36 rollback checks for data
expression frames, u32 raw-buffer fixups and actual libc++ tree erasure.
All fixtures are synthetic at two bases. Begin stores raw byte length and
resets the frame stack; end patches offsets, erases a matching keyed node,
frees its payload/node and pops one frame. Tree payload validation now uses
four-byte elements, with a separate pre-change cleanup failure reproduced.
See the
[expression/tree report](REQUEST_JNI_STARTUP_WORKERS.md#616-data-expression-frameu32-修补与树节点删除2026-10-09-asiashanghai).
Slots +f0/+100/+108/+110/+118 add 282 comparisons and 159 rollback checks
for a zero raw word and element reserve/create/expression callbacks. Element
records have stride 184 and own nested 144-byte records; reverse movement,
padding, nested destructor/free order and image constants match. The same
frame/raw/tree owner handles both data and element expressions. All inputs
are synthetic; parser composition remains open. See the
[element report](REQUEST_JNI_STARTUP_WORKERS.md#617-element-回调与嵌套记录清理2026-10-09-asiashanghai).
Slots +120/+128/+130/+138 add 230 comparisons and 133 rollback checks for
the full u64 element result type, nested capacity and nested expression
creation/end. The 144-byte records transfer type results, preserve padding
and reuse the existing frame/raw/tree owner. Six old evidence files match
byte for byte. All fixtures are synthetic; the section 9 nonempty-vector
native abort and parser composition remain open. See the
[nested expression report](REQUEST_JNI_STARTUP_WORKERS.md#618-element-结果类型与嵌套表达式2026-10-09-asiashanghai).
Slots +c0/+c8/+d0/+d8/+e0/+e8 add 398 comparisons and 122 rollback checks
for instruction predicate/end and typed f32/f64/i32/i64 constants. Predicate
returns 0/1 without dereferencing the active pointer. End retains the outer
frame and reuses existing fixup/tree erasure for inner frames. Constants
append tag and raw value separately, preserving floating bits and both
allocation/publication/free stages. All fixtures are synthetic; seven old
evidence files match byte for byte. See the
[instruction report](REQUEST_JNI_STARTUP_WORKERS.md#619-instruction-predicate-与带类型常量2026-10-09-asiashanghai).
Slots +b8/+f8 add 252 comparisons and 37 rollback checks on existing owned
data/element inline and element nested 144-byte layouts. Local groups append
full u64 type, u32 count and wrapping cumulative count; end clears active
and stores a u32 length while preserving frames and trees. Growth publication,
copying, free and later destruction match. All fixtures are synthetic; eight
old evidence files match byte for byte. See the
[local group report](REQUEST_JNI_STARTUP_WORKERS.md#620-local-group-与函数结束回调2026-10-09-asiashanghai).
Slot +50 subsequently restores function creation at output+30, an independent
64-byte type cache at callback+80 and the shared 144-byte record destructor.
All 188 native/Python comparisons and 136 rollback checks pass. Both type
copies own separate params/results; scalar truncation, padding, growth and
reverse destruction match. Function records also support existing local/end
callbacks. Nine old evidence files match byte for byte. See the
[function report](REQUEST_JNI_STARTUP_WORKERS.md#621-function-创建类型缓存与清理2026-10-09-asiashanghai).
Slot +a8 restores code begin: logical function selection, metadata/raw start,
frame-tree cleanup, function-tree fixup and owned 56-byte child append.
All 284 native/Python comparisons and 100 rollback checks pass. Frame/child
growth, padding, ordered effects and exact node budgets match; ten old
evidence files match byte for byte. All fixtures are synthetic. See the
[code-begin report](REQUEST_JNI_STARTUP_WORKERS.md#622-code-begin双修补树与-child-追加2026-10-09-asiashanghai).
Table +58/+60 now reserve output capacity and append separate 48-byte output
and cache records. All 184 comparisons and 77 rollback checks pass; eleven
old evidence files match byte for byte. Entry requires its actual stack
address to preserve the unwritten temporary word copied into +14 padding.
Guest bytes are compared without masking. See the
[table report](REQUEST_JNI_STARTUP_WORKERS.md#623-table-预留创建与显式栈-padding2026-10-09-asiashanghai).
Memory +68/+70 reserve output+60 and append independent 40-byte output/cache
records. All 272 comparisons and 65 rollback checks pass; twelve old evidence
files match byte for byte. Full 24-byte descriptors, both default maxima and
destination padding match without a copied stack word. Cache growth destroys
old records after publication; output growth only frees the old block. See the
[memory report](REQUEST_JNI_STARTUP_WORKERS.md#624-memory-预留创建与独立缓存2026-10-09-asiashanghai).
Global +78/+80 restore 176-byte output records, a separate 24-byte cache and
record destruction. All 328 comparisons and 120 rollback checks pass; thirteen
old evidence files match byte for byte. Full u64 type, mutable low bit,
destination padding and vector transfers match actual native effects.
See the [global report](REQUEST_JNI_STARTUP_WORKERS.md#625-global-预留创建与记录清理2026-10-09-asiashanghai).
Global expression +88/+90 restore shared frames, raw fixups and full-u64
end values while retaining active. Existing local/function-end callbacks
also accept owned global inline layouts. All 212 comparisons and 54 rollback
checks pass; fourteen historical evidence files match byte for byte.
See the [global expression report](REQUEST_JNI_STARTUP_WORKERS.md#626-global-expression-与内联-ast-回调2026-10-10-asiashanghai).
AST string copy +32a9c4 passes 68 comparisons and 12 rollback checks, including full inline padding and heap-to-inline conversion. See the [string report](REQUEST_JNI_STARTUP_WORKERS.md#627-ast-字符串复制基础2026-10-10-asiashanghai).
Export +98 now owns independent names and cloned nodes, including backwards cloning on growth. Export-only output cleanup is recovered; 362 comparisons and 247 rollback checks pass, with sixteen historical JSON files byte-identical. See the [export report](REQUEST_JNI_STARTUP_WORKERS.md#628-export-ast-回调与专属输出清理2026-10-10-asiashanghai).
Five import AST callbacks now own two independent names and cloned nodes, followed by separate cache append. Import-only output cleanup is recovered; 858 comparisons and 410 rollback checks pass, including real table/global stack arguments. Seventeen historical JSON files match byte for byte. See the [import report](REQUEST_JNI_STARTUP_WORKERS.md#629-import-ast-回调与专属输出清理2026-10-10-asiashanghai).
Complete output wrapper cleanup +2cbadc now handles all twelve containers, including nullable import/export nodes and direct kind4 cleanup. 330 comparisons and 214 rollback checks pass; the two affected import/export historical JSON files match byte for byte. See the [output cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#630-完整-output-wrapper-清理2026-10-10-asiashanghai).
A bounded module now composes generic/type/function/start/data-count and empty export parsing with actual AST callbacks, parser vector cleanup and callback cleanup. 214 controls and 83 rollback checks pass; old section and AST/cleanup JSON files match byte for byte. Output starts empty and pure allocation addresses cannot be reused. See the [module report](REQUEST_JNI_STARTUP_WORKERS.md#631-attached-parser-与有界-ast-module2026-10-10-asiashanghai).
Function imports with both names at least 23 bytes now compose through the actual module with `enable_function_imports=True` (default `False`). 180 controls and 43 rollback checks pass; the two old module/import evidence files match byte for byte (1072 controls, 493 guards). Short names require the additional inline opt-in below; other import kinds use the bounded opt-in below. See the [function import module report](REQUEST_JNI_STARTUP_WORKERS.md#632-heap-名称函数-import-的-attached-ast-组合2026-10-10-asiashanghai).
With both `enable_function_imports=True` and `enable_inline_function_imports=True`, empty/short/mixed function import names also compose. Three real type-helper save stores are recovered from caller addresses and counts; no stack snapshot feeds the model. 448 comparisons and 64 rollback checks pass, including relocated SP and 282 independent full inline-padding checks. Default and heap-only evidence files remain byte-identical (394/126). See the [inline import report](REQUEST_JNI_STARTUP_WORKERS.md#633-inline-名称函数-import-与真实-caller-栈写入2026-10-10-asiashanghai).
`enable_table_memory_global_imports=True` now composes actual table/memory/global imports with both names at least 23 bytes, real descriptor/ninth ABI argument, AST effects and cleanup. It defaults to `False`; mixed function imports still require their own opt-in, and heap names when the inline other-import opt-in below is False. Imports after a zero-count type section remain unsupported because the caller register word is not modeled. 406 comparisons and 72 rollback checks pass; three old module/heap/inline JSON files remain byte-identical (842/190). See the [other import report](REQUEST_JNI_STARTUP_WORKERS.md#634-tablememoryglobal-import-的-attached-ast-组合2026-10-10-asiashanghai).
`enable_inline_table_memory_global_imports=True` additionally permits empty/short/mixed names in the table/memory/global import scope; it requires `enable_table_memory_global_imports=True` and defaults to `False`. Mixed function imports still require their own permission, and short function names require their inline opt-in. Caller/helper saves and clone clearing preserve the complete inline padding passed between import kinds, without native stack snapshots as input. 612 comparisons and 41 rollback checks pass, including 436 independent entire inline-padding checks and 12 relocated SP controls. All four old module/heap/inline/other evidence files remain byte-identical (1,248/262). Zero-count type caller registers and the complete signer remain unfinished. See the [short other import report](REQUEST_JNI_STARTUP_WORKERS.md#635-短名称其他-import-与-caller-栈传递2026-10-11-asiashanghai).

`enable_table_memory_definitions=True` independently composes sections 4/5 with real AST effects and cleanup; it defaults to `False` and requires no import option. Actual table/memory descriptors are at `state-0xc0` / `state-0xe0`; caller saves supply descriptor tail bytes and table padding without native snapshots as input. 470 comparisons and 32 rollback checks pass, including 12 moved SP and 12 high guest controls, plus 1142 independent complete records. Eight old module/import/section/table/memory evidence files remain byte-identical (2582/463). Remaining attached handlers, complete reader/factory/bootstrap and the independent signer remain open. See the [definition module report](REQUEST_JNI_STARTUP_WORKERS.md#636-tablememory-definitions-的-attached-ast-组合2026-10-11-asiashanghai).

`enable_global_definitions=True` independently composes section 6 with actual global and constant-expression AST effects and cleanup; it defaults to `False`. The caller result at `state-0xb0` retains its high four bytes for end-only expressions, including the memory handler saved image pointer; initializer integer reads use `state-0x108`. The mapped `[state-0x2a0,state)` frame stays disjoint from input/output/scratch and allocation plans. 398 comparisons and 37 rollback checks pass, including 12 moved SP, 12 high guest and 780 complete global record checks. Five affected historical JSON files remain byte-identical (1614/315). Remaining attached handlers, complete reader/factory/bootstrap and the independent signer remain open. See the [global module report](REQUEST_JNI_STARTUP_WORKERS.md#637-global-definitions-与初始化表达式的-attached-ast-组合2026-10-11-asiashanghai).

`enable_code_definitions=True` independently composes section 10 with actual metadata/local/raw-word/begin/end AST effects and cleanup; it defaults to `False`. Code words are stored without execution. All five callbacks enter at `state-0xe0`; retain mapped `[state-0x210,state)` (or the larger global frame). `max_code_words=65536` bounds the whole section, including native zero-word retries without cursor advance. 256 comparisons and 42 rollback checks pass, including 8 selected complete ELF-body controls, 12 moved SP, 12 high guest, 362 entire function records and 340 entire child records. Eight deliberately interrupted native observations separately cover short-input retries. Four affected historical JSON files remain byte-identical (1124/235); the old unsupported-slot guard now uses +100. Remaining attached handlers, complete reader/factory/bootstrap and the independent signer remain open. See the [code module report](REQUEST_JNI_STARTUP_WORKERS.md#638-code-definitions-的-attached-ast-组合2026-10-11-asiashanghai).

`entry_x22` explicitly supplies the incoming uint64 register for table/memory/global imports after a zero-count type section. Its default `None` preserves the previous rejection boundary. 198 native/Python controls and 9 rollback checks pass, including caller-save observations, 12 moved SP and 6 high guest. On the same final owner, 36 selected historical controls (including both complete actual ELF modules) and all 77 guards from the two affected suites match their historical evidence. The actual ELF reader/AST is verified; parse/root, independent factory/bootstrap, signer and online acceptance remain unfinished. See the [zero-count type report](REQUEST_JNI_STARTUP_WORKERS.md#642-零条目-type-与-incoming-x222026-10-11-asiashanghai).

`convert_parser_instruction_word` now recovers the native parse codec helper, including scalar/SIMD shift differences and ignored metadata bytes. 434 fresh native/Python controls and 10 rejection checks pass, including 198 actual constructor codec controls, 16 moved SP and 12 high guest. Existing owner code is AST-identical after removing the new function. Complete parse/root, factory/bootstrap and signer remain unfinished. See the [parse codec report](REQUEST_JNI_STARTUP_WORKERS.md#643-parse-指令格式转换2026-10-11-asiashanghai).

`run_parser_conversion` now transforms the independent reader AST into the native converted-module layout, including cold/warm builtin catalogs, error paths and ordered ownership effects. 170 fresh native/Python controls and 25 rollback checks pass. Four complete actual ELF controls each match 128 allocations, 139 functions and 54533 decoded words across full guest, extra heap and image pages. Prior owner code, including the codec, remains AST-identical. Converted cleanup, root/descriptor, factory/bootstrap and signer remain unfinished. See the [parse conversion report](REQUEST_JNI_STARTUP_WORKERS.md#644-parse-模块转换与-builtin-catalog2026-10-11-asiashanghai).

`cleanup_parser_conversion` now releases the converted module in native reverse ownership order, retaining native dangling headers. 146 fresh native/Python controls and 21 rollback checks pass, including two complete actual ELF modules generated independently through Python reader/parse. Full guest, extra heap, image pages and every ordered free match. Existing owner code remains AST-identical. Root/descriptor builders, factory/bootstrap and signer remain unfinished. See the [converted cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#645-converted-module-清理2026-10-11-asiashanghai).

`initialize_instruction_builder_catalog` now constructs the native dispatch graph (529 nodes, 99 tables) and secondary catalog (600 nodes), preserving allocation padding and serial guard/finalizer behavior. 40 fresh native/Python controls and 22 rollback checks pass, including cold/warm catalogs, relocated heaps/SP and alternate thread IDs. Metadata comes from static ELF constructor stores; previous owner code remains AST-identical. Executing opcode builders, root/descriptor, factory/bootstrap and signer remain unfinished. See the [builder catalog report](REQUEST_JNI_STARTUP_WORKERS.md#646-instruction-builder-catalog2026-10-11-asiashanghai).

`build_parser_runtime_instruction` now executes recovered virtual builder semantics, including 187 leaf methods, nested dispatch and fallback. 116422 native/Python instruction calls in 22 driver batches and 24 rollback checks pass; 109066 calls cover every decoded word of two complete actual ELF modules generated by Python reader/parse. Each full 64-byte output slot and all guest/heap/image pages match. Runtime-vector moves, secondary conversion/root linking, descriptor/root, factory/bootstrap and signer remain unfinished. See the [runtime builder report](REQUEST_JNI_STARTUP_WORKERS.md#647-decoded-instruction-运行时构造2026-10-11-asiashanghai).

`link_parser_runtime_descriptor` now applies root pointers and all 600 secondary instruction rules. 3918 native/Python descriptor controls in 18 batches and 27 rollback checks pass, including two complete actual ELF modules with 109066 instruction records. All guest/heap/image pages match; inputs come from Python reader/parse/builders. Native vector moves, complete descriptor/root, factory/bootstrap and signer remain unfinished. See the [runtime linking report](REQUEST_JNI_STARTUP_WORKERS.md#648-runtime-descriptor-二次转换与-root-linking2026-10-11-asiashanghai).

`construct_parser_defined_descriptor` now composes decoded builders, native variant moves, name copies and failure cleanup for an empty name filter. 288 native/Python descriptor controls in 48 batches, 113762 runtime instructions and 35 rollback checks pass. Two fresh actual modules contribute 242 functions and 109066 instructions; full guest/heap/image pages, consumed temporary bytes and ordered effects match. Imported descriptors, complete root, factory/bootstrap and signer remain unfinished. See the [defined descriptor report](REQUEST_JNI_STARTUP_WORKERS.md#649-defined-descriptor-构造与失败清理2026-10-11-asiashanghai).

`initialize_builtin_function_catalog` now constructs 73 owned-name function entries in 128 buckets from ELF source references. 32 native/Python catalog controls, 198 name-hash controls and 34 rollback/type guards pass. Ordered effects, owner publication bytes and consumed temporary storage match; decoded names stay private. Imported descriptors, complete root, factory/bootstrap and signer remain unfinished. See the [builtin catalog report](REQUEST_JNI_STARTUP_WORKERS.md#650-builtin-function-catalog-与名称哈希2026-10-11-asiashanghai).

`construct_parser_imported_descriptor` now resolves external and builtin functions, initializes the empty registry and constructs kind-0 descriptors. 106 native/Python controls in 72 batches and 36 rollback checks pass. Two fresh actual modules contribute all 36 function imports using ELF constructor callback references. Full pages, consumed name temporaries and ordered publication effects match. Complete root, factory/bootstrap and signer remain unfinished. See the [defined descriptor report](REQUEST_JNI_STARTUP_WORKERS.md#651-imported-descriptor-解析与构造2026-10-11-asiashanghai).

`construct_parser_root` now composes binding maps, moved global data, imported/defined descriptors, owned name indexes and runtime linking. 62 native/Python root controls and 34 rollback checks pass. Two fresh complete actual modules contribute 278 descriptors and 109066 runtime instructions; each matches 544 allocations, 52 frees and 3 finalizers. Whole pages and consumed root temporaries match. Factory/bootstrap and signer remain unfinished. See the [root report](REQUEST_JNI_STARTUP_WORKERS.md#652-root-构造全局数据搬移与运行时链接2026-10-11-asiashanghai).

`run_module_factory` now composes ELF blob decoding, reader/AST, parser conversion, root linking and both temporary cleanups. 26 native/Python factory controls and 38 rollback checks pass. Each fresh actual module matches 139 descriptors, 54533 instructions, 2330 allocations, 1836 frees and 4 finalizers. Constructor publication, full bootstrap and signer remain unfinished. See the [factory composition report](REQUEST_JNI_STARTUP_WORKERS.md#653-factory-独立组合与两层清理2026-10-11-asiashanghai).

`run_module_constructor` now derives its binding/codec inputs from ELF instructions, invokes the independent factory and publishes all 121 descriptors. Two complete native/Python constructor controls and 22 rollback checks pass, including relocated SP, padding and a fault at the last publication. Full pages, 242 publications and ordered effects match. Full JNI/bootstrap, B VM execution and signer remain unfinished. See the [constructor report](REQUEST_JNI_STARTUP_WORKERS.md#654-构造器输入生成与描述符发布2026-10-11-asiashanghai).

`initialize_runtime_context` and `execute_runtime_descriptor` now cover B context setup and the initialization descriptor with explicit pure imported providers. 48 execution controls, 6 initializer controls and 27 rollback checks pass. Two independently constructed actual descriptors each match 19 dispatches and 2 provider calls, including complete pages, active frames and callback SP. Actual imported bodies, full startup and signer remain unfinished. See the [bounded runtime report](REQUEST_JNI_STARTUP_WORKERS.md#655-b-运行状态与有界描述符执行2026-10-11-asiashanghai).

The existing shared `vm9_startup` callable owner now supports B vtable +35fc28 for move/destruction, including its GOT-derived clone target. 84 native/Python controls and 12 rollback checks pass: 32 B controls and 52 existing A/queue regressions. Full B startup composition and signer remain unfinished. See the [B callable report](REQUEST_JNI_STARTUP_WORKERS.md#656-b-callable-的共享移动与清理2026-10-11-asiashanghai).

The B main-thread startup now executes both actual imported callback bodies through the shared queue owner. 28 native/Python controls and 41 rollback checks pass, including four actual startup controls from two independently constructed ELF modules. Each startup matches 19 dispatches, three deferred thread requests and 22 ordered service effects. B worker execution, full JNI/bootstrap and signer remain unfinished. See the [B startup report](REQUEST_JNI_STARTUP_WORKERS.md#657-b-主线程-startup-与真实导入回调2026-10-11-asiashanghai).

The B executor now supports signed immediate/conditional branch tags and six further fused instructions used by worker callers. 112 runtime controls, four actual startup regressions and 40 rollback checks pass. The 24 actual worker-descriptor controls use explicit pure imported providers; worker callback bodies and nested initializers remain unfinished. See the [B worker runtime report](REQUEST_JNI_STARTUP_WORKERS.md#658-b-worker-的分支与组合指令2026-10-11-asiashanghai).

The B executor now covers the evidenced worker arithmetic with 28 primary tags and 47 fused tags, plus actual CAS64/memset adapters. 310 runtime controls, 30 builtin controls, four startup regressions and 69 rollback checks pass. The 24 actual nested worker descriptor controls execute the real memset callback. Full once/worker composition and signer remain unfinished. See the [B worker arithmetic report](REQUEST_JNI_STARTUP_WORKERS.md#659-b-worker-完整算术与内存内置函数2026-10-11-asiashanghai).

The shared once owner now accepts all six B controls. 60 native/Python controls include 36 B cases and 24 A regressions; 22 rollback checks pass. Actual libc broadcast executes, while the initializer remains an explicit provider boundary in this check. Full B worker and signer remain unfinished. See the [B shared once report](REQUEST_JNI_STARTUP_WORKERS.md#660-b-复用共享-once-状态机2026-10-11-asiashanghai).

The complete B worker callable now composes six outer and 48 nested descriptor programs with the shared once gate and actual CAS64/memset semantics. 18 native/Python controls and 36 rollback checks pass. Each cold task matches 120847 dispatches, six allocations and six wakes from fresh independent ELF inputs. Queue-worker/TLS composition and the full signer remain unfinished. See the [B full callable report](REQUEST_JNI_STARTUP_WORKERS.md#661-b-完整-worker-callable-与嵌套初始化2026-10-11-asiashanghai).

B now runs the actual startup-generated queue task through normal worker return, TLS key cleanup and the full joinable guest pthread_exit body. 12 native/Python controls and 24 rollback checks pass with fresh independent ELF inputs. Main/task contexts, both TLS regions, all nonstack pages and ordered effects match. Full JNI/bootstrap and the independent signer remain unfinished. See the [B queue worker report](REQUEST_JNI_STARTUP_WORKERS.md#662-b-同次-startup-的队列-worker-与清理2026-10-11-asiashanghai).

The module constructor owner now supports all five actual ELF module constructors. Four additional entries pass 8 fresh native/Python controls, with 2 existing B constructor regressions and 77 rollback checks. Complete JNI/bootstrap and the independent signer remain unfinished. See the [module constructor report](REQUEST_JNI_STARTUP_WORKERS.md#663-另外四个-elf-module-constructors2026-10-11-asiashanghai).

Six ELF support constructors now pass 48 fresh native/Python controls and 51 rollback checks. Object and JNI cache initialization reuse existing owners; clocks, auxv, property and exit registration are explicit guest services. Together with five module constructors, 11 of 13 init_array members are covered. The complete loader, JNI/bootstrap and independent signer remain unfinished. See the [ELF support report](REQUEST_JNI_STARTUP_WORKERS.md#664-六个-elf-support-constructors2026-10-11-asiashanghai).

The guarded ELF string constructor now passes 18 fresh native/Python controls and 25 rollback checks; all six existing support entries pass 12 fresh regressions. Twelve of thirteen init_array members are covered. The complete loader, JNI/bootstrap and independent signer remain unfinished. See the [guarded string report](REQUEST_JNI_STARTUP_WORKERS.md#665-elf-guarded-string-constructor2026-10-11-asiashanghai).

The ELF configuration constructor now passes 16 fresh native/Python controls and 72 rollback checks, including actual diagnostic scopes, matching-libc broadcasts and same-run warm calls. Existing registry results remain byte-identical (38 controls/14 guards). All thirteen init_array members have independent implementations; the complete sequential loader, JNI/bootstrap and signer remain unfinished. See the [configuration constructor report](REQUEST_JNI_STARTUP_WORKERS.md#666-elf-configuration-constructor2026-10-11-asiashanghai).

The complete ELF init_array now executes all thirteen constructors in order with one shared allocation plan and passes 4 fresh native/Python controls and 40 rollback checks. Surviving pages and each ordered allocation/free, registration and OS/TLS stream match. Full binary mapping/linking, JNI/bootstrap and the independent signer remain unfinished. See the [constructor sequence report](REQUEST_JNI_STARTUP_WORKERS.md#667-elf-init_array-完整顺序组合2026-10-11-asiashanghai).

The ELF image loader now maps all PT_LOAD/BSS pages and eagerly binds every relocation from program headers and dynamic metadata. Ten independent image controls, two complete native/Python constructor sequences and 42 refusal checks pass, including sectionless and GNU-hash inputs. Full JNI/bootstrap and the independent signer remain unfinished. See the [ELF image report](REQUEST_JNI_STARTUP_WORKERS.md#668-elf-映射与完整符号链接2026-10-11-asiashanghai).

Fresh ELF mapping/linking and all thirteen constructors now compose through complete JNI_OnLoad and one conditional A/B main-thread startup. Four native/Python controls and 38 rollback checks pass; both task queues, 19 JNI calls, four JavaVM calls, three deferred worker requests and all surviving pages match. The finalizer callable adds 32 controls and nine guards; the old 84/12 callable regression is byte-identical. Same-run workers, cleanup and the independent signer remain unfinished. See the [complete JNI report](REQUEST_JNI_STARTUP_WORKERS.md#669-完整-jni-与两条主线程-startup-组合2026-10-11-asiashanghai).

The complete ELF/JNI execution now continues into the executor and actual A/B initialization queue workers, with separate thread TLS and full joinable guest exit. Four native/Python controls and 28 rollback guards pass, including all surviving pages and ordered service groups. The third finalizer queue and independent signer remain unfinished. See the [full JNI worker report](REQUEST_JNI_STARTUP_WORKERS.md#670-完整-jni-后的两条-worker-与-guest-退出清理2026-10-11-asiashanghai).

The first delayed JNI follow-up submission now preserves the native callable, deadline and executor deque, with 8 submission controls, 24 callable controls and 25 rollback guards. Both older callable regression files are byte-identical. The full finalizer worker and independent signer remain unfinished. See the [timed submission report](REQUEST_JNI_STARTUP_WORKERS.md#671-jni-finalizer-的首条延时任务提交2026-10-11-asiashanghai).

The complete JNI execution now runs all three requested workers and full joinable guest exit. Four complete native/Python controls, four actual copied-probe controls and 47 rollback guards pass; all surviving pages and ordered service groups match. Complete timed queue dispatch and the independent signer remain unfinished. See the [complete finalizer report](REQUEST_JNI_STARTUP_WORKERS.md#672-jni-finalizer-完整-worker-与-guest-退出2026-10-11-asiashanghai).

The actual delayed JNI callable now executes both guest image VMs, the unavailable Java object path, configuration publication and owning cleanup. Four fresh complete native/Python controls and 22 page rollback guards pass. Complete timed queue dispatch, live Java string conversion and the independent signer remain unfinished. See the [actual delayed callback report](REQUEST_JNI_STARTUP_WORKERS.md#673-实际延时-jni-callable-与两段-image-vm2026-10-11-asiashanghai).

Actual timed polling now transfers the owned follow-up into the drained queue and frees its wrapper/task. Four fresh complete native/Python controls, 20 page rollback guards and shared callable regressions pass. The complete executor worker wait cycle, live Java string conversion and independent signer remain unfinished. See the [timed transfer report](REQUEST_JNI_STARTUP_WORKERS.md#674-实际-timed-poll转交与-queue-清理2026-10-11-asiashanghai).

The three requested workers now cooperate across six actual waits, transfer the timed follow-up and exit in order 1, 2, 0. Four fresh complete native/Python controls and 23 page rollback guards pass; the shared executor and queue regressions are byte identical. Live Java string conversion and the independent signer remain unfinished. See the [cooperative worker report](REQUEST_JNI_STARTUP_WORKERS.md#675-三条-worker-协作等待转交与完整退出2026-10-11-asiashanghai).

The Java byte array helper now preserves binary data through the original sized-string and diagnostic-reference path. Fifty-two native/Python controls and 19 page rollback guards pass. Actual live lookup, the independent signer, fresh signature output and the online matrix remain unfinished. See the [byte array report](REQUEST_JNI_STARTUP_WORKERS.md#676-java-byte-array-转引用与实际诊断锁2026-10-11-asiashanghai).

JNI reference field access, no-argument object methods and local/global/weak cleanup now pass 74 native/Python controls and 18 page rollback guards. Actual Python live lookup, the independent signer, fresh output and the online matrix remain unfinished. See the [JNI reference member report](REQUEST_JNI_STARTUP_WORKERS.md#677-jni-引用字段无参数方法与引用清理2026-10-11-asiashanghai).

Actual diagnostic string reference scopes and the MD5 temporary reference lifecycle pass 80 native/Python controls and 16 rollback guards. The original digest regression matches its accepted result. Actual Python live lookup and the complete signer remain unfinished. See the [reference scope report](REQUEST_JNI_STARTUP_WORKERS.md#678-实际-reference-作用域与-md5-生命周期2026-10-11-asiashanghai).

Initialized live Java lookup passes 48 native/Python controls and 11 rollback guards across both SDK paths. Binary MD5 output, local cleanup, scope bytes and ordered services match. Cold initialization, live worker wiring and the complete signer remain unfinished. See the [live lookup report](REQUEST_JNI_STARTUP_WORKERS.md#679-已初始化对象的实际-live-java-lookup2026-10-11-asiashanghai).

Cold encoded SDK lookup now passes 52 getter controls and 9 rollback guards; its initialized Java lookup composition passes another 10 controls and 4 guards. Encoded and plain caches remain independent and share decimal conversion. Cold live initialization, worker wiring and the complete signer remain unfinished. See the [cold SDK report](REQUEST_JNI_STARTUP_WORKERS.md#680-cold-encoded-sdk-getter-与实际-live-lookup2026-10-11-asiashanghai).

Integer/reference argument JNI instance and static methods, void and integer/reference returns, and non-FP static fields pass 140 native/Python controls and 11 rollback guards. Consumed va_list arguments, native return widths, exception order and the legacy reference subset match. Cold initializer composition, worker wiring and the complete signer remain unfinished. See the [integer JNI report](REQUEST_JNI_STARTUP_WORKERS.md#681-带整型引用参数的-jni-方法与静态字段2026-10-11-asiashanghai).

Actual UTF construction and Java service lookup pass 42 native/Python controls and 9 rollback guards. Short/heap C++ strings, exception clearing, returned references and local cleanup match. Service lookup requires a live default Java object. Initializer composition, worker wiring and the complete signer remain unfinished. See the [Java service report](REQUEST_JNI_STARTUP_WORKERS.md#682-实际-utf-构造与-java-service-查找2026-10-12-asiashanghai).

Actual live receiver initialization and cold lookup pass 92 native/Python controls and 6 rollback guards. SDK branches, once flags, published global references, Parcel/local cleanup and complete binary MD5 lookup match. VM/worker provider wiring and the complete signer remain unfinished. See the [live initializer report](REQUEST_JNI_STARTUP_WORKERS.md#683-实际-live-initializer-与-cold-lookup2026-10-12-asiashanghai).

Delayed VM and callable entries forward explicit live JNI, allocator and SDK providers. Four evaluator and two complete callable native/Python controls, two bounded worker entry checks and sixteen rollback guards pass. Live lookup now preserves the output-reference stack padding used by a later registry setter. The complete signer remains unfinished. See the [live provider report](REQUEST_JNI_STARTUP_WORKERS.md#684-delayed-vmcallableworker-的-live-provider-接线2026-10-12-asiashanghai).

The actual request stack evaluator now restores JNI calls, prefix comparisons, UTF/local cleanup and NULL/exception behavior. 78 native/Python controls, one bounded request VM entry check and 20 rollback guards pass. The request entry forwards explicit JNI and singleton services and reaches the next scope-cleanup boundary at 965 steps. The complete signer remains unfinished. See the [stack evaluator report](REQUEST_JNI_STARTUP_WORKERS.md#685-实际-request-stack-evaluator-与请求-vm-接线2026-10-12-asiashanghai).

Actual boolean scope cleanup now records elapsed time, fetches/increments the counter and emits the sampled two-argument event. 46 native/Python controls, one bounded request VM entry check and 28 rollback guards pass. The owning request continues to 993 steps and reaches the publication callback boundary. The complete signer remains unfinished. See the [scope cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#686-实际-boolean-scope-清理与-elapsed-event2026-10-12-asiashanghai).

The actual JNI publisher now acquires the environment, dispatches both tags and cleans both references. The distinct request byte gate resolves to the original zero-return leaf at +28BB54; it has no JNI effects. 44 native/Python controls, one request VM entry check and 20 rollback guards pass. The public request reaches 1019 steps and stops at object construction +25CDD4. The complete signer remains unfinished. See the [publication and byte gate report](REQUEST_JNI_STARTUP_WORKERS.md#687-实际-jni-发布器与请求-byte-gate2026-10-12-asiashanghai).

Actual request object construction now clones the input string, copies the shared reference, stores realtime milliseconds and releases the temporary reference to one surviving owner. 60 native/Python controls, one request VM entry check and 34 rollback guards pass. The public request reaches 1419 steps and stops at callback +256AB0. The complete signer remains unfinished. See the [request object report](REQUEST_JNI_STARTUP_WORKERS.md#688-实际请求对象构造与临时引用生命周期2026-10-12-asiashanghai).

The actual registry counter now performs scoped lookup, signed saturation or cloned-key insertion and returns the old u32. 40 native/Python controls, one request VM entry check and 36 rollback guards pass. The request uses its owning TLS/registry/broadcast services, reaches 1444 steps and stops at tree construction +25BF14. The complete signer remains unfinished. See the [registry counter report](REQUEST_JNI_STARTUP_WORKERS.md#689-实际-registry-计数回调与拥有者-tls-接线2026-10-12-asiashanghai).

The request now reuses the actual tree constructor and restores begin/end iterator pairs and node/table comparison. 24 native/Python controls, one request VM entry check and 13 rollback guards pass. Its independently constructed empty header input reaches 1539 steps, where the unresolved __cxa_atexit import is rejected. The complete signer remains unfinished. See the [tree and iterator report](REQUEST_JNI_STARTUP_WORKERS.md#690-实际请求树构造与-iterator-abi2026-10-12-asiashanghai).

The actual __cxa_atexit import and process registration wrapper now pass 16 native/Python controls, one request VM entry check and 17 rollback guards. The owning request reaches 1558 steps at the fill-string constructor. Real libc exit tables and destructor execution remain unverified; the complete signer remains unfinished. See the [process registration report](REQUEST_JNI_STARTUP_WORKERS.md#691-实际进程析构导入与注册2026-10-12-asiashanghai).

The actual fill-string constructor and byte-argument wrapper pass 40 native/Python controls, one request VM entry check and 20 rollback guards. The owning request reaches 1567 steps at the tree lookup wrapper. The complete signer remains unfinished. See the [fill-string report](REQUEST_JNI_STARTUP_WORKERS.md#692-实际填充字符串构造与-wrapper-字节参数2026-10-12-asiashanghai).

The actual tree lookup and NULL-safe C-string length wrappers reuse existing owners. 28 native/Python controls, one request VM entry check and 20 rollback guards pass. The owning request reaches 1812 steps at the guest-table folded comparison; the complete signer remains unfinished. See the [collection wrapper report](REQUEST_JNI_STARTUP_WORKERS.md#693-实际树查询与-c-字符串长度-wrapper2026-10-12-asiashanghai).

Guest-table folded comparison and its actual wrapper pass 48 native/Python controls, one request VM entry check and 26 rollback guards. Both real warm singleton getter SPs, scratch and order match. The owning request reaches 1995 steps at tree count; the complete signer remains unfinished. See the [folded comparison report](REQUEST_JNI_STARTUP_WORKERS.md#694-实际-guest-table-折叠比较与-singleton-接线2026-10-12-asiashanghai).

Request tree count, string-value replacement, iterator pairs, clone and advance pass 128 native/Python controls, one request VM entry check and 40 rollback guards. The actual owning request reaches 2321 steps at local tree destruction under a finite 4000-step budget. The complete signer remains unfinished. See the [tree traversal report](REQUEST_JNI_STARTUP_WORKERS.md#695-请求树计数与-value-清理和-iterator-遍历2026-10-12-asiashanghai).

Local request tree destruction passes 32 native/Python controls, one request VM entry check and 27 rollback guards. The owning request reaches 2329 steps at request object destruction. The complete signer remains unfinished. See the [local tree destructor report](REQUEST_JNI_STARTUP_WORKERS.md#696-请求局部树析构2026-10-12-asiashanghai).

Request object cleanup, final free and deleting tree destruction pass 78 native/Python controls, one request VM entry check and 36 rollback guards. With empty headers and NULL FindClass services, the owning request VM returns in 2475 steps after 105 callbacks. Native caller return ABI and the complete signer remain unfinished. See the [cleanup and VM return report](REQUEST_JNI_STARTUP_WORKERS.md#697-请求对象与树删除清理和-vm-返回2026-10-12-asiashanghai).

Actual scoped request tree construction passes 24 native/Python controls, one request VM entry and 31 rollback guards. Descriptor visibility, logical scopes and allocation order match; the request still returns in 2475 steps after 105 callbacks. Complete signing remains unfinished. See the [scoped tree report](REQUEST_JNI_STARTUP_WORKERS.md#698-请求-scoped-tree-reference-构造2026-10-12-asiashanghai).

VM opcode 36 loads the full word and opcode 57 performs a serialized compare/store using hidden slot 34. 114 native/Python controls, one request entry and 21 rejection/rollback checks pass. The remaining main ELF byte difference in the private request probe is resolved; full signing remains unfinished. See the [VM load/store report](REQUEST_JNI_STARTUP_WORKERS.md#699-vm-load-与串行-comparestore2026-10-12-asiashanghai).

Request caller return now checks the stack canary and restores PC/SP/X19/X28/X29/X30 with the physical X0 callback sentinel. 16 native controls, one request entry and 26 rejections pass: 25 preserve all pages; the canary entry preserves existing bytes but leaves 64 allocator mapping pages. Full signing remains unfinished. See the [caller return report](REQUEST_JNI_STARTUP_WORKERS.md#6100-request-caller-物理返回2026-10-12-asiashanghai).

NULL raw cleanup now skips the provider free call: 16 new native controls and six rollback checks pass. The constructed request chain also matches 105 effective packed inputs, 10 explicit service calls and the physical caller return; remaining measured RAM differences are scoped token/short-string padding. Actual request conversion and complete signing remain unfinished. See the [raw cleanup and effective fields report](REQUEST_JNI_STARTUP_WORKERS.md#6101-null-raw-cleanup-与整链有效字段2026-10-12-asiashanghai).

Request ASCII upper/lower conversion and the receiver byte flag now pass 92 new native controls and eight rollback checks. A constructed URL and one-header prefix advances to 2174 steps; byte search and actual JNI conversion remain open. Complete signing remains unfinished. See the [ASCII and receiver flag report](REQUEST_JNI_STARTUP_WORKERS.md#6102-ascii-case-与-request-byte-flag2026-10-12-asiashanghai).

Request byte search now passes 80 new native controls, 12 rollback checks and eight scan bound checks. The constructed nonempty prefix advances to 2224 steps; sized-string dispatch, actual JNI conversion and complete signing remain unfinished. See the [byte search report](REQUEST_JNI_STARTUP_WORKERS.md#6103-request-byte-search2026-10-12-asiashanghai).

Request sized-string dispatch now passes 18 new native wrapper controls and ten rollback checks using the existing owner. The constructed nonempty prefix advances to 2243 steps; rejection preserves original bytes but retains 64 new allocator OS pages. Binary equality, actual JNI conversion and complete signing remain unfinished. See the [sized dispatch report](REQUEST_JNI_STARTUP_WORKERS.md#6104-request-sized-string-dispatch2026-10-12-asiashanghai).

Request binary equality now passes 48 new native controls and eight rollback checks, including 16 comparisons using the actual matching-libc memcmp body. Native short circuits now precede skipped fields and payload bounds. The constructed nonempty prefix advances to 2395 steps; substring construction and complete signing remain unfinished. See the [binary equality report](REQUEST_JNI_STARTUP_WORKERS.md#6105-request-binary-equality2026-10-12-asiashanghai).

A new constructed nonempty request prefix now matches the original caller and interpreter across 98 callback paths, packed addresses and effective packed inputs. Native stops before the substring body; pointed payloads, full heap/stack equivalence, actual JNI conversion and complete signing remain unfinished. See the [nonempty effective ABI report](REQUEST_JNI_STARTUP_WORKERS.md#6106-constructed-nonempty-request-effective-abi2026-10-12-asiashanghai).

Field clone and X8 substring construction now pass 74 new native controls and 20 rollback checks. Wrapped signed substring arithmetic, allocation failures and modeled scratch aliases match. The constructed nonempty prefix advances to 2510 steps; the next temporary-string composition, actual JNI conversion and complete signing remain unfinished. See the [substring report](REQUEST_JNI_STARTUP_WORKERS.md#6107-field-clone-与-substring2026-10-12-asiashanghai).

CString plus StringObject composition and temporary cleanup now pass 84 new native controls and 28 rollback checks. Allocation failures, declared binary tails and modeled temporary aliases match, including pre-free bytes. The constructed nonempty prefix advances to 2520 steps; StringObject plus CString construction, actual JNI conversion and complete signing remain unfinished. See the [composition report](REQUEST_JNI_STARTUP_WORKERS.md#6108-cstringstringobject-拼接2026-10-12-asiashanghai).

StringObject clone plus CString append construction now passes 68 new native controls and 24 rollback checks, including 12 new long-first realloc controls. Native X0, live aliases and partial reserve failures match. The constructed nonempty entry remains at 2520 steps and now stops inside this callback at the unrecovered matching-libc realloc boundary. Actual JNI conversion and complete signing remain unfinished. See the [object and CString report](REQUEST_JNI_STARTUP_WORKERS.md#6109-stringobjectcstring-构造2026-10-12-asiashanghai).

Matching-libc same small-bin realloc now passes 18 new original-instruction controls and 28 rollback checks. It retains the pointer and usable buffer while updating both TSD byte counters with uint64 wrapping. Cross-bin and NULL/zero realloc remain unfinished. The constructed nonempty prefix advances to 2538 steps; the next StringObject search callback, actual JNI conversion and complete signing remain unfinished. See the [same-bin realloc report](REQUEST_JNI_STARTUP_WORKERS.md#6110-matching-libc-同类别-realloc2026-10-12-asiashanghai).

Declared StringObject ASCII case-insensitive search now passes 72 new native controls and 20 rollback checks. Binary tails, native short circuits and the same-pointer fast path match; bounds count actual byte comparisons. The constructed nonempty prefix advances to 2590 steps; the next CString-pattern search, actual JNI conversion and complete signing remain unfinished. See the [casefold search report](REQUEST_JNI_STARTUP_WORKERS.md#6111-stringobject-ascii-casefold-搜索2026-10-12-asiashanghai).

CString-pattern search now passes 76 new native controls and 24 rollback checks. Native paired scans, contiguous-hit checks, unsigned prechecks and signed offsets match. The constructed nonempty prefix advances to 2761 steps and now stops at VM op17 sub53. Actual JNI conversion and complete signing remain unfinished. See the [CString search report](REQUEST_JNI_STARTUP_WORKERS.md#6112-cstring-pattern-搜索2026-10-12-asiashanghai).

VM signed 64-bit multiplication and hidden low-product transfer now pass 238 new native/Python controls from 220 original interpreter executions. Both full-width product halves and register backing match. The constructed nonempty prefix advances to 2850 steps; actual JNI conversion and complete signing remain unfinished. See the [signed product report](REQUEST_JNI_STARTUP_WORKERS.md#6113-vm-signed-product-与-low-copy2026-10-12-asiashanghai).

State numeric member lookup now passes 60 new native/Python controls and 18 rollback checks. Original nested shared readers and matching-libc mutex calls match, including ASCII keys and ARM64 floating-point conversion. This dependency is ready; the request state callback and its lazy service remain unfinished at the 2850-step boundary. See the [state numeric report](REQUEST_JNI_STARTUP_WORKERS.md#6114-state-numeric-member-读取2026-10-12-asiashanghai).

Lazy state service composition now passes eight fresh native/Python controls and seven rollback checks with an explicitly initialized singleton136. Cold allocation/free/registration/wake order, all ELF pages and TLS bytes match. The request state callback remains the next boundary at 2850 steps. See the [state service report](REQUEST_JNI_STARTUP_WORKERS.md#6115-lazy-state-service2026-10-12-asiashanghai).

Actual request state construction now passes 16 new native wrapper controls and seven rollback checks. Signed defaults, reference counts, TLS padding and writer cleanup match. The constructed nonempty prefix advances to 2911 steps and reaches the elapsed-time getter; complete signing remains unfinished. See the [request state report](REQUEST_JNI_STARTUP_WORKERS.md#6116-request-state-构造与清理2026-10-12-asiashanghai).

Actual request elapsed seconds now pass 36 new native wrapper controls and 12 rollback checks. Saved-start read order, wrapped signed selection, unsigned division and reader cleanup match. The constructed nonempty prefix advances to 3167 steps; complete signing remains unfinished. See the [request elapsed report](REQUEST_JNI_STARTUP_WORKERS.md#6117-request-elapsed-seconds2026-10-12-asiashanghai).

Actual request contained-reference copy and StringObject table hash64 now pass 84 new native wrapper controls and six rollback checks. Scoped ownership, hidden output, signed lengths, guest table and full-width hash results match. The constructed nonempty prefix advances to 3257 steps; complete signing remains unfinished. See the [request reference/hash report](REQUEST_JNI_STARTUP_WORKERS.md#6119-request-stringobject-table-hash642026-10-12-asiashanghai).

Actual request TLS uint32 getter and setter now pass 34 new native wrapper controls. Cold/warm libc TLS, high uint32 values, packed padding and allocation/wake order match. The constructed nonempty prefix advances to 3307 steps; complete signing remains unfinished. See the [request TLS report](REQUEST_JNI_STARTUP_WORKERS.md#6120-request-tls-uint32-读写2026-10-12-asiashanghai).

The actual request binary-transform component now passes 24 new native controls and ten rollback checks with an initialized SDK input. Allocation-dependent key bytes, S-box writes and forward mixing match. The outer transform caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [request transform report](REQUEST_JNI_STARTUP_WORKERS.md#6121-request-binary-transform2026-10-12-asiashanghai).

The actual request hexadecimal-reference helper now passes 20 new native controls and eight rollback checks. Guest alphabet, live nibble reads and scoped ownership match. The outer transform caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [hex reference report](REQUEST_JNI_STARTUP_WORKERS.md#6122-request-hexadecimal-reference2026-10-12-asiashanghai).

Raw MD5 and scoped reference assignments now pass 54 new native controls and 12 rollback checks. Digest scratch, scope overlap, alias order and ownership match. The outer transform caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [raw MD5 report](REQUEST_JNI_STARTUP_WORKERS.md#6123-request-raw-md5-and-reference-assignment2026-10-12-asiashanghai).

The request version initializer/getter now passes 40 new native controls and ten rollback checks. Packed version, separate initializer status, encoded-table reloads and cached guard paths match. The outer caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [version report](REQUEST_JNI_STARTUP_WORKERS.md#6124-request-version-word2026-10-13-asiashanghai).

The request allocated printf helper now passes 36 new native controls and nine rollback checks. Both live format passes, truncation, pointer publication and allocator effects match. The outer caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [allocated printf report](REQUEST_JNI_STARTUP_WORKERS.md#6125-request-allocated-printf2026-10-13-asiashanghai).

The outer request suffix now passes 26 new native controls and nine rollback checks; the raw-free wrapper adds six controls and two guards. Existing owners compose both output C strings and cleanup. The independently constructed nonempty entry advances from 3307 to 3405 steps, next at +287168. Full JNI, whole-request native comparison and complete signing remain unfinished. See the [outer suffix report](REQUEST_JNI_STARTUP_WORKERS.md#6126-request-outer-suffix-and-raw-free2026-10-13-asiashanghai).

Request metadata formatting and unsigned decimal now pass 46 new native controls and 12 rollback checks. Both output strings, cached input words and actual source callback match. The independently constructed nonempty entry advances to 3520 steps, next at +258d6c. Full JNI, whole-request native comparison and complete signing remain unfinished. See the [metadata report](REQUEST_JNI_STARTUP_WORKERS.md#6127-request-metadata-formatting2026-10-13-asiashanghai).

The raw Base64 encoder, two-pass StringObject composition and actual source callback now pass 68 new native controls and 10 rollback checks. Guest alphabet aliases, capacity/NUL rules, scratch and cleanup match. The independently constructed nonempty entry advances to 3538 steps, next at +2482ec. Full JNI, whole-request comparison and complete signing remain unfinished. See the [Base64 encoder report](REQUEST_JNI_STARTUP_WORKERS.md#6128-request-base64-encoder2026-10-13-asiashanghai).

The single-byte StringObject constructor and actual source callback now pass 30 new native controls and seven rollback checks. Live ELF fields, allocation publication and buffer/object aliases match. The independently constructed nonempty entry advances to 3550 steps, next at +248ef8. Full JNI, whole-request comparison and complete signing remain unfinished. See the [character report](REQUEST_JNI_STARTUP_WORKERS.md#6129-request-character-string2026-10-13-asiashanghai).

Reverse character-set search, right trim and the actual source callback now pass 64 new native controls and nine rollback checks. Bitmap aliases, signed index, length/NUL and canary match. The independently constructed nonempty entry advances to 3559 steps, next at +248eb4. Full JNI, whole-request comparison and complete signing remain unfinished. See the [right-set report](REQUEST_JNI_STARTUP_WORKERS.md#6130-request-right-character-set-trim2026-10-13-asiashanghai).

Forward character-set search, field erase, left trim and actual source callback now pass 94 new native controls and 11 rollback checks. Shared reverse-search bitmap semantics remain unchanged by expansion AST comparison. The independently constructed nonempty entry advances to 3767 steps, next at +287500. Full JNI, whole-request comparison and complete signing remain unfinished. See the [left-set report](REQUEST_JNI_STARTUP_WORKERS.md#6131-request-left-character-set-trim2026-10-13-asiashanghai).

The +287500 nested caller and its first two constant callbacks pass 20 new native controls and eight rollback checks. Its prefix reaches 179 steps, next at +26cc8c. Outer request integration and complete signing remain unfinished. See the [token VM report](REQUEST_JNI_STARTUP_WORKERS.md#6132-request-token-vm-caller-and-prefix2026-10-13-asiashanghai).

Matching-libc random state, seeding, serialized wrappers, the request getter and its actual consumer pass 98 new native controls and 15 rollback checks. gettimeofday is an explicit virtual service. The corrected random guard is +3dedb0. Nested integration and complete signing remain unfinished. See the [random report](REQUEST_JNI_STARTUP_WORKERS.md#6133-request-random-state-and-getter2026-10-13-asiashanghai).

The nested random callback and its actual outer consumer are now connected. Twelve new native controls and five rollback checks pass. Fresh nested fixtures reach 191 steps; the independently constructed owning entry reaches 158 nested steps, both next at +32a444. Complete nested return and signing remain unfinished. See the [nested random report](REQUEST_JNI_STARTUP_WORKERS.md#6134-request-nested-random-continuation2026-10-13-asiashanghai).

Actual nested shared-reader consumers now reuse the accepted reader owners. Twenty-eight new native controls and seven rollback checks pass. Fresh fixtures reach 211 nested steps; the independently constructed owning entry reaches 178, next at +26c858 diagnostic scope. Complete nested return and signing remain unfinished. See the [nested readers report](REQUEST_JNI_STARTUP_WORKERS.md#6135-request-nested-shared-readers2026-10-13-asiashanghai).

Actual nested diagnostic enter/leave consumers now reuse the accepted scope owners. Sixteen new native controls and five rollback checks pass. The independently constructed owning entry reaches 231 nested steps, next at +2483e0 StringObject clone. Whole nested-prefix comparison, full physical ABI and complete signing remain unfinished. See the [nested scopes report](REQUEST_JNI_STARTUP_WORKERS.md#6136-request-nested-diagnostic-scopes2026-10-13-asiashanghai).

Actual nested clone, default, free, destroy and delete consumers reuse accepted owners. Thirty-six new native controls and eight rollback checks pass. The independently constructed owning entry reaches 287 nested steps, next at +248908 formatting. Complete nested return and signing remain unfinished. See the [nested lifecycle report](REQUEST_JNI_STARTUP_WORKERS.md#6137-request-nested-string-lifecycle2026-10-13-asiashanghai).

Actual nested format, sized and StringObject pair consumers now reuse accepted owners. Forty-six new native controls and ten rollback checks pass, including matching-libc vsnprintf. The independently constructed owning entry reaches 321 steps, next at MD5 reference construction. Whole nested return and complete signing remain unfinished. See the [nested strings report](REQUEST_JNI_STARTUP_WORKERS.md#6138-request-nested-string-transforms2026-10-13-asiashanghai).

The actual nested MD5 consumer now reuses the accepted scoped reference lifecycle. Thirty-two new native controls and eight rollback checks pass with matching-libc recursive mutexes. The independently constructed owning entry reaches 422 steps, next at the obfuscated +287580 helper. Whole nested return and signing remain unfinished. See the [nested MD5 report](REQUEST_JNI_STARTUP_WORKERS.md#6139-request-nested-scoped-md52026-10-13-asiashanghai).

The request round schedule and block helpers now pass 32 new native controls and eight rollback checks. Encoded helper slots resolve from guest ELF, and block computation reuses the bytecode-bound Helios owner. The +287580 caller remains unfinished; the accepted owning boundary stays at 422 steps. See the [round/block report](REQUEST_JNI_STARTUP_WORKERS.md#6140-request-round-schedule-and-block-helpers2026-10-13-asiashanghai).

Allocated and StringObject cipher callers now pass 48 new native controls and ten rollback checks, including the actual +288BDC consumer. The owning entry reaches an unrecovered matching-libc cross-bin realloc from 32 to 64 bytes at nested step 422. Complete nested return and signing remain unfinished. See the [cipher caller report](REQUEST_JNI_STARTUP_WORKERS.md#6141-request-allocated-and-string-cipher-callers2026-10-13-asiashanghai).

Matching-libc small cross-bin realloc now passes 18 new native controls and nine rollback checks. The owning session composes actual allocation, live copy and free while preserving the same-bin owner. The independently constructed owning entry advances to430 nested steps, next at StringObject append. Complete signing remains unfinished. See the [cross-bin report](REQUEST_JNI_STARTUP_WORKERS.md#6142-matching-libc-cross-bin-small-realloc2026-10-13-asiashanghai).

Actual nested append and scoped Base64 reference consumers pass 34 new native controls and eight rollback checks, including live source mutations and matching-libc recursive mutexes. The independently constructed owning entry reaches505 nested steps, next at allocated printf. Complete signing remains unfinished. See the [append/Base64 report](REQUEST_JNI_STARTUP_WORKERS.md#6143-request-nested-append-and-base64-reference2026-10-13-asiashanghai).

Actual nested allocated printf passes 36 new native controls and ten rollback checks. W0 publication preserves packed padding and live inputs across malloc. The independently constructed owning entry reaches574 steps at the nested return instruction after cleanup. Complete signing remains unfinished. See the [nested printf report](REQUEST_JNI_STARTUP_WORKERS.md#6144-request-nested-allocated-printf2026-10-13-asiashanghai).

Nested caller return passes 32 new native controls and ten rollback checks, plus five constructed entry checks. Explicit continuation returns after40 nested callbacks and advances the owning outer request to3879 steps, next at the URL condition callback. Whole nested/request native equivalence and complete signing remain unfinished. See the [nested return report](REQUEST_JNI_STARTUP_WORKERS.md#6145-request-nested-caller-return2026-10-13-asiashanghai).

Actual URL condition passes 40 new native controls and seven rollback checks. Three lazy constants and ordered searches preserve the disabled URL shortcut and one-byte packed result. The constructed owning request reaches3900 steps, next at +287474. Whole request equivalence and complete signing remain unfinished. See the [URL condition report](REQUEST_JNI_STARTUP_WORKERS.md#6146-request-url-condition2026-10-13-asiashanghai).

The second request VM caller and bounded prefix pass 20 new native controls and eight rollback checks. All32 prelude/backing words and the first three decode consumers match. The constructed owning input reaches617 steps, next at default StringObject construction. Complete second VM return and signing remain unfinished. See the [second VM report](REQUEST_JNI_STARTUP_WORKERS.md#6147-request-second-vm-caller-and-prefix2026-10-13-asiashanghai).

Second VM consumers pass 153 new native controls, twelve rollback checks and five Python entry rejections. The owning bounded second VM advances to8184 steps; its32 virtual registers, callback ledger and declared memory ranges match original native code. The next child is +28048c; complete request and signing remain unfinished. See the [second consumer report](REQUEST_JNI_STARTUP_WORKERS.md#6148-request-second-vm-consumers2026-10-13-asiashanghai).

The child VM caller, hidden-X8 wrapper and first decode pass26 new native controls and ten rollback checks. The owning child reaches290 steps, next at filled StringObject construction. Complete child/request, JNI and signing remain unfinished. See the [child VM report](REQUEST_JNI_STARTUP_WORKERS.md#6149-request-child-vm-caller-and-prefix2026-10-13-asiashanghai).

Child VM consumers pass83 new native controls,13 rollback checks and five Python entry rejection checks. Its owning bounded prefix reaches19295 steps; all32 virtual registers, the callback ledger and16 declared memory ranges match original native. The next boundary is the204e50 nested helper. Complete child/request, JNI and signing remain unfinished. See the [child consumers report](REQUEST_JNI_STARTUP_WORKERS.md#6150-request-child-vm-consumers2026-10-13-asiashanghai).

Environment helper callers and decoder prefixes pass33 new native controls and11 rollback checks. The owning204e50 helper reaches134 steps at actual environment acquisition; all32 virtual registers, the complete callback ledger and five declared memory ranges match original native. Complete helpers/request, JNI and signing remain unfinished. See the [environment helper report](REQUEST_JNI_STARTUP_WORKERS.md#6151-request-environment-helper-vm-callers-and-prefixes2026-10-14-asiashanghai).

The actual environment acquisition callback passes17 new native controls, six rollback checks and three Python entry rejection checks. The owning helper reaches214 steps at StringObject construction; all32 virtual registers, the callback ledger and nine declared memory ranges match original native with the existing GetEnv provider. Complete request/JNI conversion and signing remain unfinished. See the [environment acquisition report](REQUEST_JNI_STARTUP_WORKERS.md#6152-request-environment-acquisition-callback2026-10-14-asiashanghai).

Actual environment StringObject callbacks pass39 new native controls, nine rollback checks and three Python entry rejections. The owning helper reaches226 steps before logging, with all32 virtual registers, its callback ledger and eleven declared memory ranges matching original native. Cleanup is verified separately; full request conversion and signing remain unfinished. See the [environment StringObject report](REQUEST_JNI_STARTUP_WORKERS.md#6153-request-environment-stringobject-callbacks2026-10-14-asiashanghai).

The actual environment logger passes13 new native controls, nine rollback checks and three Python entry rejections. The owning helper executes logging and cleanup through262 steps to its VM exit boundary; all32 virtual registers, the complete callback ledger and fourteen declared ranges match original native. Helper caller return and full signing remain unfinished. See the [environment logger report](REQUEST_JNI_STARTUP_WORKERS.md#6154-request-environment-logger-and-cleanup2026-10-14-asiashanghai).

Environment helper returns pass53 new native controls, eight rollback checks and four Python entry rejections. The owning +204e50 helper returns with matching physical values and packed bytes; its child reaches19302 steps before the +204b80 JNI helper. Complete request conversion and signing remain unfinished. See the [environment return report](REQUEST_JNI_STARTUP_WORKERS.md#6155-request-environment-helper-return2026-10-15-asiashanghai).

JNI availability passes32 new native controls and ten rollback checks. Actual +204b80 semantics now share one owner with the finalizer, preserving raw cache bytes, real environment acquisition and exception behavior. The child wrapper remains to be connected; complete signing remains unfinished. See the [availability report](REQUEST_JNI_STARTUP_WORKERS.md#6156-jni-static-method-availability2026-10-15-asiashanghai).

The actual JNI availability wrapper passes26 new native controls and nine rollback checks. Ten physical return values, declared frame bytes and packed W result match, including saved-register aliases. A constructed request now has an explicit initialization contract; child callback wiring and complete signing remain unfinished. See the [wrapper report](REQUEST_JNI_STARTUP_WORKERS.md#6157-jni-availability-wrapper2026-10-15-asiashanghai).

Child JNI availability wiring passes one new owning native callback and six request/child entry refusals. The initialized +204b80 callback returns1; the constructed child reaches19470 steps before +2814e4 environment acquisition. Complete child/request execution and signing remain unfinished. See the [child callback report](REQUEST_JNI_STARTUP_WORKERS.md#6158-child-jni-availability-callback2026-10-15-asiashanghai).

Child environment acquisition passes17 new native controls. The actual +2814e4 tail wrapper reuses the established owner at unchanged SP; the constructed child reaches19533 steps before +28155c string construction. Complete child/request execution and signing remain unfinished. See the [child environment report](REQUEST_JNI_STARTUP_WORKERS.md#6159-child-environment-acquisition2026-10-15-asiashanghai).

Child StringObject construction passes23 new native controls and eight rollback checks. The owning +28155c callback executes original matching-libc malloc and matches1186 declared ranges. The constructed child reaches19541 steps before +256a18 configuration lookup; complete execution and signing remain unfinished. See the [child strings report](REQUEST_JNI_STARTUP_WORKERS.md#6160-child-stringobject-construction2026-10-15-asiashanghai).

Child configuration u32 reading passes41 new native controls and12 rollback checks. The +256a18 getter uses existing shared-reader and tree owners;524 owning native instructions match1186 declared ranges and four mutex transitions. The child reaches19549 steps before StringObject destruction; full signing remains unfinished. See the [child registry read report](REQUEST_JNI_STARTUP_WORKERS.md#6161-child-configuration-u32-read2026-10-15-asiashanghai).

Child StringObject cleanup passes17 new native controls and7 rollback checks. The owning destructor executes152 original instructions and one matching-libc free with1186 declared ranges equal. The child observes VM exit at19566 steps; its physical caller/wrapper return and complete signing remain unfinished. See the [child cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#6162-child-stringobject-cleanup-and-vm-exit2026-10-15-asiashanghai).

Child physical caller/wrapper return passes23 new native controls and16 rollback checks. The owning return matches1184 declared ranges and seven physical values. The child resumes its parent, advancing the second VM to8251 steps before string construction; complete signing remains unfinished. See the [child return report](REQUEST_JNI_STARTUP_WORKERS.md#6163-child-physical-caller-and-wrapper-return2026-10-15-asiashanghai).

Second VM StringObject construction passes23 new native controls and8 rollback checks. The owning constructor executes155 original instructions and one matching-libc malloc, with1186 declared ranges equal. The second VM reaches8261 steps before shared-reader acquisition, preserving the child return; complete signing remains unfinished. See the [second strings report](REQUEST_JNI_STARTUP_WORKERS.md#6164-second-vm-stringobject-construction2026-10-15-asiashanghai).

Second VM shared-reader acquisition passes19 new native controls and11 rollback checks. The owning callback matches1185 declared ranges and two actual mutex transitions in94 instructions. The second VM reaches8279 steps before diagnostic scope entry; complete signing remains unfinished. See the [second reader report](REQUEST_JNI_STARTUP_WORKERS.md#6165-second-vm-shared-reader-acquisition2026-10-15-asiashanghai).

Second VM diagnostic scope entry passes13 new native controls and7 rollback checks. The owning warm scope matches1185 declared ranges and actual recursive-mutex events in110 instructions, with no allocation. The second VM reaches8298 steps before scope cleanup; complete signing remains unfinished. See the [second diagnostic report](REQUEST_JNI_STARTUP_WORKERS.md#6166-second-vm-diagnostic-scope-entry2026-10-15-asiashanghai).

Second VM diagnostic scope cleanup passes21 new native controls and9 rollback checks. The owning cleanup matches1185 declared ranges and actual recursive-mutex events in53 instructions. The second VM reaches8309 steps before shared-reader release; complete signing remains unfinished. See the [second diagnostic cleanup report](REQUEST_JNI_STARTUP_WORKERS.md#6167-second-vm-diagnostic-scope-cleanup2026-10-15-asiashanghai).

Second VM shared-reader release passes19 new native controls and12 rollback checks. The owning release matches1185 declared ranges and two actual mutex operations in83 instructions. The second VM reaches8355 steps before string/C-string comparison; complete signing remains unfinished. See the [second reader release report](REQUEST_JNI_STARTUP_WORKERS.md#6168-second-vm-shared-reader-release2026-10-15-asiashanghai).

Second VM string equality passes27 new native controls and9 rollback checks. The owning comparison matches1185 declared ranges in32 instructions with no allocation or external services. The second VM reaches8405 steps before StringObject assignment; complete signing remains unfinished. See the [second equality report](REQUEST_JNI_STARTUP_WORKERS.md#6169-second-vm-string-equality2026-10-15-asiashanghai).

Second VM string assignment passes37 new native controls and13 rollback checks. The owning assignment matches1185 declared ranges and actual libc malloc/free in347 instructions. The second VM reaches8416 steps before the random getter; complete signing remains unfinished. See the [second assignment report](REQUEST_JNI_STARTUP_WORKERS.md#6170-second-vm-string-assignment2026-10-15-asiashanghai).

Second VM random callback passes17 new native controls and11 rollback checks. The warm owning callback matches1191 ranges and actual libc random/mutex execution in126 instructions. The second VM reaches8532 steps before +288658 -> +257804; complete signing remains unfinished. See the [second random report](REQUEST_JNI_STARTUP_WORKERS.md#6171-second-vm-random-callback2026-10-15-asiashanghai).

Second VM reference getter passes33 new native controls and13 rollback checks. The owning getter matches1186 ranges and live diagnostic fields in429 instructions, with four shared mutex transitions and no allocation. The second VM reaches8539 steps before +288670 -> +257880; complete signing remains unfinished. See the [second reference getter report](REQUEST_JNI_STARTUP_WORKERS.md#6172-second-vm-reference-getter2026-10-15-asiashanghai).

Second VM cached u32 getter passes27 new native controls and13 rollback checks. The owning getter matches1185 ranges in237 instructions, including the W return, packed padding and four shared mutex transitions. The second VM reaches8760 steps before +28868c -> +2633a4; complete signing remains unfinished. See the [second cached u32 report](REQUEST_JNI_STARTUP_WORKERS.md#6173-second-vm-cached-u32-getter2026-10-15-asiashanghai).

Second VM pair reference getter passes29 new native controls and10 rollback checks. The three-instruction target delegates to the existing scoped reference copy. The owning callback matches1187 ranges and diagnostic fields in198 instructions with no allocation. The second VM reaches8809 steps before +2886b0 -> +1cf55c; complete signing remains unfinished. See the [second pair getter report](REQUEST_JNI_STARTUP_WORKERS.md#6174-second-vm-pair-reference-getter2026-10-15-asiashanghai).

Java object byte reference composition passes28 new native controls and12 rollback checks at two bases. The original +26fe2c uses one UTF reference argument, existing JNI/byte-array/reference owners, ordered cleanup and live table reloads. This child component leaves the request boundary at8809 before +2886b0 -> +1cf55c; complete signing remains unfinished. See the [Java object bytes report](REQUEST_JNI_STARTUP_WORKERS.md#6175-java-object-byte-reference-composition2026-10-15-asiashanghai).

Cached dispatch byte producer passes26 new native controls and13 rollback checks. The original +1cf688 composes two explicit environment acquisitions, the exact dispatcher words, existing byte conversion and empty-string fallback. Environment replacement proves live-pair reload and retained-environment cleanup. The request boundary remains8809 before +2886b0 -> +1cf55c; complete signing remains unfinished. See the [cached dispatch bytes report](REQUEST_JNI_STARTUP_WORKERS.md#6176-cached-dispatch-byte-producer2026-10-15-asiashanghai).

Cached reference initialization and refresh pass44 new native controls and18 rollback checks. The original +1cf55c inline cache composes the producer, process destructor registration and scoped references, including signed64 refresh conditions. Request remains8809 before +2886b0 -> +1cf55c; second wiring and complete signing remain unfinished. See the [cached reference report](REQUEST_JNI_STARTUP_WORKERS.md#6177-cached-reference-initialization-and-refresh2026-10-15-asiashanghai).

Second VM cached reference callback passes17 new native controls and8 rollback checks. The owning callback executes5571 instructions with1189 matching ranges; actual second entry advances8809 to8844 before 0x2884ec -> 0x32d3a0. Complete signing remains unfinished. See the [second cached reference report](REQUEST_JNI_STARTUP_WORKERS.md#6178-second-vm-cached-reference-callback2026-10-15-asiashanghai).

Second VM static guard acquire passes 33 new native controls and 14 rollback checks. The owning callback executes 94 instructions with 1185 matching ranges; actual second entry advances 8844 to 8902 before 0x2886fc -> 0x256330. Complete signing remains unfinished. See the [second guard acquire report](REQUEST_JNI_STARTUP_WORKERS.md#6179-second-vm-static-guard-acquire2026-10-15-asiashanghai).

Second VM environment constant callback passes 21 new native controls and 8 rollback checks. The owning warm callback executes 19 instructions with 1188 matching ranges; actual second entry advances 8902 to 8938 before 0x288718 -> 0x2781f4. Complete signing remains unfinished. See the [environment constant report](REQUEST_JNI_STARTUP_WORKERS.md#6180-second-vm-environment-constant-callback2026-10-15-asiashanghai).

Second VM C-string format callback passes 27 new native controls and 12 rollback checks. The owning callback executes 1013 instructions with 1188 matching ranges; actual second entry advances 8938 to 8951 before 0x28854c -> 0x32d4f8. Complete signing remains unfinished. See the [C-string format report](REQUEST_JNI_STARTUP_WORKERS.md#6181-second-vm-c-string-format-callback2026-10-15-asiashanghai).

Second VM static guard release passes 25 new native controls and 12 rollback checks. The owning callback executes 71 instructions with 1189 matching ranges; actual second entry advances 8951 to 9050 before 0x28874c -> 0x256a18. Complete signing remains unfinished. See the [guard release report](REQUEST_JNI_STARTUP_WORKERS.md#6182-second-vm-static-guard-release2026-10-15-asiashanghai).

Second VM configuration u32 reading passes 22 new native controls, including ten owning callbacks with1190 matching ranges each. Twelve prior rollback checks are reused without rerun or new counts. The actual second entry advances9050 to9374 before 0x28876c -> 0x26cc64; complete signing remains unfinished. See the [second configuration read report](REQUEST_JNI_STARTUP_WORKERS.md#6183-second-vm-configuration-u32-read2026-10-15-asiashanghai).

Second VM realtime unsigned seconds passes 15 new native controls and 10 rollback checks. Its owning callback executes54 original instructions with1188 matching ranges and one explicit clock provider call. Actual second advances9374 to9557, where wrapper28863c has a NULL target requiring investigation. Complete signing remains unfinished. See the [realtime seconds report](REQUEST_JNI_STARTUP_WORKERS.md#6184-second-vm-realtime-unsigned-seconds2026-10-15-asiashanghai).

Second VM process ID callbacks pass 26 new native controls and 12 rollback checks. Explicit ELF-derived getpid/getppid imports, cached PID, syscall172/173 and errno paths match; owning callbacks execute18/13 instructions across1190/1189 ranges. Actual second advances9557 to9729, next28876c->204f58. Complete signing remains unfinished. See the [process ID report](REQUEST_JNI_STARTUP_WORKERS.md#6185-second-vm-process-id-callbacks2026-10-15-asiashanghai).

Second VM cached thread pointer passes 15 new native controls and 7 rollback checks. Original obfuscated getter returns cached X64 or initializes it from TPIDR_EL0; owning65 instructions/1188 ranges match. Actual second advances9729 to9752, next288788->26edc4. Complete signing remains unfinished. See the [thread pointer report](REQUEST_JNI_STARTUP_WORKERS.md#6186-second-vm-cached-thread-pointer2026-10-15-asiashanghai).

Second VM environment acquisition passes 17 new native controls, reusing 6 existing rollback guards without rerunning them. The12-byte wrapper reuses the shared TLS/JavaVM owner; owning160 instructions/997 ranges and one GetEnv effect match. Actual second advances9752 to9780, next288794->282b84. Complete signing remains unfinished. See the [environment acquisition report](REQUEST_JNI_STARTUP_WORKERS.md#6187-second-vm-environment-acquisition2026-10-15-asiashanghai).

Second VM locked pointer getter passes 19 new native controls and 13 rollback checks. Real normal mutexes retain the owner while reading receiver+0x40; owning86 instructions/1191 ranges match. Actual second advances9780 to9813, next2887b0->256b84. Complete signing remains unfinished. See the [locked pointer report](REQUEST_JNI_STARTUP_WORKERS.md#6188-second-vm-locked-pointer-getter2026-10-15-asiashanghai).

Second VM tree pointer getter passes 41 new native controls and 18 rollback checks. Existing tree/shared-reader owners produce full X64 before release; owning321 instructions/1191 ranges match. Actual second advances9813 to9940, next2886b0->25bd8c. Complete signing remains unfinished. See the [tree pointer report](REQUEST_JNI_STARTUP_WORKERS.md#6189-second-vm-tree-pointer-getter2026-10-15-asiashanghai).

Second VM cold cached identifier passes 45 new native controls and 19 rollback checks. Explicit seed-file providers, two state advances, template formatting and existing reference owners match the original; owning3918 instructions/1192 ranges match. Actual second advances9940 to9950, next288508->32a1f0. Complete signing remains unfinished. See the [identifier report](REQUEST_JNI_STARTUP_WORKERS.md#6190-second-vm-cold-cached-identifier2026-10-15-asiashanghai).

Second VM allocation callback passes 22 new native controls and 9 rollback checks. It reuses the explicit allocator owner, normalizes zero size to one and writes full X64 at packed+16. Two actual owning allocations match144/579 instructions across1190 ranges each. Actual second advances9950 to9998, next28880c->248908. Complete signing remains unfinished. See the [allocation report](REQUEST_JNI_STARTUP_WORKERS.md#6191-second-vm-allocation-callback2026-10-15-asiashanghai).

Second VM string format callback passes 21 new native controls and 12 rollback checks. Existing formatter and allocator owners handle one W2 argument; owning1839 instructions/1193 ranges match real libc. The entry forwards prepare_format and raises second budget10000 to20000. Actual second advances9998 to10009, next2887f0->248780. Complete signing remains unfinished. See the [string format report](REQUEST_JNI_STARTUP_WORKERS.md#6192-second-vm-string-format-callback2026-10-15-asiashanghai).

Second VM string pair callback passes 17 new native controls and 8 rollback checks. Its complete28-byte wrapper equals the accepted token wrapper, so the existing clone/append owner handles both; actual owning629 instructions/1191 ranges match. Actual second advances10009 to10021, next2887d0->25874c. Complete signing remains unfinished. See the [string pair report](REQUEST_JNI_STARTUP_WORKERS.md#6193-second-vm-string-pair-callback2026-10-15-asiashanghai).

Second VM digest reference callback passes 33 new native controls and retains 8 prior rollback controls without rerunning them. The equivalent wrapper reuses unchanged digest/reference owners; actual owning4955 instructions/1194 ranges match. Actual second advances10021 to10030, next288820->258bac. Complete signing remains unfinished. See the [digest report](REQUEST_JNI_STARTUP_WORKERS.md#6194-second-vm-digest-reference-callback2026-10-15-asiashanghai).

Second VM CRC callback passes 33 new native controls and 18 rollback guards. The equivalent wrapper reuses the unchanged guest-table CRC owner and stores only four result bytes. Actual owning247 instructions/1439 ranges match. Actual second advances10030 to10059, next288610->32a264. Complete signing remains unfinished. See the [CRC report](REQUEST_JNI_STARTUP_WORKERS.md#6195-second-vm-crc-callback2026-10-15-asiashanghai).

Second VM deallocation callback passes 17 new native controls and 12 rollback guards. The equivalent tail wrapper forwards explicit free with no packed result store. Actual owning137 instructions/1193 ranges match real matching-libc free. Actual second advances10059 to10070, next2884cc->2484fc. Complete signing remains unfinished. See the [deallocation report](REQUEST_JNI_STARTUP_WORKERS.md#6196-second-vm-deallocation-callback2026-10-15-asiashanghai).

Second VM deleting destructor passes 17 new native controls and 12 rollback guards. The existing consumer reuses the unchanged object destructor with deletion enabled. Actual owning295 instructions/1198 ranges match real payload/object free and pre-free bytes. Actual second advances10070 to10101, next28883c->261404. Complete signing remains unfinished. See the [deleting destructor report](REQUEST_JNI_STARTUP_WORKERS.md#6197-second-vm-deleting-destructor2026-10-15-asiashanghai).

Second VM empty JSON reference passes 25 new native controls and 16 rollback guards. NULL source and empty-object prefixes compose existing container/reference owners; other JSON remains unsupported. Actual owning1603 instructions/1248 ranges match real allocator/free and recursive locks. Actual second advances10101 to10110, next28863c->1c3018. Complete signing remains unfinished. See the [empty JSON report](REQUEST_JNI_STARTUP_WORKERS.md#6198-second-vm-empty-json-reference2026-10-16-asiashanghai).




The actual ELF reader/AST is verified in the bounded module scope. Allocation/free remain explicit services;
nonempty element aborts and parse/root remain open. Independent Medusa, fresh
signatures and online acceptance remain unfinished. See [the startup/worker
report](REQUEST_JNI_STARTUP_WORKERS.md) and [VM9_PROGRESS.md](VM9_PROGRESS.md).
Older observations below are historical.

Actual JNI dispatcher/exception handling now passes 54 native/Python controls
and 10 negatives; Long conversion adds 34 controls and 11 negatives with an
explicit cache mutex. Two original JNI_OnLoad observations execute the actual
dispatcher and stop before Long conversion; once remains 1 and the cache mutex
global is zero in those probes. The later +0x271940 cache mutex constructor
passes 8 controls/6 negatives; combining it with the same fresh cold startup
and producing a fresh signer output remain open.
See [REQUEST_JNI_DISPATCH.md](REQUEST_JNI_DISPATCH.md).


The later cold getter composition adds 14 native/Python controls and four
negatives. Four constructor-to-original-JNI_OnLoad prefix probes, with one
explicit driver continuation, naturally complete cold once and stop before
the two startup VM entries. VM bodies, all ELF constructors and Python full
bootstrap remain open. See [REQUEST_JNI_COLD_ONCE.md](REQUEST_JNI_COLD_ONCE.md).

This directory is limited to the `com.dragon.read` / Tomato material. Douyin and Qidian are documented in their own directories.

Read in this order:

1. [REPORT.md](REPORT.md) — algorithm and confidence summary;
2. [API_CALLS.md](API_CALLS.md) — the request chain and response evidence;
3. [SIGNATURE.md](SIGNATURE.md) — header dependencies, six/seven-god terminology, and the 16-selector result;
4. [SEARCH.md](SEARCH.md) — static search model and the still-empty live responses;
5. [COMPLETE_ANALYSIS_AND_USAGE.md](COMPLETE_ANALYSIS_AND_USAGE.md) — consolidated status, interface/analysis/usage guide, evidence rules, and product boundary;
6. [VM9_PROGRESS.md](VM9_PROGRESS.md) — the current independent-execution checkpoint and blocker;
7. [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md) — callback-8 allocator/refill evidence;
8. [ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md) — empty bins, real mapped-slab initialization, cleanup and same-capture validation;
9. [RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md) — generated TLS/TSD/arena/cache and input-driven constructor evidence;
10. [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md) — default A/B constructor graph, callback pair binding, JNI cleanup, and fresh-memory evidence;
11. [rust/README.md](rust/README.md) — what the no-JVM Rust crate can and cannot do today.

The Python folder contains the verified primitives and the old Medusa snapshot interpreter. It is labelled carefully because a successful old snapshot replay is not proof of current online compatibility.

Latest constructor work restores configuration-tree lookup/insertion,
the complete 136/320-byte constructor bodies and both lazy getters.
Fresh differences and same-run checks include cold TLS/key/destructor
registration, scoped writer cleanup and observable stack padding. Guard/OS
boundaries remain explicit; the complete Python prelude and 88-byte
initialization are still open. See
[SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md).

The configuration cipher work now restores the mode-0 decrypt callback and
advances parser to step 725, with fresh component and same-run cold-state
differences. Read [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) for the memory ABI,
reproduction commands and evidence limits. Complete Python startup, Rust
current-interface signing and a usable search/download webpage remain open.

The separate stream/reference path is also restored and verified. Read
[STREAM_REFERENCE.md](STREAM_REFERENCE.md) for RC4 state, X5 call convention,
reference ownership and the next fill/resize boundary.


The bounded root factory/caller now runs from fresh ELF/TLS/reference inputs
without a native entry prelude. Eight controls compare all32 terminal slots,
heap, main image, TLS/generation and ordered effects; full factory counts are
206/93. Read [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md) for the exact
input and allocator/OS boundary. Complete current Medusa and the final
search/download product remain open.

The outer startup caller now passes four fresh-input controls (86 steps, 16 allocations, three deferred worker creations). Worker TLS/support prefixes pass 16 cold/warm controls; executor context initialization adds eight controls with the actual emulated-TLS model. New condition/queue/executor scheduler controls pass 92/94/62 native differences; eight same-fresh-startup controls now run idle workers through wait, stop and argument cleanup. The older native-only probe remains boundary evidence. The shared OP45 register decode is corrected with 308 native differences and fresh root/parser regressions. Read [STARTUP_INITIALIZATION.md](STARTUP_INITIALIZATION.md) for the exact thread and allocator boundary. Default initialization task bodies, OS thread-exit cleanup, real allocator boot and independent Medusa signing remain open.

### Python once/mask 与原始启动导入边界

新增 34 组原生/Python 差分、9 项负控制，恢复正常 cold once、缓存 getter 和完整
64 位 mask。另 4 条原始启动前缀及 4 条 memcpy ABS64 导入观察定位 A 的 pthread_create
与 B 的 descriptor publication 缺口。完整 Python bootstrap 对照仍 0，fresh Medusa
和下载产品尚未完成。详见 [本轮报告](REQUEST_JNI_COLD_MASK.md)。

### 原始 JNI 与同次默认 worker 的后续检查点

原有 A 原始启动/六个 caller/wait-stop 控制回归通过；新增 2 个同次 TLS cleanup、
2 个 guest joinable exit 观察，实际 support 清零及三次 free/poison 通过。B 新增两个
原始 constructor/factory 自然返回与 121 个 descriptor 发布观察，另 242 个 Python
lookup 控制使用 native 生成 root。另 82 个独立 XOR prefix 控制和 8 个回滚通过，
仍停在 reader 前。Python factory / 完整 bootstrap 对照仍 0，真实 OS
线程与独立签名链仍待完成。详见 [后续报告](REQUEST_JNI_STARTUP_WORKERS.md)。
