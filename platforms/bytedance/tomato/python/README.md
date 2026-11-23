# Tomato Python material

`verify_vm9_native_171_post_crc_scope_leave_return_dynamic_20261123.py`
continues the retained request through `+0x288540 -> +0x26c9d0` and the
matching Bionic unlock. **Sample verified**: observations 42/45 show owner
137 becoming zero, then recursive mutex state `0x4001 -> 0x4000`; callback
return at 55 preserves SP, X19-X29 and the packed descriptor. Scope fields
are omitted from return onward, and the released header is protected again.
The full parent serializer remains equal, with no new allocations, frees,
SVC, JNI or explicit service effects. Existing independent scope/model
controls are reused: 16 native/Python cases and six page-rollback checks;
22 damaged-evidence cases are rejected. No new semantic owner is introduced.
Capture, default offline validation and the full `--replay` CLI pass; the
second ELF/Bionic execution reproduces the complete frozen result field for field.

The 635-point interval advances VM cursor `+0x10a41c -> +0x10a43c` and stops
before the next call: wrapper `+0x2884cc`, descriptor target `+0x2484b8`.
That target is the base StringObject destructor, whereas the earlier MD5
deletion targeted `+0x2484fc`. Wrapper identity alone does not establish
object ownership or authorize an object-storage free. The next argument's
ownership, next callback execution, complete VM return, independent signer
and online acceptance remain unverified. See the
[scope-release evidence](../evidence/vm9_native_171_post_crc_scope_leave_return_dynamic_20261123.json).

`verify_vm9_native_171_post_crc_md5_delete_return_dynamic_20261123.py`
revalidates the frozen 966-point counter-free prefix and executes the complete
12-byte tail wrapper `+0x2884cc -> +0x2484fc`. **Sample verified**: the deleting
destructor calls base destructor `+0x2484b8`, frees payload `0x136df180`, then
object `0x136d9680`. Matching Bionic free entries occur at observations 21/166;
their returns are observed at 152/297. Payload fields/hashes are omitted from
21 onward, and object fields/hashes from 166 onward. Retired counter fields
are never decoded.

While object storage remains allocated, the verifier permits only the three
original destructor stores: vtable at 17, payload pointer clear at 152 and scalar
reset at 155. Observations 153/156 check the completed resets. Capacity becomes
zero and the former length field receives signed destructor sentinel -221,
matching the ELF constant; it is not consumed as a readable string length.
Callback return at 297 restores SP and X19-X29 and preserves the descriptor.
Void return X0 is omitted, and no packed result is stored.

The following VM continuation clears the old pair's object-pointer slot
`0x7004c560` at 421, PC `+0x171268`. The source register is decoded from the actual
instruction. Observation 422 verifies NULL and that the full 16-byte pair storage
is zero; the pointer slot then joins write protection again. Released pair storage
is not interpreted as an owning reference. There are two new frees and no
allocation, GC/flush or SVC effect; allocator counts become 602/275/3/4. The scope
remains held, with bucket 104's entry at `0x4001`/owner 137; the table and global
lock stay unchanged. All other retained live regions stay protected, with no new
provider or import binding.

The 1181-point segment advances the VM cursor from `+0x10a3e8` to `+0x10a41c`.
It stops before descriptor `0x7004cd70` calls scope leave `+0x26c9d0` through the
complete 12-byte tail wrapper `+0x288540`, with the active scope as argument.
That VM call, wrapper and target do not execute.

Twenty original/Python controls cover both image bases, NULL/negative-length,
cross-page/alias and explicit-provider mutation cases. Four independently prepared
length-32/capacity-64 cases overwrite retired payload/object bytes and check the
reset state before object free. Twelve refusals preserve guest pages, excluding
external provider effects. Component free remains explicit synthetic service
behavior; owning allocator parity and whole physical stack/GP/FP/PAC ABI are not
claimed. Raw inputs, words, CRC values, descriptors, allocation contents, padding
and register dumps are omitted; native snapshots never enter semantic models.
Standalone Python VM, remaining VM return, complete signing, JVM/Android and
online acceptance remain unverified. Use `--capture` or `--replay` with `--elf` and
`--libc`, or omit arguments for frozen validation. See the
[post-CRC MD5 deletion evidence](../evidence/vm9_native_171_post_crc_md5_delete_return_dynamic_20261123.json).

Frozen capture and default offline validation pass with 1181 observations,
20 original/Python controls, 12 component rollback checks and 76 damaged-evidence
rejections. An independent fresh ELF/Bionic process executes the public `run()`
and `validate()` functions; its JSON matches the frozen evidence field for field,
including the payload/object free order and object-pointer clear at 421/422.
All 688 repository Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, full parent-result equality, retired payload/object/counter lifetime
filtering, decoded store-source and NULL checks, raw input/CRC/register omission,
unique static ranges, LF/attribute rules and whitespace checks pass. All 52
earlier evidence and owner files retain their baseline hashes. Scope leave and
the complete standalone signer remain unverified.

`verify_vm9_native_171_post_crc_counter_free_return_dynamic_20261123.py`
revalidates the complete frozen 1249-point held-scope prefix, then executes the
full 12-byte tail wrapper `+0x288610 -> +0x32a264`. **Sample verified**: its
argument is the prior zero-count storage `0x136d8300`. Observation 7 reaches the
free PLT and 8 enters matching Bionic `free` at `libc+0x1bac0`. Counter fields
are omitted from that entry onward; snapshots do not read retired counter bytes.
Callback return at 139 restores SP and X19-X29 and preserves the descriptor.
Void free has no packed result, and physical return X0 is omitted.

The following original VM continuation clears the old pair's eight-byte counter
pointer slot `0x7004c568` at observation 263, PC `+0x171268`. The old word matches
the retired counter address; observation 264 at `+0x17126c` verifies the actual
NULL writeback. That pointer cell then joins write protection again. Pair storage
is never interpreted as an active owning reference after deallocation. The MD5
object `0x136d9680`, its payload and the held scope/diagnostic entry stay intact.
Bucket 104 remains held at `0x4001`/owner 137. There is exactly one new free and
no allocation; allocator counts become 602/273/3/4. Inherited JNI/SVC and explicit
service ledgers are unchanged, with no new provider or import binding.

The 966-point segment advances the VM cursor from `+0x10a3bc` to `+0x10a3e8`.
It stops before descriptor `0x7004cdf8` selects the MD5 object's deleting
destructor `+0x2484fc` through the complete 12-byte wrapper `+0x2884cc`. That VM
call, wrapper and target do not execute. Object/payload deletion and scope leave
remain outside this checkpoint.

Twenty original/Python controls cover two image bases, NULL/high/unaligned
pointers, cross-page/alias cases and explicit free-provider writes. Four added
cases independently prepare a four-byte zero counter, including a packed-tail
alias, and compare provider bookkeeping and overwritten bytes. Twelve refusals
preserve guest pages, excluding external provider effects. Component free is an
explicit synthetic service; owning allocator parity is not claimed. Raw inputs,
words, CRC values, descriptors, allocation contents, padding and register dumps
are omitted, and native snapshots never enter semantic models. Whole physical
stack/GP/FP/PAC ABI, standalone Python VM, complete signing, JVM/Android and online
acceptance remain unverified. Use `--capture` or `--replay` with `--elf` and `--libc`,
or omit arguments for frozen validation. See the
[post-CRC counter free evidence](../evidence/vm9_native_171_post_crc_counter_free_return_dynamic_20261123.json).

Frozen capture and default offline validation pass with 966 observations,
20 original/Python controls, 12 component rollback checks and 70 damaged-evidence
rejections. An independent fresh ELF/Bionic process executes the public `run()`
and `validate()` functions; its JSON matches the frozen evidence field for field,
including Bionic free entry/return at 8/139 and the pointer clear at 263/264.
All 687 repository Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, full parent-result equality, retired-counter and pointer-cell lifetime
filtering, raw input/CRC/register omission, unique static ranges, LF/attribute rules
and whitespace checks pass. All 50 earlier evidence and owner files retain their
baseline hashes. MD5 object deletion, scope leave and the complete standalone
signer remain unverified.

`verify_vm9_native_171_post_crc_diagnostic_scope_entry_dynamic_20261123.py`
revalidates the complete frozen 1206-point CRC result, then executes the full
16-byte tail wrapper `+0x288530 -> +0x26c858`. **Sample verified**: scope storage
`0x7004c660` guards the retained MD5 object `0x136d9680`. Bucket 104 reuses entry
`0x136d40e0`; the table and global lock remain unchanged. The actual matching
Bionic recursive mutex changes from unlocked `0x4000`/owner zero to held
`0x4001`/owner 137. Scope fields are read only after their stores at observation
26. The saved lock result changes from -233 to zero at 102; callback return at
112 restores SP and X19-X29 and preserves the descriptor and four padding bytes.

The following VM continuation writes the reference counter `0x136d8300` from
one to zero at observation 522, PC `+0x17208c`. Observation 523 checks the stored
value, then the counter storage joins write protection again. This is the sole
permitted counter write; the diagnostic scope and selected entry remain held.
Zero-count storage is still allocated, and no subsequent owned-reference fields
are decoded. The original source/object/payload and other retained regions stay
protected. There are no new allocations, frees, JNI/SVC or explicit provider
effects; allocator counts remain 602/272/3/4. The full parent serializer result
matches the frozen CRC prefix.

The 1249-point segment advances the VM cursor from `+0x10a37c` to `+0x10a3bc`.
It stops before descriptor `0x7004cc80` calls `+0x32a264` through the complete
12-byte tail wrapper `+0x288610`. Its argument matches the zero-count counter
storage; static code identifies a branch to the free route. That VM call,
wrapper and target do not execute. Scope leave and counter/object cleanup remain
outside this checkpoint.

Eighteen original/Python controls cover two image bases, cold/warm paths,
recursive and saturated locks, alias/cross-page cases, existing/missing slots
and independently prepared former StringObject storage at bucket 104. Seven
refusals preserve all guest pages; external provider effects are excluded from
rollback. Component allocation is explicit synthetic service behavior. Raw
words, CRC values, strings, descriptors, allocation contents, padding and register
dumps are omitted, and native snapshots never enter semantic models. Whole
physical stack/GP/FP/PAC ABI, independent owning allocator parity, standalone
Python VM, remaining VM return, complete signing, JVM/Android and online
acceptance remain unverified. Use `--capture` or `--replay` with `--elf` and `--libc`,
or omit arguments for frozen validation. See the
[post-CRC diagnostic scope evidence](../evidence/vm9_native_171_post_crc_diagnostic_scope_entry_dynamic_20261123.json).

Frozen capture and default offline validation pass with 1249 observations,
18 original/Python controls, seven component rollback checks and 79 damaged-
evidence rejections. An independent fresh ELF/Bionic process executes the public
`run()` and `validate()` functions; its JSON matches the frozen evidence field
for field, including the held scope and counter transition at 522/523. All 686
repository Python files compile. Public scanning, three invalid CLI combinations,
frozen overwrite refusal with unchanged evidence bytes, source fingerprints,
full parent-result equality, scope/counter lifetime filtering, raw word/CRC/register
omission, unique static ranges, LF/attribute rules and whitespace checks pass.
All 48 earlier evidence and owner files retain their baseline hashes. The next
counter deletion, scope leave and complete standalone signer remain unverified.

`verify_vm9_native_171_post_md5_crc_return_dynamic_20261123.py` revalidates the
complete frozen 6014-point MD5 reference result and executes the full 28-byte
wrapper `+0x288820 -> +0x258bac`. **Sample verified**: its receiver is the retained
length-32 MD5 hexadecimal StringObject at `0x136d9680`, with payload `0x136df180`.
The original buffer CRC entry `+0x24b298` is observed at 12 and returns at 244.
The guest ELF's 256-entry, 1024-byte table matches the independently generated
reflected CRC32 table; native W0 matches both guest-table CRC and `binascii.crc32`
of the same-run input. Those bytes and the CRC value are omitted from evidence.

The wrapper writes exactly four bytes to `0x7004ca70` at observation 246;
observation 247 checks the completed store. The descriptor's preceding 16 and
following 28 bytes are preserved through callback return at 249. SP and X19-X29
are restored. Unwritten output storage is recorded only by hash; its value is
checked after the observed store. The source, all retained MD5/reference/diagnostic
regions and guest CRC table remain write protected. There are no new allocator,
JNI or service effects, and the full parent case result matches field for field.

The new segment has 1206 observations and advances the VM cursor from `+0x10a348`
to `+0x10a37c`. It stops before descriptor `0x7004cd80` selects diagnostic scope
entry `+0x26c858` through the complete 16-byte tail wrapper `+0x288530`. That VM
call, wrapper and target do not execute.

Thirty-two existing original/Python cases plus four independently prepared
32/42-byte cases cover two image bases, signed nonpositive lengths, binary/NUL
input, cross-page and alias cases, declared-length bounds and a mutated guest
table. Eighteen refusals preserve all guest pages. Native snapshots never enter
semantic models. Whole physical stack/GP/FP/PAC ABI, standalone Python VM,
remaining VM return, complete signing, JVM/Android and online acceptance remain
unverified. Use `--capture` or `--replay` with `--elf` and `--libc`, or omit arguments
for frozen validation. See the
[post-MD5 CRC return evidence](../evidence/vm9_native_171_post_md5_crc_return_dynamic_20261123.json).

Frozen capture and default offline validation pass with 36 original/Python
controls, 18 component rollback checks and 69 damaged-evidence rejections.
An independent fresh ELF/Bionic process executes the public `run()` and
`validate()` functions; its JSON matches the frozen evidence field for field.
All 685 repository Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, full parent-result equality, unwritten-output filtering, raw source/
CRC/register omission, unique static ranges, LF/attribute rules and whitespace
checks pass. All 46 earlier evidence and owner files retain their baseline hashes.
The next diagnostic scope call and complete standalone signer remain unverified.

`verify_vm9_native_171_post_pair_md5_return_dynamic_20261123.py` revalidates
the frozen 1624-point clone/append segment and executes the complete 32-byte
hidden-X8 wrapper `+0x2887d0 -> +0x25874c`. **Sample verified**: its actual
42-byte source is the preceding concatenated StringObject. Native MD5 entry
`+0x243c34` is observed at 74 and returns at 871; its 16-byte result matches
independent MD5 of the same-run input. The selected hexadecimal branch produces
a length-32, capacity-64 StringObject. Raw input, raw digest and rendered digest
bytes are omitted; relations, lengths and hashes are retained.

The temporary reference at `0x7004b8c8` starts with count one. Publication to
output `0x7004c560` returns at observation 5175 with count two; temporary release
returns at 5369 with the output count back to one. Released temporary storage is
retained only by hash. The result object is `0x136d9680`, counter `0x136d8300`,
payload `0x136df180`. Callback return at 5392 restores SP and X19-X29. The output
pair is not decoded before publication, and no physical return-X0 parity is
claimed. Same-run source bytes enter only relation checks, never semantic models.

Constructor, assignment and release each execute a diagnostic scope through
actual entry `+0x26c858` and leave `+0x26c9d0`. The verifier captures entry return,
active leave entry and retired leave return separately. Bucket 104's one new
eight-byte table publication is permitted; its entry at `0x136d40e0` remains
allocated and unlocked after the three scope pairs. Global-lock header changes
are permitted during the callback, while its vtable/tail and other live regions
stay protected. Published entry vtable/tail stores are rejected. Output objects,
counter/payload, the table and completed diagnostic state join protection after
callback return. Retired scope fields are not decoded.

The new malloc requests are 24, eight, 48, four and 64 bytes; only the initial
eight-byte result payload is freed. The inherited counters change from malloc
597 to 602 and free 271 to 272; gc/flush and inherited service/JNI/SVC/dispatch
ledgers are unchanged. No provider or import binding is added. Prior strings,
the 42-byte source, cache/output pairs, counters and initialized word remain
protected. The 6014-point segment advances the VM cursor from `+0x10a324` to
`+0x10a348`, stopping before the complete 28-byte wrapper `+0x288820` calls CRC
helper `+0x258bac`. That VM call, wrapper and target do not execute.

Thirty-two existing original/Python controls plus four independent 42-byte
raw/hex cases at two image bases pass through the actual wrapper and matching
Bionic recursive mutexes. The added cases use an initialized global table with
an empty target slot. Component allocator effects are explicit synthetic
services. Eight rejections verify guest-page rollback, excluding external
provider effects. Whole physical stack/GP/FP/PAC ABI, independent owning
allocator parity, native failure/throw paths, host concurrency, standalone
Python VM, remaining VM return, complete signing, JVM/Android and online
acceptance remain unverified. Use `--capture` or `--replay` with `--elf` and
`--libc`, or omit arguments for frozen validation. See the
[post-pair MD5 reference evidence](../evidence/vm9_native_171_post_pair_md5_return_dynamic_20261123.json).

Frozen capture and default offline validation pass with 36 original/Python
controls, eight component rollback checks and 90 damaged-evidence rejections.
An independent fresh ELF/Bionic process executes the public `run()` and
`validate()` functions; its JSON matches the frozen evidence field for field.
All 681 Python files compile. Public scanning, three invalid CLI combinations,
frozen overwrite refusal with unchanged evidence bytes, source fingerprints,
unpublished-output and retired-scope/reference lifetime checks, raw source/
digest/register omission, unique static ranges, LF/attribute rules and whitespace
checks pass. All 44 earlier evidence and owner files retain their baseline hashes.
The next CRC call and complete standalone signer remain unverified.

`verify_vm9_native_171_post_formatter_pair_return_dynamic_20261123.py`
revalidates the frozen 3156-point formatter segment and executes the complete
28-byte hidden-X8 wrapper `+0x2887f0 -> +0x248780`. **Sample verified**: the
first input is the 36-byte identifier and the second is the six-byte formatted
StringObject. Clone return at observation 166 exposes a new length-36,
capacity-37 object; append return at 629 exposes their ordered 42-byte
concatenation with a terminating NUL and status W0=0. The callback returns to
VM at observation 631 with SP and X19-X29 restored. Same-run source bytes are
used only for clone/concatenation assertions and never enter semantic models.

The hidden destination `0x7004d1d8` reuses the completed diagnostic scope's
retired stack storage. Until clone return, only its address, width and storage
hash are retained; its fields are decoded only after the new StringObject is
constructed. Neither the former scope fields nor an unconstructed destination
are interpreted as a live object. Both source objects/payloads and all retained
strings, pairs, counters, initialized word and diagnostic table/locks/entries
remain protected. The destination and its current payload join the protected
ranges after callback return.

The clone requests 37 bytes. An actual matching Bionic realloc then moves its
payload from `0x136d40e0` to `0x136df280` with capacity 64. The verifier checks
the realloc PLT and Bionic entry, successful return, pointer store and capacity
store separately, without decoding the retired payload while the object's
fields are being updated. The inherited event ledger adds only the explicit
37-byte malloc event: malloc 596 to 597, free remains 271, and gc/flush remain
unchanged. That ledger does not enumerate realloc's internal allocation/free
effects; those counts do not establish independent owning-allocator parity.
Inherited service/JNI/SVC/dispatch ledgers are unchanged, and no provider or
import binding is added.

The 1624-point segment advances the VM cursor from `+0x10a2f4` to `+0x10a324`.
It stops before the 32-byte wrapper `+0x2887d0` calls MD5 reference helper
`+0x25874c`. That VM call, wrapper and target do not execute. Raw source/output
strings, identifiers/seed, packed descriptors, allocation contents, padding,
per-write values and register dumps are omitted.

Sixteen existing fresh original/Python controls plus two independently prepared
36-plus-six-byte controls cover both image bases. They include binary/empty
inputs, input/output aliases, synthetic allocation/growth failures and cross-page
output. Eight rejection checks verify guest-page rollback, excluding external
provider effects. Component allocator effects are explicit synthetic services.
Whole physical stack/GP/FP/PAC ABI, independent owning allocator, native failure/
throw paths, host concurrency, standalone Python VM, remaining VM return,
complete signing, JVM/Android and online acceptance remain unverified. Use
`--capture` or `--replay` with `--elf` and `--libc`, or omit arguments for frozen
validation. See the
[post-formatter pair evidence](../evidence/vm9_native_171_post_formatter_pair_return_dynamic_20261123.json).

Frozen capture, 18 original/Python controls, eight component rollback checks and
81 damaged-evidence rejections pass. Default offline validation and an
independent fresh ELF/Bionic replay pass; replay matches the frozen JSON field
for field, including realloc return at observation 594 and pointer/capacity
writeback checks at 599/600. All 680 Python files compile. Public scanning, three
invalid CLI combinations, frozen overwrite refusal with unchanged evidence
bytes, source fingerprints, destination-lifetime and retired-scope checks, raw
source/register omission, unique static ranges, LF/attribute rules and whitespace
checks pass. All 37 earlier evidence and owner files retain their baseline hashes.
The next MD5 call and complete standalone signer remain unverified.

`verify_vm9_native_171_post_diagnostic_formatter_return_dynamic_20261123.py`
revalidates the frozen 921-point diagnostic scope-leave segment, then executes
the complete 20-byte tail wrapper `+0x28880c -> +0x248908` and matching Bionic
`vsnprintf`. **Sample verified**: the callback returns at observation 2276 with
SP and X19-X29 restored. The destination StringObject stays at `0x136d9660`,
retains capacity eight and payload `0x136d82e8`, and changes from length zero to
six with a terminating NUL. The verifier checks the same-run W2 decimal
conversion against the destination's length and payload hash; it exports no
actual W2 value, format bytes or rendered text. Only the supplied W2 projection
and zero-extension are checked, without claiming full GP/FP varargs or return-X0
ABI parity.

The formatter adds three allocations (16, eight and 32 bytes), followed by their
three releases. Original matching Bionic allocator routes remain in use; malloc
593 to 596 and free 268 to 271 are the only ledger changes. Earlier live strings,
payloads, cache/output pairs, reference counter, initialized word and diagnostic
table/locks/entries retain their protected state. The target vtable is not
written. After return, the formatted object and its complete payload capacity
join the protected ranges. The completed diagnostic scope is not decoded again.
Packed arguments are preserved through callback return and may be reused later.

The 3156-point segment advances the VM cursor from `+0x10a2c8` to `+0x10a2f4`.
It stops before `+0x2887f0 -> +0x248780`; the complete 28-byte next wrapper is
fingerprinted, but that VM call, wrapper and target do not execute. No new
provider or import binding is added. Raw identifiers/seed, packed descriptors,
allocation contents, padding, per-write values and register dumps are omitted.

Twenty fresh original/Python controls execute the actual formatter wrapper at
two image bases, covering signed/unsigned integers, W2 truncation, percent and
literal/empty formats, a long string, cross-page packed input and format/output
aliasing. Component allocator effects are explicit synthetic services; matching
Bionic printf executes. Twelve rejection checks verify guest-page rollback,
excluding external provider effects. Native snapshots never enter semantic
models. Independent owning-allocator parity, native failure/throw paths, whole
physical stack/GP/FP/PAC ABI, host concurrency, standalone Python VM, remaining
VM return, complete signing, JVM/Android and online acceptance remain unverified.
Use `--capture` or `--replay` with `--elf` and `--libc`, or omit arguments for frozen
validation. See the
[post-diagnostic formatter evidence](../evidence/vm9_native_171_post_diagnostic_formatter_return_dynamic_20261123.json).

Frozen capture, 20 original/Python controls, 12 component rollback checks and
62 damaged-evidence rejections pass. Default offline validation and an
independent fresh ELF/Bionic replay pass; replay matches the frozen JSON field
for field, including the same-run W2 conversion assertion. All 679 Python files
compile. Public scanning, three invalid CLI combinations, frozen overwrite
refusal with unchanged evidence bytes, source fingerprints, retired-scope and
raw format/variadic/register omission, unique static ranges, LF/attribute rules
and whitespace checks pass. All 34 earlier evidence and owner files retain their
baseline hashes. The next clone/append call and complete standalone signer
remain unverified.

`verify_vm9_native_171_post_diagnostic_scope_leave_return_dynamic_20261123.py`
revalidates the frozen 1009-point four-byte-allocation segment, then executes
`+0x288540 -> +0x26c9d0` and the original matching Bionic unlock body.
**Sample verified**: owner 137 is cleared with a four-byte store, followed by a
two-byte release of the mutex state from `0x4001` to `0x4000`. The callback
returns at observation 55 with SP and X19-X29 restored. This closes the sampled
scope entry/leave pair; bucket 102's entry remains allocated in the process table.

The scope's four padding bytes and storage hash are preserved through callback
return. Once its lifetime ends, its fields stop being decoded; later snapshots
retain only the retired storage's address and hashes. Internal unlock GP
registers are omitted. The selected entry's vtable/tail remain protected during
unlock, and its released header joins the protected regions after return. All
other live strings, payloads, cache/output pairs, counter, initialized four-byte
word, diagnostic table, global lock and other entries remain protected. The new
word stays one. No allocation/free or inherited service/JNI/SVC/dispatch ledger
change occurs, and no provider or import binding is added.

The 921-point segment advances the VM cursor from `+0x10a29c` to `+0x10a2c8`.
It stops before wrapper `+0x28880c` calls formatter `+0x248908`, selecting the
new heap StringObject as destination. The complete 20-byte wrapper and target
entry are fingerprinted. The format pointer is recorded; packed W2 is retained
by width/hash only, with its zero-extension noted. No format bytes, raw variadic
value, identifier/seed bytes, packed descriptor or per-write values are exported.
This next VM call, wrapper and formatter do not execute.

Sixteen fresh original/Python leave controls exercise the actual wrapper at two
image bases: zero/high-bit input, cross-page scope, ordinary release, recursive
count, nonzero saved result, empty entry and wrong owner. Component states are
prepared independently by Python; leave callbacks do not allocate or free.
Six rejection checks verify guest-page rollback, excluding external observer
effects. Native snapshots never enter semantic models. Host contention/concurrency,
whole physical stack/return ABI, standalone Python VM continuation, remaining VM
return, complete signing, JVM/Android/PAC and online acceptance remain unverified.
Use `--capture` or `--replay` with `--elf` and `--libc`, or omit arguments for frozen
validation. See the
[post-diagnostic scope-leave evidence](../evidence/vm9_native_171_post_diagnostic_scope_leave_return_dynamic_20261123.json).

Frozen capture, 16 original/Python controls, six component rollback checks and
60 damaged-evidence rejections pass. Default offline validation and an
independent fresh ELF/Bionic replay pass; replay matches the frozen JSON field
for field. All 678 Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, retired-scope field and internal-unlock register omission, unique
static ranges, LF/attribute rules and whitespace checks pass. All 27 earlier
evidence and owner files retain their baseline hashes. The next formatter call
and complete standalone signer remain unverified.

`verify_vm9_native_171_post_diagnostic_small_allocation_return_dynamic_20261123.py`
revalidates the frozen 947-point diagnostic-entry segment, then executes
`+0x288508 -> +0x32a1f0` with X64 size four. **Sample verified**: inherited
original matching Bionic malloc returns `0x136d82f0`; the wrapper stores it at
packed descriptor+16 (`0x7004cdb8`). The callback returns at observation 146
with SP and X19-X29 restored and the input/descriptor tail preserved.

The VM subsequently performs one four-byte store at observation 584,
`+0x17208c: str w11, [x12, x10]`, initializing the allocation to one. The
post-store observation at 585 exports only the initialization predicate and
hashes; internal VM GP registers are omitted. The initialized allocation joins
the protected regions from that point. The 1009-point segment advances the VM
cursor from `+0x10a270` to `+0x10a29c` and stops before the scope-leave call.
Its complete 12-byte tail wrapper `+0x288540` would pass scope `0x7004d1d8` to
`+0x26c9d0`; this next VM call, wrapper and target do not execute.

All prior live strings, payloads, output/cache pairs, counter, cache mutex,
related globals and errno stay protected. The active scope, held entry, complete
diagnostic table, global lock and their pointer fields are also write-protected.
Bucket 102 remains held at `0x4001`, owner 137; its scope result stays zero and
identifier bucket 100 remains unchanged. Only one allocation is added (malloc
592 to 593); other allocator and inherited service/JNI/SVC/dispatch ledgers are
unchanged. No provider or import binding is added. Before the observed W32 store,
uninitialized allocation bytes are retained only by hash. Packed arguments and
raw identifier/seed bytes and per-write values are omitted.

Twenty existing original/Python allocation controls plus two explicit size-four
controls cover both image bases; component malloc is an explicit synthetic
provider. Nine existing rejections verify guest-page rollback, excluding external
provider effects. Native snapshots never enter Python semantic models. The next
unlock, full scope lifetime, independent owning-allocator parity, native NULL/
new-handler/throw, standalone Python VM continuation, remaining VM return,
complete signing, JVM/Android/PAC and online acceptance remain unverified. Use
`--capture` or `--replay` with `--elf` and `--libc`, or omit arguments for frozen
validation. See the
[post-scope four-byte allocation evidence](../evidence/vm9_native_171_post_diagnostic_small_allocation_return_dynamic_20261123.json).

Frozen capture, 22 original/Python controls, nine component rollback checks and
62 damaged-evidence rejections pass. Default offline validation and an
independent fresh ELF/Bionic replay pass; replay matches the frozen JSON field
for field. All 677 Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, internal-register omission, unique static ranges, LF/attribute
rules and whitespace checks pass. All 25 earlier evidence and owner files retain
their baseline hashes.

`verify_vm9_native_171_post_identifier_diagnostic_scope_entry_dynamic_20261123.py`
revalidates the frozen 858-point heap-string constructor segment and executes
`+0x288530 -> +0x26c858`. **Sample verified**: string pointer `0x136d9660`
selects diagnostic bucket 102, whose slot `0x136f8330` was empty. Original
matching Bionic malloc allocates a 48-byte recursive-mutex object at
`0x136d40b0`. The entry is constructed and published, the global mutex is
released, and the selected entry is locked through the original matching Bionic
mutex body. It remains held at state `0x4001`, owner 137, at the stop boundary.

Scope `0x7004d1d8` retains its four padding bytes by hash and records lock result
zero. The target returns at observation 390 and reaches the VM at 391 with SP
and X19-X29 restored; its packed descriptor is preserved through callback return.
The 947-point segment advances the VM cursor from `+0x10a250` to `+0x10a270`.
All earlier strings, payloads, output/cache pairs, counter, cache mutex, related
globals and errno remain protected. Identifier bucket 100 and the initialized
diagnostic guard are also write-protected. Only bucket 102 changes in the table;
the global lock is restored. The active scope and held entry join the protected
regions after callback return. One allocation is added (malloc 591 to 592);
other allocator and inherited service/JNI/SVC/dispatch ledgers are unchanged.

The next descriptor at `0x7004cda8` selects `+0x288508 -> +0x32a1f0`, requests
four bytes and would store its result at `0x7004cdb8`. Its VM call, wrapper and
allocation do not execute. The selected diagnostic mutex is not unlocked in
this segment. No provider or import binding is added. Public records retain
hashes, lengths, defined fields and write locations/widths, omitting raw
identifier/seed bytes, packed descriptors, padding and allocation contents.

Fourteen fresh original/Python controls cover seven profiles at two image bases,
including an initialized table with an empty selected slot. Component allocation
is explicitly synthetic; matching Bionic mutex bodies execute. Seven existing
rejections check guest-page rollback, excluding external allocator effects.
Native snapshots never enter Python semantic models. The full scope lifetime,
contention/concurrency, independent owning-allocator parity, standalone Python VM,
remaining VM return, complete signing, JVM/Android/PAC and online acceptance
remain unverified. Use `--capture` or `--replay` with `--elf` and `--libc`, or omit
arguments for frozen validation. See the
[post-identifier diagnostic-entry evidence](../evidence/vm9_native_171_post_identifier_diagnostic_scope_entry_dynamic_20261123.json).

Frozen capture, 14 original/Python controls, seven component rollback checks and
62 damaged-evidence rejections pass. Default offline validation and an
independent fresh ELF/Bionic replay pass; replay matches the frozen JSON field
for field. All 676 Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, unique static-code ranges, LF/attribute rules and whitespace
checks pass. All 23 earlier evidence and owner files retain their baseline hashes.

`verify_vm9_native_171_post_identifier_heap_string_constructor_return_dynamic_20261123.py`
revalidates the frozen 681-point allocation segment and runs the original
`+0x2884cc -> +0x2481ac` default constructor on heap object `0x136d9660`.
**Sample verified**: it loads the ELF initial descriptor, publishes vtable
`+0x34f5f8`, capacity eight and length zero, and requests an eight-byte payload
through the inherited original matching Bionic malloc. Payload `0x136d82e8`
receives one NUL byte; the other seven bytes retain their pre-store hash. The
constructor returns at observation 147 and reaches the VM at 148 with SP and
X19-X29 restored. The packed descriptor remains unchanged through callback return.

The 858-point segment advances the VM cursor from `+0x10a228` to `+0x10a250`.
The identifier, three earlier default strings, output/cache pairs, counter,
mutex, related globals and errno remain write-protected. The new object and its
payload join the protected regions after callback return. Only one allocation
is added (malloc 590 to 591); other allocator and inherited service/JNI/SVC/
dispatch ledgers remain unchanged. No provider or import binding is added.

The next 48-byte descriptor at `0x7004cd80` selects the complete 16-byte tail
wrapper `+0x288530` and diagnostic-scope target `+0x26c858`, with X0 pointing to
scope `0x7004d1d8` and X1 to the new string object. That VM call, wrapper and
target do not execute. Public records contain hashes, lengths, defined fields
and write locations/widths, omitting raw identifier, seed, packed descriptor and
allocation contents. Uninitialized bytes are retained only by hash.

Eighteen existing native layout/store-width/SP controls and eight fresh
original/Python consumer controls use explicit synthetic component malloc.
Twelve existing consumer-family rejection checks verify guest-page rollback;
external provider effects remain outside rollback. Native snapshots never enter
Python semantic models. Independent owning-allocator parity, the actual Bionic
NULL path, standalone Python VM continuation, remaining VM return, successful
entropy access, complete signing, JVM/Android/PAC and online acceptance remain
unverified. Use `--capture` or `--replay` with `--elf` and `--libc`, or omit
arguments for frozen validation. See the
[post-identifier heap-string evidence](../evidence/vm9_native_171_post_identifier_heap_string_constructor_return_dynamic_20261123.json).

Frozen capture, 18 native layout controls, eight original/Python comparisons,
12 component rollback checks and 54 damaged-evidence rejections pass. Default
offline validation and an independent fresh ELF/Bionic replay pass; replay
matches the frozen JSON field for field. All 675 Python files compile. Public
scanning, three invalid CLI combinations, frozen overwrite refusal with unchanged
evidence bytes, source fingerprints, LF/attribute rules and whitespace checks
pass. All 15 earlier evidence and owner files retain their baseline hashes.

`verify_vm9_native_171_post_identifier_allocation_return_dynamic_20261123.py`
revalidates the frozen 686-point VM prefix, then executes the allocation call at
`+0x16aa48`. **Sample verified**: original wrapper `+0x288508` and operator new
`+0x32a1f0` request 24 bytes through the inherited matching Bionic malloc at
`libc+0x1bb08`. The returned pointer `0x136d9660` is stored at descriptor+16
(`0x7004cdb8`). The callback returns at observation 146 with SP and X19-X29
restored. The 681-point segment advances the VM cursor from `+0x10a208` to
`+0x10a228`, stopping before the next VM call. Its 12-byte wrapper `+0x2884cc`
would pass the allocation pointer to `+0x2481ac`; this next call does not execute.

The identifier, prior default objects, output/cache pairs, counter, mutex,
related globals and errno remain under continuous write protection. The
allocation count increases from 589 to 590; all other allocator and inherited
service/JNI/SVC/dispatch ledgers are unchanged. No provider or import binding is
added. Public records contain hashes, defined pointers/scalars and write
locations/widths, omitting raw identifier, seed, descriptor and allocation bytes.

Twenty existing fresh original/Python allocation-wrapper controls and nine
guest-page rollback checks remain separate from the main path's original
Bionic execution. Component malloc is an explicit synthetic provider; external
provider effects are outside rollback. Independent owning-allocator parity,
native NULL/new-handler/throw, standalone Python VM continuation, remaining VM
return, successful entropy access, complete signing, JVM/Android/PAC and online
acceptance remain unverified. Use `--capture` or `--replay` with `--elf` and
`--libc`, or omit arguments for frozen validation. See the
[post-identifier allocation evidence](../evidence/vm9_native_171_post_identifier_allocation_return_dynamic_20261123.json).

Frozen capture, 20 original/Python controls, nine component rollback checks and
50 damaged-evidence rejections pass. Default offline validation and an
independent fresh ELF/Bionic replay pass; replay matches the frozen JSON field
for field. All 674 Python files compile. Public scanning, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprints, LF/attribute rules and whitespace checks pass. The 11 earlier
evidence and owner files retain their baseline hashes.

`verify_vm9_native_171_post_identifier_vm_boundary_dynamic_20261123.py`
resumes the original VM at `+0x16aa4c` after revalidating the frozen 633-point
identifier-publication segment. **Sample verified**: this 686-point continuation
advances the VM cursor from `+0x10a1e0` to `+0x10a208` and reaches its next call
at `+0x16aa48`. Both boundaries retain the same SP and X19-X29 digest. All live
identifier/default-object regions remain unchanged under continuous write
protection: output and cache still share the string/count pair, count stays two,
the cache mutex remains unlocked, and errno remains two. Allocator and inherited
service/JNI/SVC/late-dispatch ledgers are unchanged; no provider or binding is added.

The next 48-byte packed descriptor is at `0x7004cda8`, separate from the prior
descriptor. Wrapper `+0x288508` would load target `+0x32a1f0` and X64 size 24,
then store the returned pointer at descriptor+16 (`0x7004cdb8`). Its complete
28-byte wrapper and the target entry are fingerprinted. This next VM call,
wrapper, allocation and result store do not execute. Public records retain only
the descriptor hash and defined scalar/address fields; raw descriptor, identifier
and seed bytes and per-write values are omitted. VM parameter writes are recorded
as locations and widths while live output/cache/object regions stay protected.

Twenty fresh original/Python allocation-wrapper controls cover ten existing
profiles at two image bases: size zero/one/24/4097/uint64 max, high pointers,
cross-page input/result, provider rewrites and packed aliases. Synthetic malloc
is explicit; nine existing rejection checks verify guest-page rollback, excluding
external provider effects. These controls execute the component independently;
the next main-path allocation remains unexecuted. Native snapshots never enter
Python semantic models. A standalone Python VM continuation, successful entropy
access, remaining VM return, independent signing, native NULL/new-handler/throw,
JVM/Android/PAC and online acceptance remain unverified. Use `--capture` or
`--replay` with `--elf` and `--libc`, or omit arguments for frozen validation. See
the [post-identifier VM evidence](../evidence/vm9_native_171_post_identifier_vm_boundary_dynamic_20261123.json).

Frozen capture, 20 original/Python allocation controls, nine component rollback
checks and 42 damaged-evidence rejections pass. Default offline validation and a
fresh ELF/Bionic replay pass; replay matches the frozen JSON field for field.
All 673 Python files compile. The public scan, three invalid CLI combinations,
frozen overwrite refusal with unchanged evidence bytes, source fingerprint
matching and whitespace checks pass. Earlier frozen evidence and semantic owners
retain their baseline hashes.

`verify_vm9_native_171_identifier_cache_publication_dynamic_20261123.py`
continues `+0x25be18` after revalidating the frozen 1485-point reference/factory
segment. **Sample verified**: original output assignment `+0x162620` publishes
the string/count pair and increments the counter from one to two. Temporary
release `+0x15e1a8` decrements it to one without clearing the temporary pair's
bytes. Original cache assignment `+0x1633b0` publishes the same pair to the cache
and increments the counter to two. Output and cache hold the same string
`0x136d9640` and counter `0x136d82e0`; the temporary's lifetime has ended.

The cache mutex is unlocked at observation 622. Getter `+0x25bd8c` returns at
631, and wrapper `+0x2886b0` returns at 633 with SP and X19-X29 restored against
the saved caller frame. This 633-point segment stops before VM continuation
`+0x16aa4c`; its instruction does not execute. X0 is incidental; the object
result is verified through the output reference. Three diagnostic lock/unlock
cycles reuse the existing entry. No allocation/free or inherited service/JNI/
SVC/late-dispatch ledger changes occur; no provider or import binding is added.
The three prior default objects/payloads, descriptor, string object/payload,
identifier globals and errno remain write-protected. Later calls reuse the
former formatter stack window, which is recorded by hash and is no longer
protected as a live payload.

Sixteen fresh original/Python cache controls cover eight existing profiles at
two image bases, including cold/warm caches, failed seed-open, zero seed, output
aliases and cross-page output. Nineteen existing rejection checks verify guest
page rollback; external provider effects remain outside it. Component file,
allocation and thread services are explicit; native snapshots never initialize
Python semantic models. Raw identifier/seed bytes and write values are omitted.
Subsequent VM execution, successful entropy access, independent signing, JVM/
Android/PAC and online acceptance remain unverified. Use `--capture` or `--replay`
with `--elf` and `--libc`, or omit arguments for frozen validation. See the
[identifier cache-publication evidence](../evidence/vm9_native_171_identifier_cache_publication_dynamic_20261123.json).

Frozen capture, 16 original/Python controls, 19 component rollback checks and
43 damaged-evidence rejections pass. Default offline validation and a fresh
ELF/Bionic replay pass; replay matches the frozen JSON field for field. All 672
Python files compile. The public scan, three invalid CLI combinations, frozen
overwrite refusal with unchanged evidence bytes, source fingerprint matching
and whitespace checks pass. Earlier frozen evidence and semantic owners retain
their baseline hashes.

`verify_vm9_native_171_identifier_reference_factory_return_dynamic_20261123.py`
continues the BL at `+0x25bd3c` after revalidating the frozen 295-point string
constructor segment. **Sample verified**: original `+0x1625a4` clears the temporary
pair, enters the diagnostic scope, publishes the string pointer and allocates a
four-byte counter initialized to one. Diagnostic table slot 100 was empty; an
original 48-byte allocation creates its recursive mutex at `0x136d4080`. The
scope locks it, then releases it to state `0x4000` with owner zero. The existing
diagnostic guard, global lock and table stay allocated.

The reference constructor returns at observation 1474. The identifier factory
returns at 1483, restoring SP and X19-X29 against its saved frame and unchanged
registers. Temporary reference `0x7004b8c0` owns string `0x136d9640` with counter
`0x136d82e0` equal to one. This 1485-point segment stops before `+0x25be18` calls
output assignment `+0x162620`; that call does not execute. The output reference
and cache remain empty, and their mutex remains held. The three earlier default
objects/payloads, full descriptor, string object/payload, source window, cache
state and errno remain write-protected. Only 48-byte and four-byte malloc events
are added; other allocator counts and inherited service/JNI/SVC/dispatch ledgers
remain unchanged. Returned X0 is incidental and is not interpreted as the string
or counter result. No provider or import binding is added.

Eight fresh original/Python reference-constructor controls cover both image
bases, cold/warm diagnostic locks and ordinary/NULL string pointers. They compare
declared image pages, guest payload, scope bytes and ordered allocation/lock
effects using explicit synthetic allocation and thread-id services. Four existing
constructor rejection cases verify guest-page rollback; external provider effects
remain outside it. Native snapshots never enter Python semantic models. Public
records omit identifier/seed bytes, uninitialized pointer/counter values and write
values. Output assignment, temporary release, cache publication, getter/VM return,
independent signing, JVM/Android/PAC and online acceptance remain unverified.
Use `--capture` or `--replay` with `--elf` and `--libc`, or omit arguments for
frozen validation. See the
[identifier reference/factory evidence](../evidence/vm9_native_171_identifier_reference_factory_return_dynamic_20261123.json).

Frozen capture, eight original/Python controls, four component rollback checks
and 45 damaged-evidence rejections pass. Default offline validation and a fresh
ELF/Bionic replay pass; replay matches the frozen JSON field for field. All 671
Python files compile. The public scan, three invalid CLI combinations, frozen
overwrite refusal with unchanged evidence bytes, source fingerprint matching
and whitespace checks pass. Earlier frozen evidence and semantic owners retain
their baseline hashes.

`verify_vm9_native_171_identifier_string_constructor_return_dynamic_20261123.py`
continues the BL at `+0x25bd24` after revalidating the frozen 1140-point formatter
segment. **Sample verified**: original operator new allocates a 24-byte string
object, and original constructor `+0x248344` allocates its 37-byte payload through
the inherited matching Bionic malloc route. Four native header stores establish
the vtable, capacity 37, length 36 and payload pointer. The inherited host strlen
and memcpy providers measure/copy the formatter output including NUL; original
Bionic strlen/memcpy bodies do not execute. Raw identifier/seed bytes and write
values are omitted from public evidence.

The constructor returns at observation 293 with SP and X19-X29 restored. This
295-point segment stops before `+0x25bd3c` calls reference constructor `+0x1625a4`.
Its arguments select temporary reference `0x7004b8c0` and string `0x136d9640`;
that call does not execute. The three earlier default objects/payloads, full
descriptor, cache globals/mutex/pair, output reference, source window and errno
remain write-protected. Only two malloc events are added (24 and 37 bytes);
all other allocator counts and inherited service/JNI/SVC/late-dispatch ledgers
remain unchanged. No provider or import binding is added.

Fourteen fresh original/Python controls cover six existing string-constructor
cases and successful operator new at two image bases. Synthetic allocators are
explicit in these controls. Nine existing string-wrapper rejection checks verify
guest-page rollback; external provider effects remain outside that rollback.
Native snapshots never enter Python semantic models. Reference construction,
cache publication, the surrounding identifier callback return, successful entropy
access, full VM return, independent signing, JVM/Android/PAC and online acceptance
remain unverified. Use `--capture` or `--replay` with `--elf` and `--libc`, or omit
arguments for frozen validation. See the
[identifier string-constructor evidence](../evidence/vm9_native_171_identifier_string_constructor_return_dynamic_20261123.json).

Frozen capture, 14 original/Python controls, nine component rollback checks and
42 damaged-evidence rejections pass. Default offline validation and a fresh
ELF/Bionic replay pass; replay matches the frozen JSON field for field. All 670
Python files compile. The public scan, three invalid CLI combinations, frozen
overwrite refusal with unchanged evidence bytes, source fingerprint matching
and whitespace checks pass. Earlier frozen evidence and semantic owners retain
their baseline hashes.

`verify_vm9_native_171_identifier_formatter_return_dynamic_20261122.py`
continues the BL at `+0x25bd1c` after revalidating the frozen 381-point failed
seed-open prefix. **Sample verified**: original formatter `+0x255d84` decodes
its lazy template/alphabet and executes two original `+0x255ec0` state advances.
The zero input state remains zero despite four eight-byte state stores; two
eight-byte scratch stores also retain zero. Thirty-seven original byte stores
produce 36 characters plus NUL. Output length, including-NUL hash and the
untouched remainder of the 64-byte output window are checked; raw identifier
and seed bytes are omitted from public evidence.

The formatter returns at observation 1139 with SP and X19-X29 restored. Its
incidental X0 is not interpreted as a success status. This 1140-point segment
stops before the BL at `+0x25bd24` to `+0x32a1f0`, with X0=24; that allocation
does not execute. The surrounding identifier callback and cache publication
remain pending. Three earlier default objects/payloads, the full callback
descriptor, cache objects/guards, output reference and errno are protected.
Allocator events/counts and inherited service/JNI/SVC/late-dispatch ledgers
remain unchanged. No provider or import binding is added.

Fourteen independent original/Python formatter controls cover the six existing
template/alphabet/seed/output cases and an explicit zero-seed case at each of
two image bases. They compare declared guest image/payload memory and entropy
scratch from fresh ELF inputs. Nineteen existing component rejection checks
verify page rollback; external provider effects remain outside that rollback.
Native snapshots never enter Python semantic models. Successful entropy access,
the current identifier object's construction/publication, full VM return,
independent signing, real JVM/Android/PAC and online acceptance remain unverified.
Use `--capture` or `--replay` with `--elf` and `--libc`, or omit arguments for
frozen validation. See the
[identifier formatter evidence](../evidence/vm9_native_171_identifier_formatter_return_dynamic_20261122.json).

Frozen capture, 14 original/Python formatter controls, 19 component rollback
checks and 35 damaged-evidence rejections pass. Default offline validation and
a fresh ELF/Bionic replay pass; replay matches the frozen JSON field for field.
All 669 Python files compile. The public working-tree scan, three invalid CLI
combinations, frozen overwrite refusal with unchanged evidence bytes, source
fingerprint matching and whitespace checks pass. Four Rust unit tests pass.
The scanner regression suite could not create temporary `.git` fixtures under
the sandbox permissions; that suite remains unverified in this run.

`verify_vm9_native_171_identifier_seed_open_failure_dynamic_20261122.py`
continues the original BL at `+0x255d38` after revalidating the frozen
1147-point seed-open prefix. **Sample verified**: the inherited fopen import
route reaches original matching Bionic `+0x57cd8`. Its openat SVC at
`libc+0x6a6a0` uses the same decoded pathname, AT_FDCWD, flags 0 and mode 0.
The unchanged virtual OS rejects this non-/proc/stat path with -2. Original
Bionic stores errno=2, clears the selected static FILE's acquired flag, and
returns NULL at observation 303. No file or entropy provider is added.

The selected FILE is `0x510e5bb8`, with its 0x68-byte extension at `0x510e54d0`.
The 0x98-byte FILE, extension, four-byte errno store and four-byte failed-open
flag clear are checked. The seed initializer returns W0=`0xffffffff` (-1) at
observation 308; its caller then publishes the seed guard with two original
one-byte writes. The 16-byte seed state remains zero and write-protected.
The main descriptor and three earlier default strings remain protected, the
output/cache pair remain empty, and the cache mutex remains held. Main-image
allocator events and counts remain unchanged. The service ledger gains one
syscall-56 count, and its libc SVC ledger gains exactly that original SVC;
other inherited JNI/SVC/syscall-172/173 and late-dispatch ledgers are preserved.

This 381-point segment stops before `+0x25bd1c`, the BL to formatter `+0x255d84`.
fread, fclose and the formatter do not execute. fopen and seed-initializer stack
returns are checked; the surrounding identifier callback remains in progress.
The failed open still publishes its initialization guard in this sample.

Sixteen fresh original/Python readonly FILE controls at two image bases cover
single/repeated open, failure, fd zero/limit/overflow, binary and invalid modes. Twenty-seven
component rejection checks preserve guest pages, mapping records and cursor;
external provider effects are outside that rollback. These independently built
fixtures compare declared stdio/global/TLS/guest/mapping bytes and ordered OS
effects without feeding native snapshots to Python models. Inherited virtual
OS/TLS/JNI and serialized guards remain explicit; successful entropy access,
current identifier generation, full VM return, independent signing, Android/PAC
and online acceptance remain unverified. Use `--capture` or `--replay` with
`--elf` and `--libc`, or omit arguments for frozen validation. See the
[seed-open failure evidence](../evidence/vm9_native_171_identifier_seed_open_failure_dynamic_20261122.json).

Frozen capture, 16 original/Python FILE controls, 27 component rollback checks
and 43 damaged-evidence rejections pass. Default offline validation and a fresh
ELF/Bionic replay pass; replay matches the frozen JSON field for field. All 668
Python files compile. The public scan, three invalid CLI combinations, frozen
overwrite refusal with unchanged evidence bytes, source fingerprint matching
and whitespace checks pass.

`verify_vm9_native_171_identifier_seed_open_boundary_dynamic_20261122.py`
continues cursor `+0x10a1e0` through `+0x2886b0 -> +0x25bd8c` after
revalidating the frozen 734-point query-destructor prefix. **Sample verified**:
the wrapper retains packed descriptor `0x7004cbe8` in X0 and passes output
reference `0x7004d178` in X8. This is a cold identifier-cache path. Two original
matching-Bionic allocations create a 48-byte normal mutex at `0x136d4020` and
a 16-byte empty cache pair at `0x136d73a0`. The mutex reuses the previously freed
query payload address. Both cache initialization guards are published; the
output reference is cleared with original stores.

This 1147-point segment stops before the original BL at `+0x255d38` to fopen
PLT `+0x348460`. The decoded path and mode have lengths 12 and 2; only their
including-NUL hashes are retained. fopen/fread/fclose do not execute. The cache
pair and output remain empty, the cache mutex remains held, and the seed guard
is still pending. Identifier formatting, publication, callback return, scope
release and register restoration are not claimed for this in-progress call.

The full 48-byte callback descriptor, cache globals and native write widths are
checked. All three earlier default objects and payloads remain write-protected
through the stop boundary. Allocator counts gain exactly two mallocs (585 total),
with free/gc/flush unchanged; inherited service/JNI/SVC, syscall-172/173 and
late-JNI/Java-dispatch ledgers match the parent. No provider or import binding is
added. The stop is at the caller's BL so inherited PLT routing cannot redirect
past the observation boundary.

Forty-four fresh original/Python component controls reuse the identifier owner
at two image bases: 32 cache cases and 12 formatter cases, with fixed explicit
seed-file services confined to those controls. Nineteen rollback checks verify
guest pages only; external provider effects are not rolled back. Declared image
pages, guest payload memory and explicit outer-scope/formatter scratch are
compared; other physical spills and PAC are excluded. Native snapshots never
become model inputs. Serialized guards and inherited gettid/OS/JNI providers
remain explicit. Real JVM, complete identifier generation in this prefix, later
VM/suffix return, complete signing, Android, physical PAC and online acceptance
remain unverified. Use `--capture` or `--replay` with `--elf` and `--libc`, or
omit arguments for frozen validation. See the
[identifier seed-open boundary evidence](../evidence/vm9_native_171_identifier_seed_open_boundary_dynamic_20261122.json).

Frozen capture, 44 fresh original/Python controls, 19 component page-rollback
checks and 44 damaged-evidence rejections pass. Default offline validation and
an independent fresh ELF/Bionic replay pass; replay matches the frozen JSON
field for field. All 667 Python files compile. The public scan, three invalid
CLI combinations, frozen overwrite refusal with unchanged evidence bytes,
source fingerprint matching and whitespace checks pass.

`verify_vm9_native_171_post_u32_query_destructor_return_dynamic_20261122.py`
continues cursor `+0x10a1c0` through `+0x2884cc -> +0x2484b8` after revalidating
the complete 1190-point u32-lookup prefix. **Sample verified**: the query object
at `0x7004d1d8` owns the same 33-byte payload at `0x136d4020` recorded before
lookup. The original free PLT route executes once, entering matching Bionic
free at observation 16 and returning at 147. The allocator ledger gains exactly
one free; its count becomes 268, with malloc/gc/flush unchanged.

Three original eight-byte stores restore the vtable, clear the payload pointer
after free returns, and load the empty descriptor bits from ELF `+0x6e208`.
Both native reads, all three stores, the full 48-byte callback descriptor,
the query's adjacent eight bytes, SP and X19-X29 restoration are checked.
The earlier u32 result's full 48-byte descriptor remains unchanged through the
destructor return. All three earlier 24-byte default objects and their eight-byte
payloads remain write-protected until the next call boundary. The destructor's
incidental X0 value is recorded without giving it a success-status meaning.

The callback returns at observation 154. This 734-point segment stops before
cursor `+0x10a1e0`, wrapper `+0x2886b0` and target `+0x25bd8c`. The unexecuted
wrapper statically keeps descriptor `0x7004cbe8` in X0 and loads output object
`0x7004d178` into X8. Its complete 20 bytes and the target's first 16 bytes are
pinned; that invocation does not execute. Only the inherited free PLT route is
reached in the current segment. Service/JNI/SVC, syscall-172/173 and
late-JNI/Java-dispatch ledgers stay unchanged; no provider or import binding is
added to the prefix.

Twelve fresh original-code controls reuse the established destructor owner at
two image bases, covering normal/NULL payloads, a cross-page object, free-time
object mutation, a custom empty descriptor and a payload/object alias. They
compare the full declared 0xa000-byte guest payload span, descriptor/neighbors
and saved registers with an explicit synthetic free observer. Other native
stack and synthetic thread-pointer memory are outside that comparison. Native
snapshots never become Python semantic-model inputs. JNI acquisition remains an
inherited synthetic provider. Real JVM, later VM/suffix return, complete signing,
Android, physical PAC and online acceptance remain unverified. Use `--capture` or
`--replay` with `--elf` and `--libc`, or omit arguments for frozen validation.
See the [post-u32 query-destructor evidence](../evidence/vm9_native_171_post_u32_query_destructor_return_dynamic_20261122.json).

Frozen capture, 12 independent original-code controls, 56 damaged-evidence
rejections, default offline validation and a fresh ELF/Bionic replay pass; replay
matches the frozen JSON field for field. All 666 Python files compile. The public
scan, three invalid CLI combinations, frozen overwrite refusal with unchanged
evidence bytes, source fingerprint matching and whitespace checks pass.

`verify_vm9_native_171_post_defaults_u32_lookup_return_dynamic_20261122.py`
continues the verified source constructor at cursor `+0x10a198` through
`+0x28874c -> +0x256a18`. **Sample verified**: receiver `0x136e0000` and query
`0x7004d1d8` enter the configuration tree at receiver+8. Lookup returns NULL
under an active shared reader; the original getter selects `0xa985f` without
executing the found-value load. Reader count changes `0 -> 1 -> 0`; the existing
read-mode flag is written as 1. Four original matching-Bionic mutex calls
protect count updates. The lookup runs while the logical reader is active and
the mutex is released. Only those mutex PLT routes are reached in this segment.

Reader release returns at observation 513. At 523 the wrapper writes W0 to
descriptor+24 using four bytes, preserving the next four bytes and all other
descriptor padding. The low word already held `0xa985f`; its actual store is
recorded separately. Scope pointer/status stores, retained scope read, mutex
writes, SP and X19-X29 restoration are checked. The query's 24-byte body and
33-byte payload, plus all three earlier 24-byte objects and eight-byte payloads,
are protected from writes throughout the segment. Query neighbors, the tree's
40-byte header, the 0x98-byte reader area and scope padding are checked at return.

The callback returns at observation 526. This 1190-point segment stops before
cursor `+0x10a1c0`, selecting query destruction `+0x2884cc -> +0x2484b8` with
static X0=`0x7004d1d8`; that invocation does not execute. The preceding 783-point
constructor path, native object stores, explicit host strlen/memcpy effects,
full descriptor and three-object protection record must match first. Allocator,
inherited service/JNI/SVC, syscall-172/173 and late-JNI/Java-dispatch ledgers stay
unchanged. No provider, import binding or native snapshot-fed Python semantic
model is added.

Twenty-four independent original-code controls cover two image bases, NULL
lookup/value, zero/max/high-bit W32 values, existing readers, cross-page values,
packed output aliasing and reader-count/scope-field aliases. They verify held
four-byte reads and output after reader release, full declared 0xa000-byte guest
payload memory and the explicit 24-byte scope; other native stack and synthetic
thread-pointer memory are outside that comparison. Inputs are freshly built;
native snapshots never enter Python semantic models. JNI acquisition remains an
inherited synthetic provider; real JVM, later VM/suffix return, complete signing,
Android, physical PAC and online acceptance remain unverified. Use `--capture`
or `--replay` with `--elf` and `--libc`, or omit arguments for frozen validation.
See the [post-defaults u32 lookup evidence](../evidence/vm9_native_171_post_defaults_u32_lookup_return_dynamic_20261122.json).

Frozen capture, 24 independent original-code controls, 74 damaged-evidence
rejections, default offline validation and a fresh ELF/Bionic replay pass; replay
matches the frozen JSON field for field. All 665 Python files compile. The public
scan, three invalid CLI combinations, frozen overwrite refusal with an unchanged
evidence hash, source fingerprint matching and whitespace checks pass.

`verify_vm9_native_171_post_defaults_string_constructor_return_dynamic_20261122.py`
continues the verified third default constructor at cursor `+0x10a178` through
`+0x2885d0 -> +0x248344`. **Sample verified**: object `0x7004d1d8` receives
source `0x126a1330` with 32 bytes before its NUL. Original matching-Bionic
malloc(33) returns `0x136d4020`, reusing the earlier freed address. Its 33-byte
contents still have the earlier payload digest at allocation return. The
inherited host memcpy writes the new source including NUL; the after-write
observer records the new matching source/payload digest. Original Bionic strlen
and memcpy bodies do not execute; those inherited host providers remain explicit.

The frozen source-constructor owner supplies the native object-store, service,
copy-effect and return observers. Vtable, capacity 33, length 32 and pointer
stores, object neighbors, unchanged source, SP and X19-X29 are checked. A new
48-byte descriptor guard and return comparison cover the entire current block
at `0x7004ccc0`. The three earlier 24-byte objects and their eight-byte payloads
match the preceding evidence at activation, return and stop; writes overlapping
any of their six protected ranges are rejected throughout this segment.

The constructor returns at observation 157. This 783-point segment stops before
cursor `+0x10a198`, selecting the u32 tree lookup `+0x28874c -> +0x256a18`.
Its descriptor is `0x7004cb30`; receiver `0x136e0000` and query `0x7004d1d8`
remain static wrapper interpretations. That invocation does not execute. The
32-byte wrapper and 152-byte getter range are pinned separately. The preceding
3232-point path, allocation, object writes, two-object protection record and
next descriptor must match first. One malloc event is added; free/GC/flush,
inherited service/JNI/SVC and explicit syscall-172/173 ledgers stay unchanged.
No provider, import binding or native snapshot-fed Python semantic model is added.

Sixteen independent original-code controls include the earlier constructor
owner's twelve fresh cases and four three-object success/failure cases across
two image bases. Their synthetic malloc provider is explicit; host strlen and
memcpy remain declared. Memory comparisons cover the 0xa000-byte declared guest
payload span, excluding native stack and synthetic thread-pointer memory. JNI
acquisition remains an inherited synthetic provider; real JVM, later VM/suffix
return, complete signing, Android, physical PAC and online acceptance remain
unverified. Use `--capture` or `--replay` with `--elf` and `--libc`, or omit
arguments for frozen validation. See the
[post-defaults source-constructor return evidence](../evidence/vm9_native_171_post_defaults_string_constructor_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 68 damaged variants, including semantic changes with repaired
row digests. All 664 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_third_default_string_constructor_return_dynamic_20261122.py`
continues the second default-constructor checkpoint at cursor `+0x109ef0`.
**Sample verified**: the third `+0x2884cc -> +0x2481ac` invocation initializes
object `0x7004d148`. Original matching-Bionic malloc(8) returns `0x136d82d8`;
the constructor writes its vtable, descriptor `0800000000000000`, payload
pointer and one NUL byte. The other seven allocation bytes, object neighbors,
descriptor, SP and X19-X29 are checked at return. The allocation was already
eight zero bytes at malloc return; the single-byte store is observed separately.
Raw X0 retains the allocation result without independent status semantics.

Both prior 24-byte objects (`0x7004d118`, `0x7004d130`) and their eight-byte
payloads (`0x136d82c0`, `0x136d82d0`) match the preceding evidence at activation,
return and stop. The entire new segment rejects writes overlapping any of these
four protected ranges. The preceding 804-point second-constructor path, its
allocation, object writes, first-object retention and next descriptor must match
before the shared constructor observers begin the third invocation.

The constructor returns at observation 148. This segment has 3232 points and
stops before cursor `+0x10a178`, selecting source-string construction through
`+0x2885d0 -> +0x248344`. The next descriptor is `0x7004ccc0`; X0=`0x7004d1d8`
and X1=`0x126a1330` are static wrapper interpretations. That invocation, wrapper
and target do not execute. Its original 16-byte wrapper and 156-byte constructor
body are pinned separately. One malloc event is added; free/GC/flush, inherited
service/JNI/SVC and explicit syscall-172/173 ledgers stay unchanged. No provider,
import binding or native snapshot-fed Python semantic model is added.

Twenty-six independent original-code controls include the parent's twenty-two
fresh cases and four two-object success/failure cases across two image bases.
The synthetic malloc provider is explicit. Memory comparisons cover the declared
0xa000-byte guest payload span, excluding native stack and synthetic
thread-pointer memory. JNI acquisition remains an inherited synthetic provider;
real JVM, later VM/suffix return, complete signing, Android, physical PAC and
online acceptance remain unverified. Use `--capture` or `--replay` with `--elf`
and `--libc`, or omit arguments for frozen validation. See the
[third-default-constructor return evidence](../evidence/vm9_native_171_third_default_string_constructor_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 73 damaged variants, including semantic changes with repaired
row digests. All 663 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_second_default_string_constructor_return_dynamic_20261122.py`
continues the first default-constructor checkpoint at cursor `+0x109ecc`.
**Sample verified**: the second `+0x2884cc -> +0x2481ac` invocation initializes
object `0x7004d130` through the original matching-Bionic malloc(8) route, which
returns `0x136d82d0`. The frozen parent's read/store/return observers are reused
for this invocation. Vtable and descriptor `0800000000000000`, pointer storage,
one-byte NUL storage, the other seven allocation bytes, object neighbors,
descriptor, SP and X19-X29 are checked. The eight allocation bytes were already
zero at malloc return; the one-byte store has its own instruction and write
observation. Raw X0 retains the allocation result without separate status
semantics.

The first object's 24-byte body at `0x7004d118` and eight-byte payload at
`0x136d82c0` match the preceding evidence at activation, return and stop.
Writes overlapping either protected range are rejected throughout the new
segment. The prior 804-point path, allocation event, object writes and next
descriptor must match before the observers begin the second invocation.

This segment also has 804 observation points; the constructor returns at 148.
It stops before cursor `+0x109ef0`, selecting a third default-constructor
invocation for object `0x7004d148`. That invocation does not execute and its X0
argument remains static. One malloc event is added; free/GC/flush, inherited
service/JNI/SVC and explicit syscall-172/173 ledgers stay unchanged. No provider,
import binding or native snapshot-fed Python semantic model is added.

Twenty-two independent original-code controls include the parent's eighteen
fresh cases and four adjacent-object success/failure cases across two image
bases. The synthetic malloc provider is explicit. Memory comparisons cover the
declared 0xa000-byte guest payload span; native stack and synthetic thread-pointer
memory are outside that span. JNI acquisition remains an inherited synthetic
provider; real JVM, later VM/suffix return, complete signing, Android, physical
PAC and online acceptance remain unverified. Use `--capture` or `--replay` with
`--elf` and `--libc`, or omit arguments for frozen validation. See the
[second-default-constructor return evidence](../evidence/vm9_native_171_second_default_string_constructor_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 65 damaged variants, including semantic changes with repaired
row digests. All 662 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_default_string_constructor_return_dynamic_20261122.py`
continues the verified destructor boundary through `+0x2884cc -> +0x2481ac`.
**Sample verified**: the original default constructor initializes object
`0x7004d118`, stores the vtable and ELF descriptor `0800000000000000`, then
requests 8 bytes through the inherited original matching-Bionic malloc route.
The returned pointer is `0x136d82c0`. Original instructions store that pointer
and write one NUL byte; the other seven allocation bytes remain unchanged.
The store is observed even though the first byte was already zero. Object
neighbors, the descriptor, SP and X19-X29 are checked at return. Raw X0 retains
the allocation result without an independent success-status interpretation.

The constructor returns at observation 148. This 804-point segment stops before
the VM BLR at cursor `+0x109ecc`, selecting the same default constructor for
object `0x7004d130`. That next invocation does not execute; its X0 argument
remains a static interpretation. The preceding 2374-point destructor path,
original free and exact descriptor restoration must match first. Malloc count
increases by one; free/GC/flush, inherited service/JNI/SVC and explicit
syscall-172/173 ledgers stay unchanged. No provider or import binding is added,
and no native snapshot feeds a Python semantic model.

Eighteen independent original-code controls cover two image bases, allocation
failure, cross-page object/payload spans, descriptor/object/payload aliases and
custom initial descriptors. They check the entire declared 0xa000-byte guest
payload span, exact store widths, write order and register restoration. The
native stack and synthetic thread-pointer area are outside that memory span.
Failure clears only the 32-bit capacity
field, retaining the custom descriptor's length field. Their synthetic malloc
provider is declared separately. JNI acquisition remains an inherited synthetic
provider; real JVM, later VM/suffix return, complete signing, Android, physical
PAC and online acceptance remain unverified. Use `--capture` or `--replay` with
`--elf` and `--libc`, or omit arguments for frozen validation. See the
[default-string-constructor return evidence](../evidence/vm9_native_171_default_string_constructor_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 56 damaged variants, including semantic changes with repaired
row digests. All 661 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_string_destructor_return_dynamic_20261122.py` continues
the verified tree-query boundary through `+0x2884cc -> +0x2484b8`.
**Sample verified**: the StringObject still owns the previous 33-byte allocation
at `0x136d4020`. The inherited import route enters the original matching-Bionic
free body and records one returned free. Original instructions rewrite the
vtable, clear the payload pointer and restore the ELF descriptor's exact eight
bytes, `0000000023ffffff`. The D0 store preserves that opaque representation;
no conventional zero-length interpretation is substituted. Object neighbors,
the descriptor, SP and X19-X29 are checked at return. X0 is recorded as an
incidental register value on this void destructor, without status semantics.

The callback returns at observation 154. This 2374-point segment stops before
the next VM BLR at cursor `+0x109ea8`, selecting default StringObject construction
`+0x2884cc -> +0x2481ac`. That call, wrapper and target do not execute; its X0
argument remains a static interpretation. The previous 987-point tree lookup,
reader/mutex writes and scope release must match before continuation. Free count
increases by one; malloc/GC/flush, inherited service/JNI/SVC and explicit
syscall-172/173 ledgers stay unchanged. No provider or import binding is added,
and no native snapshot feeds a Python semantic model.

Twelve independent original-code controls cover two image bases, NULL payload,
a cross-page object, free-time object mutation, a custom empty descriptor and
payload/object aliasing. Their synthetic free observer is declared separately;
they compare the full guest payload and register restoration. Original JNI
acquisition, real JVM, later VM/suffix return, complete signing, Android,
physical PAC and online acceptance remain unverified. Use `--capture` or
`--replay` with `--elf` and `--libc`, or omit arguments for frozen validation.
See the [string-destructor return evidence](../evidence/vm9_native_171_string_destructor_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 49 damaged variants, including semantic changes with repaired
row digests. All 660 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_tree_pointer_return_dynamic_20261122.py` continues the
verified StringObject constructor through `+0x2887b0 -> +0x256b84`.
**Sample verified**: receiver `0x136e0000` and query `0x7004d1d8` reach the
original lookup under a shared reader. Reader count changes `0 -> 1 -> 0`;
the existing read-mode flag is written as 1. Four original matching-Bionic mutex
calls protect the count changes. The lookup returns NULL in this class0 control,
so its found-value load does not execute. The reader scope releases before the
wrapper writes the full X64 zero at descriptor+24. Descriptor padding, reader
neighbors, tree header, query/payload, scope padding and SP/X19-X29 are checked.

The callback returns at observation 323. This 987-point segment stops before
the next VM BLR at cursor `+0x109e30`, selecting StringObject destruction
`+0x2884cc -> +0x2484b8`. That call, wrapper and target do not execute; the next
argument is interpreted statically. The preceding 771-point constructor path,
33-byte allocation and explicit strlen/memcpy events must match first.
No allocator/service/JNI/SVC/syscall-172/173 increment occurs in the new segment;
its mutex calls, count/flag writes, retained scope read and X64 store have their
own ledger. No provider/import binding or native snapshot-fed Python model is
added. Original JNI acquisition, real JVM, later VM/suffix return, complete
signing, Android, physical PAC and online acceptance remain unverified.

Sixteen independent fresh original-code controls cover two image bases, empty
or missing lookup, a NULL stored pointer, zero/high X64 values, existing readers,
reader-count/value aliasing and a cross-page value. They verify found reads
while the reader is active and output only after release, including the alias
case's differing before/after reader counts. Use `--capture` or `--replay` with
`--elf` and `--libc`, or omit arguments for frozen validation. See the
[tree-pointer return evidence](../evidence/vm9_native_171_tree_pointer_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 58 damaged variants, including semantic changes with repaired
row digests. All 659 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_string_constructor_return_dynamic_20261122.py` continues
the verified locked-getter boundary through `+0x2885d0 -> +0x248344`.
**Sample verified**: the original tail wrapper supplies object `0x7004d1d8`
and source `0x126a12f0`. The 32-byte source uses a 33-byte allocation from
the original matching-Bionic malloc path, returning `0x136d4020`. Four original
object stores establish the vtable, capacity 33, length 32 and payload pointer.
The inherited host strlen and memcpy providers remain explicit: memcpy copies
the trailing NUL, and its observer runs after the host write. Original Bionic
strlen/memcpy bodies do not execute. Source and payload hashes, the neighboring
eight object bytes, descriptor, SP and X19-X29 are checked at return.

The constructor returns at observation 157; this 771-point segment stops before
the VM BLR at cursor `+0x109e08`, selecting tree getter
`+0x2887b0 -> +0x256b84`. That call, wrapper and target do not execute; the
receiver/query arguments remain static interpretations. The prior 1804-point
locked-getter receipt, mutex stores, held read and descriptor must match first.
One new malloc event requests 33 bytes; free/GC/flush counts and inherited
service/JNI/SVC/syscall-172/173 ledgers stay unchanged. No provider or import
binding is added, and no native memory snapshot feeds a Python semantic model.

Twelve independent original-code controls cover two image bases, empty/NULL
sources, allocation failure, a cross-page object and an embedded NUL, comparing
the full payload memory and register restoration. These controls declare their
synthetic allocator separately. JNI acquisition remains an inherited synthetic
provider; its original body, real JVM, later VM/suffix return, complete signing,
Android and online acceptance remain unverified. Use `--capture` or `--replay`
with `--elf` and `--libc`, or omit arguments for frozen validation. See the
[string-constructor return evidence](../evidence/vm9_native_171_string_constructor_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 53 damaged variants with repaired row digests for semantic
mutations. All 658 Python files compile; public scanning, default offline mode,
three invalid CLI combinations, frozen overwrite refusal with an unchanged hash,
and whitespace checks pass.

`verify_vm9_native_171_locked_pointer_return_dynamic_20261122.py` continues the
verified JNI-provider boundary through native `+0x288794 -> +0x282b84`.
**Sample verified**: receiver `0x136f3000` retains the mutex owner from +0x98,
locks owner+8 through the original matching-Bionic body, and reads the full X64
at receiver+0x40 while the mutex is held. The original `+0x15f778` destructor
reads the saved scope owner and unlocks through Bionic. Two original 16-bit
atomic stores change the mutex `0 -> 1 -> 0`; all 16 observed mutex bytes are
restored. The native wrapper writes eight bytes at descriptor+16, preserves
other descriptor bytes, and restores SP/X19-X29 before its VM return.

This class0 control returns zero at observation 88. Its 1804-point segment stops
before the next VM BLR at cursor `+0x109de8`, selecting the string constructor
`+0x2885d0 -> +0x248344`. That call, wrapper and target do not execute; their
arguments remain a static interpretation. The preceding 1887-point JNI-provider
path, original code, reads and provider event must match before continuation.
The new receipt retains the observation path, original-code hashes, mutex/body
entries, held read, retained-owner read and descriptor store. Allocation,
inherited service/JNI/SVC and explicit syscall-172/173 ledgers stay unchanged;
the two mutex calls/stores are recorded separately. No provider, import binding
or native snapshot-fed Python semantic model is added.

Eight independent fresh original-code controls cover two image bases, a high
64-bit value, value/mutex aliasing, and a receiver-owner field changed by the
mutex itself. They verify the held read, saved-owner unlock, full result,
padding and register restoration. JNI acquisition remains an inherited synthetic
provider; its original body, real JVM, later VM/suffix return and complete
signing remain unverified. Use `--capture` or `--replay` with `--elf` and `--libc`,
or omit arguments for frozen validation. See the
[locked-pointer return evidence](../evidence/vm9_native_171_locked_pointer_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 54 damaged variants, including semantic changes with repaired
row digests. All 657 Python files compile; public scanning, three invalid CLI
combinations, frozen overwrite refusal with an unchanged hash, and whitespace
checks pass.

`verify_vm9_native_171_jni_provider_return_dynamic_20261122.py` continues the
verified thread-pointer boundary through the original VM BLR and three-instruction
`+0x288788` tail wrapper. **Sample verified**: its two descriptor reads load
target `+0x26edc4` and output pair `0x7004d1d8`; the actual target-entry X0,
unchanged SP/X19-X29 and return to `+0x16aa4c` are checked. Acquisition uses the
inherited synthetic provider in `verify_vm9_signer_objects.native`: it writes
only the first eight pair bytes with environment `0x70007800`, returns X0=0 and
redirects to LR. The original acquisition body and a real ART/JVM do not execute.
The pair's second word retains `0xffffff2300000000`; this is inherited data,
not a verified TLS owner. The descriptor remains unchanged at return.

The 1887-point segment stops before the next `+0x16aa48` VM BLR at cursor
`+0x109c44`, selecting `+0x288794 -> +0x282b84`. That call, wrapper and target
do not execute; the next X0 is only a static descriptor interpretation.
The complete observation path and observed code reconstruct the trace digest;
target entry and the final unexecuted BLR are observations, not executed native
acquisition instructions. Allocator, service, inherited JNI/SVC and explicit
syscall-172/173 ledgers stay unchanged. The acquisition-provider event is
recorded separately. No provider or import binding is added, and no native
snapshot is supplied to a Python semantic model. Eight independent original
wrapper/provider controls cover two image bases, cross-page pairs and zero/nonzero
environment values, checking the entire payload memory and preserved pair tail.
This is one synthetic class0 continuation, with native acquisition, later
VM/suffix return and complete signing still open. Use `--capture` or `--replay`
with `--elf` and `--libc`, or omit arguments for frozen validation. See the
[JNI provider-return evidence](../evidence/vm9_native_171_jni_provider_return_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Frozen
validation rejects 48 damaged variants with repaired row digests for semantic
mutations. All 656 Python files compile; public scanning, three invalid CLI
combinations, frozen overwrite refusal with an unchanged evidence hash, and
whitespace checks pass.

`verify_vm9_native_171_thread_pointer_before_jni_dynamic_20261122.py` continues
the verified getppid return through the native `+0x28876c -> +0x204f58` thread
pointer callback. **Sample verified**: the cold cache at `+0x3da090` changes from
zero to the inherited synthetic TPIDR_EL0 value `0x7000a000`. The original MRS and
eight-byte store at `+0x205020` execute, and the following eight cache bytes stay
unchanged. The wrapper stores the full X64 result at descriptor+8, preserves the
other descriptor bytes, restores SP/X19-X29 and returns. Two original helper
calls at `+0x20513c` advance LR by 12 and 20 bytes; the skipped bogus stack
instructions do not execute. The getppid callback records, instruction/code
receipt, import provenance and allocation prefix must match before continuation.

This segment has 2269 instruction observations. Its callback cursor is
`+0x109b60`; the next call cursor is `+0x109bbc`. Execution stops before the
`+0x16aa48` VM BLR selecting wrapper `+0x288788` and JNI environment acquisition
target `+0x26edc4`. The descriptor, wrapper code and mapped output pair are bound;
the target argument is described statically. That VM call, its wrapper, target
body and JNI provider do not execute. Allocator, service, JNI, SVC and explicit
syscall-172/173 ledgers stay unchanged. No new provider, import binding or native
snapshot-fed Python model is introduced. Frozen capture rejects 46 damaged
variants, including repaired row digests for semantic mutations. This remains
one synthetic class0 control; JNI acquisition, later VM/suffix return, complete
signing, ordinary Cronet six headers, Android, physical PAC and online acceptance
remain unverified. Use `--elf`, `--libc`, `--replay`, or omit arguments for frozen
validation. See the
[thread-pointer/JNI-boundary evidence](../evidence/vm9_native_171_thread_pointer_before_jni_dynamic_20261122.json).

Independent fresh ELF/Bionic replay matches the frozen JSON exactly. All 655
Python files compile; public scanning, three invalid CLI combinations, frozen
evidence overwrite refusal and whitespace checks pass.

`verify_vm9_native_171_getppid_import_return_dynamic_20261122.py` continues
the returned getpid control through twelve further callbacks and a returned
getppid callback. **Sample verified**: the getpid receipt's instruction path,
trace/code digests, import bindings, descriptor provenance, syscall 172 and
return fields match before continuation. The new segment completes two shared
reader pairs and four diagnostic entry/exit pairs. All thirteen calls bind
wrapper bytes, descriptor arguments, output/padding and exact call/return
indices, and restore SP/X19-X29. Reader count is zero at the final boundary;
the other bytes in each observed shared-reader object are preserved.

ELF `.rela.dyn` symbol 59 identifies the getppid ABS64 slot `+0x3833b8`, with
zero addend, resolved to matching Bionic `+0x6a36c`. The existing getpid binding
is preserved. The original VM reads this slot at `+0x109b2c`, stores virtual
register 1, then writes the descriptor at logical bytecode `+0x109b30` with
the observed cursor at `+0x109b34`. Two actual reads and two actual stores bind
that source chain; the binding does not write the descriptor. getppid executes
libc syscall 173 with an explicit synthetic parent PID `17`. The wrapper
replaces the earlier test PID `919` in its four-byte result field and preserves
the adjacent padding. No host process is queried and the public loader is
unchanged. The 13291-observation segment stops before `+0x16aa4c` resumes.

One 48-byte malloc is added, with no free. Inherited service/JNI/SVC ledgers
stay unchanged; the inherited syscall 172 and the added syscall 173 each have
their own explicit records. Frozen capture rejects 143 damaged variants.
Independent fresh ELF/Bionic replay matches the frozen JSON exactly. Three
invalid CLI combinations and frozen-evidence overwrite attempts are rejected;
654 Python files compile, and the public scan and whitespace checks pass.
This remains one synthetic class0 control. No native snapshot supplies a Python
model. Later VM work, suffix return,
complete signing, ordinary Cronet six headers, Android, physical PAC and online
acceptance remain unverified. Use `--elf`, `--libc`, `--replay`, or omit arguments
for frozen validation. See the
[getppid import and return evidence](../evidence/vm9_native_171_getppid_import_return_dynamic_20261122.json).

`verify_vm9_native_171_getpid_import_return_dynamic_20261122.py` resolves the
preceding NULL callback's import provenance and returns through the original
wrapper. **Sample verified**: `.rela.dyn` symbol 20 identifies the eight-byte
`getpid` ABS64 relocation at `+0x3833b0`, with zero addend, resolved to matching
Bionic `+0x1fe6c`. After the prior 26 callbacks return, only this import slot is
bound. The adjacent getppid slot stays zero; the public loader is unchanged.
The original VM reads the import at bytecode `+0x109628`, stores virtual register
1, then transfers that value into the descriptor at `+0x10962c`. For the latter
operation the observed cursor has advanced to `+0x109630`. The two reads and two
stores bind their code bytes, addresses, register values and observation indices.
The original VM builds the descriptor; the binding never writes it directly.

All 26 earlier callback records and the full 28561-observation instruction/code
prefix match the old receipt through its indirect-call boundary. The pending
descriptor differs only in its resolved function word. The native getpid cold
path reads a zero cached PID, executes libc syscall 172 and receives the explicit
synthetic result `919`. The original wrapper stores exactly W0 at descriptor+8,
preserves the padding from +12 onward, restores SP/X19-X29 and returns to
`+0x16aa4c`. The 16-point continuation includes that unexecuted final VM boundary.
Observed TLS bytes and the zero PID cache remain unchanged. Inherited allocator,
service, JNI and SVC ledgers match the prior receipt; the added syscall 172 is
recorded separately, so this is one additional libc SVC. No host PID is read and
no native memory seeds a Python model. Frozen capture rejects 52 damaged variants,
including semantic mutations with repaired row digests. Independent fresh
ELF/Bionic replay matches the frozen JSON exactly. Three invalid CLI combinations
and attempts to overwrite frozen evidence are rejected; 653 Python files compile,
and the public scan and whitespace checks pass. Suffix return, getppid,
complete dynamic linking, standalone signing, ordinary Cronet six headers, Android,
physical PAC and online acceptance remain unverified. Use `--elf`, `--libc`,
`--replay`, or omit arguments for frozen validation. See the
[getpid import and return evidence](../evidence/vm9_native_171_getpid_import_return_dynamic_20261122.json).

`verify_vm9_native_171_post_configuration_callback_boundary_dynamic_20261122.py`
continues the configuration boundary through 26 further returned callbacks,
then stops before `blr x8` at `+0x288648`. **Sample verified**: descriptors,
seven wrapper code ranges, target arguments, result stores and padding, return
indices, SP and X19-X29 restoration are checked. Two shared-reader pairs change
the count `0 -> 1 -> 0` while preserving the other receiver bytes. The original
time helpers convert the inherited clock provider's timespec through
microseconds and milliseconds to `1791023800` seconds. The added segment has
28561 instruction observations, including its unexecuted final BLR; VM call
cursors span `+0x108bdc..+0x10963c`. It adds five mallocs, five frees and one
explicit clock call; JNI, Java dispatch and libc/main-image SVC ledgers stay
unchanged. No provider is added and no native memory seeds a Python model.
Frozen capture rejects 254 damaged variants, including repaired row digests
for semantic-field mutations. Three invalid CLI combinations and attempts to
overwrite frozen evidence are rejected.
Independent fresh ELF/Bionic replay matches the frozen JSON exactly; 652
Python files compile, and the public scan and whitespace checks pass.

At the final `+0x28863c` wrapper, the descriptor's first word and X8 are zero.
The saved caller frame, unchanged descriptor and first three executed wrapper
instructions are checked before the fourth instruction, the indirect call.
The callback body, result store at `+0x28864c` and callback return do not execute.
This is the current synthetic class0 control's unresolved input boundary; it
does not establish a NULL callback or crash in the real Android app. Recovering
the callback slot's construction/publication provenance is the next dependency.
The earlier independent second-VM fixture reached the same bytecode cursor and
bound getpid/getppid through ELF ABS64 metadata (see
[section 6.185](../REQUEST_JNI_STARTUP_WORKERS.md#6185-second-vm-process-id-callbacks2026-10-15-asiashanghai)).
That is a lead for checking this execution's descriptor source; this record
does not infer its target from the independent fixture.
Suffix return, standalone signing, ordinary Cronet six headers, Android and
online acceptance remain unverified. Use `--elf`, `--libc`, `--replay`, or omit
arguments for frozen validation. See the
[callback-boundary evidence](../evidence/vm9_native_171_post_configuration_callback_boundary_dynamic_20261122.json).

`verify_vm9_native_171_post_scope_configuration_dynamic_20261122.py` continues
the verified scope-cycle boundary through 32 further VM callbacks. **Sample
verified**: guard acquisition/release, formatting, five copies, StringObject
construction/destruction and configuration reads return in the original VM's
observed order. Ten wrapper code ranges, target arguments, descriptor result
stores and adjacent padding are bound. SP and X19-X29 restore on every return;
reader count is zero at each callback boundary. VM call cursors advance from
`+0x10769c` to `+0x108bb8`, with 45352 instruction observations including the
final unexecuted `+0x16aa4c` boundary. Allocator events add 12 mallocs and seven
frees; the only explicit service delta is one destructor registration.
One Java-dispatch entry uses the inherited explicit NULL-result provider;
early/late JNI and libc/main-image SVC ledgers stay unchanged. The five copies
are 16/16/16/48/192 bytes and preserve their source bytes. They use the existing
memcpy provider, so this record does not claim native Bionic memcpy-body or
ART/JVM execution. No new provider or native-snapshot-fed Python model is added.
The verifier rejects 350 damaged evidence variants and three invalid CLI
combinations. Independent fresh ELF/Bionic replay matches the frozen JSON
exactly. This remains a single synthetic class0 control; complete heap or
business equivalence, suffix return, standalone signing, ordinary Cronet six
headers, Android and online acceptance remain unverified. Use `--elf`, `--libc`,
`--replay`, or no arguments for frozen validation. See the
[configuration continuation evidence](../evidence/vm9_native_171_post_scope_configuration_dynamic_20261122.json).

`verify_vm9_native_171_post_reader_scope_cycles_dynamic_20261122.py` continues
the eight-callback boundary below. **Sample verified**: the pending scope exits,
seven further scope entry/exit pairs complete, and one `+0x2633a4` getter returns.
Its X0 is zero while its 16-byte output contains two nonzero words; this does
not establish the business meaning or construction provenance of that result.
All 16 callbacks restore SP and X19-X29. The observed scope uses the original
`+0x288530/+0x288540` wrappers; each selected mutex moves `0x4000/0 -> 0x4001/137`
on entry and back on exit. Scope padding, all other selected-entry bytes and
the 2048-byte diagnostic table are checked. VM call cursors span
`+0x1070a4..+0x10766c`; the prior eight calls, trace/code digests and allocation
prefix must match their frozen record before continuation. This stage adds
18689 instruction observations, including its final unexecuted return boundary,
and no allocator, explicit service, JNI, Java-dispatch or SVC events. It rejects
207 damaged variants and three invalid CLI combinations. Independent fresh
ELF/Bionic replay matches the frozen JSON exactly. At the final
`+0x16aa4c` stop, the observed scope is closed. Later VM work, suffix return,
complete signing, ordinary Cronet six headers, Android and online acceptance
remain unverified; one synthetic class0 control is covered. No native snapshot
is supplied to a Python model. Use `--elf`, `--libc`, `--replay`, or omit arguments
for frozen validation. See the
[scope-cycle evidence](../evidence/vm9_native_171_post_reader_scope_cycles_dynamic_20261122.json).

`verify_vm9_native_171_post_reader_callbacks_dynamic_20261122.py` continues
the accepted shared-reader release on the same Unicorn CPU. **Sample verified**:
eight callbacks return in order: `+0x32a444`, `+0x26c858`, `+0x26c9d0`,
`+0x32a4fc`, `+0x257804`, `+0x257880`, `+0x248344`, `+0x26c858`.
The repeated reader pair moves its count from 0 to 1 and back to 0; the getter
returns are zero. Six original wrapper code ranges, descriptor words, target
argument registers, result stores and adjacent descriptor bytes are checked.
Each callback restores SP and X19-X29. The continuation records 8566 instruction
observations, including its final unexecuted VM return boundary; code/trace
digests and call/return indices are frozen. Two native allocations of 48 and
1 bytes are added; frees, explicit services, early/late JNI, Java dispatch,
libc SVC and main-image SVC ledgers do not increase. It rejects 113 damaged
variants and three invalid capture/replay CLI combinations. Fresh ELF/Bionic
replay matches the complete frozen JSON exactly. The record stops
before `+0x16aa4c` after the eighth callback; that last diagnostic scope still
needs cleanup. It covers one synthetic class0 control and supplies no native
snapshot to a Python model. Suffix return, complete standalone signing,
ordinary Cronet six headers, Android and online acceptance remain unverified.
See the [post-reader callback evidence](../evidence/vm9_native_171_post_reader_callbacks_dynamic_20261122.json).
Omit arguments for frozen validation, or run:

```powershell
python platforms/bytedance/tomato/python/verify_vm9_native_171_post_reader_callbacks_dynamic_20261122.py --elf <matching-private-so> --libc <matching-private-libc> --replay
```

`verify_vm9_native_171_diagnostic_scope_entry_dynamic_20261121.py` continues
the accepted shared-reader return through the diagnostic callback at
`+0x288530 -> +0x26c858`. **Sample verified**: the mapped 24-byte descriptor
binds target, object and input word `0x136d9140`; all 61 observed target
instructions return with X0 zero to `+0x16aa4c`. The 24-byte object changes
from `...40906d13` to `...40916d13`, with before/after SHA-256 values frozen.
The malloc count increases by one; explicit service, JNI, libc-SVC and
main-image-SVC ledgers stay unchanged. Execution stops before the resumed VM
instruction. Sixteen damaged variants are rejected. This does not establish
the following cleanup, current suffix return, complete signer, ordinary Cronet
headers, Android execution or online acceptance. Run with `--elf`, `--libc`,
`--replay` for fresh execution; without arguments it validates frozen evidence.
See the [diagnostic-entry evidence](../evidence/vm9_native_171_diagnostic_scope_entry_dynamic_20261121.json).

`verify_vm9_native_171_diagnostic_cleanup_entry_dynamic_20261121.py` resumes
after the diagnostic callback returns to `+0x16aa4c`. **Sample verified**:
1168 VM instruction observations reach `blr x8` at `+0x16aa48`, target wrapper
`+0x288540`, and its three-instruction descriptor path to `+0x26c9d0`. The
descriptor's first word identifies the cleanup target and its second word
identifies the same scope object updated by the preceding callback. Execution
stops at the cleanup target entry before its body; the object hash and all
allocator, service, JNI and SVC ledgers remain unchanged across this continuation.
Eighteen damaged variants are rejected. Cleanup execution, later VM work,
current suffix return and complete signing remain unverified. Use `--elf`,
`--libc`, `--replay` for fresh execution; see the
[cleanup-entry evidence](../evidence/vm9_native_171_diagnostic_cleanup_entry_dynamic_20261121.json).

`verify_vm9_native_171_diagnostic_cleanup_return_dynamic_20261121.py` executes
the original `+0x26c9d0` cleanup body and stops before resumed VM instruction
`+0x16aa4c`. **Sample verified**: the selected table entry reaches the original
pthread unlock path at `+0x347f10`; its mutex changes from state `0x4001`/owner
`137` to `0x4000`/owner `0`. The 24-byte scope object remains unchanged, X0
returns zero, and allocator, explicit service, JNI and SVC ledgers do not change.
Sixteen damaged variants are rejected. Later VM instructions, suffix return and
complete signing remain unverified. Use `--elf`, `--libc`, `--replay`; see the
[cleanup-return evidence](../evidence/vm9_native_171_diagnostic_cleanup_return_dynamic_20261121.json).

`verify_vm9_native_171_shared_reader_release_dynamic_20261121.py` continues
that cleanup return through `+0x2885e0` to shared-reader release `+0x32a4fc`.
**Sample verified**: the descriptor selects the same receiver used by the
earlier acquire callback. Its reader count at `+0x88` changes from 1 to 0;
all other bytes in the observed `0x90`-byte object stay unchanged, and the full
object matches its bytes before acquisition. Original lock/unlock helpers
execute; the mutex, stack pointer and X19-X29 are restored before returning
to `+0x16aa4c`, where observation stops before the caller instruction.
Allocator, explicit service, JNI and SVC ledgers remain unchanged. This is
native execution evidence with no native snapshot supplied to a Python model.
It rejects 27 damaged evidence variants; fresh replay matches the frozen record.
Writer/signal/wait paths, physical PAC authentication, later VM work, suffix
return and complete signing remain unverified. Use `--elf`, `--libc`, `--replay`
for fresh execution, or no arguments for frozen validation. See the
[reader-release evidence](../evidence/vm9_native_171_shared_reader_release_dynamic_20261121.json).

`verify_vm9_native_171_shared_reader_return_dynamic_20261121.py` executes the
resolved `+0x32a444` callback on the same Unicorn CPU. **Sample verified**:
the uncontended path calls the original lock/unlock helpers, increments the
receiver's u32 reader count at `+0x88` from 0 to 1, and preserves every other
byte in the observed `0x90`-byte object. The native canary save, restored stack
and X19-X29, original `ret`, and return to `+0x16aa4c` are checked; execution
stops before that resumed caller instruction. Allocator, service, JNI and SVC
ledgers match the prior resolution boundary. This adds no provider or Python
model seeded with native memory. The existing semantic reader owner remains
`vm9_objects.acquire_uncontended_shared_reader`; this verifier observes native
execution rather than adding a second model. It rejects 23 damaged variants;
a fresh native replay matches the captured result exactly.
Waiting/writer branches, physical PAC authentication, subsequent VM execution,
current suffix return, complete signing, Android and online acceptance remain
unverified. See the [reader-return evidence](../evidence/vm9_native_171_shared_reader_return_dynamic_20261121.json).
Run with `--elf <matching-private-so> --libc <matching-private-libc> --replay`
for a complete native rerun, or no arguments for frozen-evidence validation.

`verify_vm9_native_171_next_vm_indirect_call_dynamic_20261121.py` resumes the
VM after the random wrapper returns to `+0x16aa4c`. **Sample verified**:
857 instruction observations lead to the next `blr x8` at `+0x16aa48`, whose
target is `+0x2885e0`; this record stops before the call. It rejects six
damaged variants. See the [next-call evidence](../evidence/vm9_native_171_next_vm_indirect_call_dynamic_20261121.json).

`verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121.py` executes
that three-instruction trampoline. **Sample verified**: the descriptor's
first word becomes the `br x1` target `+0x32a444`, and its second word becomes
the callback argument. This record stops before that tail branch and rejects
eight damaged variants; a fresh `--replay` matches the frozen result exactly.
It establishes callback resolution, with no callback-target execution in this
record. See the [resolution evidence](../evidence/vm9_native_171_resolve_next_vm_callback_dynamic_20261121.json).
Both verifiers accept `--elf <matching-private-so> --libc <matching-private-libc>
--replay`; omit these arguments for frozen-evidence validation. They retain the
explicit inherited OS/JNI providers and establish no current suffix return,
ordinary Cronet six headers, standalone signer, Android or online result.

`verify_vm9_native_171_random_callback_dynamic_20261121.py` continues the
accepted gettimeofday dynamic prefix through its warm indirect random getter.
The pinned ELF target is `+0x26cc8c`; the matching Bionic `rand` PLT is called
on the same Unicorn CPU, then the original wrapper writes the returned `W0` to
the callback object's `+8` slot at `+0x28864c`. The result slot matches the
return register and adjacent padding is preserved. Canary comparison occurs
after the native prologue saves it. The initial capture stops before wrapper
epilogue; the follow-on replay below independently continues that boundary.
This does not claim caller-body execution, current suffix return, ordinary
Cronet six headers, Android execution, online acceptance or a complete signer.
Evidence is [here](../evidence/vm9_native_171_random_callback_dynamic_20261121.json);
run the verifier with `--elf`, `--libc`, `--capture` or `--replay`.

`verify_vm9_native_171_random_wrapper_return_dynamic_20261121.py` continues the
same warm native callback through the original `ldp/ret` epilogue and confirms
return to VM dispatch address `+0x16aa4c`, stopping before its first instruction.
Both records reject damaged variants and replay deterministically. It does not
execute the caller body, the next AST callback, cleanup or the current suffix
return; ordinary Cronet headers, Android execution, online acceptance and a
complete signer remain unverified. See the
[wrapper return evidence](../evidence/vm9_native_171_random_wrapper_return_dynamic_20261121.json).

`verify_vm9_native_171_post_digest_svc_boundary_20261120.py` continues the
accepted original digest execution and freezes the first unpermitted main-image
SVC boundary. It keeps the four-SVC, two-handler-read and 400000-instruction
limits, and stops before the fifth SVC handler. Fresh ELF/Bionic replay binds
syscall 169 to the pinned `gettimeofday` thunk and statically links its caller's
`LR`, timeval pointer (`sp+8`) and NULL timezone to the return instructions.
The success/error result selection and optional output store are static ELF
semantics; the syscall return is not dynamically executed. Current suffix
return, configuration provenance, ordinary Cronet six headers, online
acceptance and complete standalone signer remain unverified. Use `--elf`,
`--libc`, `--replay`; see the
[gettimeofday boundary evidence](../evidence/vm9_native_171_gettimeofday_return_20261120.json).

`verify_vm9_native_171_gettimeofday_dynamic_20261121.py` continues one
class0 control through the explicit syscall 169 provider and the observed
gettimeofday return/caller instructions. It preserves the four inherited
main-image SVC boundaries while recording the dynamic fifth syscall. The next
native boundary is `+0x288648` (`blr x8`); replay stops before executing its
indirect target and records the matching object first word and function
pointer. The class0 path observes two late synthetic JNI calls and does not
reach the Java dispatcher before this boundary. This remains synthetic
Unicorn evidence: no ART/JVM execution, current suffix return, ordinary
Cronet six headers, online acceptance or complete standalone signer is
claimed. Use `--elf`, `--libc`, `--capture` or `--replay`; see the
[dynamic gettimeofday evidence](../evidence/vm9_native_171_gettimeofday_dynamic_20261121.json).

`verify_vm9_native_171_suffix_digest_20261120.py` verifies current original
scratch/header reads, constant string construction, mode-zero raw MD5,
reference assignment and temporary release. Native digest bytes obey the MD5
relation to source bytes within that same execution; they never seed Python.
The count transitions 1 to 2 to 1, with exactly five allocations of sizes
17/24/17/48/4 and no frees. One diagnostic slot is created from the digest
object index: the new mutex, exact pointer slot, all other table bytes, old
guard/global state and eight balanced lock events are checked. Input/frame,
source, old non-diagnostic heap/TLS/constants remain preserved. The complete
accepted constant-stage instruction/code/allocation prefix agrees before only
its observer retires. Execution stops at +0x286e10 before the next sized string
and version word, with no new service/JNI/SVC. Sixteen independent component
controls at two bases execute the existing suffix source prefix with declared
length/mode/warm/NULL cases, matching full semantic guest/image, selected
scratch objects and ordered effects/pre-free/live-block state. Physical spills
and void X0 are excluded. Four current controls, four new and four old CLI
replays, sixteen component replays, four bad CLI calls, thirteen instruction
bindings and 156 damaged-evidence rejections pass. No duplicate owner/provider
or native-snapshot model input is introduced; limits remain 400000/2/4.
Current suffix return, configuration provenance, whole-request equality,
ordinary six headers, online acceptance and complete signer remain unverified.
Use `--elf`, `--libc`, `--replay`; see the
[digest evidence](../evidence/vm9_native_171_suffix_digest_20261120.json).

`verify_vm9_native_171_suffix_constants_20261120.py` enters the actual current
suffix wrapper/body and checks three ELF selector/decoder calls and release
flag stores. Constant destinations, padding and flags equal independently
initialized ELF pages using the existing suffix owner's source prefix. The
input frame, header, TP/canary, old TLS/heap/tables and allocation ledger are
preserved. The complete accepted call instruction/code/allocation prefix is
checked before retiring only its observer. Execution stops at +0x286ce8,
before further scratch setup and the first string constructor; no allocator,
service, JNI or SVC delta occurs. Sixteen independent native/source-prefix
controls cover both bases and all eight warm-flag combinations, comparing
full semantic guest/image bytes and cold-only decoder arguments. No native
snapshot seeds the model and no duplicate decoder or provider is introduced.
Four current controls, four new and four old CLI replays, sixteen component
replays, four bad CLI calls, thirteen instruction bindings and 126 damaged
evidence rejections pass. Bounds remain 400000 observations / two handler
reads / four main SVCs. Current suffix return, configuration provenance,
whole-request equality, ordinary six headers, online acceptance and complete
signing remain unverified. Use `--elf`, `--libc`, `--replay`; see the
[constant evidence](../evidence/vm9_native_171_suffix_constants_20261120.json).

`verify_vm9_native_171_configuration_suffix_call_20261120.py` verifies seven
original words preparing the frame+2088 header, helper +0x2869f0 and wrapper
+0x285e80 in packed frame+2752. Two loads, two eight-byte stores, selected and
unselected registers, padding and the surrounding 8 KiB window are checked.
The complete copy56 instruction/code/allocation prefix agrees before only
copy56_active retires; original scope remains live. Current execution stops
at +0x16aa48 before entering the wrapper, with no allocator/service/JNI/SVC
delta and preserved header, old TLS/heap/tables and count1 references.
Four separately declared VM cases execute the same words and actual request
callback, reusing construct_request_suffix for complete non-NULL outputs.
Four original suffix-helper controls from independent inputs match the actual
callback's full semantic guest/image bytes, output slots, ordered ownership
effects, pre-free payloads and live blocks. Allocator, initialized SDK, thread137
and atoi0 remain explicit inputs from the existing suffix fixture; physical
stack spills and void X0 are excluded. Native snapshots never seed Python.
Four current native handoffs, four independent new CLI replays, four exact old
copy rows, four declared VM/helper controls and CLI replays, four bad CLI calls,
seven instruction bindings, seven ELF words and 166 damaged-evidence
rejections pass. Limits remain 400000 observations, two handler reads and four
main SVCs, with no new provider or Android execution. Complete current-request
suffix return, numeric/whole-request equality, business/configuration provenance,
ordinary six headers, online acceptance and complete signing remain unverified.
Use `--elf`, `--libc`, `--replay`; see the
[suffix call evidence](../evidence/vm9_native_171_configuration_suffix_call_20261120.json).

`verify_vm9_native_171_configuration_copy56_20261120.py` binds 27 original
words after the TLS store. They prepare the scalar/string/seed/output-pointer
header at frame+4920, mode0 and preserved final four-byte padding, save three
pointers and pack a 56-byte memcpy to frame+2088. The original tail-call wrapper
reaches the memcpy PLT entry; the existing oracle memory-import provider
performs the copy and returns the destination in X0. Acceptance covers original
argument preparation and wrapper/import ABI, not a Bionic memcpy body. Source, destination adjacent
eight bytes, all 5 KiB frame bytes outside allowed write ranges, old TLS/hash,
clone/tables and both count1 references remain intact. Six loads, 14 argument
stores and selected/unselected registers are checked as native instruction
contracts. The 8 KiB surrounding window also stays unchanged except its
separately checked native cursor/register backing. Four fresh declared VM cases (two bases, small/wide scalars) execute
the actual request callback on separate pages; no native snapshot seeds Python
and no current-request numeric equality is claimed. Four native continuations,
four independent new CLI replays, four exact old setter rows, four declared VM
cases and CLI replays, four bad CLI calls, 13 instruction bindings, 27 words,
one frame-allocation word, two memcpy relocations and 213 damaged-evidence rejections pass.
The complete old instruction/code/allocation prefix agrees before retiring
only store_active. Original scope remains live; copy56 observer fields are
separate from earlier contained-reference copy fields. Allocation/service/JNI/
libc/main-SVC ledgers stay unchanged, read/main-SVC caps remain 2/4, and no new
provider or Android execution is introduced. Stop before consuming the copy
return; next word +0xfd698. Suffix return, full configuration provenance,
business identity, key generation, current/whole-request equality, ordinary
six headers, online acceptance and complete signing remain unverified.
Use `--elf`, `--libc`, `--replay`; see the
[configuration copy evidence](../evidence/vm9_native_171_configuration_copy56_20261120.json).

`verify_vm9_native_171_configuration_tls_store_20261119.py` verifies 16
original words after the TLS getter: scalar/hash/opaque-input XOR, ror64 by
60, low32 sign extension, signed getter-word XOR and a four-byte packed input.
The original tail-call wrapper invokes the actual setter/warm emutls and
stores that uint32 into the existing TLS slot, returning its existing pointer.
TLS and packed adjacent 12 bytes, prior getter word/hash/clone/tables,
descriptor/array and both count1 references remain intact. Fresh declared VM
pages instead use separate hash/scalar/index8 inputs and getter words zero,
all bits and high bit; six VM cases execute the actual request callback source
and check a direct arithmetic expression. Six original warm setter controls
with declared derived words match the actual callback's guest/image/TLS bytes,
packed padding and allocation/wake behavior. Native snapshots never seed
Python, and current-request numeric equality is not claimed. Four native
continuations, four independent new CLI replays, four exact old getter rows,
six fresh setter controls and replays, four bad CLI calls, 17 instruction
bindings, 16 words, one GOT relocation and 201 damaged-evidence
rejections pass. The full prior instruction/code/allocation prefix agrees
before only its completed getter observer retires; original scope stays live.
Allocation/free and service/JNI/libc/main-SVC ledgers stay unchanged, with
read/main-SVC limits 2/4, no new providers or Android run. Stop before consuming
the setter return; next word +0xfd62c. Full configuration provenance, business
identity, key generation, current-request/whole-request equality, ordinary six
headers, online acceptance and complete signing remain unverified. Use
`--elf`, `--libc`, `--replay`. See the
[TLS store evidence](../evidence/vm9_native_171_configuration_tls_store_20261119.json).

`verify_vm9_native_171_configuration_tls_20261119.py` verifies the original
flags OR256 and a cold TLS variable in an initialized thread array. It executes
12 words through the actual getter/emutls bodies: native index 0 becomes 5,
one 19-byte allocation supplies block+8, and the zero uint32 result writes
four bytes at frame+2808 while adjacent 12 bytes, prior hash, clone, tables
and both count1 references stay intact. Fresh declared pages instead use
counter7/index8, the actual request callback source and the existing TLS
owner; two fresh VM cases and two original getter controls compare those
declared semantics. Native snapshots never seed Python inputs, and the current
and declared indices/hashes are not compared. The existing TLS native fixture
now selects warm pthread key pages by completed once state, including a cold
descriptor; all 14 old fixture cases pass. Four original continuations, four
independent CLI replays, four exact old hash rows, two declared native TLS
controls and replays, four bad CLI calls, 32 instructions, 12 words, one GOT
relocation and 261 damaged-evidence rejections pass. The full prior
instruction/code/allocation prefix agrees. Only the completed hash observer
retires; original scope stays live. Service/JNI/libc/main-SVC ledgers and
read/main-SVC limits 2/4 stay unchanged, with no new providers or Android run.
The TLS return is not consumed; next word +0xfd5ec. Current-request hash numeric
equality, complete TLS heap/physical stack equivalence, full provenance, key
values, ordinary six headers, whole-request equivalence, online acceptance
and complete signing remain unverified. Use `--elf`, `--libc`, `--replay`. See
the [TLS evidence](../evidence/vm9_native_171_configuration_tls_20261119.json).

`verify_vm9_native_171_configuration_hash64_20261119.py` continues through
the warm registry flag branch into the preserved clone's original uint64
table hash. Guard bit0 is one, so cold initialization is skipped. Registry
pointer reads, GOT target, clone argument and wrapper sources are bound.
The original executes ten rounds using its immutable ELF table. Native
operand observations verify pointer advances, table indices, shifted XORs
and remaining counts; they never seed a Python model. X0 is stored as eight
bytes at packed+16/frame+2832. Clone, table, owner and both count1 references
stay intact. Fresh VM pages instead use declared clone bytes and a synthetic
table; two fresh original helper controls with those same declared inputs
match Python numeric results and declared guest arena bytes. Those independent inputs are
not the current request's inputs: current-request numeric Python equality
is not claimed. No standard CRC variant is assumed. Four native continuations,
four independent CLI replays, four exact old-owner rows, two fresh declared
helper controls and replays, four bad CLI calls, 30 instruction bindings,
21 words, one new GOT relocation and 265 damaged-evidence rejections
pass. The complete prior prefix agrees before its completed observer retires;
original scope execution stays enabled. Allocation/free, service, JNI and
SVC ledgers are unchanged with read/main-SVC limits 2/4 and no new providers
or Android execution. The hash return is not consumed; next word +0xfd5bc.
Cold initialization, full configuration provenance, business identity/state,
key values, ordinary six headers, whole-request equivalence, online acceptance
and complete signing remain unverified. Use `--elf`, `--libc`, `--replay`. See
the [clone hash64 evidence](../evidence/vm9_native_171_configuration_hash64_20261119.json).

`verify_vm9_native_171_configuration_owner_cleanup_20261119.py` checks the
next retained configuration reference. R17/R18 match owner fields +160/+168
and differ from the already released clone source reference. The original
enters the warm scope, writes count2->1 as four bytes, preserves adjacent
twelve bytes and takes the positive branch past deletion. A frame-held GOT
slot pointer supplies the exit target; frame+2032 supplies the scope in R20.
The original exits at +0xfd424 with X0=0, restoring the lock to 0x4000/owner0.
Owner, reference pair, source, clone and payload stay intact; both counters
end at one. Fresh Python VM pages execute 21 words including the scope-enter
CALL at two bases, and the existing scoped-reference owner independently
checks selected cleanup semantics on its own aligned stack. No native memory
seeds either model. Only the completed prior cleanup observer retires after
the entire accepted prefix agrees; original scope execution stays enabled.
Four native controls, four independent CLI replays, four exact old-cleanup
rows, four bad CLI requests, 17 instruction bindings, 22 bytecode words,
two GOT relocations and 247 damaged-evidence rejections pass.
Allocation/free, service, JNI and SVC ledgers remain unchanged, with limits
of two handler reads/four main SVCs and no new providers or Android execution.
The exit return is not consumed; the next word is +0xfd428. Deleting cleanup,
full configuration provenance, business identity/state, key values, ordinary
six headers, whole-request equivalence, online acceptance and complete
signing remain unverified. Use `--elf`, `--libc`, `--replay`. See the
[owner reference cleanup evidence](../evidence/vm9_native_171_configuration_owner_cleanup_20261119.json).

`verify_vm9_native_171_configuration_cleanup_20261119.py` continues the
original request after its configuration clone. It enters the existing warm
diagnostic scope, reads the copied reference counter, stores only count2->1
as four bytes, preserves the adjacent twelve bytes, takes the positive-count
branch over deletion and executes the matching unlock. X0 is zero; the lock
returns to state 0x4000/owner0, while the reference pair, source, clone and
payload remain intact. Fresh Python VM pages exercise the argument, count
and branch words with existing diagnostic owners at both image bases; an
independent scoped-reference helper checks the selected cleanup semantics
on its own aligned stack. No native memory seeds either model, and no
physical stack identity is claimed. Completed observer windows retire only
after the entire clone prefix agrees; original diagnostic execution stays
enabled. Four native cases, four independent CLI replays, four exact old
clone rows, four bad CLI calls, 17 instruction bindings, 25 bytecode words,
two GOT relocations and 221 damaged-evidence rejections pass.
Allocation/free, service, JNI and SVC ledgers are unchanged; read/main-SVC
limits remain 2/4 with no new providers or Android execution. Observation
stops before consuming the cleanup exit return; the next word is +0xfd390.
Deleting cleanup, full configuration provenance, business state/identity,
key values, ordinary six headers, whole-request equivalence, online
acceptance and complete signing remain unverified. Use `--elf`, `--libc`,
`--replay`. See the
[configuration cleanup evidence](../evidence/vm9_native_171_configuration_cleanup_20261119.json).

`verify_vm9_native_171_configuration_clone_20261119.py` continues the
original request from the copied configuration reference into its string clone.
Nine argument bytecodes match independent fresh Python VM pages at two bases;
the ELF-relative target, frame sources, packed arguments, unselected registers
and neighboring bytes are bound. The original clone reads length 10, allocates
11 bytes, copies the declared length, appends zero and returns its new payload.
Source header/payload, copied reference/count, lock table and destination
neighbors are preserved. The allocator ledger records return PC +0x24841c;
the actual allocation BL is +0x248418. Existing Python string ownership uses
fresh declared content with an embedded zero. Selected copy/allocation and
preservation semantics agree; native and model input bytes are independent.
Full configuration value construction and business identity remain unverified.
Four native cases, four independent CLI replays, four exact old-reference
rows, four bad CLI requests, 22 instruction bindings, ten bytecode words and
181 damaged-evidence rejections pass. The complete old instruction,
code and allocation prefix agrees. One 11-byte allocation is added; service,
JNI and SVC ledgers stay unchanged with read/main-SVC limits of 2/4.
Observation stops before consuming the clone return. Saved NULL business
branches, actual business state, KMSV/key values, ordinary six headers,
whole-request equivalence, online acceptance and complete signing remain
unverified. Use `--elf`, `--libc`, `--replay`. See the
[configuration clone evidence](../evidence/vm9_native_171_configuration_clone_20261119.json).

`verify_vm9_native_171_contained_reference_20261119.py` continues the
original configuration reference getter through its scoped copy and unlock.
Eight argument bytecodes match fresh declared Python VM inputs at two bases.
The original getter reads the receiver's member at +24, clears the destination
pair, reloads and copies the source under lock, then retains its u32 counter
from 1 to 2. Adjacent counter/destination bytes, the receiver and selected
source header are preserved. A missing slot in the warm table adds one
48-byte entry, whose recursive lock is released before return. Existing
Python scope/reference owners use fresh declared pages; no native snapshot
seeds them. Full source-pair construction and business identity are unverified.
The prior instruction/code/allocation prefix agrees; services, JNI and SVC
ledgers stay unchanged, with read/main-SVC limits of 2/4. Four native cases,
four independent CLI replays, four exact old-exit rows, four bad CLI requests,
25 instruction bindings, nine bytecode words and 205 damaged-evidence
rejections pass. Observation stops before consuming the getter return.
Saved NULL business branches, real business state, KMSV/key values, complete
request/VM equivalence, ordinary six headers, online acceptance and complete
signing remain unverified. Use `--elf`, `--libc`, `--replay`. See the
[reference-copy evidence](../evidence/vm9_native_171_contained_reference_20261119.json).

`verify_vm9_native_171_kmsv_scope_exit_20261119.py` follows the original
configuration counter retain and the matching diagnostic scope exit.
The selected branch compares the configuration's counter pointer with zero;
it falls through and retains its u32 count from 1 to 2, preserving the next
12 bytes. It does not consume the saved KMSV NULL. The current live counter
allocation is four bytes; address reuse is allowed and full construction
provenance remains unverified. Thirteen argument bytecodes agree with fresh
declared Python VM inputs at two bases. The original exit body tail-calls
matching Bionic unlock, preserving the scope object and table while releasing
the selected recursive lock. Existing Python enter/leave owners independently
construct and release that state. No native memory seeds the model.
The cold scope instruction/code prefix and all allocation/service/JNI/SVC
ledgers agree. Four native cases, four independent CLI replays, four exact
old-scope rows, four bad CLI requests, 23 instruction bindings, 14 bytecode
words and 138 damaged-evidence rejections pass. Read/main-SVC limits remain
2/4. Observation stops before consuming the zero exit return. Saved NULL
business branches, key values, actual business state, full VM equivalence,
ordinary six headers, online acceptance and complete signing remain unverified.
Use `--elf`, `--libc`, `--replay`. See the
[scope-exit evidence](../evidence/vm9_native_171_kmsv_scope_exit_20261119.json).

`verify_vm9_native_171_kmsv_scope_20261119.py` continues the original KMSV
NULL result through its frame spill and the next cold diagnostic scope.
The scope input comes from the configuration object's member at +0xa0;
the selected source frame write and 264/88-byte allocations are observed,
but complete member construction provenance remains unverified.
Existing `vm_full.VM` executes eleven argument bytecodes on fresh declared
pages at two bases. The original scope body and matching Bionic mutexes
execute only after the selected entry enables the existing diagnostic option.
Cold guard, table, selected recursive lock, input and padding agree with
the existing independent `vm9_diagnostics` owner. Three allocations of
48/2048/48 bytes are added; services and JNI/libc/main-SVC rows stay unchanged.
The previous KMSV instruction/code/allocation prefix agrees; read/main-SVC
limits stay 2/4. Four native controls, four independent public CLI replays,
four exact old-KMSV rows, four bad CLI requests, 21 instruction bindings,
12 ELF bytecode words and 150 damaged-evidence rejections pass.
Observation stops before the interpreter consumes the zero return; the
selected entry lock is still held. Scope exit, full VM/physical stack
equivalence, later NULL business branches, KMSV/key values, actual business
state, ordinary six headers, online acceptance and complete signing remain
unverified. Use `--elf`, `--libc`, `--replay`. See the
[KMSV scope evidence](../evidence/vm9_native_171_kmsv_scope_20261119.json).

`verify_vm9_native_171_kmsv_lookup_20261119.py` joins the original
`X-BD-KMSV` ELF decode, separate static guard, ten-byte name construction,
matching-Bionic destructor registration, guard publication and NULL lookup.
The decoder writes nine bytes and preserves the initial zero terminator.
Two bound protection requests surround a uniquely observed registration
record, at byte 112 in all four controls. The request tree still contains
only the declared `X-TEST: value`. Lookup returns NULL and preserves the
other packed bytes; observation stops before the interpreter consumes it.
Existing Python owners run on independent fresh pages and declared inputs.
The previous result's instruction/code/allocation prefix agrees; one ten-byte
allocation and two libc SVC 226 requests are added. JNI/main-SVC rows and
the read/main-SVC limits of 2/4 remain unchanged. Four native cases, four
independent public CLI replays, four exact old-result rows, four bad CLI
requests, 36 instruction bindings, six bytecode words and 118 damaged-evidence
rejections pass. This verifies the name and missing-key behavior. KMSV/key
values, actual business state, full VM/Bionic state equivalence, later NULL
consumption, ordinary six headers, online acceptance and complete signing
remain unverified. Use `--elf`, `--libc`, `--replay`. See the
[KMSV lookup evidence](../evidence/vm9_native_171_kmsv_lookup_20261119.json).

`verify_vm9_native_171_client_key_result_20261119.py` continues the NULL
lookup through its frame-local spill and the next static guard precheck.
The branch consumes that other guard's low bit; it does not consume the
saved lookup result. The original cold guard falls through and prepares
its acquisition callback using a bound ELF GOT relocation. Observation
stops before that callback's bytecode executes. Existing `vm_full.VM` runs
the fifteen selected bytecodes on fresh declared pages at two bases, without
native memory inputs. Six native loads, three frame stores, their selected
adjacent bytes and the remaining virtual registers are checked. Four native
cases reproduce the entire previous lookup row; allocation/service/JNI/SVC
ledgers remain unchanged and read/main-SVC limits remain 2/4. Four independent
public CLI replays, four exact old-lookup rows, four bad CLI requests,
18 instruction bindings, 16 ELF bytecode words and 108 damaged-evidence
rejections pass. Later consumption of the saved NULL, the next guard call,
key values, actual business state, full VM equivalence, ordinary six headers,
online acceptance and complete signing remain unverified. Use `--elf`,
`--libc`, `--replay`. See the
[lookup-result evidence](../evidence/vm9_native_171_client_key_result_20261119.json).

`verify_vm9_native_171_client_key_lookup_20261119.py` continues the original
name constructor through matching-Bionic process destructor registration,
static guard release and a NULL configuration lookup. The original writes
the declared destructor/object/DSO words into its registration page, with
two bound SVC 226 requests (same 4096-byte page, protection arguments 3/1).
The wrapper stores status u32 zero and preserves the other 36 packed bytes.
The guard publishes completion; the current synthetic request tree contains
only `X-TEST: value`, so querying `X-BD-CLIENT-KEY` returns NULL. Its wrapper
stores the actual result at packed+24 and preserves the other 24 bytes.
Existing Python registration/guard/tree owners use fresh declared inputs,
without native memory inputs. Four native cases, four independent public
CLI replays, four exact old-name rows, four bad CLI requests, 16 additional
instruction bindings and 101 damaged-evidence rejections pass. The name's
trace/code prefix and the complete allocation ledger agree; service counts
add only the two explicit libc SVCs. Read/main-SVC limits remain 2/4.
This verifies selected registration, publication and missing-key behavior.
It does not generate a key value, execute process exit, establish full
Bionic/VM state equivalence, restore actual business state, produce ordinary
six headers or verify complete signing. Use `--elf`, `--libc`, `--replay`.
See the [missing-key lookup evidence](../evidence/vm9_native_171_client_key_lookup_20261119.json).

`verify_vm9_native_171_client_key_name_20261119.py` joins the original masked
ELF constant to the `X-BD-CLIENT-KEY` name, cold static guard acquisition and
its StringObject construction. The decoder writes 15 bytes into an initially
zero span; its terminator is preserved. Independent ELF decoding agrees.
The original guard callback returns 1, stores u32 at packed+16 and preserves
the other 20 bytes. The original constructor allocates 16 bytes, creates the
15-byte name plus terminator and returns its actual payload pointer to the
interpreter at `+0x16aa4c`. The static guard is still initializing at this
observation stop. Existing Python guard/mutex/string owners run on fresh
declared inputs; selected complete guard/mutex/string projections agree.
Native memory never seeds the model. Four native cases and four independent
public CLI replays agree; eight old native rows, four bad CLI calls, 20 new
instruction bindings, four bytecode words and 127 damaged-evidence rejections
pass. The retained instruction/code and allocation-ledger prefixes agree;
only one 16-byte allocation is added. Service/JNI/libc-SVC rows and the
two-handler-read/four-main-SVC limits stay unchanged. This verifies the header
name; its value, guard release, request insertion, whole VM/physical stack,
actual identity/cache, ordinary six headers, online acceptance and complete
signing remain unverified. Use `--elf`, `--libc`, `--replay`. See the
[client-key name evidence](../evidence/vm9_native_171_client_key_name_20261119.json).

`verify_vm9_native_171_null_payload_20261118.py` verifies the original
constructor's zero write to handler+8, the second handler load into R2 and
its consuming equality branch. A separate read profile binds the exact
native site, outer cursor, member, width, destination and constructed value;
old profiles still permit only the first handler read. The original branch
compares R2=0 with R0=0 and stores cursor `+0xfd064` with displacement 214
words. The observer stops before native `+0x16ee38`; the next bytecode is
fetched but its handler has not executed. Existing `vm_full.VM` executes
the two bytecodes at two bases using fresh declared inputs, without native
memory seeds. Four native cases and four independent public CLI replays
agree; eight old native rows, four actual policy negatives, four invalid
profile selections, four bad CLI calls, 13 instruction bindings, three
bytecode words and 110 damaged-evidence rejections pass. The entire previous
file-check row is reproduced; service/JNI/libc-SVC/allocation ledgers do not
change in the added segment. Handler, empty state and source directory are
preserved. This proves a selected two-instruction projection; full request
VM/physical-stack equivalence, actual business cache restoration, real JVM,
ordinary six headers, whole requests, online acceptance and complete signing
remain unverified. Use `--elf`, `--libc`, `--replay`. See the
[NULL payload evidence](../evidence/vm9_native_171_null_payload_20261118.json).

`verify_vm9_native_171_file_check_20261118.py` continues through the generated
cache file's ENOENT result under an explicit four-call profile. The added
faccessat binds its exact site, outer cursor, path, arguments and return PC.
Original code changes errno from 17 to 2, returns -1, produces false and
writes byte zero to packed+16 while preserving the other 31 bytes. It then
constructs a 64-byte empty state container, publishes that pointer as the
state root and returns from state initialization. Existing Python
`StateCallbacks` run on independent pages with declared inputs; selected
false/errno/write projections and all 64 container bytes agree. Native memory
does not seed the model; full state-VM or physical-stack equivalence is not
claimed. Four cases and four independent public CLI native replays agree;
eight old native rows, three actual policy negatives, four bad CLI calls,
18 new instruction bindings, one bytecode word and 125 damaged-evidence
rejections pass. JNI rows are unchanged; inherited service deltas explicitly
include one faccessat, two futex, two memory-protection and one clock call.
No provider is added. The observer stops before the next handler+8 load at
native `+0x16f96c`, outer cursor `+0xfcd04`, destination virtual register 2.
Real file/cache state, business restoration, actual JVM, ordinary six headers,
whole requests, online acceptance and complete signing remain unverified.
Use `--elf`, `--libc`, `--replay`. See the
[file-check evidence](../evidence/vm9_native_171_file_check_20261118.json).

`verify_vm9_native_171_cache_path_20261118.py` joins the original decoded
default `def` constant to its StringObject construction/clone, original
SHA-1 hexadecimal result, filename formatter and file-readability arguments.
Fresh ELF decoding and independent hashlib agree for this declared default.
The formatter consumes the actual digest data pointer in `%s/%s%s`, after
the directory helper has failed and the environment helper has returned.
The 76-byte path retains the original double separator. The formatted object
and its CString pointer reach the file check with mode 4 and errno 17.
An observation sentinel stops before the BL at `+0x25de04`; the file check
and a fourth main-image SVC have not executed. Existing profiles/providers
are unchanged. Four cases at two bases and two NULL JNI scenarios reproduce
exactly through the actual public CLI. 23 new instruction bindings, fresh
ELF default decoding, 101 damaged-evidence rejections, three legacy entry
checks and four real bad CLI calls pass. Complete service-count and libc-SVC
rows match the previous directory cases. The independent formula does not
consume native memory. This covers the selected default only, not other
identities/paths, full guest digest/formatter stack equivalence, actual file
state, restored business state, JVM identity, ordinary six headers, online
acceptance or complete signing. Use `--elf`, `--libc`, `--replay`. See the
[cache-path evidence](../evidence/vm9_native_171_cache_path_20261118.json).

`verify_vm9_native_171_directory_20261118.py` continues the constructed aid
request through directory handling under a separately selected profile. Three
ordered main-image SVCs bind the original faccessat and two fstatat calls to
exact sites, cursors, paths and arguments; stat buffers must be 128-byte native
stack regions at the declared SP offset. Both queries return the inherited
ENOENT result, original code stores errno 2 and returns -1, and each buffer
remains unchanged. Existing mkdir receives `/data`, mode 0755, then sets errno
17 and returns u32 -1. The original directory helper returns false to its
caller. An observation sentinel stops before `+0x25ef7c`, with no request RET.
The existing Python `ensure_environment_directory` runs on independent pages
and a declared static path. Provider sequence, false result, errno 17 and the
31-byte scratch projection match native observations; no native memory seeds
the model. This is a selected projection, not complete physical-stack or
whole-request equivalence. Four controls at two bases, 30 added instruction
bindings, four public CLI native replays, eight unchanged old aid/diagnostic
rows, 164 damaged-evidence rejections and four real bad CLI calls pass. Two
native negative controls prove the default and old one-SVC profiles retain
their rejection boundaries. Use `--elf`, `--libc`, `--replay`. Existing providers
are unchanged. Real filesystem state, successful creation, restored business
state, actual JVM identity, ordinary six headers and complete signing remain
unverified. See the [directory evidence](../evidence/vm9_native_171_directory_20261118.json).

`verify_vm9_native_171_aid_cache_20261118.py` uses a separately selected synthetic
`?aid=1` / absent-cache profile. Four controls at two bases observe the original
aid search, local length one and the non-equal branch to `+0xfc244`. Only one
main-image SVC is allowed, binding site `+0x271dbc`, cursor `+0xfca40`, syscall
48, the static cache pathname and all four syscall arguments. The inherited
absent-filesystem service returns -2; original code stores errno 2, returns -1,
converts readability to false and falls through to directory handling. An
observation sentinel stops before `+0x25ef6c`; no callback or ordinary wrapper
return is claimed. Guard one and the 128-byte handler are retained. The new
path adds one existing file check and two existing clock calls, with no new
OS/JNI/helper service. Twenty-four instruction bindings, one added bytecode
binding, four public CLI native replays, eight unchanged legacy rows, 177
damaged-evidence rejections and four actual negative CLI invocations pass.
A separate native negative control proves the default profile still rejects
the main-image SVC before execution. Use `--elf`, `--libc`, `--replay`.
This synthetic absence says nothing about Android cache state. Directory
handling, restored business state, real JVM identity, ordinary six headers,
whole-request equivalence and complete signing remain unverified.
See the [aid/cache evidence](../evidence/vm9_native_171_aid_cache_20261118.json).

`verify_vm9_native_171_diagnostic_gates_20261118.py` observes both diagnostic
gates without changing the upstream fixture, services or registry guard. Four
controls reproduce the entire previous output row exactly. The synthetic URL
has no query: two original case-insensitive searches for `&aid=` and `aid=`
observe empty sources and return `0xffffffff`. Bytecode `+0xfc23c` reads a local
string length of zero; `+0xfc240` branches to `+0xfc5cc/0x7f01fafb`, which
actually stores R0 minus eight in R21. `+0xfc5dc` branches back to `+0xfc258`
before the existing first formatter/insertion. Later `+0xfee08` reads the registry
guard byte at `image+0x3d1558` as one, `+0xfee10` masks its low bit, and `+0xfee14` branches
to `+0xfef5c` before the existing minus-eleven store. Both status writes are
checked after completion; native comparison operands and three branch targets
are observed. Thirteen added instruction bindings, eleven bytecode bindings,
independent field decoding, four public CLI native replays, 117 damaged-evidence
rejections and four actual negative CLI calls pass. Use `--elf`, `--libc`,
`--replay`. Existing provider limits remain. These are direct branch conditions
of synthetic inputs, not the complete cause of absent six headers. Real JVM
identity, restored business state, whole-request equivalence, ordinary six
headers and complete signing remain unverified. No Android or production signer
changes. See the [diagnostic gate evidence](../evidence/vm9_native_171_diagnostic_gates_20261118.json).

`verify_vm9_native_171_output_20261118.py` extends the constructed ordinary
`0x171` request through callback return, serialization and the original wrapper
RET. Four controls cover two bases and the existing NULL class/static-ID JNI
profiles. The upstream member-load prefix remains identical; no observation
sentinel rewrites PC in this extension. The native service flag getter reads
byte `+0x52 == 1`, and the boolean wrapper stores one. Two `X-Neptune`
insertions format `-8` then `-11`: duplicate insertion keeps the original key,
replaces its value, and releases the duplicate key and previous value. The
final `-11` is observed at bytecode `+0xfef94/0x7ea0f97b`, with source R0 zero.
Four discarded string allocations are freed before callback return; ten final
tree allocations are freed before RET, checked by allocation epochs and actual
free calls. The 25-byte serialization matches the final one-node tree; its
return buffer remains live and caller-owned. Four public CLI native replays,
213 damaged-evidence rejections, 14 added instruction bindings and eight
bytecode bindings pass. The old default context-load CLI still reproduces all
four rows and rejects 63 damaged controls. Four real negative CLI calls reject
missing replay arguments and wrong ELF digests. Use `--elf`, `--libc`, `--replay`.
Inherited OS/JNI, matching Bionic, deferred virtual threads and diagnostic
helper substitutions remain explicit. This is diagnostic output under synthetic
services: real JVM identity, the reason six headers are absent, complete service
semantics, whole-request Python/native equivalence, ordinary six headers and a
complete signer remain unverified. No Android or production signer changes.
See the [diagnostic return evidence](../evidence/vm9_native_171_output_20261118.json).

`verify_vm9_native_171_context_load_20261118.py` continues original outer
construction into the ordinary `0x171` request VM on the same CPU. It reuses
the accepted stack evaluator JNI provider for explicit NULL class and NULL
static method ID scenarios, across two image bases. The original evaluator
returns zero; bytecode `+0xfae4c/0x10820418` then loads the constructed
handler's `+0x50` member with original `+0x16f96c` and stores its payload in
R2 at `+0x16f974`. The member count remains two and all 128 handler bytes
remain unchanged. Each scenario retains 185881/185914 instruction observations,
including provider boundaries, with the existing libc syscall boundaries
explicitly recorded. Nine instructions, one bytecode word and 63 damaged
evidence rejections are bound. The CLI supports `--elf`, `--libc`, `--replay`.
The observer stops before the next bytecode fetch at `+0x16f978` and moves PC
to the oracle sentinel; this is an observation terminal, not callback return.
Existing outer continuation postconditions remain active. Inherited OS/JNI,
virtual-thread and diagnostic services remain explicit; memory imports resolve
to matching Bionic. These NULL scenarios do not establish a real JVM stack or
complete service semantics. Packed-context first consumption, callback return,
serialization, successful cleanup, whole-request differential, ordinary six
headers and complete signing remain unverified. No Android action is included.
See the [context load evidence](../evidence/vm9_native_171_context_load_20261118.json).

`verify_vm9_native_171_constructed_graph_20261118.py` keeps the original
outer constructor's output on the same Unicorn CPU, enters the ordinary
wrapper with fresh synthetic CStrings, and stops before callback `+0x2830c4`.
Four controls cover two image bases and absent/sdk_30 property inputs.
Original getter/copy instructions populate the initially empty ordinary cache
with the constructed root and increment its reference count from 1 to 2.
The selected context is the constructed service_refs handler; its four live
reference members and unchanged 128-byte digest are checked. W2 is `0x171`,
and URL/tree counts are 3. Each control retains 10168 instruction observations,
including provider boundaries. Eight additional instructions and 42 damaged
evidence rejections are bound; `--elf`, `--libc`, `--replay` are supported.
An explicit private runner supplies the stop; default outer execution and
final postconditions remain intact. This inherits the older outer oracle's
explicit OS/JNI, virtual thread descriptors and diagnostic helper services,
plus actual matching-Bionic allocation. Its provider profile differs from
the tag-only mode-read controls. Ordinary callback/VM execution, context
consumption, live business identity, whole-request differential and complete
signing remain unverified. No Android action is included.
See the [constructed graph evidence](../evidence/vm9_native_171_constructed_graph_20261118.json).

`verify_vm9_native_171_mode_read_20261118.py` continues the same synthetic
ordinary path into request bytecode. At `+0xf7e08`, word `0x03024001`
decodes to R1 = s32[R4+24]. Original `+0x170308` reads the packed mode's
four bytes, and `+0x17030c` stores `0x171` in R1. Execution stops before
the next bytecode fetch at `+0x170310`. Four controls across two bases retain
34029 instructions from VM entry and 443 bytecode cursor states each,
unchanged prefix/allocation/mutex ledgers and distinct nonzero mode padding.
Five native instructions and one bytecode word are bound; 50 damaged-evidence
rejections pass. The CLI accepts `--elf`, `--libc` and `--replay`.
No additional OS/JNI provider is introduced. Packed context and both tag-only
context fixtures are guarded against reads and remain unread at this stop.
Full context, callback return, successful cleanup, actual business execution,
ordinary six headers and complete signing remain unverified. A longer private
exploration stopped at runtime initialization's `pthread_create`; it is
outside the retained passing controls.
See the [first mode-read evidence](../evidence/vm9_native_171_mode_read_20261118.json).

`verify_vm9_native_171_vm_prelude_20261118.py` extends the ordinary native path
through 115 original generic VM instructions, stopping before `+0x1684f0`.
Four synthetic controls cover two image bases, registry/fallback, null context
and an existing shared-reader count. All 32 virtual-register backing words and
their PC slot match the existing model from observed local callback state;
prefix traces and allocation/mutex summaries match corresponding upstream
controls. The default CLI rejects 34 damaged records. Use
`--elf <original-Metasec> --libc <matching-Bionic> --replay` to rebuild the four
retained results and bind the additional generic-VM code range. An explicit
observation harness extends the stop without changing original helper bodies;
the upstream default CLI retains its stop before VM entry. Request bytecode,
full context state, callback return/cleanup, actual business execution, ordinary
six heads and the complete signer remain unverified. Signer production code is
unchanged.

`verify_vm9_native_171_vm_handoff_20261118.py` continues the original ordinary
wrapper through input conversion, child dispatch and `+0x2830c4`, stopping
before the first VM-entry instruction at `+0x168324`. Twelve synthetic cases
cover two image bases, registry/fallback selection, null callback skipping,
null context and an existing shared-reader count. The selected pair's context
and mode `0x171` reach the packed arguments; URL/tree reference counts are
three at callback entry. Defined wrapper spans and five VM call registers
match the existing caller model using observed local callback state as input.
Seeded upper mode-slot bytes survive. Packed context at `+0x20` differs from
the direct VM `x3=image+0x35e690`. Context objects carry a known handler vtable
tag only; their complete state and real identity are unverified.
The default CLI rejects 54 damaged evidence records. Use
`--elf <original-Metasec> --libc <matching-Bionic> --replay` to bind both sample
digests and rebuild every retained result. Beyond upstream input bindings,
this binds 28 instructions, three code ranges and one handler-vtable relative
relocation. No Android action, new hook, VM prelude/bytecode, callback return
or successful cleanup is exercised. Whole-request differential, native/Java
mode equivalence, ordinary six heads and the complete signer remain unverified.

`verify_vm9_native_171_inputs_20261118.py` executes the ordinary wrapper
`+0x27ed14` through original input conversion and its native `0x171` virtual
call, stopping before the first child-dispatcher instruction at `+0x27dd04`.
Thirty-two synthetic controls cover CRLF fragment pairing, empty/odd lists,
empty keys/values, last-value replacement, case, whitespace, binary bytes, NUL,
two image bases and both delimiter initialization states. Nineteen reach the
child entry with URL/tree reference counts of two; thirteen return zero with
all temporary allocations freed. The output slot is FP-0x48; its initial bytes
are not assumed to be zero. A colon-formatted line is not split into a pair.
The default CLI checks retained evidence and rejects 91 damaged records.
`--elf <original-libmetasec_ml.so> --libc <matching-libc.so> --replay` binds both
sample digests and rebuilds all frozen traces, heap and effect summaries.
Metasec bindings cover 21 instructions, three code ranges, one data range,
eleven imports and one relative relocation. The root/child graph, diagnostic
state and TLS are synthetic and initialized. Internal Metasec helpers execute;
matching Bionic executes uncontended recursive mutex and string comparison
paths, with explicit synthetic allocation and memory providers. No Android,
child dispatcher body, VM, successful callback return/cleanup, complete heap
Python-model differential or real business execution is established. Native
`0x171` and Java `0x138` equivalence and the complete signer remain unverified.
See the [native input evidence](../evidence/vm9_native_171_inputs_20261118.json).

`verify_vm9_registered_security_handoff_20261118.py` checks the original registered
entry `+0x27d288` through the existing `+0x271998` adapter to its first callback.
The tested case-insensitive `ws` prefix selects `+0x27ecbc` with a concatenated
text argument; other tested inputs reach `+0x27ed14` with the original two input
words. Seventy isolated original-code controls compare argument blocks, query
checksum/context writes and the existing Python adapter's retained frame and
registers. The default CLI checks retained evidence and rejects 87 damaged
records. `--elf <original-libmetasec_ml.so>` binds 52 instructions, 16 code ranges,
three data ranges, three imports and one relative relocation; adding `--replay` reruns all 70 controls
with Capstone, pyelftools and Unicorn. Initialized singleton/TLS state and the
pthread lookup, allocation and decimal parsing providers are synthetic. Callback
bodies, later prefix-path continuation, Android execution and a complete signer
are outside this proof. A separate static connection follows `+0x27f84c` through
the outer singleton's child `+0x18` and virtual slot `+0x20`. If the child has the
previously modeled vtable, the slot targets `+0x27dd04`, with native mode `0x171`.
The Java facade model uses `0x138`; actual child identity, virtual-call execution
and equivalence between these modes remain unverified. See the
[registered entry handoff evidence](../evidence/vm9_registered_security_handoff_20261118.json).

`verify_vm9_cronet_native_security_selector_20261118.py` checks the original
native/JNI selector and two independent read-only registration windows. Four slot
samples point to executable `libmetasec_ml.so+0x27d288`; two also bind its first
64 bytes to the shipped ELF. No hooks, callback calls, setters or UI actions were
used. Thirty-two retained synthetic controls exercise native selection, JNI
fallback and the skip flag, with zero native callback/JNI executions; 57 damaged
records are rejected. Optional `--elf <original-libsscronet.so>` and
`--metasec-elf <original-libmetasec_ml.so>` verify original instructions, code
digests and runtime prefix bindings. The CLI checks retained evidence without
connecting to Android or replaying the emulator. Registration and zero Java
callback counts do not prove which branch a business request executed. See the
[native selector evidence](../evidence/vm9_cronet_native_security_selector_20261118.json).

`verify_vm9_cronet_candidate_security_route_20261118.py` verifies a conditional
upstream route: entry x2 becomes intermediate x5, then security-bridge x4 when
the virtual slot selects the known wrapper. It checks 24 retained synthetic
ARM64 cases and 44 damaged-evidence controls. Optional `--elf <original-libsscronet.so>`
binds 39 instructions, seven unchanged code ranges and two relative relocations.
Each case executes three original helpers on controlled empty/immediate-return
paths, then stops at the fallback, initialization or bridge external-call boundary,
or returns from the bridge's null guard. The bound-callback setup/trampoline is
static evidence only. This CLI checks retained summaries, without replaying the
emulator or identifying a live business caller. See the
[conditional route evidence](../evidence/vm9_cronet_candidate_security_route_20261118.json).

`verify_vm9_cronet_security_bridge_guard_20261118.py` checks the retained static
guard/forwarding evidence and 29 damaged-evidence controls. It records 12 bounded
ARM64 emulations, with no Android or external-call execution. Run it from the
repository root; `--elf <original-libsscronet.so>` additionally checks the pinned
SHA-256, 17 exact instructions and three relative relocations using Capstone and
pyelftools. The CLI verifies the retained emulation summary; it does not replay
Unicorn or observe a business request's fifth argument. See the
[guard evidence](../evidence/vm9_cronet_security_bridge_guard_20261118.json).
The null guard is not established as the reason security callbacks remained zero.

`capture_vm9_cronet_route_android_20261117.py` attaches to an already running
app and observes client selection, Cronet request creation and the security
callbacks through manager/r4. Start with the default observation mode. Use a
Frida client/server (or Gadget) pair and Java bridge that match the current
device runtime; omit `--bridge-js` when that runtime already supplies `Java`.
It does not start the app or generate a request: after `route_ready` reports
`required_hooks_ready=true`, exercise the business page during the window.

From the repository root, with a new capture path outside the repository:

```powershell
python platforms/bytedance/tomato/python/verify_vm9_cronet_route_capture_20261117.py
python platforms/bytedance/tomato/python/capture_vm9_cronet_route_android_20261117.py `
  --device remote --remote <current-host:port> --bridge-js <matching-bridge.js> `
  --operation-timeout 15 --duration 60 --output <new-private-capture.jsonl>
```

The host verifier needs Python `frida` and Node.js. `--pid <running-pid>` skips
process enumeration; USB mode requires `--adb-serial <exact-device-id>`.
An embedded Gadget enumerates its own host as `Gadget`. Check that runtime's
actual Java package name and UID against the target app before choosing a PID
or loading hooks. A reachable port can belong to another app. Use a dedicated
device port for the Tomato test build when another Gadget is already running.
`--operation-timeout` bounds each Frida operation separately, including cleanup;
`--duration` is the observation window after hook readiness. Existing output
files are refused. Failure, missing required hooks, an event limit or incomplete
cleanup returns a nonzero status. Exit 0 only means that the observation window
finished with the required hooks installed; it can contain zero business calls.
The JSONL keeps method names, counts, thread nesting and standard security key
names. It omits request arguments, header values and exception messages. Nesting
does not prove Java object identity or online acceptance.

`--force-selector` explicitly enables a temporary session-only override of
`isCronetClientEnable`; use it as a separate diagnostic run after the passive
control. It does not prove that a business request reached Cronet. Android hook
installation and request creation/start were verified on the dedicated Android
13 arm64 test process on 2026-11-17. The pinned 7.2.5.32 DEX uses
`CronetUrlRequestContext.X` and `CronetUrlRequest.o`; the probe now observes those
names. A passive window recorded 52 calls at each of client selection, connection,
creation and start, with zero security-factor callbacks. A separate extended
window observed 55 response callbacks. See the
[aggregate evidence](../evidence/vm9_cloud_cronet_route_20261117.json).
These observations do not establish the six-header chain or online acceptance.
The earlier transport timeout was a connection failure, not a negative business
observation.

`--observe-reader-response` adds passive hooks for the pinned reader's `F0`,
`i0` and `y0` methods. It records incoming `FullResponse` numeric codes,
rejection-cache membership and membership before/after the original update.
The cache field is read by reflection because a method can hide its Frida
property. No chapter identifiers, response content or exception messages are
recorded. These three hooks become required when this option is enabled;
`route_reader_observation_unavailable` reports a metadata read failure without
changing the original call, result or exception. A completed window alone does
not prove that reader metadata was collected; check its events as well.

The actual CLI completed a 45-second Android window with 69 Cronet creation/start
calls. Its reader events were cache miss, incoming code 110, `y0` cache membership
false before/true after, then cache hit. The response and update ran on the same
thread. This locates a local secondary rejection cache; it does not identify the
wire response, initial rejection cause or matching objects across calls. See the
[reader provenance evidence](../evidence/vm9_reader_response_cache_20261117.json).

A separate private passive extension observed code 110 in the JSON string before
the original `Gson.fromJson(String,Type)`, then in its decoded FullResponse and
the exact same object received by F0. Probe-owned IdentityHashMap positive and
negative controls passed on Android; the 45-second window completed with 62
Cronet create/start calls and foreground checks before each UI action. This
joins the reader response only. That window left earlier stream/interceptor
ownership and the raw HTTP response unverified; see the
[JSON provenance evidence](../evidence/vm9_reader_json_provenance_20261117.json).

Two later private passive windows joined the actual Cronet response stream to
StreamParser, its unchanged stream result, the constructed `m90.b`, the RPC
wrapper at its real read, `c.m`, Gson and the reader's same response object.
The original conversion ran once, produced code 110 and matched Gson's input
character for character. No business stream was consumed or replaced by the
probe. Stream-identity positive/negative controls, source bindings, event order,
foreground guards and cleanup passed; 65 damaged captures were rejected.
The 45-second windows recorded 46 and 76 Cronet create/start calls. Raw HTTP
bytes, cache/native interception, initial rejection cause and original-signature
runtime equivalence remain unverified; the six-header callbacks stayed at zero.
See the [stream provenance evidence](../evidence/vm9_reader_stream_provenance_20261117.json).

A later private passive window copied the filled ByteBuffer region at the entry
to `CronetUrlRequest.onReadCompleted`, before the original method ran. It already
contained code 110. The actual stream read returned the exact complete copied
chunk, then joined the existing RPC/Gson/reader chain. Buffer, request and
connection identity joined the callback and reader across different threads;
the adapter reported HTTP 200. The duplicate-buffer observation preserved the
original position/limit and made no extra business-stream read. The 45-second
window had 612 rows and 55 create/start calls; source binding, cleanup and 90
damaged-capture rejections passed. Its inspected post-window screenshot was the
recommendation home page. Native/cache/transport production before this Java
callback, server attribution and the six-header chain remain unverified. See the
[read-buffer evidence](../evidence/vm9_cronet_read_buffer_provenance_20261118.json).

A subsequent private window joined the request's concrete response-info object
to the read adapter and retained the buffer/reader chain. Original DEX semantics
and true/false control instances identify `impl.z.k()` as `wasCached`; the
observed value was false, with HTTP 200 and an HTTPS URL scheme. This is Cronet's
cache flag and does not exclude earlier caches or native interception. Protocol
and proxy metadata remain opaque classifications, and the exact legacy
reader/full path comparison did not match. The 45-second window had 1,382 rows,
132 create/start calls, complete cleanup and 109 damaged-capture rejections.
Its inspected screenshot still showed the unsafe-version message. See the
[response metadata evidence](../evidence/vm9_cronet_response_metadata_20261118.json).

Two complete private JNI windows joined the actual `CallVoidMethodV` receiver to
the Java read-completion callback and existing buffer/request/stream/reader chain.
The return site `libsscronet.so+0x1f009c` belongs to a generic JNI helper. Reflected
method-ID, actual JNI A and distinct-method controls passed. The 45-second windows
had 602 and 740 rows, 54 and 68 create/start calls, complete cleanup and 123
damaged-capture rejections. A separate three-second read-only window identified
method cache slot `+0x5ef8a0` and matched the original helper code. Exact static
references identify callback candidate `+0x201f30`, but its deeper runtime trials
are excluded: one timed out during cleanup and another detached with signal 11
in exit history. The recovered target passed identity, original-instruction and
unload/detach checks without clearing app data. Neither a full native stack nor
the earliest response producer, crash cause or six-header chain is established.
See the [JNI/native boundary evidence](../evidence/vm9_cronet_native_boundary_20261118.json).

A further private window reused only the stable JNI entrypoints and read eight
saved return candidates by masking unmapped returns to their low 48 bits. Each
candidate mapped to executable module memory and followed an original ELF BL/BLR
instruction; the first matched the callback helper callsite. Unsigned-module,
synthetic-high-bit and unmapped-negative controls passed. The 45-second window
had 701 rows, 64 create/start calls, full cleanup and 135 damaged-capture
rejections. Its inspected post-window image showed recommendation home. A static
relative relocation points to the callback in `.data.rel.ro`; the live virtual
table role remains unverified. Masking does not authenticate PAC or establish a
complete unwind, earliest response production or the six-header chain. See the
[saved-return candidate evidence](../evidence/vm9_cronet_saved_return_candidates_20261118.json).

A later private window identified the live delegate table at `libsscronet.so+0x5c90a0`:
slot `+0x20` points to the read callback and `+0x28` to the security bridge. The
restored caller owner refers to the current delegate, whose Java reference is
the JNI receiver. Thirteen original instructions, four runtime code windows,
source binding, full cleanup and 152 damaged-capture/action rejections passed
(45 seconds, 683 rows, 62 create/start calls). The security JNI caches were null
at the sampled times. A guarded tap ran; a swipe was skipped when the target
foreground was unconfirmed. The inspected final image showed a second book cover.

After process recovery, a separate Java-only window observed the same response
request's context provider as non-null `org.chromium.c`, matching its declared
type. Its shipped definition is in `classes17.dex`, identical in the original
and test APKs, and directly delegates to the security manager. That manager also
has null internal-provider return paths; its actual internal registration is
still unverified. This window completed with 708 rows, 65 create/start calls,
one foreground-guarded tap, full cleanup and 133 damaged-capture/action rejections.
Its inspected final image showed recommendation home. Each window retained the
existing HTTP-200, `wasCached=false`, code-110 response identity chain, with zero
security-stage calls. Objects are not joined across these windows or processes.
Failed setup and zero-target-response trials are excluded; a later signal-11
exit remains unattributed, and recovery preserved app data. The live table and
non-null provider do not prove security bridge execution, six-header generation
or a complete signer. See the [dispatch/provider evidence](../evidence/vm9_cronet_dispatch_provider_20261118.json).

A subsequent Java-only window read the existing manager singleton directly.
Both its interface provider and reflection adapter were present and reported
class `com.dragon.read.base.http.b`; their object identities were not compared.
The current false `sOptReflection` flag selected the adapter, whose type resolved
the public `onCallToAddSecurityFactor(String,Map)` method returning Map. The
lookup may resolve an inherited method and does not prove execution. Original
and test DEX entries bind the singleton layout and boolean getter. No singleton
accessor, registration setter or signer was invoked by the probe. The same
response identity chain remained code 110, HTTP 200 and `wasCached=false`, with
zero security-stage calls. The 45-second window had 710 rows, 65 create/start
calls, one guarded tap, full cleanup and 164 damaged-record/action rejections;
the inspected final image showed a third book cover. This is a response-time
snapshot, leaving earlier registration state and native dispatch unresolved.
See the [manager registration evidence](../evidence/vm9_cronet_manager_registration_20261118.json).

Focused static lookup then located the provider's inherited security method in
`AbsCronetDependAdapter`: it converts header values to lists and delegates to
`NetworkParams.tryAddSecurityFactor`, which calls its non-null registered callback
or returns null. The inherited owner and NetworkParams DEX entries match the
original APK. The application's `classes3.dex` differs as a whole; only the
provider's superclass and declared method signatures were compared. A separate
three-second read-only snapshot found `ms.bd.c.r4` registered in the downstream
field. Identity/type and present/null controls, exact source binding, cleanup
and survival of the same target process passed, with no business/native hooks,
UI action or signer invocation. This snapshot is not joined to a business
response and does not prove callback execution or six-header generation. See the
[downstream callback evidence](../evidence/vm9_cronet_downstream_callback_20261118.json).

The [novel-sound comparison](../NOVEL_SOUND_REFERENCE.md) describes its four local
header implementations, the Argus variant differences and the 13 passing offline
crypto-vector tests. No upstream implementation or golden vectors were copied
into this MIT repository.

`verify_vm9_framesign_watched_region_ownership_20261103.py` checks the read-only
follow-up: in two independent four-call runs, the watched bytes lie at the start
of a new 112-byte callback allocation and the same pointer enters cleanup.
The prior A-B-A-B digests remain unchanged. This corrects the unsupported
persistent-manager-state attribution behind the restoration experiment.
Optional `--probe-dir` verifies the separate private callback harness and logs;
`--elf` verifies allocator argument/return instructions. Final deallocation and
the direct dynamic signature source remain unverified.

`verify_vm9_framesign_state_boundary_restore_20261103.py` checks the paired
FrameSign boundary-restoration intervention against the existing four-call
baseline and four earlier restoration runs. The control retains A-B-A-B; the
intervention yields array/null/array/array. This does not identify the dynamic
signature source or prove continuous suppression. Optional `--probe-dir` checks
private sanitized logs and the paired harness/class hashes; `--elf` checks all
15 static instruction records through the ELF PT_LOAD file/VA mapping. No raw
signature values are needed or retained in the evidence.

Official-app reader observation now has its own retained evidence verifier:
`verify_vm9_official_okhttp_reader_20261102.py`. Seven Full/BatchFull responses
have preceding six-header OkHttp callbacks with matching thread/path digests,
HTTP 200 and business code 0. A later screenshot showed readable chapter text.
This validates the built-in app path, not a standalone signer or header necessity.
Use `--capture <first.jsonl> --capture <second.jsonl>` to additionally verify
the source digests, event counts and selected events against local raw captures.

The existing business probe's `--diagnose-reader-errors` now records up to six
nested cause types/stacks, with cycle detection and no exception messages. Host
checks cover these bounds; the next live run did not reproduce the reader error,
so the nested-cause runtime behavior remains unverified. The existing chunked
`--bridge-js` loader worked against the initialized official emulator process.

The new `capture_vm9_cronet_jni_runtime_20261101.py` probe obtains a live
ART `JNIEnv` through `JNI_GetCreatedJavaVMs`, then hooks the indirect
`GetMethodID`/`CallObjectMethodV` table entries at `0x108`/`0x118`. It does not
require the optional JavaScript Java bridge and retains only the
`addSecurityFactor(String,String[])` method identity and event counts. A
zero-call capture is a bounded negative window. Verify it with
`verify_vm9_cronet_jni_runtime_20261101.py`. The earlier cold capture ended
before a business page was verified; its termination cause remains unknown.
The 2026-11-02 warm captures reached book detail, but still observed no target
call. The Cronet business branch remains unproven.

```powershell
python python/capture_vm9_cronet_jni_runtime_20261101.py `
  --device remote --remote 127.0.0.1:27043 --adb-serial emulator-5554 `
  --launch --duration 60 --output <new.jsonl>
python python/verify_vm9_cronet_jni_runtime_20261101.py --capture <new.jsonl>
```

热接入时，native 可能已缓存 method ID。应用进入正常页面后可用
`--pid <running-pid> --resolve-cached-methods`，通过应用 ClassLoader 主动解析
两个目标 ID；不需要完整 Java bridge，也不调用签名方法。
该选项不能与 `--launch` 或 `--spawn` 同用。主动解析可能加载/初始化目标类，
因此为显式选项，记录为 `jni_method_seed`/`jni_seed_complete`；这两个事件不证明
业务请求或签名执行。只有后续被动 `jni_call_object_method_v` 才计目标调用。
解析错误、缺少任一方法、调用早于解析或 method ID 未知均被 verifier 拒绝。
零事件仍需考虑实际网络栈及 ARM 转译边界，不能断言 Cronet 不可达。

当启动阶段进程很快退出或 PID 轮询存在竞态时，使用 `--spawn` 让 Frida
先挂起进程、加载 hook 后再恢复：

```powershell
python python/capture_vm9_cronet_jni_runtime_20261101.py `
  --device remote --remote 127.0.0.1:27043 --spawn `
  --duration 60 --output <new.jsonl>
```

探针会在目标进程终止时立即结束等待，并在卸载脚本前清理当前线程的 JavaVM
attach；因此退出事件和清理失败都会进入校验器的错误检查。`--launch` 与
`--spawn` 互斥，二者都只保留脱敏的方法身份和事件计数。

如果 Frida 无权附加目标，或脚本加载失败，捕获器会写出脱敏的
`attach_error`/`script_error` 事件并返回非零状态；校验器会拒绝这类记录，
不会把权限失败误判成 Cronet 的有界负观测。
连接、进程查找、启动和恢复失败分别记录 `device_error`、`process_error`、
`spawn_error`/`launch_error` 和 `resume_error`；ADB 启动和 PID 等待共用
`--launch-timeout`，单次 ADB 调用最多等待 10 秒。

同时连接多台 Android 时，USB 模式的 `--adb-serial` 也用于精确选择 Frida
设备；例如 `--adb-serial emulator-5554 --pid <pid>`。省略序列号时保留 Frida
默认 USB 选择行为；remote 模式仍以 `--remote` 为 Frida 连接目标。捕获器先独占
创建输出文件，再连接设备或启动应用，因此已有文件会在产生设备副作用前拒绝。


The 2026-10-31 native scan closes the static indirect boundary left by the
27-DEX scan. `libsscronet.so` contains two AArch64 chains that resolve the
Cronet request/context classes, call JNI `GetMethodID` for the private
`addSecurityFactor(String,String[])`, and reach JNI `CallObjectMethodV`.
The evidence keeps only section/string offsets, helper addresses, JNI table
offsets, and the ELF digest; it keeps no native bytes or full instruction text.
This is static dispatch evidence, not proof of a live Cronet request or online
header acceptance. See `scan_vm9_cronet_native_jni_boundary_20261031.py` and
`verify_vm9_cronet_native_jni_boundary_20261031.py`.

The passive Android capture now observes a real six-header business callback
through `OkHttp3SecurityFactorInterceptor -> NetworkParams -> r4`. Matching path
digests and thread ids associate the signature and an HTTP 200 response with
business code 110. The retained capture comes from a re-signed Gadget build;
Cronet execution, standalone signing, whole-request Python/native equality,
and online header acceptance remain unverified. See
`verify_vm9_networkparams_runtime_20261031.py`.

The 2026-10-31 DEX scan covers all 27 DEX files and records no direct business
caller for the three selected Cronet security-factor methods. Only the two
implementation-level `addSecurityFactor -> o0` edges are present; this points to
an indirect native/reflection dispatch boundary and does not prove runtime
unreachability. See `scan_vm9_cronet_static_callers_20261031.py` and
`verify_vm9_cronet_static_callers_20261031.py`.

The 2026-10-31 remote-device follow-up exercised the UI with the static overlay
Gadget build. It recorded three additional ordinary `r4` six-header callbacks;
the three Cronet entry hooks were installed but had zero calls in that page.
The result is path-separation evidence, not Cronet or online-acceptance proof.
See `capture_vm9_networkparams_followup_20261031.py` and
`verify_vm9_networkparams_followup_20261031.py`.

The fresh handle2 frameSign verifier records the first structured native
`String[]` result: tag `0x4000002` returns the Java-lifecycle handle used by
`core.c.frameSign` for tag `0x200000A`, producing ten entries across the five
`frametype`/`lid`/`signinfo`/`signvalue`/`signversion` pairs. The evidence keeps
only lengths and SHA-256 digests; explicit unidbg Java/OS callbacks remain, so
live Android-JVM/provider behavior, whole-request differential, standalone
signing, and online acceptance remain open. See
`verify_vm9_frame_sign_handle2_result_dynamic_probe_20261028.py`.

The follow-up type sweep reuses that handle2 and changes only `frameType` across
0, 1, 2, and 3. The native result shape and `signinfo` digest stay invariant,
while all four `signvalue` digests differ. This is a bounded sensitivity result,
not a claim about frame semantics or standalone signing. See
`verify_vm9_frame_sign_handle2_types_dynamic_probe_20261028.py`.

The URL sweep reuses handle2 and `frameType=0` across homepage, query-variant,
and search-route profiles. The result shape stays fixed while both `signinfo`
and `signvalue` digests change. URL and returned values are retained only as
lengths and SHA-256 digests; the same run changes `X-Gorgon`/`X-Medusa` while
the other four controlled header digests remain invariant. This remains
explicit-callback unidbg sensitivity evidence. See
`verify_vm9_frame_sign_handle2_url_dynamic_probe_20261028.py`.

The first attach-safe Android-JVM probe now reaches the real Tomato startup
task `x1.k()` and its `MSManagerUtils.init()` call. The live process returns a
real manager for app id `1967`; reflection then invokes
`MSManager.frameSign(String,int)` for three distinct URL profiles. All calls
return the five-key result shape, and both `signinfo` and `signvalue` change
with the URL. The capture stores only lengths and SHA-256 digests. This closes
the live Android-JVM/provider boundary for `frameSign`, but not the whole
request native/Python differential, a fresh standalone signer, or online
acceptance. See
`verify_vm9_actual_android_jvm_frame_sign_20261028.py`.

For a live process, `capture_vm9_business_framesign_android_20261028.py`
installs the same redacted hooks without triggering a request. It separates the
ordinary `r4`/Cronet callback from the independent `MSManager.frameSign` API and
emits only lengths and SHA-256 digests. Attach to an already-running app:

```powershell
python -B platforms/bytedance/tomato/python/capture_vm9_business_framesign_android_20261028.py --pid <PID> --duration 60
```

When multiple USB devices are attached, add `--adb-serial <SERIAL>` to select the exact target. Without it, capture proceeds only when exactly one USB device is available.

For Gadget, use `--device remote --process-name Gadget --bridge-js <bundle>`.
`--output <new.jsonl>` refuses overwrites. Optional `--diagnose-reader-errors`
adds bounded class/method stacks, path fingerprints, HTTP/business response
codes, and reader error constructors without retaining raw request values.
Installed hooks survive retries without replacement; pending Java installation
is deduplicated. The process detaches and closes its output on completion or
target exit. `verify_vm9_capture_lifecycle_20261031.py` checks those host-side
behaviors; it does not substitute for the passive Android evidence above.

`verify_vm9_signer_boundary_audit_20261024.py` now audits the public outer and
request owners before standalone-signer work. It confirms the `+17b8f8 →
+27dd04 → +2830c4` composition while keeping synthetic JNI/JavaVM, live JVM/OS
providers, and online acceptance explicitly open. Completed request pages now pass
through the owning session's explicit `publish_request_state` commit owner; duplicate
publication is rejected. The audit is read-only and does not execute private ELF or
replay native snapshots.

The opt-in `vm9_effects.EffectJournal` now gives allocator/JNI/OS providers an
explicit nested rollback boundary. Native service hooks can restore provider
undo records and, when requested, live CPU page bytes after a failed hook; the
owning request VM and child dispatcher accept the same journal, and the Java facade
forwards it into the nested callback VM. The signer-handle publisher, request
state elapsed getter, second-VM realtime wrappers and request-environment
acquisition callback, StringObject callbacks, the environment logger callback and
the JNI availability wrapper, second-VM allocation callback, formatter,
consumer free tail, StringObject assignment and the two configuration reference
getters, cached JNI reference callback, JSON string, StringObject fill, empty
JSON reference, token string transform, token digest, token cipher, token append
tail, Base64 tail and allocated-printf paths also have opt-in JNI/clock/provider
rollback boundaries. Thirty-two Python controls and thirty-two rollback controls
pass.
Implicit mapping remains rejected and
complete signing is unfinished. See [the provider-effect report](../REQUEST_JNI_STARTUP_WORKERS.md#6255-explicit-provider-effect-rollback-journal2026-10-24-asiashanghai).

The owning request handoff now resolves the 35 matching ELF memory imports before
entering request VM and constructs its synthetic configuration tree/reference and
JavaVM/JNI table from the same outer allocator session. Four absent/`sdk_30` cases
return at `+0xffb78`: low base 957 steps/26 callbacks and high base 2475 steps/105
callbacks. The high-base path executes the existing JNI acquisition, tree cleanup and
request-return owners. This remains synthetic Python composition; real Android JVM,
URL/header conversion, whole-native handoff memory equivalence and fresh independent
Medusa/signer output remain open. See [the owning handoff evidence](../evidence/vm9_request_allocator_handoff_fresh_20261024.json).

`GuestOS` mapping owners now register page, mapping-metadata and cursor snapshots
with the same journal for map/unmap/name/protect and allocator region registration.
Four Python controls and three rollback controls pass; this is owner-state
evidence only and does not claim real kernel mapping or complete allocator
rollback. See [the GuestOS report](../REQUEST_JNI_STARTUP_WORKERS.md#6256-guestos-mapping-owner-effect-rollback2026-10-24-asiashanghai).

`register_os_region` also records the GuestOS/allocator owner snapshot under the
same journal. Two captured-checkpoint controls and two rollback controls pass; the
checkpoint is identified only by hash and no native output is used as input.
Fresh allocator boot and real kernel mapping remain outside this result. See
[the region report](../REQUEST_JNI_STARTUP_WORKERS.md#6257-allocator-region-registration-effect-rollback2026-10-24-asiashanghai).

The opted-in state now scopes cold environment-service construction. Adds 36 native controls, 6 rollback checks and 96 Python regressions. The isolated cold-state fixture now matches payload/image/TLS and allocation/free effects, including its live constructor scope; full-request differences remain 13 pages and 5042 bytes. Full signing remains unfinished. See the [environment service report](../REQUEST_JNI_STARTUP_WORKERS.md#6254-environment-service-reference-scope2026-10-21-asiashanghai).

The full-request residual attribution is read-only: 4860 bytes are physical stack/ABI scratch, 3 bytes are a caller-stack pointer alias, 166 bytes are format-token padding, and 13 bytes are short-string tail bytes. Semantic token fields and event payloads match; no production model change was made. See the [residual diff evidence](../evidence/vm9_full_outer_residual_diff_20261024.json).

The shared clock service now preserves matching bionic guard/cache initialization. Adds8 native controls and14 refusal checks; the constructed whole second retains391 matching callbacks and seven matching return values, with1433/1439 pages equal. Two dtoa pages and four stack pages still differ; complete signing remains unfinished. See the [clock cache report](../REQUEST_JNI_STARTUP_WORKERS.md#6239-matching-libc-clock-cache2026-10-20-asiashanghai).

The reusable native service bridge passes2 original GetEnv controls and13 refusal checks. Original287474 now returns through the same explicit JavaVM/JNI providers:391 callbacks and seven return values match;1432/1439 pages match, with7 libc/stack pages still differing. Full memory equivalence and complete signing remain unfinished. See the [native provider report](../REQUEST_JNI_STARTUP_WORKERS.md#6238-live-native-provider-bridge2026-10-20-asiashanghai).

The owning request VM now has a reusable production entry and a normal Java facade adapter. The constructed chain returns14 Java elements with complete scoped cleanup;2 Python prefix checks and25 refusal/rollback checks pass. Historical native groups were not replayed. JNI/OS services remain synthetic and complete signing is unfinished. See the [owning entry report](../REQUEST_JNI_STARTUP_WORKERS.md#6237-reusable-owning-request-vm-entry2026-10-20-asiashanghai).

`vm9_request_vm.invoke_java_request_facade_service` now composes that facade
entry with child `+27dd04` and owning VM `+2830c4` under one allocator session.
Fresh four-case handoff evidence returns at `+0xffb78` with 115 callbacks per
case; JNI/JavaVM providers remain synthetic. See the [handoff evidence](../evidence/vm9_java_request_handoff_fresh_20261024.json).

The signer child dispatcher now preserves callback/fallback ABI and scoped result ownership. Adds36 original native controls and18 rollback checks. A fresh constructed Java facade/input to owning request VM/output chain returns14 elements; JNI/OS services remain synthetic and complete signing is unfinished. See the [child dispatch report](../REQUEST_JNI_STARTUP_WORKERS.md#6236-signer-child-request-dispatch2026-10-20-asiashanghai).

The normal Java request facade now composes URL/header conversion, a live virtual request target, Java output and complete scoped cleanup. Adds22 native controls and15 rollback checks. The request method is an explicit synthetic provider in these controls; actual request VM integration and complete signing remain unfinished. See the [Java facade report](../REQUEST_JNI_STARTUP_WORKERS.md#6235-normal-java-request-facade2026-10-20-asiashanghai).

JNI header input now builds an owning configuration tree through object-byte conversion and cloning. Adds52 input and20 tree-release native controls plus32 rollback checks. A synthetic six-element input becomes four ordered Java output elements and its tree is deleted; actual Java request integration and complete signing remain unfinished. See the [header input report](../REQUEST_JNI_STARTUP_WORKERS.md#6234-jni-header-input-and-tree-reference-release2026-10-20-asiashanghai).

Header array conversion now restores cold String class lookup and global retention with explicit serial lock services. Adds24 native comparisons and16 rollback checks. A constructed request result with7 pairs converts to14 ordered Java array elements; actual Java request wiring and complete signing remain unfinished. See the [cold class report](../REQUEST_JNI_STARTUP_WORKERS.md#6233-cold-string-class-and-constructed-output2026-10-20-asiashanghai).

Cached-class JNI header array conversion271384 now composes existing tree, UTF and reference owners. Adds42 two-base native comparisons and42 page rollback checks. Actual request output integration and complete signing remain unfinished. See the [JNI header array report](../REQUEST_JNI_STARTUP_WORKERS.md#6232-cached-class-jni-header-array2026-10-20-asiashanghai).

Public outer entry now forwards explicit identifier file and mutex services. Constructed request returns at5182/322callbacks with public outer8000/second500000 call budgets, without changing second execution kwargs. Adds30 early refusal checks; no new native comparisons. Complete signing remains unfinished. See the [public service report](../REQUEST_JNI_STARTUP_WORKERS.md#6231-public-second-services2026-10-20-asiashanghai).

Outer configuration setter passes39 new native controls and64 refusal checks. Constructed outer request returns at5182/+FFB78 with322callbacks; second retains96740/391callbacks using private500000 budget. Public outer budget is8000; public second budget remains20000. Complete signing remains unfinished. See the [configuration setter report](../REQUEST_JNI_STARTUP_WORKERS.md#6230-outer-configuration-set2026-10-20-asiashanghai).

Second VM selected return passes21 new native controls and15 refusal checks. Actual caller return matches seven physical values and1437 declared pages. Outer resumes3900→4000;next285EF0→2568C8. Complete signing remains unfinished. See the [second return report](../REQUEST_JNI_STARTUP_WORKERS.md#6229-second-vm-return2026-10-19-asiashanghai).

Second allocated printf passes 50 new native controls and 39 refusal/rollback checks. Both actual calls match memory, result, canary and ordered real allocation effects. Second reaches96740/+112434 and the unrecovered VM return; complete signing remains unfinished. See the [allocated printf report](../REQUEST_JNI_STARTUP_WORKERS.md#6228-second-allocated-printf2026-10-19-asiashanghai).

Second Base64 reference construction passes 31 new native controls and 33 refusal/rollback checks. All 1 actual calls match declared memory, ordered allocation/free and prefree bytes. Second reaches 96588/0x1121d4; next 0x288ad4→0x278314. Complete signing remains unfinished. See the [Base64 reference report](../REQUEST_JNI_STARTUP_WORKERS.md#6227-second-base64-reference2026-10-18-asiashanghai).

Second flag-controlled string cleanup passes 34 new native controls and 19 refusal/rollback checks. All 2 actual calls match declared memory and free effects. Second reaches 96519/0x1120c0; next 0x288a4c→0x258c14. Complete signing remains unfinished. See the [flagged cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#6226-second-flagged-cleanup2026-10-18-asiashanghai).

Second byte filling passes 50 new native controls and 20 refusal/rollback checks, using actual matching libc memset. 2 selected actual input shapes are compared; 17 total modeled calls are recorded separately. Second reaches 93021/0x111bc0; next 0x288ac8→0x1b55f8. Complete signing remains unfinished. See the [memory fill report](../REQUEST_JNI_STARTUP_WORKERS.md#6225-second-memory-fill2026-10-18-asiashanghai).

Second explicit-length string construction passes 35 new native controls and 28 refusal/rollback checks. Every one of 3 actual request calls matches native allocation effects and declared memory. Second reaches 86800/0x11387c; next 0x288ab4→0x347f20. Complete signing remains unfinished. See the [sized string report](../REQUEST_JNI_STARTUP_WORKERS.md#6224-second-sized-string2026-10-18-asiashanghai).

Second binary string clone passes 31 new native controls and 29 refusal/rollback checks. Actual request matches 155 instructions/1200 ranges and 1 allocation. Second reaches 11263/+10BDB0; next 288A74→2481FC. Complete signing remains unfinished. See the [string clone report](../REQUEST_JNI_STARTUP_WORKERS.md#6223-second-string-clone2026-10-18-asiashanghai).

Second decoded reference wrapper passes 31 new native controls and 33 refusal/rollback checks. Actual request matches 3159 instructions/1243 ranges and 4 allocations/1 free. Second reaches 11128/+10BB50; next 288A64→2483E0. Complete signing remains unfinished. See the [decoded reference report](../REQUEST_JNI_STARTUP_WORKERS.md#6222-second-decoded-reference2026-10-18-asiashanghai).

Second configuration lookup and nested reference scopes pass 19 new native controls and 33 rollback/refusal checks. Actual request matches 65 allocations/57 frees and 304121 instructions/1981 ranges. Second reaches 11118/+10BB28; next 288A4C→258E7C. Complete signing remains unfinished. See the [configuration lookup report](../REQUEST_JNI_STARTUP_WORKERS.md#6221-second-configuration-lookup2026-10-18-asiashanghai).

Second JSON deleting destructor passes53 new native controls and30 refusal/rollback checks. Actual request matches31 original libc frees and8409 instructions/1230 ranges. Second reaches11108/0x10bb00,next0x288a30->0x263174; complete signing remains unfinished. See the [JSON delete report](../REQUEST_JNI_STARTUP_WORKERS.md#6220-second-json-delete2026-10-18-asiashanghai).

Second explicit normal mutex unlock callback passes15 new native controls and24 refusal/rollback checks. Matching-libc actual request passes30 instructions/1187 ranges andmutex1->0. Second reaches10788/+10b3ec,next288a24->2614ec; complete signing remains unfinished. See the [mutex unlock report](../REQUEST_JNI_STARTUP_WORKERS.md#6219-second-mutex-unlock2026-10-18-asiashanghai).

Second Protobuf-C pack callback passes57 new native controls and32 refusal/rollback checks. Actual706-byte encoding and tail match over9402 instructions/1439 ranges. Second reaches10680/+10b23c,next2889a8 with an unresolved NULL pthread_mutex_unlock import; complete signing remains unfinished. See the [protobuf pack report](../REQUEST_JNI_STARTUP_WORKERS.md#6218-second-protobuf-pack2026-10-18-asiashanghai).

Second string fill tail callback passes29 new native controls and26 refusal/rollback checks. Existing fill owner is reused; actual request passes3657 instructions/1245 ranges with the original allocator. Second reaches10671/+10b218,next2889f4->2a337c; complete signing remains unfinished. See the [string fill report](../REQUEST_JNI_STARTUP_WORKERS.md#6217-second-string-fill2026-10-18-asiashanghai).

Second Protobuf-C size callback passes53 new native controls and35 refusal/rollback checks. Bounded proto3 size agrees with the original actual-request result706 over7168 instructions/1186 ranges. Second reaches10662/+10b1f4,next2889e0->248dd8; complete signing remains unfinished. See the [protobuf size report](../REQUEST_JNI_STARTUP_WORKERS.md#6216-second-protobuf-packed-size2026-10-18-asiashanghai).

Second raw realtime milliseconds callback passes15 new native controls and14 refusal/rollback checks. Existing signed wrapped-microsecond arithmetic is reused; actual request input passes48 instructions/1186 ranges. Second reaches10651/+10b1c8,next2889c4->2a3378; complete signing remains unfinished. See the [realtime milliseconds report](../REQUEST_JNI_STARTUP_WORKERS.md#6215-second-realtime-milliseconds2026-10-18-asiashanghai).

Second explicit pthread_mutex_lock import/callback passes15 new native controls and24 refusal/rollback checks. Actual request input passes26 instructions/1187 ranges; second reaches10599/+10b0f8,next28876c->26cc60. Only serialized uncontended normal locks are supported; complete signing remains unfinished. See the [mutex lock report](../REQUEST_JNI_STARTUP_WORKERS.md#6214-second-mutex-lock2026-10-18-asiashanghai).

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

The module constructor owner now supports all five actual ELF module constructors. Four additional entries pass 8 fresh native/Python controls, with 2 existing B constructor regressions and 77 rollback checks. Complete JNI/bootstrap and the independent signer remain unfinished. See the [module constructor report](../REQUEST_JNI_STARTUP_WORKERS.md#663-另外四个-elf-module-constructors2026-10-11-asiashanghai).

Six ELF support constructors now pass 48 fresh native/Python controls and 51 rollback checks. Object and JNI cache initialization reuse existing owners; clocks, auxv, property and exit registration are explicit guest services. Together with five module constructors, 11 of 13 init_array members are covered. The complete loader, JNI/bootstrap and independent signer remain unfinished. See the [ELF support report](../REQUEST_JNI_STARTUP_WORKERS.md#664-六个-elf-support-constructors2026-10-11-asiashanghai).

The guarded ELF string constructor now passes 18 fresh native/Python controls and 25 rollback checks; all six existing support entries pass 12 fresh regressions. Twelve of thirteen init_array members are covered. The complete loader, JNI/bootstrap and independent signer remain unfinished. See the [guarded string report](../REQUEST_JNI_STARTUP_WORKERS.md#665-elf-guarded-string-constructor2026-10-11-asiashanghai).

The ELF configuration constructor now passes 16 fresh native/Python controls and 72 rollback checks, including actual diagnostic scopes, matching-libc broadcasts and same-run warm calls. Existing registry results remain byte-identical (38 controls/14 guards). All thirteen init_array members have independent implementations; the complete sequential loader, JNI/bootstrap and signer remain unfinished. See the [configuration constructor report](../REQUEST_JNI_STARTUP_WORKERS.md#666-elf-configuration-constructor2026-10-11-asiashanghai).

The complete ELF init_array now executes all thirteen constructors in order with one shared allocation plan and passes 4 fresh native/Python controls and 40 rollback checks. Surviving pages and each ordered allocation/free, registration and OS/TLS stream match. Full binary mapping/linking, JNI/bootstrap and the independent signer remain unfinished. See the [constructor sequence report](../REQUEST_JNI_STARTUP_WORKERS.md#667-elf-init_array-完整顺序组合2026-10-11-asiashanghai).

The ELF image loader now maps all PT_LOAD/BSS pages and eagerly binds every relocation from program headers and dynamic metadata. Ten independent image controls, two complete native/Python constructor sequences and 42 refusal checks pass, including sectionless and GNU-hash inputs. Full JNI/bootstrap and the independent signer remain unfinished. See the [ELF image report](../REQUEST_JNI_STARTUP_WORKERS.md#668-elf-映射与完整符号链接2026-10-11-asiashanghai).

Fresh ELF mapping/linking and all thirteen constructors now compose through complete JNI_OnLoad and one conditional A/B main-thread startup. Four native/Python controls and 38 rollback checks pass; both task queues, 19 JNI calls, four JavaVM calls, three deferred worker requests and all surviving pages match. The finalizer callable adds 32 controls and nine guards; the old 84/12 callable regression is byte-identical. Same-run workers, cleanup and the independent signer remain unfinished. See the [complete JNI report](../REQUEST_JNI_STARTUP_WORKERS.md#669-完整-jni-与两条主线程-startup-组合2026-10-11-asiashanghai).

The complete ELF/JNI execution now continues into the executor and actual A/B initialization queue workers, with separate thread TLS and full joinable guest exit. Four native/Python controls and 28 rollback guards pass, including all surviving pages and ordered service groups. The third finalizer queue and independent signer remain unfinished. See the [full JNI worker report](../REQUEST_JNI_STARTUP_WORKERS.md#670-完整-jni-后的两条-worker-与-guest-退出清理2026-10-11-asiashanghai).

The first delayed JNI follow-up submission now preserves the native callable, deadline and executor deque, with 8 submission controls, 24 callable controls and 25 rollback guards. Both older callable regression files are byte-identical. The full finalizer worker and independent signer remain unfinished. See the [timed submission report](../REQUEST_JNI_STARTUP_WORKERS.md#671-jni-finalizer-的首条延时任务提交2026-10-11-asiashanghai).

The complete JNI execution now runs all three requested workers and full joinable guest exit. Four complete native/Python controls, four actual copied-probe controls and 47 rollback guards pass; all surviving pages and ordered service groups match. Complete timed queue dispatch and the independent signer remain unfinished. See the [complete finalizer report](../REQUEST_JNI_STARTUP_WORKERS.md#672-jni-finalizer-完整-worker-与-guest-退出2026-10-11-asiashanghai).

The actual delayed JNI callable now executes both guest image VMs, the unavailable Java object path, configuration publication and owning cleanup. Four fresh complete native/Python controls and 22 page rollback guards pass. Complete timed queue dispatch, live Java string conversion and the independent signer remain unfinished. See the [actual delayed callback report](../REQUEST_JNI_STARTUP_WORKERS.md#673-实际延时-jni-callable-与两段-image-vm2026-10-11-asiashanghai).

Actual timed polling now transfers the owned follow-up into the drained queue and frees its wrapper/task. Four fresh complete native/Python controls, 20 page rollback guards and shared callable regressions pass. The complete executor worker wait cycle, live Java string conversion and independent signer remain unfinished. See the [timed transfer report](../REQUEST_JNI_STARTUP_WORKERS.md#674-实际-timed-poll转交与-queue-清理2026-10-11-asiashanghai).

The three requested workers now cooperate across six actual waits, transfer the timed follow-up and exit in order 1, 2, 0. Four fresh complete native/Python controls and 23 page rollback guards pass; the shared executor and queue regressions are byte identical. Live Java string conversion and the independent signer remain unfinished. See the [cooperative worker report](../REQUEST_JNI_STARTUP_WORKERS.md#675-三条-worker-协作等待转交与完整退出2026-10-11-asiashanghai).

The Java byte array helper now preserves binary data through the original sized-string and diagnostic-reference path. Fifty-two native/Python controls and 19 page rollback guards pass. Actual live lookup, the independent signer, fresh signature output and the online matrix remain unfinished. See the [byte array report](../REQUEST_JNI_STARTUP_WORKERS.md#676-java-byte-array-转引用与实际诊断锁2026-10-11-asiashanghai).

JNI reference field access, no-argument object methods and local/global/weak cleanup now pass 74 native/Python controls and 18 page rollback guards. Actual Python live lookup, the independent signer, fresh output and the online matrix remain unfinished. See the [JNI reference member report](../REQUEST_JNI_STARTUP_WORKERS.md#677-jni-引用字段无参数方法与引用清理2026-10-11-asiashanghai).

Actual diagnostic string reference scopes and the MD5 temporary reference lifecycle pass 80 native/Python controls and 16 rollback guards. The original digest regression matches its accepted result. Actual Python live lookup and the complete signer remain unfinished. See the [reference scope report](../REQUEST_JNI_STARTUP_WORKERS.md#678-实际-reference-作用域与-md5-生命周期2026-10-11-asiashanghai).

Initialized live Java lookup passes 48 native/Python controls and 11 rollback guards across both SDK paths. Binary MD5 output, local cleanup, scope bytes and ordered services match. Cold initialization, live worker wiring and the complete signer remain unfinished. See the [live lookup report](../REQUEST_JNI_STARTUP_WORKERS.md#679-已初始化对象的实际-live-java-lookup2026-10-11-asiashanghai).

Cold encoded SDK lookup now passes 52 getter controls and 9 rollback guards; its initialized Java lookup composition passes another 10 controls and 4 guards. Encoded and plain caches remain independent and share decimal conversion. Cold live initialization, worker wiring and the complete signer remain unfinished. See the [cold SDK report](../REQUEST_JNI_STARTUP_WORKERS.md#680-cold-encoded-sdk-getter-与实际-live-lookup2026-10-11-asiashanghai).

Integer/reference argument JNI instance and static methods, void and integer/reference returns, and non-FP static fields pass 140 native/Python controls and 11 rollback guards. Consumed va_list arguments, native return widths, exception order and the legacy reference subset match. Cold initializer composition, worker wiring and the complete signer remain unfinished. See the [integer JNI report](../REQUEST_JNI_STARTUP_WORKERS.md#681-带整型引用参数的-jni-方法与静态字段2026-10-11-asiashanghai).

Actual UTF construction and Java service lookup pass 42 native/Python controls and 9 rollback guards. Short/heap C++ strings, exception clearing, returned references and local cleanup match. Service lookup requires a live default Java object. Initializer composition, worker wiring and the complete signer remain unfinished. See the [Java service report](../REQUEST_JNI_STARTUP_WORKERS.md#682-实际-utf-构造与-java-service-查找2026-10-12-asiashanghai).

Actual live receiver initialization and cold lookup pass 92 native/Python controls and 6 rollback guards. SDK branches, once flags, published global references, Parcel/local cleanup and complete binary MD5 lookup match. VM/worker provider wiring and the complete signer remain unfinished. See the [live initializer report](../REQUEST_JNI_STARTUP_WORKERS.md#683-实际-live-initializer-与-cold-lookup2026-10-12-asiashanghai).

Delayed VM and callable entries forward explicit live JNI, allocator and SDK providers. Four evaluator and two complete callable native/Python controls, two bounded worker entry checks and sixteen rollback guards pass. Live lookup now preserves the output-reference stack padding used by a later registry setter. The complete signer remains unfinished. See the [live provider report](../REQUEST_JNI_STARTUP_WORKERS.md#684-delayed-vmcallableworker-的-live-provider-接线2026-10-12-asiashanghai).

The actual request stack evaluator now restores JNI calls, prefix comparisons, UTF/local cleanup and NULL/exception behavior. 78 native/Python controls, one bounded request VM entry check and 20 rollback guards pass. The request entry forwards explicit JNI and singleton services and reaches the next scope-cleanup boundary at 965 steps. The complete signer remains unfinished. See the [stack evaluator report](../REQUEST_JNI_STARTUP_WORKERS.md#685-实际-request-stack-evaluator-与请求-vm-接线2026-10-12-asiashanghai).

Actual boolean scope cleanup now records elapsed time, fetches/increments the counter and emits the sampled two-argument event. 46 native/Python controls, one bounded request VM entry check and 28 rollback guards pass. The owning request continues to 993 steps and reaches the publication callback boundary. The complete signer remains unfinished. See the [scope cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#686-实际-boolean-scope-清理与-elapsed-event2026-10-12-asiashanghai).

The actual JNI publisher now acquires the environment, dispatches both tags and cleans both references. The distinct request byte gate resolves to the original zero-return leaf at +28BB54; it has no JNI effects. 44 native/Python controls, one request VM entry check and 20 rollback guards pass. The public request reaches 1019 steps and stops at object construction +25CDD4. The complete signer remains unfinished. See the [publication and byte gate report](../REQUEST_JNI_STARTUP_WORKERS.md#687-实际-jni-发布器与请求-byte-gate2026-10-12-asiashanghai).

Actual request object construction now clones the input string, copies the shared reference, stores realtime milliseconds and releases the temporary reference to one surviving owner. 60 native/Python controls, one request VM entry check and 34 rollback guards pass. The public request reaches 1419 steps and stops at callback +256AB0. The complete signer remains unfinished. See the [request object report](../REQUEST_JNI_STARTUP_WORKERS.md#688-实际请求对象构造与临时引用生命周期2026-10-12-asiashanghai).

The actual registry counter now performs scoped lookup, signed saturation or cloned-key insertion and returns the old u32. 40 native/Python controls, one request VM entry check and 36 rollback guards pass. The request uses its owning TLS/registry/broadcast services, reaches 1444 steps and stops at tree construction +25BF14. The complete signer remains unfinished. See the [registry counter report](../REQUEST_JNI_STARTUP_WORKERS.md#689-实际-registry-计数回调与拥有者-tls-接线2026-10-12-asiashanghai).

The request now reuses the actual tree constructor and restores begin/end iterator pairs and node/table comparison. 24 native/Python controls, one request VM entry check and 13 rollback guards pass. Its independently constructed empty header input reaches 1539 steps, where the unresolved __cxa_atexit import is rejected. The complete signer remains unfinished. See the [tree and iterator report](../REQUEST_JNI_STARTUP_WORKERS.md#690-实际请求树构造与-iterator-abi2026-10-12-asiashanghai).

The actual __cxa_atexit import and process registration wrapper now pass 16 native/Python controls, one request VM entry check and 17 rollback guards. The owning request reaches 1558 steps at the fill-string constructor. Real libc exit tables and destructor execution remain unverified; the complete signer remains unfinished. See the [process registration report](../REQUEST_JNI_STARTUP_WORKERS.md#691-实际进程析构导入与注册2026-10-12-asiashanghai).

The actual fill-string constructor and byte-argument wrapper pass 40 native/Python controls, one request VM entry check and 20 rollback guards. The owning request reaches 1567 steps at the tree lookup wrapper. The complete signer remains unfinished. See the [fill-string report](../REQUEST_JNI_STARTUP_WORKERS.md#692-实际填充字符串构造与-wrapper-字节参数2026-10-12-asiashanghai).

The actual tree lookup and NULL-safe C-string length wrappers reuse existing owners. 28 native/Python controls, one request VM entry check and 20 rollback guards pass. The owning request reaches 1812 steps at the guest-table folded comparison; the complete signer remains unfinished. See the [collection wrapper report](../REQUEST_JNI_STARTUP_WORKERS.md#693-实际树查询与-c-字符串长度-wrapper2026-10-12-asiashanghai).

Guest-table folded comparison and its actual wrapper pass 48 native/Python controls, one request VM entry check and 26 rollback guards. Both real warm singleton getter SPs, scratch and order match. The owning request reaches 1995 steps at tree count; the complete signer remains unfinished. See the [folded comparison report](../REQUEST_JNI_STARTUP_WORKERS.md#694-实际-guest-table-折叠比较与-singleton-接线2026-10-12-asiashanghai).

Request tree count, string-value replacement, iterator pairs, clone and advance pass 128 native/Python controls, one request VM entry check and 40 rollback guards. The actual owning request reaches 2321 steps at local tree destruction under a finite 4000-step budget. The complete signer remains unfinished. See the [tree traversal report](../REQUEST_JNI_STARTUP_WORKERS.md#695-请求树计数与-value-清理和-iterator-遍历2026-10-12-asiashanghai).

Local request tree destruction passes 32 native/Python controls, one request VM entry check and 27 rollback guards. The owning request reaches 2329 steps at request object destruction. The complete signer remains unfinished. See the [local tree destructor report](../REQUEST_JNI_STARTUP_WORKERS.md#696-请求局部树析构2026-10-12-asiashanghai).

Request object cleanup, final free and deleting tree destruction pass 78 native/Python controls, one request VM entry check and 36 rollback guards. With empty headers and NULL FindClass services, the owning request VM returns in 2475 steps after 105 callbacks. Native caller return ABI and the complete signer remain unfinished. See the [cleanup and VM return report](../REQUEST_JNI_STARTUP_WORKERS.md#697-请求对象与树删除清理和-vm-返回2026-10-12-asiashanghai).

Actual scoped request tree construction passes 24 native/Python controls, one request VM entry and 31 rollback guards. Descriptor visibility, logical scopes and allocation order match; the request still returns in 2475 steps after 105 callbacks. Complete signing remains unfinished. See the [scoped tree report](../REQUEST_JNI_STARTUP_WORKERS.md#698-请求-scoped-tree-reference-构造2026-10-12-asiashanghai).

VM opcode 36 loads the full word and opcode 57 performs a serialized compare/store using hidden slot 34. 114 native/Python controls, one request entry and 21 rejection/rollback checks pass. The remaining main ELF byte difference in the private request probe is resolved; full signing remains unfinished. See the [VM load/store report](../REQUEST_JNI_STARTUP_WORKERS.md#699-vm-load-与串行-comparestore2026-10-12-asiashanghai).

Request caller return now checks the stack canary and restores PC/SP/X19/X28/X29/X30 with the physical X0 callback sentinel. 16 native controls, one request entry and 26 rejections pass: 25 preserve all pages; the canary entry preserves existing bytes but leaves 64 allocator mapping pages. Full signing remains unfinished. See the [caller return report](../REQUEST_JNI_STARTUP_WORKERS.md#6100-request-caller-物理返回2026-10-12-asiashanghai).

NULL raw cleanup now skips the provider free call: 16 new native controls and six rollback checks pass. The constructed request chain also matches 105 effective packed inputs, 10 explicit service calls and the physical caller return; remaining measured RAM differences are scoped token/short-string padding. Actual request conversion and complete signing remain unfinished. See the [raw cleanup and effective fields report](../REQUEST_JNI_STARTUP_WORKERS.md#6101-null-raw-cleanup-与整链有效字段2026-10-12-asiashanghai).

Request ASCII upper/lower conversion and the receiver byte flag now pass 92 new native controls and eight rollback checks. A constructed URL and one-header prefix advances to 2174 steps; byte search and actual JNI conversion remain open. Complete signing remains unfinished. See the [ASCII and receiver flag report](../REQUEST_JNI_STARTUP_WORKERS.md#6102-ascii-case-与-request-byte-flag2026-10-12-asiashanghai).

Request byte search now passes 80 new native controls, 12 rollback checks and eight scan bound checks. The constructed nonempty prefix advances to 2224 steps; sized-string dispatch, actual JNI conversion and complete signing remain unfinished. See the [byte search report](../REQUEST_JNI_STARTUP_WORKERS.md#6103-request-byte-search2026-10-12-asiashanghai).

Request sized-string dispatch now passes 18 new native wrapper controls and ten rollback checks using the existing owner. The constructed nonempty prefix advances to 2243 steps; rejection preserves original bytes but retains 64 new allocator OS pages. Binary equality, actual JNI conversion and complete signing remain unfinished. See the [sized dispatch report](../REQUEST_JNI_STARTUP_WORKERS.md#6104-request-sized-string-dispatch2026-10-12-asiashanghai).

Request binary equality now passes 48 new native controls and eight rollback checks, including 16 comparisons using the actual matching-libc memcmp body. Native short circuits now precede skipped fields and payload bounds. The constructed nonempty prefix advances to 2395 steps; substring construction and complete signing remain unfinished. See the [binary equality report](../REQUEST_JNI_STARTUP_WORKERS.md#6105-request-binary-equality2026-10-12-asiashanghai).

A new constructed nonempty request prefix now matches the original caller and interpreter across 98 callback paths, packed addresses and effective packed inputs. Native stops before the substring body; pointed payloads, full heap/stack equivalence, actual JNI conversion and complete signing remain unfinished. See the [nonempty effective ABI report](../REQUEST_JNI_STARTUP_WORKERS.md#6106-constructed-nonempty-request-effective-abi2026-10-12-asiashanghai).

Field clone and X8 substring construction now pass 74 new native controls and 20 rollback checks. Wrapped signed substring arithmetic, allocation failures and modeled scratch aliases match. The constructed nonempty prefix advances to 2510 steps; the next temporary-string composition, actual JNI conversion and complete signing remain unfinished. See the [substring report](../REQUEST_JNI_STARTUP_WORKERS.md#6107-field-clone-与-substring2026-10-12-asiashanghai).

CString plus StringObject composition and temporary cleanup now pass 84 new native controls and 28 rollback checks. Allocation failures, declared binary tails and modeled temporary aliases match, including pre-free bytes. The constructed nonempty prefix advances to 2520 steps; StringObject plus CString construction, actual JNI conversion and complete signing remain unfinished. See the [composition report](../REQUEST_JNI_STARTUP_WORKERS.md#6108-cstringstringobject-拼接2026-10-12-asiashanghai).

StringObject clone plus CString append construction now passes 68 new native controls and 24 rollback checks, including 12 new long-first realloc controls. Native X0, live aliases and partial reserve failures match. The constructed nonempty entry remains at 2520 steps and now stops inside this callback at the unrecovered matching-libc realloc boundary. Actual JNI conversion and complete signing remain unfinished. See the [object and CString report](../REQUEST_JNI_STARTUP_WORKERS.md#6109-stringobjectcstring-构造2026-10-12-asiashanghai).

Matching-libc same small-bin realloc now passes 18 new original-instruction controls and 28 rollback checks. It retains the pointer and usable buffer while updating both TSD byte counters with uint64 wrapping. Cross-bin and NULL/zero realloc remain unfinished. The constructed nonempty prefix advances to 2538 steps; the next StringObject search callback, actual JNI conversion and complete signing remain unfinished. See the [same-bin realloc report](../REQUEST_JNI_STARTUP_WORKERS.md#6110-matching-libc-同类别-realloc2026-10-12-asiashanghai).

Declared StringObject ASCII case-insensitive search now passes 72 new native controls and 20 rollback checks. Binary tails, native short circuits and the same-pointer fast path match; bounds count actual byte comparisons. The constructed nonempty prefix advances to 2590 steps; the next CString-pattern search, actual JNI conversion and complete signing remain unfinished. See the [casefold search report](../REQUEST_JNI_STARTUP_WORKERS.md#6111-stringobject-ascii-casefold-搜索2026-10-12-asiashanghai).

CString-pattern search now passes 76 new native controls and 24 rollback checks. Native paired scans, contiguous-hit checks, unsigned prechecks and signed offsets match. The constructed nonempty prefix advances to 2761 steps and now stops at VM op17 sub53. Actual JNI conversion and complete signing remain unfinished. See the [CString search report](../REQUEST_JNI_STARTUP_WORKERS.md#6112-cstring-pattern-搜索2026-10-12-asiashanghai).

VM signed 64-bit multiplication and hidden low-product transfer now pass 238 new native/Python controls from 220 original interpreter executions. Both full-width product halves and register backing match. The constructed nonempty prefix advances to 2850 steps; actual JNI conversion and complete signing remain unfinished. See the [signed product report](../REQUEST_JNI_STARTUP_WORKERS.md#6113-vm-signed-product-与-low-copy2026-10-12-asiashanghai).

State numeric member lookup now passes 60 new native/Python controls and 18 rollback checks. Original nested shared readers and matching-libc mutex calls match, including ASCII keys and ARM64 floating-point conversion. This dependency is ready; the request state callback and its lazy service remain unfinished at the 2850-step boundary. See the [state numeric report](../REQUEST_JNI_STARTUP_WORKERS.md#6114-state-numeric-member-读取2026-10-12-asiashanghai).

Lazy state service composition now passes eight fresh native/Python controls and seven rollback checks with an explicitly initialized singleton136. Cold allocation/free/registration/wake order, all ELF pages and TLS bytes match. The request state callback remains the next boundary at 2850 steps. See the [state service report](../REQUEST_JNI_STARTUP_WORKERS.md#6115-lazy-state-service2026-10-12-asiashanghai).

Actual request state construction now passes 16 new native wrapper controls and seven rollback checks. Signed defaults, reference counts, TLS padding and writer cleanup match. The constructed nonempty prefix advances to 2911 steps and reaches the elapsed-time getter; complete signing remains unfinished. See the [request state report](../REQUEST_JNI_STARTUP_WORKERS.md#6116-request-state-构造与清理2026-10-12-asiashanghai).

Actual request elapsed seconds now pass 36 new native wrapper controls and 12 rollback checks. Saved-start read order, wrapped signed selection, unsigned division and reader cleanup match. The constructed nonempty prefix advances to 3167 steps; complete signing remains unfinished. See the [request elapsed report](../REQUEST_JNI_STARTUP_WORKERS.md#6117-request-elapsed-seconds2026-10-12-asiashanghai).

Actual request contained-reference copy and StringObject table hash64 now pass 84 new native wrapper controls and six rollback checks. Scoped ownership, hidden output, signed lengths, guest table and full-width hash results match. The constructed nonempty prefix advances to 3257 steps; complete signing remains unfinished. See the [request reference/hash report](../REQUEST_JNI_STARTUP_WORKERS.md#6119-request-stringobject-table-hash642026-10-12-asiashanghai).

Actual request TLS uint32 getter and setter now pass 34 new native wrapper controls. Cold/warm libc TLS, high uint32 values, packed padding and allocation/wake order match. The constructed nonempty prefix advances to 3307 steps; complete signing remains unfinished. See the [request TLS report](../REQUEST_JNI_STARTUP_WORKERS.md#6120-request-tls-uint32-读写2026-10-12-asiashanghai).

The actual request binary-transform component now passes 24 new native controls and ten rollback checks with an initialized SDK input. Allocation-dependent key bytes, S-box writes and forward mixing match. The outer transform caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [request transform report](../REQUEST_JNI_STARTUP_WORKERS.md#6121-request-binary-transform2026-10-12-asiashanghai).

The actual request hexadecimal-reference helper now passes 20 new native controls and eight rollback checks. Guest alphabet, live nibble reads and scoped ownership match. The outer transform caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [hex reference report](../REQUEST_JNI_STARTUP_WORKERS.md#6122-request-hexadecimal-reference2026-10-12-asiashanghai).

Raw MD5 and scoped reference assignments now pass 54 new native controls and 12 rollback checks. Digest scratch, scope overlap, alias order and ownership match. The outer transform caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [raw MD5 report](../REQUEST_JNI_STARTUP_WORKERS.md#6123-request-raw-md5-and-reference-assignment2026-10-12-asiashanghai).

The request version initializer/getter now passes 40 new native controls and ten rollback checks. Packed version, separate initializer status, encoded-table reloads and cached guard paths match. The outer caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [version report](../REQUEST_JNI_STARTUP_WORKERS.md#6124-request-version-word2026-10-13-asiashanghai).

The request allocated printf helper now passes 36 new native controls and nine rollback checks. Both live format passes, truncation, pointer publication and allocator effects match. The outer caller and complete signing remain unfinished; the nonempty prefix stays at 3307 steps. See the [allocated printf report](../REQUEST_JNI_STARTUP_WORKERS.md#6125-request-allocated-printf2026-10-13-asiashanghai).

The outer request suffix now passes 26 new native controls and nine rollback checks; the raw-free wrapper adds six controls and two guards. Existing owners compose both output C strings and cleanup. The independently constructed nonempty entry advances from 3307 to 3405 steps, next at +287168. Full JNI, whole-request native comparison and complete signing remain unfinished. See the [outer suffix report](../REQUEST_JNI_STARTUP_WORKERS.md#6126-request-outer-suffix-and-raw-free2026-10-13-asiashanghai).

Request metadata formatting and unsigned decimal now pass 46 new native controls and 12 rollback checks. Both output strings, cached input words and actual source callback match. The independently constructed nonempty entry advances to 3520 steps, next at +258d6c. Full JNI, whole-request native comparison and complete signing remain unfinished. See the [metadata report](../REQUEST_JNI_STARTUP_WORKERS.md#6127-request-metadata-formatting2026-10-13-asiashanghai).

The raw Base64 encoder, two-pass StringObject composition and actual source callback now pass 68 new native controls and 10 rollback checks. Guest alphabet aliases, capacity/NUL rules, scratch and cleanup match. The independently constructed nonempty entry advances to 3538 steps, next at +2482ec. Full JNI, whole-request comparison and complete signing remain unfinished. See the [Base64 encoder report](../REQUEST_JNI_STARTUP_WORKERS.md#6128-request-base64-encoder2026-10-13-asiashanghai).

The single-byte StringObject constructor and actual source callback now pass 30 new native controls and seven rollback checks. Live ELF fields, allocation publication and buffer/object aliases match. The independently constructed nonempty entry advances to 3550 steps, next at +248ef8. Full JNI, whole-request comparison and complete signing remain unfinished. See the [character report](../REQUEST_JNI_STARTUP_WORKERS.md#6129-request-character-string2026-10-13-asiashanghai).

Reverse character-set search, right trim and the actual source callback now pass 64 new native controls and nine rollback checks. Bitmap aliases, signed index, length/NUL and canary match. The independently constructed nonempty entry advances to 3559 steps, next at +248eb4. Full JNI, whole-request comparison and complete signing remain unfinished. See the [right-set report](../REQUEST_JNI_STARTUP_WORKERS.md#6130-request-right-character-set-trim2026-10-13-asiashanghai).

Forward character-set search, field erase, left trim and actual source callback now pass 94 new native controls and 11 rollback checks. Shared reverse-search bitmap semantics remain unchanged by expansion AST comparison. The independently constructed nonempty entry advances to 3767 steps, next at +287500. Full JNI, whole-request comparison and complete signing remain unfinished. See the [left-set report](../REQUEST_JNI_STARTUP_WORKERS.md#6131-request-left-character-set-trim2026-10-13-asiashanghai).

The +287500 nested caller and its first two constant callbacks pass 20 new native controls and eight rollback checks. Its prefix reaches 179 steps, next at +26cc8c. Outer request integration and complete signing remain unfinished. See the [token VM report](../REQUEST_JNI_STARTUP_WORKERS.md#6132-request-token-vm-caller-and-prefix2026-10-13-asiashanghai).

Matching-libc random state, seeding, serialized wrappers, the request getter and its actual consumer pass 98 new native controls and 15 rollback checks. gettimeofday is an explicit virtual service. The corrected random guard is +3dedb0. Nested integration and complete signing remain unfinished. See the [random report](../REQUEST_JNI_STARTUP_WORKERS.md#6133-request-random-state-and-getter2026-10-13-asiashanghai).

The nested random callback and its actual outer consumer are now connected. Twelve new native controls and five rollback checks pass. Fresh nested fixtures reach 191 steps; the independently constructed owning entry reaches 158 nested steps, both next at +32a444. Complete nested return and signing remain unfinished. See the [nested random report](../REQUEST_JNI_STARTUP_WORKERS.md#6134-request-nested-random-continuation2026-10-13-asiashanghai).

Actual nested shared-reader consumers now reuse the accepted reader owners. Twenty-eight new native controls and seven rollback checks pass. Fresh fixtures reach 211 nested steps; the independently constructed owning entry reaches 178, next at +26c858 diagnostic scope. Complete nested return and signing remain unfinished. See the [nested readers report](../REQUEST_JNI_STARTUP_WORKERS.md#6135-request-nested-shared-readers2026-10-13-asiashanghai).

Actual nested diagnostic enter/leave consumers now reuse the accepted scope owners. Sixteen new native controls and five rollback checks pass. The independently constructed owning entry reaches 231 nested steps, next at +2483e0 StringObject clone. Whole nested-prefix comparison, full physical ABI and complete signing remain unfinished. See the [nested scopes report](../REQUEST_JNI_STARTUP_WORKERS.md#6136-request-nested-diagnostic-scopes2026-10-13-asiashanghai).

Actual nested clone, default, free, destroy and delete consumers reuse accepted owners. Thirty-six new native controls and eight rollback checks pass. The independently constructed owning entry reaches 287 nested steps, next at +248908 formatting. Complete nested return and signing remain unfinished. See the [nested lifecycle report](../REQUEST_JNI_STARTUP_WORKERS.md#6137-request-nested-string-lifecycle2026-10-13-asiashanghai).

Actual nested format, sized and StringObject pair consumers now reuse accepted owners. Forty-six new native controls and ten rollback checks pass, including matching-libc vsnprintf. The independently constructed owning entry reaches 321 steps, next at MD5 reference construction. Whole nested return and complete signing remain unfinished. See the [nested strings report](../REQUEST_JNI_STARTUP_WORKERS.md#6138-request-nested-string-transforms2026-10-13-asiashanghai).

The actual nested MD5 consumer now reuses the accepted scoped reference lifecycle. Thirty-two new native controls and eight rollback checks pass with matching-libc recursive mutexes. The independently constructed owning entry reaches 422 steps, next at the obfuscated +287580 helper. Whole nested return and signing remain unfinished. See the [nested MD5 report](../REQUEST_JNI_STARTUP_WORKERS.md#6139-request-nested-scoped-md52026-10-13-asiashanghai).

The request round schedule and block helpers now pass 32 new native controls and eight rollback checks. Encoded helper slots resolve from guest ELF, and block computation reuses the bytecode-bound Helios owner. The +287580 caller remains unfinished; the accepted owning boundary stays at 422 steps. See the [round/block report](../REQUEST_JNI_STARTUP_WORKERS.md#6140-request-round-schedule-and-block-helpers2026-10-13-asiashanghai).

Allocated and StringObject cipher callers now pass 48 new native controls and ten rollback checks, including the actual +288BDC consumer. The owning entry reaches an unrecovered matching-libc cross-bin realloc from 32 to 64 bytes at nested step 422. Complete nested return and signing remain unfinished. See the [cipher caller report](../REQUEST_JNI_STARTUP_WORKERS.md#6141-request-allocated-and-string-cipher-callers2026-10-13-asiashanghai).

Matching-libc small cross-bin realloc now passes 18 new native controls and nine rollback checks. The owning session composes actual allocation, live copy and free while preserving the same-bin owner. The independently constructed owning entry advances to430 nested steps, next at StringObject append. Complete signing remains unfinished. See the [cross-bin report](../REQUEST_JNI_STARTUP_WORKERS.md#6142-matching-libc-cross-bin-small-realloc2026-10-13-asiashanghai).

Actual nested append and scoped Base64 reference consumers pass 34 new native controls and eight rollback checks, including live source mutations and matching-libc recursive mutexes. The independently constructed owning entry reaches505 nested steps, next at allocated printf. Complete signing remains unfinished. See the [append/Base64 report](../REQUEST_JNI_STARTUP_WORKERS.md#6143-request-nested-append-and-base64-reference2026-10-13-asiashanghai).

Actual nested allocated printf passes 36 new native controls and ten rollback checks. W0 publication preserves packed padding and live inputs across malloc. The independently constructed owning entry reaches574 steps at the nested return instruction after cleanup. Complete signing remains unfinished. See the [nested printf report](../REQUEST_JNI_STARTUP_WORKERS.md#6144-request-nested-allocated-printf2026-10-13-asiashanghai).

Nested caller return passes 32 new native controls and ten rollback checks, plus five constructed entry checks. Explicit continuation returns after40 nested callbacks and advances the owning outer request to3879 steps, next at the URL condition callback. Whole nested/request native equivalence and complete signing remain unfinished. See the [nested return report](../REQUEST_JNI_STARTUP_WORKERS.md#6145-request-nested-caller-return2026-10-13-asiashanghai).

Actual URL condition passes 40 new native controls and seven rollback checks. Three lazy constants and ordered searches preserve the disabled URL shortcut and one-byte packed result. The constructed owning request reaches3900 steps, next at +287474. Whole request equivalence and complete signing remain unfinished. See the [URL condition report](../REQUEST_JNI_STARTUP_WORKERS.md#6146-request-url-condition2026-10-13-asiashanghai).

The second request VM caller and bounded prefix pass 20 new native controls and eight rollback checks. All32 prelude/backing words and the first three decode consumers match. The constructed owning input reaches617 steps, next at default StringObject construction. Complete second VM return and signing remain unfinished. See the [second VM report](../REQUEST_JNI_STARTUP_WORKERS.md#6147-request-second-vm-caller-and-prefix2026-10-13-asiashanghai).

Second VM consumers pass 153 new native controls, twelve rollback checks and five Python entry rejections. The owning bounded second VM advances to8184 steps; its32 virtual registers, callback ledger and declared memory ranges match original native code. The next child is +28048c; complete request and signing remain unfinished. See the [second consumer report](../REQUEST_JNI_STARTUP_WORKERS.md#6148-request-second-vm-consumers2026-10-13-asiashanghai).

The child VM caller, hidden-X8 wrapper and first decode pass26 new native controls and ten rollback checks. The owning child reaches290 steps, next at filled StringObject construction. Complete child/request, JNI and signing remain unfinished. See the [child VM report](../REQUEST_JNI_STARTUP_WORKERS.md#6149-request-child-vm-caller-and-prefix2026-10-13-asiashanghai).

Child VM consumers pass83 new native controls,13 rollback checks and five Python entry rejection checks. Its owning bounded prefix reaches19295 steps; all32 virtual registers, the callback ledger and16 declared memory ranges match original native. The next boundary is the204e50 nested helper. Complete child/request, JNI and signing remain unfinished. See the [child consumers report](../REQUEST_JNI_STARTUP_WORKERS.md#6150-request-child-vm-consumers2026-10-13-asiashanghai).

Environment helper callers and decoder prefixes pass33 new native controls and11 rollback checks. The owning204e50 helper reaches134 steps at actual environment acquisition; all32 virtual registers, the complete callback ledger and five declared memory ranges match original native. Complete helpers/request, JNI and signing remain unfinished. See the [environment helper report](../REQUEST_JNI_STARTUP_WORKERS.md#6151-request-environment-helper-vm-callers-and-prefixes2026-10-14-asiashanghai).

The actual environment acquisition callback passes17 new native controls, six rollback checks and three Python entry rejection checks. The owning helper reaches214 steps at StringObject construction; all32 virtual registers, the callback ledger and nine declared memory ranges match original native with the existing GetEnv provider. Complete request/JNI conversion and signing remain unfinished. See the [environment acquisition report](../REQUEST_JNI_STARTUP_WORKERS.md#6152-request-environment-acquisition-callback2026-10-14-asiashanghai).

Actual environment StringObject callbacks pass39 new native controls, nine rollback checks and three Python entry rejections. The owning helper reaches226 steps before logging, with all32 virtual registers, its callback ledger and eleven declared memory ranges matching original native. Cleanup is verified separately; full request conversion and signing remain unfinished. See the [environment StringObject report](../REQUEST_JNI_STARTUP_WORKERS.md#6153-request-environment-stringobject-callbacks2026-10-14-asiashanghai).

The actual environment logger passes13 new native controls, nine rollback checks and three Python entry rejections. The owning helper executes logging and cleanup through262 steps to its VM exit boundary; all32 virtual registers, the complete callback ledger and fourteen declared ranges match original native. Helper caller return and full signing remain unfinished. See the [environment logger report](../REQUEST_JNI_STARTUP_WORKERS.md#6154-request-environment-logger-and-cleanup2026-10-14-asiashanghai).

Environment helper returns pass53 new native controls, eight rollback checks and four Python entry rejections. The owning +204e50 helper returns with matching physical values and packed bytes; its child reaches19302 steps before the +204b80 JNI helper. Complete request conversion and signing remain unfinished. See the [environment return report](../REQUEST_JNI_STARTUP_WORKERS.md#6155-request-environment-helper-return2026-10-15-asiashanghai).

JNI availability passes32 new native controls and ten rollback checks. Actual +204b80 semantics now share one owner with the finalizer, preserving raw cache bytes, real environment acquisition and exception behavior. The child wrapper remains to be connected; complete signing remains unfinished. See the [availability report](../REQUEST_JNI_STARTUP_WORKERS.md#6156-jni-static-method-availability2026-10-15-asiashanghai).

The actual JNI availability wrapper passes26 new native controls and nine rollback checks. Ten physical return values, declared frame bytes and packed W result match, including saved-register aliases. A constructed request now has an explicit initialization contract; child callback wiring and complete signing remain unfinished. See the [wrapper report](../REQUEST_JNI_STARTUP_WORKERS.md#6157-jni-availability-wrapper2026-10-15-asiashanghai).

Child JNI availability wiring passes one new owning native callback and six request/child entry refusals. The initialized +204b80 callback returns1; the constructed child reaches19470 steps before +2814e4 environment acquisition. Complete child/request execution and signing remain unfinished. See the [child callback report](../REQUEST_JNI_STARTUP_WORKERS.md#6158-child-jni-availability-callback2026-10-15-asiashanghai).

Child environment acquisition passes17 new native controls. The actual +2814e4 tail wrapper reuses the established owner at unchanged SP; the constructed child reaches19533 steps before +28155c string construction. Complete child/request execution and signing remain unfinished. See the [child environment report](../REQUEST_JNI_STARTUP_WORKERS.md#6159-child-environment-acquisition2026-10-15-asiashanghai).

Child StringObject construction passes23 new native controls and eight rollback checks. The owning +28155c callback executes original matching-libc malloc and matches1186 declared ranges. The constructed child reaches19541 steps before +256a18 configuration lookup; complete execution and signing remain unfinished. See the [child strings report](../REQUEST_JNI_STARTUP_WORKERS.md#6160-child-stringobject-construction2026-10-15-asiashanghai).

Child configuration u32 reading passes41 new native controls and12 rollback checks. The +256a18 getter uses existing shared-reader and tree owners;524 owning native instructions match1186 declared ranges and four mutex transitions. The child reaches19549 steps before StringObject destruction; full signing remains unfinished. See the [child registry read report](../REQUEST_JNI_STARTUP_WORKERS.md#6161-child-configuration-u32-read2026-10-15-asiashanghai).

Child StringObject cleanup passes17 new native controls and7 rollback checks. The owning destructor executes152 original instructions and one matching-libc free with1186 declared ranges equal. The child observes VM exit at19566 steps; its physical caller/wrapper return and complete signing remain unfinished. See the [child cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#6162-child-stringobject-cleanup-and-vm-exit2026-10-15-asiashanghai).

Child physical caller/wrapper return passes23 new native controls and16 rollback checks. The owning return matches1184 declared ranges and seven physical values. The child resumes its parent, advancing the second VM to8251 steps before string construction; complete signing remains unfinished. See the [child return report](../REQUEST_JNI_STARTUP_WORKERS.md#6163-child-physical-caller-and-wrapper-return2026-10-15-asiashanghai).

Second VM StringObject construction passes23 new native controls and8 rollback checks. The owning constructor executes155 original instructions and one matching-libc malloc, with1186 declared ranges equal. The second VM reaches8261 steps before shared-reader acquisition, preserving the child return; complete signing remains unfinished. See the [second strings report](../REQUEST_JNI_STARTUP_WORKERS.md#6164-second-vm-stringobject-construction2026-10-15-asiashanghai).

Second VM shared-reader acquisition passes19 new native controls and11 rollback checks. The owning callback matches1185 declared ranges and two actual mutex transitions in94 instructions. The second VM reaches8279 steps before diagnostic scope entry; complete signing remains unfinished. See the [second reader report](../REQUEST_JNI_STARTUP_WORKERS.md#6165-second-vm-shared-reader-acquisition2026-10-15-asiashanghai).

Second VM diagnostic scope entry passes13 new native controls and7 rollback checks. The owning warm scope matches1185 declared ranges and actual recursive-mutex events in110 instructions, with no allocation. The second VM reaches8298 steps before scope cleanup; complete signing remains unfinished. See the [second diagnostic report](../REQUEST_JNI_STARTUP_WORKERS.md#6166-second-vm-diagnostic-scope-entry2026-10-15-asiashanghai).

Second VM diagnostic scope cleanup passes21 new native controls and9 rollback checks. The owning cleanup matches1185 declared ranges and actual recursive-mutex events in53 instructions. The second VM reaches8309 steps before shared-reader release; complete signing remains unfinished. See the [second diagnostic cleanup report](../REQUEST_JNI_STARTUP_WORKERS.md#6167-second-vm-diagnostic-scope-cleanup2026-10-15-asiashanghai).

Second VM shared-reader release passes19 new native controls and12 rollback checks. The owning release matches1185 declared ranges and two actual mutex operations in83 instructions. The second VM reaches8355 steps before string/C-string comparison; complete signing remains unfinished. See the [second reader release report](../REQUEST_JNI_STARTUP_WORKERS.md#6168-second-vm-shared-reader-release2026-10-15-asiashanghai).

Second VM string equality passes27 new native controls and9 rollback checks. The owning comparison matches1185 declared ranges in32 instructions with no allocation or external services. The second VM reaches8405 steps before StringObject assignment; complete signing remains unfinished. See the [second equality report](../REQUEST_JNI_STARTUP_WORKERS.md#6169-second-vm-string-equality2026-10-15-asiashanghai).

Second VM string assignment passes37 new native controls and13 rollback checks. The owning assignment matches1185 declared ranges and actual libc malloc/free in347 instructions. The second VM reaches8416 steps before the random getter; complete signing remains unfinished. See the [second assignment report](../REQUEST_JNI_STARTUP_WORKERS.md#6170-second-vm-string-assignment2026-10-15-asiashanghai).

Second VM random callback passes17 new native controls and11 rollback checks. The warm owning callback matches1191 ranges and actual libc random/mutex execution in126 instructions. The second VM reaches8532 steps before +288658 -> +257804; complete signing remains unfinished. See the [second random report](../REQUEST_JNI_STARTUP_WORKERS.md#6171-second-vm-random-callback2026-10-15-asiashanghai).

Second VM reference getter passes33 new native controls and13 rollback checks. The owning getter matches1186 ranges and live diagnostic fields in429 instructions, with four shared mutex transitions and no allocation. The second VM reaches8539 steps before +288670 -> +257880; complete signing remains unfinished. See the [second reference getter report](../REQUEST_JNI_STARTUP_WORKERS.md#6172-second-vm-reference-getter2026-10-15-asiashanghai).

Second VM cached u32 getter passes27 new native controls and13 rollback checks. The owning getter matches1185 ranges in237 instructions, including the W return, packed padding and four shared mutex transitions. The second VM reaches8760 steps before +28868c -> +2633a4; complete signing remains unfinished. See the [second cached u32 report](../REQUEST_JNI_STARTUP_WORKERS.md#6173-second-vm-cached-u32-getter2026-10-15-asiashanghai).

Second VM pair reference getter passes29 new native controls and10 rollback checks. The three-instruction target delegates to the existing scoped reference copy. The owning callback matches1187 ranges and diagnostic fields in198 instructions with no allocation. The second VM reaches8809 steps before +2886b0 -> +1cf55c; complete signing remains unfinished. See the [second pair getter report](../REQUEST_JNI_STARTUP_WORKERS.md#6174-second-vm-pair-reference-getter2026-10-15-asiashanghai).

Java object byte reference composition passes28 new native controls and12 rollback checks at two bases. The original +26fe2c uses one UTF reference argument, existing JNI/byte-array/reference owners, ordered cleanup and live table reloads. This child component leaves the request boundary at8809 before +2886b0 -> +1cf55c; complete signing remains unfinished. See the [Java object bytes report](../REQUEST_JNI_STARTUP_WORKERS.md#6175-java-object-byte-reference-composition2026-10-15-asiashanghai).

Cached dispatch byte producer passes26 new native controls and13 rollback checks. The original +1cf688 composes two explicit environment acquisitions, the exact dispatcher words, existing byte conversion and empty-string fallback. Environment replacement proves live-pair reload and retained-environment cleanup. The request boundary remains8809 before +2886b0 -> +1cf55c; complete signing remains unfinished. See the [cached dispatch bytes report](../REQUEST_JNI_STARTUP_WORKERS.md#6176-cached-dispatch-byte-producer2026-10-15-asiashanghai).

Cached reference initialization and refresh pass44 new native controls and18 rollback checks. The original +1cf55c inline cache composes the producer, process destructor registration and scoped references, including signed64 refresh conditions. Request remains8809 before +2886b0 -> +1cf55c; second wiring and complete signing remain unfinished. See the [cached reference report](../REQUEST_JNI_STARTUP_WORKERS.md#6177-cached-reference-initialization-and-refresh2026-10-15-asiashanghai).

Second VM cached reference callback passes17 new native controls and8 rollback checks. The owning callback executes5571 instructions with1189 matching ranges; actual second entry advances8809 to8844 before 0x2884ec -> 0x32d3a0. Complete signing remains unfinished. See the [second cached reference report](../REQUEST_JNI_STARTUP_WORKERS.md#6178-second-vm-cached-reference-callback2026-10-15-asiashanghai).

Second VM static guard acquire passes 33 new native controls and 14 rollback checks. The owning callback executes 94 instructions with 1185 matching ranges; actual second entry advances 8844 to 8902 before 0x2886fc -> 0x256330. Complete signing remains unfinished. See the [second guard acquire report](../REQUEST_JNI_STARTUP_WORKERS.md#6179-second-vm-static-guard-acquire2026-10-15-asiashanghai).

Second VM environment constant callback passes 21 new native controls and 8 rollback checks. The owning warm callback executes 19 instructions with 1188 matching ranges; actual second entry advances 8902 to 8938 before 0x288718 -> 0x2781f4. Complete signing remains unfinished. See the [environment constant report](../REQUEST_JNI_STARTUP_WORKERS.md#6180-second-vm-environment-constant-callback2026-10-15-asiashanghai).

Second VM C-string format callback passes 27 new native controls and 12 rollback checks. The owning callback executes 1013 instructions with 1188 matching ranges; actual second entry advances 8938 to 8951 before 0x28854c -> 0x32d4f8. Complete signing remains unfinished. See the [C-string format report](../REQUEST_JNI_STARTUP_WORKERS.md#6181-second-vm-c-string-format-callback2026-10-15-asiashanghai).

Second VM static guard release passes 25 new native controls and 12 rollback checks. The owning callback executes 71 instructions with 1189 matching ranges; actual second entry advances 8951 to 9050 before 0x28874c -> 0x256a18. Complete signing remains unfinished. See the [guard release report](../REQUEST_JNI_STARTUP_WORKERS.md#6182-second-vm-static-guard-release2026-10-15-asiashanghai).

Second VM configuration u32 reading passes 22 new native controls, including ten owning callbacks with1190 matching ranges each. Twelve prior rollback checks are reused without rerun or new counts. The actual second entry advances9050 to9374 before 0x28876c -> 0x26cc64; complete signing remains unfinished. See the [second configuration read report](../REQUEST_JNI_STARTUP_WORKERS.md#6183-second-vm-configuration-u32-read2026-10-15-asiashanghai).

Second VM realtime unsigned seconds passes 15 new native controls and 10 rollback checks. Its owning callback executes54 original instructions with1188 matching ranges and one explicit clock provider call. Actual second advances9374 to9557, where wrapper28863c has a NULL target requiring investigation. Complete signing remains unfinished. See the [realtime seconds report](../REQUEST_JNI_STARTUP_WORKERS.md#6184-second-vm-realtime-unsigned-seconds2026-10-15-asiashanghai).

Second VM process ID callbacks pass 26 new native controls and 12 rollback checks. Explicit ELF-derived getpid/getppid imports, cached PID, syscall172/173 and errno paths match; owning callbacks execute18/13 instructions across1190/1189 ranges. Actual second advances9557 to9729, next28876c->204f58. Complete signing remains unfinished. See the [process ID report](../REQUEST_JNI_STARTUP_WORKERS.md#6185-second-vm-process-id-callbacks2026-10-15-asiashanghai).

Second VM cached thread pointer passes 15 new native controls and 7 rollback checks. Original obfuscated getter returns cached X64 or initializes it from TPIDR_EL0; owning65 instructions/1188 ranges match. Actual second advances9729 to9752, next288788->26edc4. Complete signing remains unfinished. See the [thread pointer report](../REQUEST_JNI_STARTUP_WORKERS.md#6186-second-vm-cached-thread-pointer2026-10-15-asiashanghai).

Second VM environment acquisition passes 17 new native controls, reusing 6 existing rollback guards without rerunning them. The12-byte wrapper reuses the shared TLS/JavaVM owner; owning160 instructions/997 ranges and one GetEnv effect match. Actual second advances9752 to9780, next288794->282b84. Complete signing remains unfinished. See the [environment acquisition report](../REQUEST_JNI_STARTUP_WORKERS.md#6187-second-vm-environment-acquisition2026-10-15-asiashanghai).

Second VM locked pointer getter passes 19 new native controls and 13 rollback checks. Real normal mutexes retain the owner while reading receiver+0x40; owning86 instructions/1191 ranges match. Actual second advances9780 to9813, next2887b0->256b84. Complete signing remains unfinished. See the [locked pointer report](../REQUEST_JNI_STARTUP_WORKERS.md#6188-second-vm-locked-pointer-getter2026-10-15-asiashanghai).

Second VM tree pointer getter passes 41 new native controls and 18 rollback checks. Existing tree/shared-reader owners produce full X64 before release; owning321 instructions/1191 ranges match. Actual second advances9813 to9940, next2886b0->25bd8c. Complete signing remains unfinished. See the [tree pointer report](../REQUEST_JNI_STARTUP_WORKERS.md#6189-second-vm-tree-pointer-getter2026-10-15-asiashanghai).

Second VM cold cached identifier passes 45 new native controls and 19 rollback checks. Explicit seed-file providers, two state advances, template formatting and existing reference owners match the original; owning3918 instructions/1192 ranges match. Actual second advances9940 to9950, next288508->32a1f0. Complete signing remains unfinished. See the [identifier report](../REQUEST_JNI_STARTUP_WORKERS.md#6190-second-vm-cold-cached-identifier2026-10-15-asiashanghai).

Second VM allocation callback passes 22 new native controls and 9 rollback checks. It reuses the explicit allocator owner, normalizes zero size to one and writes full X64 at packed+16. Two actual owning allocations match144/579 instructions across1190 ranges each. Actual second advances9950 to9998, next28880c->248908. Complete signing remains unfinished. See the [allocation report](../REQUEST_JNI_STARTUP_WORKERS.md#6191-second-vm-allocation-callback2026-10-15-asiashanghai).

Second VM string format callback passes 21 new native controls and 12 rollback checks. Existing formatter and allocator owners handle one W2 argument; owning1839 instructions/1193 ranges match real libc. The entry forwards prepare_format and raises second budget10000 to20000. Actual second advances9998 to10009, next2887f0->248780. Complete signing remains unfinished. See the [string format report](../REQUEST_JNI_STARTUP_WORKERS.md#6192-second-vm-string-format-callback2026-10-15-asiashanghai).

Second VM string pair callback passes 17 new native controls and 8 rollback checks. Its complete28-byte wrapper equals the accepted token wrapper, so the existing clone/append owner handles both; actual owning629 instructions/1191 ranges match. Actual second advances10009 to10021, next2887d0->25874c. Complete signing remains unfinished. See the [string pair report](../REQUEST_JNI_STARTUP_WORKERS.md#6193-second-vm-string-pair-callback2026-10-15-asiashanghai).

Second VM digest reference callback passes 33 new native controls and retains 8 prior rollback controls without rerunning them. The equivalent wrapper reuses unchanged digest/reference owners; actual owning4955 instructions/1194 ranges match. Actual second advances10021 to10030, next288820->258bac. Complete signing remains unfinished. See the [digest report](../REQUEST_JNI_STARTUP_WORKERS.md#6194-second-vm-digest-reference-callback2026-10-15-asiashanghai).

Second VM CRC callback passes 33 new native controls and 18 rollback guards. The equivalent wrapper reuses the unchanged guest-table CRC owner and stores only four result bytes. Actual owning247 instructions/1439 ranges match. Actual second advances10030 to10059, next288610->32a264. Complete signing remains unfinished. See the [CRC report](../REQUEST_JNI_STARTUP_WORKERS.md#6195-second-vm-crc-callback2026-10-15-asiashanghai).

Second VM deallocation callback passes 17 new native controls and 12 rollback guards. The equivalent tail wrapper forwards explicit free with no packed result store. Actual owning137 instructions/1193 ranges match real matching-libc free. Actual second advances10059 to10070, next2884cc->2484fc. Complete signing remains unfinished. See the [deallocation report](../REQUEST_JNI_STARTUP_WORKERS.md#6196-second-vm-deallocation-callback2026-10-15-asiashanghai).

Second VM deleting destructor passes 17 new native controls and 12 rollback guards. The existing consumer reuses the unchanged object destructor with deletion enabled. Actual owning295 instructions/1198 ranges match real payload/object free and pre-free bytes. Actual second advances10070 to10101, next28883c->261404. Complete signing remains unfinished. See the [deleting destructor report](../REQUEST_JNI_STARTUP_WORKERS.md#6197-second-vm-deleting-destructor2026-10-15-asiashanghai).

Second VM empty JSON reference passes 25 new native controls and 16 rollback guards. NULL source and empty-object prefixes compose existing container/reference owners; other JSON remains unsupported. Actual owning1603 instructions/1248 ranges match real allocator/free and recursive locks. Actual second advances10101 to10110, next28863c->1c3018. Complete signing remains unfinished. See the [empty JSON report](../REQUEST_JNI_STARTUP_WORKERS.md#6198-second-vm-empty-json-reference2026-10-16-asiashanghai).

Second VM global unsigned-word getter passes 17 new native controls and 10 rollback guards. Actual owning10 instructions/1189 ranges match unsigned W0, exact four-byte output and padding. Constructed entry then rejects unimplemented opcode34 at second+10a4a8 on attempted step10118; the second prefix does not return. Complete signing remains unfinished. See the [global unsigned-word report](../REQUEST_JNI_STARTUP_WORKERS.md#6199-second-vm-global-unsigned-word2026-10-16-asiashanghai).

VM opcode34 operation30 uint32-to-double passes 32 new native controls and 6 rejection checks. Implicit R4 low32 converts exactly to R2 double bits, including guest backing; other floating operations remain unsupported. Constructed second prefix now returns at10124/+10a4c0, next288854->261350. Complete signing remains unfinished. See the [uint32-to-double report](../REQUEST_JNI_STARTUP_WORKERS.md#6200-vm-uint32-to-double2026-10-16-asiashanghai).

Second VM JSON number insertion passes 69 new native controls and 16 rejection/rollback checks. Exact binary64 bits, native int32 saturation/NaN-zero, owned key append, allocation-failure cleanup and one-byte bool results agree. Constructed prefix advances to10131/+10a4dc, next28863c->1c3024. Complete signing remains unfinished. See the [JSON number report](../REQUEST_JNI_STARTUP_WORKERS.md#6201-json-number2026-10-16-asiashanghai).

Second global uint32 getter passes 17 new native controls and 10 rejection/rollback checks. Target1c3024 reads37a790 through the existing owner;1c3018 semantics remain. Constructed prefix advances to10150/0x10a528, next0x28863c->0x204e50. Complete signing remains unfinished. See the [second global getter report](../REQUEST_JNI_STARTUP_WORKERS.md#6202-second-global-u32-b2026-10-16-asiashanghai).

Second environment helper passes 27 new native controls and 14 rejection/rollback checks. The existing204e50 owner now returns through28863c; the old wrapper default remains. The actual warm helper matches32 virtual slots, four callbacks and seven physical return values. Constructed prefix reaches10169/0x10a574, next0x28863c->0x1e53d0. Complete signing remains unfinished. See the [second helper report](../REQUEST_JNI_STARTUP_WORKERS.md#6203-second-environment-helper2026-10-16-asiashanghai).

Third second-VM global uint32 getter passes 17 new native controls and 10 rejection/rollback checks. Target1e53d0 reads3d60d4 through the existing owner; both old getters and the environment helper remain. Constructed prefix reaches10208/0x10a760, next0x28887c->0x256f58. Complete signing remains unfinished. See the [third global getter report](../REQUEST_JNI_STARTUP_WORKERS.md#6204-second-global-u32-c2026-10-16-asiashanghai).

Serial atomic field getter passes 19 new native controls and 14 rejection/rollback checks. Target256f58 reads receiver+138 through the existing cached-u32 adapter; its old shared-reader path remains. Constructed execution reaches10266/0x10a848, where opcode34 operation34 is rejected; no second prefix is returned there. Complete signing remains unfinished. See the [serial atomic getter report](../REQUEST_JNI_STARTUP_WORKERS.md#6205-second-atomic-u322026-10-16-asiashanghai).

VM opcode34 operation34 int32-to-double passes 32 new native controls and 6 rejection checks. Implicit R4 signed low32 converts exactly to R2 double bits, including guest backing; operation30 remains unchanged. Constructed second prefix returns at10294/+10aa00, next288898->2850a8. Complete signing remains unfinished. See the [int32-to-double report](../REQUEST_JNI_STARTUP_WORKERS.md#6206-vm-int32-to-double2026-10-16-asiashanghai).

Second TLS uint32 getter passes 15 new native controls and 15 rejection/rollback checks. New wrapper288898 reuses the existing TLS provider and stores exactly four packed bytes. Actual warm callback passes63 native instructions/1190 declared ranges. Constructed second prefix reaches10320/+10aa68, next2888b4->248908. Complete signing remains unfinished. See the [second TLS getter report](../REQUEST_JNI_STARTUP_WORKERS.md#6207-second-tls-u322026-10-16-asiashanghai).

Five-argument second formatter passes 17 new native controls and 16 rejection/rollback checks. Existing printf owner now handles unsigned64 %lu/%llu; exact wrapper2888b4 passes W2 plus four X words and retains the old one-argument default. Actual native allocator/formatter call passes12997 instructions/1193 declared ranges. Second reaches10332/+10aa98, next2888d0->2613e4. Complete signing remains unfinished. See the [five-argument formatter report](../REQUEST_JNI_STARTUP_WORKERS.md#6208-second-five-argument-format2026-10-16-asiashanghai).

Second JSON string insertion passes 53 new native controls and 24 rejection/rollback checks. The configuration owner creates type0x10 nodes, copies value/key and appends with native cleanup order. Actual native allocation/copy call passes923 instructions/1221 declared ranges. Second reaches10341/+10aabc, next2888f4->28794c. Complete signing remains unfinished. See the [JSON string report](../REQUEST_JNI_STARTUP_WORKERS.md#6209-second-json-string2026-10-16-asiashanghai).

Second numeric string construction passes 31 new native controls and 34 rejection/rollback checks. Nine unsigned globals and one TLS value use measured libc++ reserve/append/shrink semantics. Actual native allocation/TLS call passes2579 instructions/1224 ranges. Second reaches10403/+10ad04, next28890c->256ce0; complete signing remains unfinished. See the [numeric string report](../REQUEST_JNI_STARTUP_WORKERS.md#6210-second-numeric-string2026-10-16-asiashanghai).

Second configuration string lookup passes 29 new native controls and 24 rejection/rollback checks. Existing reader/tree/clone owners implement guarded copy or empty construction; actual native allocation/locks pass909 instructions/1215 ranges. Second reaches10471/+10aef8, next288968->261580; complete signing remains unfinished. See the [configuration string report](../REQUEST_JNI_STARTUP_WORKERS.md#6211-second-configuration-string2026-10-18-asiashanghai).

Second JSON bool insertion passes 41 new native controls and 22 rejection/rollback checks. The low bit selects type1/2; key duplication, append and failure cleanup match. Actual native allocation passes384 instructions/1208 ranges. Second reaches10481/+10af20, next288990->2616b4; complete signing remains unfinished. See the [JSON bool report](../REQUEST_JNI_STARTUP_WORKERS.md#6212-second-json-bool2026-10-18-asiashanghai).

Second compact JSON printing and string reference construction pass 49 new native controls and 36 rejection/rollback checks. Actual original allocation passes27222 instructions/1375 ranges; scope fields match while4 padding bytes and internal libc numeric state remain unverified. Second reaches10494/+10af54, next2889a8 with NULL target; complete signing remains unfinished. See the [JSON print report](../REQUEST_JNI_STARTUP_WORKERS.md#6213-second-json-print2026-10-18-asiashanghai).





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
