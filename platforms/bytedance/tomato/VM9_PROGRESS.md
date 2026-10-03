# Current VM9 progress checkpoint

This file records the current state of the independent VM9 work. It is a
checkpoint, not a completion claim.

## Latest bridge initialization evidence (2026-10-03)

Same-URL controls reproduce an initialization failure before the bridge
publishes the callback-1 network signer handle. The old fallback then passes
the app-manager pointer to signing and dereferences a non-vtable word at
`+0x2a6604`. The private bridge now stops with `SIGNER_INIT_UNAVAILABLE`,
retains failed-run logs, and clears a previous consumable signature. The
positive/negative/positive regression preserves successful signing and a
fresh accepted detail response (HTTP 200, code 0, 24,335 bytes).

Eleven time-input cases return seven signatures and four initialization
failures. Small offsets 0/1/15/16 ms share one output, but +999 ms already
fails within the same seconds timestamp; +2 seconds succeeds while +4
seconds fails. This is a bounded initialization observation, not a general
time-grid rule or recovery of all 16 dispatch branches. Native initialization
from arbitrary fresh inputs is still missing.

Details: [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md) and
[vm9_handle_initialization_20261003.json](evidence/vm9_handle_initialization_20261003.json).
The older external Java search service now has measured nonempty two-page
responses, while the current session-aware first-stage search is still
empty; see [SEARCH.md](SEARCH.md). Independent Python Medusa and no-JVM Rust
remain unfinished.

## Latest verified checkpoint: generated thread state and constructor (2026-10-03)

Python now implements generation-checked pthread TLS, mapped base allocation,
fresh TSD/arena/tcache creation and the input-driven string constructor at
`0x12508344`. The 85-case native differential checks all 4,256 pages, including
nonzero arena/TSD prefills and the entire empty-TLS path through tcache
publication. Eleven rejected cases preserve caller memory. The earlier
83-case allocator lifecycle regression still passes.

The same-capture chain completes again with 303 Python malloc/free calls and
seven Python target constructor calls, with zero native fallback for both.
Its 779-byte output equals the native control and captured MEDCOPY. Seg1 and
Seg2 retain identical nonstack memory; the earlier 15 differing Seg3 bytes
outside the body remain. Other callbacks and host continuation still run
native ARM64, and the integration retains captured thread/region state.

A separate native empty-TLS malloc now returns under an explicit guest policy
for an actual zero-filled anonymous mapping and VMA naming. Python now owns
the corresponding zero-filled mapping transaction and region registration:
from a new arena, `0x13600000..0x13640000` registers a 62-page free extent and
the first class-3 allocation returns `0x13602000`, with native metadata values.
A failed first allocation rolls back the staged mapping and allocator pages.
The global boot reader/publisher covers only the explicit arena/TLS/cache
fields; lookup-cache generation and the remaining callback/object graph are
still unfinished. This does not complete parameterized current Medusa or
prove live server acceptance.

Two native callback boundaries are now input-driven in
`python/vm9_callbacks.py`: the clock wrapper's timespec/result writes and the
active descriptor trampoline's two-field publication. Invalid clock inputs
and the still-uncaptured packed callback-object composition reject atomically.
The remaining constructor/destructor object graph still executes natively in
the same-capture chain.

The 2026-10-03 callback writer probe separates the trampoline from the missing
data flow. Static code at `+0x2584ac` is only `ldr/blr/ldp/br`: descriptor+0
is the branch target and descriptor+8 is passed as `x0`. In the paired native
capture, VM writer `+0x171268` executes `str x15,[x17,x16]`; the observed
descriptor object fields are reached from the writer frame at `x17+0x140` and
`x17+0x148` (equivalent to descriptor `+0x00` and `+0x08`) directly from
`x15`. No independent upper/lower-word packed-x8 formula was observed. The
sanitized record is
[evidence/vm9_callback_writer_20261003.json](evidence/vm9_callback_writer_20261003.json).
This explains the callback boundary but does not parameterize the VM values
that feed `x15`, so the public Python rejection remains intentional.

Details and reproducible boundaries:
[RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md),
[component and integration evidence](evidence/vm9_runtime_initialization_20261003.json).

The bounded region/global component is independently checked by
[python/verify_vm9_os_region.py](python/verify_vm9_os_region.py). It compares
the new-arena path on 4,256 trusted checkpoint pages, verifies zero-filled
guest pages, the available-tree node at `region+0x258`, first allocation
`0x13602000`, and four rejected mapping requests with no mutation. Its
sanitized result is
[evidence/vm9_os_region_register_20261003.json](evidence/vm9_os_region_register_20261003.json).

## Previous checkpoint: lifecycle and paired chain (2026-10-03)

Empty-bin refill, mapped new-slab initialization across 36 classes, compact
trees, full-bin flush, periodic cleanup and slab release/purge are now modeled
in Python. The 83-case native differential compares all 4,256 checkpoint pages;
360 continuous malloc/free operations also match after every step. Purge needs
an explicit guest OS outcome; fresh OS region/TLS/arena initialization remains
unsupported.

The same detail capture now runs from initial memory through Seg1, the actual
native host continuation, Seg2 and Seg3. It matches 95,979 VM events and 293
callbacks, replacing 303 malloc/free calls with Python and no native allocator
fallback. No trained handoff, transition free list, callback-page injection or
target-pointer patch is used. Captured entry registers/native frames and the
existing two-byte Seg1 pointer-tag normalization still remain.

An interpreter correction separates native x28 register backing from virtual
R28. Twelve native divmod/commit pairs validate it, including zero divisors.
Seg1 and Seg2 have identical nonstack memory between allocator controls. Seg3
retains 15 differing bytes at native copy sites outside the final body, plus
call-stack differences. The 779-byte body exactly matches both native control
and captured output. Whole-memory equivalence is not claimed.

Implementation, reproducible checks and limitations:
[ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md),
[lifecycle evidence](evidence/vm9_allocator_lifecycle_20261003.json), and
[paired-chain evidence](evidence/vm9_allocator_same_capture_20261003.json).
Earlier checkpoints below are historical; their refill/cleanup and artificial
transition limitations are superseded only for this verified sampled path.

Current Python Medusa parameterization, independent fresh initialization,
no-JVM Rust signing/download and live nonempty search remain unfinished. The
next step is Python OS-region/global-boot and remaining callback/object initialization, followed
by a new-input run without captured state and then the live server matrix.

## Reproduced diagnostic path

The historical `seg3_verified_final_20260929.txt` path can be reproduced with
the captured `event0_cb66_vm9_*` memory image and the real callback pages for
callbacks 9, 64, and 66. The fresh replay reached:

```text
SUMMARY events=1057/1057 callbacks=87 syscalls=3
```

This proves that the VM bytecode trace, the selected native callback execution,
and the recorded page injections are internally consistent for that captured
sample. It remains trace-assisted because the callback pages and native ARM64
execution are supplied externally.

## Current checkpoint mismatch

The newer `mem_after_seg2_full_diag_20260929.pkl` checkpoint does not reproduce
that path. It diverges at trace 758 after callback 8:

| Path | callback 8 allocator result | callback 8 writes |
| --- | ---: | ---: |
| reproduced historical path | `0x1296b940` | 80 |
| new full-Seg2 checkpoint | `0x1296ba60` | 33 |

The native callback therefore selects a different allocator/free-list branch.
The divergence is before callback 9's real-page injection and is not fixed by
adding Perseus, changing the timestamp, or replaying the same callback pages.

The follow-up allocator audit narrowed the branch further. For callback 8 the
requested size maps to size class `3` and bin `0x12282060`. The historical
checkpoint has count `0` and returns `0x1296b940` through the refill path; the
new checkpoint has count `4` and returns `0x1296ba60` from free-list index `2`.
Forcing only the count to zero, or copying the complete `0x12282000` bin page,
still returned `0x1296b9a0`. Native disassembly and a controlled transplant
then isolated the missing state to the slab counter `[0x1294110c]` and bitmap
word `[0x12941128]`; with those two fields plus the count corrected, callback 8
returned `0x1296b940`.

## Seg1 entry-base and native-frame corrections

The first independent Seg1 runner used the nested-frame jump-base field that
belongs to the later segments. That made the first apparent branch at trace
120 look like a VM or allocator mismatch. Re-running with the actual Seg1
entry base `0x1235a6f0` removed that false divergence. A second mismatch was
then isolated to the native callback context: the diagnostic runner still used
Seg2's `SP=0xe4ffbd70` and `X29=0xe4ffbe90` for Seg1, while the captured Seg1
frame has `SP=0xe4ffb320` and `X29=0xe4ffb440`. With the wrong frame, callback
19 overwrote its argument area and callback 20 reached libc's explicit
`Invalid address 0xe4ffb848 passed to free` abort. Returning zero from
`exit_group` in the early syscall probe had hidden that abort and produced an
irrelevant unmapped read and `accept4` loop.

With the Seg1 frame corrected, the real ARM64 callback runner completed the
captured Seg1 trace: `4592/4592` VM events, 85 callbacks, and one `madvise`
syscall. No callback-page injection was needed for this Seg1 run. The resulting
checkpoint advanced into Seg2 and matched its first 10 native callbacks. The
sanitized diagnostic record is
[evidence/vm9_seg1_frame_probe_20260930.json](evidence/vm9_seg1_frame_probe_20260930.json).

An earlier continuation reached callback 45 and appeared to diverge at VM
trace `12085` (`[0xe4ffcd00]` was `0x2f8` while the older checkpoint expected
`0x2f6`). Pairing the trace with its same-capture memory files showed that this
was a mixed-capture artifact: the paired trace also expects `0x2f8`. The old
`0x2f6` value came from a different capture/checkpoint and must not be copied
into the corrected run.

This is a diagnostic correction, not a completion claim. The runner still
executes captured ARM64 native code against captured memory, and its Seg1
`X22` frame value is inferred from the frame offset rather than directly
observed. The next independent proof must carry the corrected state through
Seg2 and Seg3 without captured-field transplants, then repeat with a fresh
input before treating it as a parameterized signer.

Applying that fixed checkpoint transplant at callback 8 allowed the full
captured Seg2 replay to complete at `90161/90161` events with `121` callbacks.
This closes the captured branch diagnostic, not the independent parameterization
requirement. See [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).

## Same-run full handoff capture (2026-09-30)

A fresh Unidbg capture was taken with a frozen clock and deterministic emulated
random source. Seg1 was replayed from that capture at `4592/4592` events and
85 callbacks. Full memory snapshots taken at the real host transitions were
then supplied to the offline runner:

- Seg2 reached `90153/90153` events and 121 callbacks from the real `NEXT#1`
  handoff, with no callback-page injection or allocator-field transplant.
- Seg3 reached callback 86 and event 1,028 from the real `NEXT#2` handoff. The
  first unexplained host-return boundary is the callback result slot at
  `0xe4ffe630`; setting that slot to the trace-observed zero as an explicit
  diagnostic override lets the replay complete at `1057/1057` events and 87
  callbacks.

This is stronger evidence about the segment and host handoff boundaries, but it
still consumes captured full-memory handoffs from one run. It is therefore a
trace-assisted diagnostic and not a fresh-input, pure-Python Medusa proof. The
sanitized record is
[evidence/vm9_handoff_probe_20260930.json](evidence/vm9_handoff_probe_20260930.json).

## Callback 86 clock-slot provenance (2026-09-30)

The earlier `0xe4ffe630` boundary was then watched in a real Unidbg run. At
entry to callback function `0x12545f60`, the slot contained `0x67e0c91`. The
native callback returned `x0=0`, and the write hook observed an 8-byte zero
store at `0xe4ffe630` from PC `0x12545f70`. The captured code at that PC is:

```text
0x12545f60: stp x30, x19, [sp, #-0x10]!
0x12545f64: mov x19, x0
0x12545f68: ldp x8, x0, [x0]
0x12545f6c: blr x8
0x12545f70: str x0, [x19, #0x10]
```

This identifies the zero as the ordinary result store performed by the native
callback wrapper after the indirect clock function returns. It is not an
unexplained Java-side or host-memory transplant. The sanitized record is
[evidence/vm9_clockslot_native_write_20260930.json](evidence/vm9_clockslot_native_write_20260930.json).

The offline `--clock-slot-zero` replay therefore modeled a real native store,
but it remains a diagnostic replay.

## Native clock model replay (2026-10-01)

The callback-86 path was traced through `0x125514d0 -> 0x12551488 ->
0x125e94b0 -> clock_gettime(1)`. The native helper converts the timespec to
nanoseconds, subtracts the saved start value `123456789000000` ns, then divides
the signed difference by 1000. The offline runner had supplied its wall-clock
timespec to clock ID 1. A same-input failure run returned a nonzero callback
result and diverged at VM event 1,028.

The runner now matches the real Unidbg handler: clock ID 0 uses the frozen wall
clock; nonzero IDs use the frozen monotonic value `123456789000000` ns. With
`--clock-slot-zero` disabled and no callback-page injection, the same Seg3
snapshot reached `1057/1057` events and 87 callbacks. Callback 86 naturally
returned zero and the native wrapper wrote it to `0xe4ffe630`. The sanitized
paired evidence is
[evidence/vm9_clock_model_replay_20261001.json](evidence/vm9_clock_model_replay_20261001.json).

This closes the clock-model discrepancy for one captured input. The runner
still depends on full memory handoffs and native ARM64 images from that run;
it is not yet a fresh-input pure-Python signer.

## Static constructor argument replay (2026-10-01)

The second captured URL exposed a concrete constructor-argument error in the
independent runner. Native constructor `0x12508344` treats nonzero `x1` as a
string pointer: it calls the length helper at `0x12607f40`, allocates
`strlen(x1)+1` through `0x12607fd0`, and copies through `0x12607f60`. The old
diagnostic used `0x1296ba90`, an allocator dynamic-area address. The same-capture
trace supplies `0x1232fe64` as the static argument for this replay.

The old dynamic pointer failed at trace event 13 with `r2=0` instead of
`0x122a0d00`. Re-running with `x1=0x1232fe64` completed Seg2 at
`90385/90385` events and 121 native callbacks. The resulting checkpoint matched
the ten captured `NEXT#2` handoff pages except for 153 bytes in two synthetic
native-stack pages. Starting Seg3 directly from that checkpoint still failed at
callback 9, so the full host handoff has not been removed. Supplying the
captured `NEXT#2/vm9_m0.bin` image allowed Seg3 to complete at `1057/1057`
events and 87 callbacks, with two clock syscalls and no clock-slot override or
callback-page injection.

This is a constructor-boundary improvement for one captured input, not a
parameterized signer. It still depends on captured native state for Seg3 and
does not change the pure-Python current-Medusa or no-JVM Rust status. The
sanitized evidence record is
[evidence/vm9_static_constructor_x1_20261001.json](evidence/vm9_static_constructor_x1_20261001.json).

## Dispatcher continuation and input-pairing correction (2026-10-01)

The successful `90385/90385` Seg2 result requires the paired input set used by
the evidence record: the corrected Seg1 checkpoint, the same-capture `NEXT#1`
handoff, and the clean runner whose SHA256 is
`8e1f2b031091d0588dcab46368c2f6b6ca8b1151bf2e890bfeb418b4bc2aa741`. A fresh
recheck with that tuple reproduced 121 callbacks and the existing checkpoint
SHA256 `86a379cca5c8f98cd5c47ac79d001e3a82de3ff2db2263eaaf9a814f027dd3cd`.
Running the raw trial memory files as if they were the same input is invalid:
their allocator state is different and the transition cleanup fails before
Seg2.

Starting that rechecked checkpoint with the paired `NEXT#2` handoff also
reached `1057/1057` Seg3 events and 87 callbacks, with two `clock_gettime`
syscalls, no callback-page injection, and no clock-slot override. This is the
same captured-state boundary proof as the existing static-constructor record,
not a fresh-input signer.

The later continuation experiment was a diagnostic branch, not a replacement
runner. It changed callback `0x12548a4c` to return through `0x1242aa4c`, injected
dispatcher scratch registers, copied native backing slots into the Python VM,
and stopped before `0x125083e0`. That branch observed
`e4ffc9a0=0` and `R2=0` while the trace expected `R2=0x122a0d00`; the full
backing readback therefore created a false register interpretation. The
paired clean replay completes without that injection. `e4ffc9a0` is a native
boundary object slot, not a directly readable Python R2 backing slot. The
sanitized diagnostic record is
[evidence/vm9_dispatcher_slot_refutation_20261001.json](evidence/vm9_dispatcher_slot_refutation_20261001.json).

## OP29 generic rule and second-input recheck (2026-10-01)

The native handler at `libmetasec_ml_71332.so + 0x16e8f0` was disassembled as
OP29/sub34, a signed `BLEZ` branch. Its source register is
`((dw >> 27) & 0x10) | ((dw >> 7) & 0x0f)` and its 16-bit branch immediate is
assembled from the five encoded fields. The VM advances by `4 + imm * 4` only
when the signed source value is non-positive; otherwise it advances by four.
The old `dw == 0x1800811d` fixed-jump special case was removed.

A second URL capture then exercised that exact encoding at trace event 119035:
the source was `R2`, the decoded immediate was `208`, and the native write at
`+0x16eaa4` changed BCP from `0x123ceadc` to `0x123cee20`:

```text
0x123ceadc + 4 + 208 * 4 = 0x123cee20
```

With the generic rule, the paired second-input replay reached `90385/90385`
Seg2 events and 121 native callbacks from `NEXT#1`, then `1057/1057` Seg3
events and 87 callbacks from `NEXT#2`. The clean recheck used no callback-page
injection, allocator-field transplant, clock-slot override, or dispatcher
backing-slot injection. This closes the OP29 decoder/branch assumption for the
captured pair. It still consumes captured host handoffs and native ARM64
images, so it does not close current pure-Python Medusa parameterization.
The sanitized record is
[evidence/vm9_op29_generic_20261001.json](evidence/vm9_op29_generic_20261001.json).

## Minimal paired handoff reduction (2026-10-01)

The second-input capture was rechecked with its paired trace, native images, and
`mem_after_seg1_offline.pkl`; mixed trial memory files were excluded. Comparing
the Seg1 checkpoint with the real `NEXT#1` handoff found only 14 changed pages
and 560 changed bytes:

```text
0x12240000 0x12280000 0x12282000 0x12296000 0x12297000 0x1229e000
0x1229f000 0x122a0000 0x122ac000 0x128a3000 0x1296b000
0xe4ffb000 0xe4ffc000 0xe4ffd000
```

Applying only those byte deltas, without loading the full `NEXT#1` directory and
without the old synthetic `0xe4ffcaa0=0x122a0c20` overwrite, completed Seg2 at
`90385/90385` events with 121 callbacks and zero syscalls. The clean paired
record is [evidence/vm9_minimal_handoff_pair_20261001.json](evidence/vm9_minimal_handoff_pair_20261001.json).

The resulting Seg2 checkpoint differs from the real `NEXT#2` handoff on four
pages, but Seg3 does not need those full pages. A single four-byte state patch at
`0x12641b28`, changing `0x0000001d` to `0x1250c59c`, supplies the indirect native
call target used at callback 9. Starting from the paired Seg2 checkpoint with
that patch and no other `NEXT#2` pages completed Seg3 at `1057/1057` events, 87
callbacks, and two `clock_gettime` syscalls, with no callback-page injection,
allocator-field transplant, or clock-slot override.

This reduces the captured handoff surface, but it does not make the current VM a
fresh-input pure-Python signer: the baseline checkpoint, native ARM64 images,
and callback execution are still captured-state inputs.

## Byte-rule holdout and cross-interface counterexample (2026-10-01)

The paired second URL and a new homepage capture have identical 560-byte change
masks across 14 pages. Of their target bytes, 558 are identical; the other two
are source-byte increments modulo 256: `0x12282018 += 0x1f` and
`0x12296019 += 1`. The public `python/vm9_handoff_rule.py` learned those rules
from the two captures and predicted a third homepage input using only its Seg1
checkpoint. A later comparison with that held-out `NEXT#1` found zero changed
pages or bytes. Seg2 then completed `90332/90332` events and 121 callbacks;
Seg3 completed `1057/1057` events and 87 callbacks with the previously observed
four-byte target correction, two clock syscalls, and no full handoff images,
callback-page injection, or clock-slot override.

The same byte rule fails on the captured detail input: six pages differ by 34
bytes and Seg2 diverges at event 3 (`R2=0x122a0c40`, expected `0x122a0c20`).
This is a counterexample to a general handoff rule, even though the homepage
holdout passed. The initialization-failure capture with the adjacent frozen
timestamp is excluded from the successful evidence set.

## Allocator-derived detail holdout (2026-10-02)

The detail mismatch was narrowed to structural fields. The next 24-byte object
can be derived from the Seg1 size-class state:

```text
count  = read64(0x12282070)
list   = read64(0x12282078)
object = read64(list + (count - 1) * 8)
```

The homepage state has count 6 and selects `0x122a0c40`; the detail state has
count 7 and selects `0x122a0c20`. The optional `--allocator-model` relocates
the trained object to that computed address and writes it into the four
boundary slots. It also applies the shared whole-word training deltas:

| Address | Seg1-to-Seg2 delta |
| --- | ---: |
| `0x12240730` | `+12` |
| `0x12282060` | `+1` |
| `0x12282070` | `-1` |
| `0x12296018` | `+0x78` |
| `0x12296020` | `+0x2e8` |

The scratch word at `0xe4ffb9e0` receives the shared target `0x500` as a full
word. The remaining byte at `0xe4ffbb78` is left unpatched. Static disassembly
shows that this location is a native VM dispatcher slot, slot index 3 when
`x28=0xe4ffbb60`. The available transition write watch shows two store sites
in this dispatcher family: `0x1242d8a4` uses
`str x15, [x28, x10, lsl #3]`, while `0x1242f974` uses
`str x9, [x28, x14, lsl #3]`. The current detail run was not instrumented to
attribute its final store to one site.
The new detail capture predicts `0xc4` and the captured `NEXT#1` contains
`0xb4`; this is a native dispatch-state difference, not a final Python R2
value. The sanitized provenance and body comparison are in
[evidence/vm9_detail_body_compare_20261002.json](evidence/vm9_detail_body_compare_20261002.json).
Substituting the final Python R2 is refuted: that value is `0x122974b8` in
both diagnosis runs and is not the handoff scratch value.

| Capture | Role | NEXT#1 difference after model | Seg1 | Seg2 | Seg3 |
| --- | --- | --- | --- | --- | --- |
| homepage third input | earlier holdout / regression | 0 pages, 0 bytes | `4592/4592` | `90332/90332` | `1057/1057` |
| detail first input | diagnosis; used to develop the correction | 1 page, 1 byte | `4592/4592` | `90352/90352` | `1057/1057` |
| detail new query | held out from correction development | 1 page, 1 byte | `4592/4592` | `90330/90330` | `1057/1057` |

The new detail query's uncorrected control still fails at event 3; only the
structural correction changes that result. Its prediction reads no held-out
`NEXT#1`, and the public CLI produces the same checkpoint hash as the private
prototype. Both detail replays use 85/121/87 native callbacks across the three
segments. Seg3 still uses `0x12641b28: 0x1d -> 0x1250c59c` as a four-byte
target rule. No full handoff image, callback-page injection, or clock-slot
override is supplied. These are offline captures of signed input variations;
the new detail query was not sent to the online endpoint.

The evidence is
[evidence/vm9_handoff_holdouts_20261002.json](evidence/vm9_handoff_holdouts_20261002.json).
This narrows the allocator/object boundary, while captured baseline images,
native ARM64 callbacks, trace entry registers, training target bytes, and the
Seg3 call-target rule remain inputs. Size-class refill is unsupported. The
held-out detail trace's 779-byte body was independently reconstructed from its
STORE8/STORE64 trace regions and compared with the final captured `MEDCOPY`
body; the result is exact (`0` differing bytes). That validates body assembly
for this capture while leaving fresh-input Medusa generation open. Full trace
completion is not a general pure-Python current-Medusa proof.

## Direct native transition watch (2026-10-03)

The temporary independent runner was corrected to use the detail capture's
Seg1 native frame (`SP=0xe4ffb320`, `X29=0xe4ffb440`) and the VM entry base.
With that correction, Seg1 completed `4592/4592` events, 85 callbacks, and one
syscall without callback-page injection. The transition then ran the captured
allocator/constructor, recursive cleanup, and final reference free while
watching the dispatcher slot at `0xe4ffbb78`.

The slot now has direct native attribution in this run: `0x125150d0` wrote
`0x125151b0` four times during recursive cleanup, `0x1218199c` wrote
`0xe4ffbde0` during transition cleanup, and `0x1217f00c` wrote `0x1210bb20`
on Seg2 callback 1. These are native state writes, not VM9 bytecode stores.

The first unassisted Seg2 divergence is relative event 13: the native callback
leaves `0xe4ffc9a0` as zero while the trace requires the transition object
`0x122a0ce0`. Controlled diagnostic slot repairs moved the boundary to event
747 (33 callbacks), where the native-derived word at `0x12296380` differed
(`0x32357c32` versus `0x78c1d3ab`). Supplying that one captured page word moved
the boundary to event 752, where an adjacent unaligned word still differed
(`0x30333830` versus `0xffffffffad396da4`). The repaired values included the
object slot, constructor pointer, string reference slot/refcount, object field,
and slab-derived addresses. This sequence demonstrates that the remaining gap
is allocator and host-handoff page state, not a missing VM opcode.

The direct-write and boundary log is
[evidence/vm9_detail_native_transition_watch_20261003.json](evidence/vm9_detail_native_transition_watch_20261003.json).
The interventions are diagnostic only and are not part of the public signer.

## Capture-page A/B boundary (2026-10-03)

The next diagnostic separated a page transplant from the state it represents.
Starting from the same Seg1 checkpoint and the existing boundary repairs, the
clean baseline diverged at relative event 747 when `R1` read `0x32357c32`
instead of `0x78c1d3ab`. Installing the local captured page at `0x12296000`
supplied that first word and advanced the replay to relative event 788.

The replay then read `0x1dc9821c` where the trace requires `0x440132f7`.
That adjacent value is not supplied by the page transplant, so the page alone
is not the missing constructor. The remaining state is produced by later
allocator/refill and host/native initialization. This closes the callback-page
copy shortcut while leaving fresh-input parameterization open. The redacted
comparison is in
[evidence/vm9_detail_capture_page_ab_20261003.json](evidence/vm9_detail_capture_page_ab_20261003.json).

## Dynamic native load provenance (2026-10-03)

Static disassembly and the same trace identify how the later `0x440132f7` value
enters the VM. The OP1 handler at `+0x170270` performs
`ldrsw x9, [x10, x11]` followed by `str x9, [x28, x14, lsl #3]`. In the
held-out detail trace, instruction `0x8d08d7c1` at event `131392` reads from
`0xe4ffa7b8` through `R29=0xe4ffc0b0` and produces
`R4=0xffffffff8ef8fc19`. The later instruction `0x8d02d7c1` at event
`132739` reads `0x440132f7` from `0xe4ffd098` through the same `R29` object
and stores it into `R1`.

`R29` changes from `0xe4ffbc00` at the previous exit marker to `0xe4ffc0b0`
at the first event after the native/host transition. The next callback receives
that loaded value as `x1=0x440132f7`, alongside the recorded `x0`, `x2`, `x3`,
and `x4` inputs. A second handler at `+0x168eb0` also writes a sign-extended
register-table result into a VM slot, confirming that these values are dynamic
VM/native state rather than fixed callback-page bytes.

This closes the narrow provenance question for `0x440132f7`: the value is a
handoff-backed memory load followed by a VM register store. It does not close
the constructor, allocator refill, callback-registration, or fresh-input
parameterization requirements. The sanitized record is
[evidence/vm9_native_dynamic_load_20261003.json](evidence/vm9_native_dynamic_load_20261003.json).

## Native entry `x8` liveness (2026-10-03)

The paired captures also narrow the native callback entry at `0x12506ba0`.
The callee reloads `x8` at `0x12506bcc` with `ldr x8, [x20, #8]`, so the
incoming value is overwritten before this function consumes it. The packed
entry value is assembled on the caller side: `0x125487f4` loads `x9` and `x1`
from the callback object, `0x125487f8` loads `x10` and `x8`, and
`0x12548800` performs the indirect `blr x10`.

Across the detail and second-URL captures, the packed values are
`0x440132f775952fa9` and `0x1dc9821c75952fa9`. Their upper 32 bits match the
input-dependent OP1 results recorded immediately before the callback, while
the common lower `0x75952fa9` is written by the native copy helper at
`0x125692dc` (`str w6, [x0]`) to `0xe4ffc9c8`. Therefore the entry `x8` value is caller-side
native handoff state, not a constant generated by `0x12506ba0` and not a value
that can be recovered by copying one callback page.

The exact callback-object field writer and the native composition instruction
that combines the two words remain uncaptured. The sanitized record is
[evidence/vm9_native_entry_x8_liveness_20261003.json](evidence/vm9_native_entry_x8_liveness_20261003.json).

## Callback trampoline path check (2026-10-03)

A fresh current detail run with callback and descriptor watches reached the
`+0x2584ac..+0x2584c0` trampoline. The older static candidate at `+0x2887f0`
was not executed in that run (`X8-CALL` count zero). The active path performs
`ldp x1, x8, [x0]`, then `mov x0, x8; br x1`; the observed `[obj+8]` value is
therefore the object passed to the branch target, not proof that this helper
constructs the packed entry `x8` pair from the prior liveness capture.

The descriptor fields were already populated before the trampoline was
entered. The earlier probe did not retain the writer because its narrow watch
counter was exhausted by unrelated descriptor-pool traffic.

## Active descriptor writer (2026-10-03)

The corrected probe was rerun twice with the same frozen runtime setup and a
one-digit input change. Both runs reached the same active descriptor at
`0xe4ffe290`. Immediately before the trampoline, the VM store at `+0x171268`
(`str x15, [x17, x16]`) wrote the descriptor fields:

```text
[0xe4ffe290] = 0x125ea444, then 0x125ea4fc
[0xe4ffe298] = 0x1284a288
```

The trampoline then executed `ldp x1, x8, [x0]; mov x0, x8; br x1`. This
directly closes the active descriptor-writer location and confirms that it is
a VM/native boundary store. It does not capture the separate composition that
produces the packed entry values `0x440132f775952fa9` and
`0x1dc9821c75952fa9`; later allocator/native state still diverged after the
observation. The sanitized record is
[evidence/vm9_callback_descriptor_writer_20261003.json](evidence/vm9_callback_descriptor_writer_20261003.json).

The older `+0x2887f0` static helper remains unexecuted in both fresh probes.
The writer result is evidence for the active descriptor path only and is not a
parameterized Medusa implementation.

## Static class-3 refill primitive (2026-10-03)

The empty-bin branch is now mapped through the native allocator image:
`0x1217f450` writes `-1` to `[bin+0x28]`, calls `0x12187ecc`, and that wrapper
delegates the slab/free-list work to `0x1216970c`. The existing-slab branch
uses `[slab+4]` as a remaining-slot counter, selects a set bit from the slab
bitmap with `RBIT/CLZ`, clears it by XOR, and decrements the counter. The
wrapper then publishes the returned batch in the bin list.

For class 3, the checkpoint record is `0x12240950 -> 0x12941108`. The
historical state (`counter=0x24`, `bitmap=0xfffffffff0000000`) selects bit 28
and the current full-Seg2 state (`counter=0x20`,
`bitmap=0xffffffcfc0000000`) selects bit 30. The corresponding observed
buffers are `0x1296b940` and `0x1296ba60`. The public
`python/vm9_allocator.py` now exposes only this bitmap-word transition; it
does not claim the slab address formula or a fresh-input allocator.

The sanitized evidence is
[evidence/vm9_allocator_refill_static_20261003.json](evidence/vm9_allocator_refill_static_20261003.json).

## Existing-slab batch replay (2026-10-03)

The public allocator model now covers the captured non-node branch through the
wrapper boundary. `refill_existing_slab_and_pop` replays the eight-slot class-3
batch, stores the pointers at target-list indexes `7..0`, publishes the count,
and consumes the first entry as `0x12187ecc` does. On the historical checkpoint
it returns `0x1296b940`, leaves the bin count at `7`, decrements the slab
counter from `0x24` to `0x1c`, and consumes bitmap bits `28..35` in order.

This is a stronger captured-state allocator checkpoint, not a fresh-input
implementation. The model still requires the caller to provide the selected
slab record, target list, batch width, and initialized arena pages.

The sanitized evidence is
[evidence/vm9_allocator_batch_replay_20261003.json](evidence/vm9_allocator_batch_replay_20261003.json).

## Meaning for the deliverables

- Seg2 has complete captured diagnostic runs, including the new detail holdout
  at `90330/90330` without full host handoff loading. It still uses captured
  baseline/native state and trained target bytes.
- Seg3 now completes `1057/1057` from the same-run handoff without a clock-slot
  override. The older page-assisted replay remains complete only for its
  captured sample. Neither is a general current-version signer.
- The old 225-byte Python Medusa implementation remains valid only for its old
  snapshot vectors.
- The no-JVM Rust crate must continue to return an explicit unavailable error
  for current Medusa until state initialization, constructor/allocator behavior,
  and native callbacks are reproduced independently from fresh inputs.

## Next experiment

Replace the learned target-byte state and the Seg3 target correction with the
actual constructor/cleanup/callback-registration semantics. Generate the
arena lookup cache and complete global boot fields, then repeat with a new
input and time branch. Remove captured initialization/native callbacks and
compare an independently generated body before running a fresh live
directory/reader matrix. The current all-segment diagnostic is a component
checkpoint; the pure-Python signer, no-JVM Rust chain, non-empty search, and
later usable search/download webpage remain open.

## Available-slab branch replay (2026-10-03, corrected)

The forced callback-1 probe clears class-3 bin count `0x12282090` and current
slab slot `0x12240950`, enters the empty-bin acquire path, and returns
`0x12a479b0`. The earlier claim that it created a new slab was refuted by
input-checkpoint inspection: record `0x12a403e8` was already class `3`, with
counter `0x34` and leaf bitmap `0x3fffffffffeffe00`.

Direct native `0x12165d44` selects the available node `0x12a403d8`, changes the
tree root to sentinel `0x12240960`, increments the selection count from `4`
to `5`, and returns `node+0x10 = 0x12a403e8`. It does not create that record.
Native `0x121687dc` publishes it as current and consumes the first object slot.

The Python owner now reproduces this singleton-node selection and the
four-slot refill/wrapper pop. Native and Python return `0x12a479b0`, leave
count `3`, decrement the slab counter to `0x30`, and leave bitmap
`0x3fffffffffefe000`. All 4,256 checkpoint pages match for selection, available
refill, an existing-slab regression, and an adjacent metadata-word challenge.
The native transient lock writes remain outside this single-threaded model.

The metadata challenge also exposed and fixed a field-width bug: native reads
`metadata+0x58` with `LDR W8`; the Python model now uses `read_u32` instead of
`read_u64`. Unsupported tree shapes and batches are rejected before writes in
the seven tested negative cases.

The corrected original evidence retains its filename for provenance:
[evidence/vm9_allocator_new_slab_native_replay_20261003.json](evidence/vm9_allocator_new_slab_native_replay_20261003.json).
The native differential result is
[evidence/vm9_allocator_available_slab_20261003.json](evidence/vm9_allocator_available_slab_20261003.json).

The forced full run's event-146 pointer mismatch remains an observation against
an unmodified trace, not proof of missing VM behavior. The paired control
reclaims `0x1296ba60` after the runner explicitly frees it. The diagnostic free
setup does not independently derive live transition history, and native free
has no return value.

This closes a bounded checkpoint branch. Fresh slab/arena initialization,
general tree operations, constructor/cleanup and callback registration remain
open. Current parameterized Python Medusa, the no-JVM Rust download chain,
nonempty search, the other platforms, and the usable webpage remain unfinished.
The next allocator work must reconstruct free publication and its actual
caller history, then exercise a new input without captured initialization.

## Python malloc/free fast paths (2026-10-03)

`allocate_small_object_fast` and `publish_small_object_free` now replace the
normal initialized-thread small-object native paths, with request/region class
selection, free-list publication/pop, count-floor updates, byte accounting,
class allocation counts, and the shared periodic-cleanup counter.

Ten direct native stages across classes 0, 1, 2 and 3 match return pointers,
ordered nonstack writes, and every one of the 4,256 checkpoint pages. The
class-0, class-1 and class-3 free/reallocate pairs return the same freed slots;
zero-size malloc and the signed floor update also match. Twelve unsupported
branches are rejected without writes. A second captured input's initialized
checkpoint adds nine matching malloc/free/malloc stages for classes 0, 2 and 3,
bringing the total to 19. Its `malloc(0x18)` returns `0x122a0c40` versus the
primary checkpoint's `0x122a0c20`; slot identity follows the allocator state.
Both tests still depend on captured initialization.

In a Seg2 diagnostic, Python intercepts all 44 malloc/free wrapper calls before
the existing mixed-capture event `12085`, while other callbacks still execute
native ARM64. It completes 45 callbacks and matches the native control's
ordered object sequence (four transition setup operations and 40 callback
operations). Both have `R2=0x2f8` where the old reference expects `0x2f6`.
The earlier mixed-capture correction in this file already explains that stop;
it must not be reported as a new model failure or repaired with a trace-value
injection.

Details: [ALLOCATOR_FAST_PATHS.md](ALLOCATOR_FAST_PATHS.md), with sanitized
[evidence/vm9_allocator_fast_paths_20261003.json](evidence/vm9_allocator_fast_paths_20261003.json).

This removes two native allocator fast paths from one captured diagnostic
prefix. It still does not derive fresh allocator initialization, TLS discovery,
the true transition cleanup history, empty-bin malloc dispatch, full-bin flush,
periodic cleanup, native constructor/callback state, or an independent Medusa
body. The next run must use a trace and memory from the same capture before
extending interception across the refill/cleanup boundaries. The current
Python signer, no-JVM Rust chain and live search/download remain unfinished.
