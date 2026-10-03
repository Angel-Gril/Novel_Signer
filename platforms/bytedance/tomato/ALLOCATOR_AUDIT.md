# VM9 callback-8 allocator audit

The latest implementation and same-capture result are recorded in
[ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md). Empty-bin dispatch, mapped
new-slab initialization, trees, flush and cleanup are now implemented; fresh
OS/TLS/arena setup remains open. The sections below retain the earlier branch
evidence and its corrections.

This note records the original blocker in the independent VM9 path. It is
separate from the online header matrix: the observation is made inside the
native constructor callback that builds the `X-Medusa` body.

## Branch evidence

The native routine at `0x1217f0e8` reads the size-class bin count from
`[bin + 0x30]`. The class-table byte for this callback is `3`, so the bin is
`0x12282060`.

| checkpoint | count | allocator branch | returned buffer | native writes |
| --- | ---: | --- | ---: | ---: |
| historical success path | `0` | refill/slab path | `0x1296b940` | `80` |
| current full-Seg2 path | `4` | free-list path, chosen index `2` | `0x1296ba60` | `33` |

Both paths then run the same string constructor. The bytes written are the
same 32-byte value (`"2e8ab1223d07836ad4fc65fc581b4808"`); only the destination
address and allocator side effects differ.

The relevant native control flow is:

```text
class = class_table[(requested_size - 1) >> 3] = 3
bin   = arena_bins + class * 0x20 = 0x12282060
count = [bin + 0x30]
if count != 0:
    count -= 1
    result = [bin + 0x38][count]
else:
    [bin + 0x28] = -1
    refill(arena, bin, class)
```

## Native implementation evidence

The allocator code is present in the captured `new_vm9_libc.bin` image. The
callback reads the class byte from `0x12196a80 + ((size - 1) >> 3)` and the
class-width table from `0x12196c80 + class * 8`; for this request the values
are class `3` and block width `0x30` (corrected by the direct malloc/free probe). The arena object points at the bin table
through `[0x12296000 + 0x10] = 0x12282000`, so the count field is
`0x12282060 + 0x30 = 0x12282090`.

The zero-count branch calls the refill helper at `0x12187ecc`, which in turn
uses the class-3 control record at `0x12240950`. That record points to slab
metadata at `0x12941108`. The two checkpoint states differ at the metadata
counter and bitmap word:

| field | historical success | current full-Seg2 |
| --- | ---: | ---: |
| `[0x1294110c]` | `0x24` | `0x20` |
| `[0x12941128]` | `0xfffffffff0000000` | `0xffffffcfc0000000` |

The refill code scans the bitmap with `RBIT/CLZ`, clears the selected bit, and
derives the returned slab address. This explains why changing only the bin
count or copying the bin page cannot reproduce the historical pointer.

## Static refill control flow

The empty-bin branch at `0x1217f450` stores `-1` at `[bin+0x28]` and calls
`0x12187ecc` with the arena, the bin table, the next size-class bin, and the
class id. The wrapper calls `0x1216970c`. That routine first computes the batch
size from the class-count table and the next-bin shift. It consumes the current
slab when that record still has slots; otherwise it tries the available-node
tree before entering the unmodeled initialization path. In the current-slab path:

1. the slab record is loaded from the class state at `+0x530`;
2. `[slab+4]` is the remaining-slot counter;
3. the bitmap word is selected through `[slab+8 + word_index*8]`;
4. `RBIT` followed by `CLZ` finds the lowest set bit, and an XOR store clears
   it;
5. the counter is decremented and the selected object is returned;
6. the refill wrapper writes the batch of returned objects to the bin free list
   and publishes the new count at `[bin+0x10]`.

The class-3 checkpoint values make the bit operation independently checkable:

| state | counter before | bitmap before | selected bit | bitmap after | counter after |
| --- | ---: | ---: | ---: | ---: | ---: |
| historical success | `0x24` | `0xfffffffff0000000` | `28` | `0xffffffffe0000000` | `0x23` |
| current full-Seg2 | `0x20` | `0xffffffcfc0000000` | `30` | `0xffffffcf80000000` | `0x1f` |

This is a static and checkpoint-backed primitive. The public model now also
replays the observed existing-slab batch: it consumes the selected slab slots,
writes the returned object pointers into the target list in reverse order,
publishes the batch count, and applies the wrapper's first pop. It still does
not model slab base discovery, new-node allocation, region initialization, or
the preceding allocation/free sequence, so it cannot produce a fresh-input
Medusa body by itself.

## Controlled intervention

For the current checkpoint, forcing only `[0x12282060 + 0x30]` to zero did
not reproduce the historical address; the refill path returned `0x1296b9a0`.
Copying the complete `0x12282000` bin page from the historical checkpoint
also returned `0x1296b9a0`. This rules out a single count field or a single bin
page as the missing parameter. The refill cursor, slab/bitmap state, or the
preceding allocation/free history is also different.

A minimal checkpoint transplant that changed only the bin count and the two
slab fields above returned `0x1296b940` and produced the historical 80-byte
write pattern. Applying that transplant at callback 8 in the independent
runner let the captured Seg2 trace complete (`90161/90161` events,
`121` callbacks). This is a trace-assisted diagnostic result: it uses one
captured allocator state and does not establish a fresh-input or online
parameterized Medusa implementation.

## Consequence

The current Medusa implementation cannot be called an independent parameterized
signer yet. Adding `Perseus`, freezing the timestamp, or changing ordinary HTTP
headers cannot repair this divergence; the mismatch occurs before the next
real callback page is injected.

The next proof is to model the allocator's size-class table, slab cursor,
bitmap/free-list words, and allocation/free sequence from a fresh chain, then
rerun the full VM9 trace with a new input vector. A historical replay that
injects captured pages remains diagnostic evidence only.

## Existing-slab batch replay

For the historical class-3 checkpoint, the observed batch width is eight. The
native helper stores the selected objects at list indexes `7..0`; the wrapper
decrements the published count to seven and returns list index seven. The
public replay produces the captured sequence:

```text
0x1296b940, 0x1296b970, 0x1296b9a0, 0x1296b9d0,
0x1296ba00, 0x1296ba30, 0x1296ba60, 0x1296ba90
```

This verifies the batch ordering and the counter/bitmap transition for the
existing slab. It remains a checkpoint replay and is not a fresh allocator.

## Controlled available-slab native replay (2026-10-03, corrected)

The probe forced the class-3 free-list count at `0x12282090` from `3` to
`0` and cleared the current slab pointer at `0x12240950` immediately before
Seg2 callback 1. It observed:

```text
0x1217f450 -> 0x12187ecc -> 0x1216970c -> 0x121687dc
```

The callback returned `0x12a479b0`, recorded 273 native writes over 10 pages,
and left the selected slab counter at `0x30`. The earlier report called this
fresh slab creation. **That interpretation was refuted**: the input checkpoint
already contains slab `0x12a403e8`, class `3`, counter `0x34`, leaf bitmap
`0x3fffffffffeffe00`, and a linked available-tree node at `0x12a403d8`.

The original filename remains for provenance:
[evidence/vm9_allocator_new_slab_native_replay_20261003.json](evidence/vm9_allocator_new_slab_native_replay_20261003.json).
Its correction points to the direct native differential evidence below.

## Available-node selection and Python reproduction

Native `0x12165d44(control)` follows left links to the lowest available node,
removes it with `0x121657f4`, increments `[control+0xd0]`, and returns
`node+0x10`, the already initialized slab record. For the captured singleton:

| field | before | after native selection |
| --- | --- | --- |
| root `[0x12240958]` | `0x12a403d8` | sentinel `0x12240960` |
| selection count `[0x122409f8]` | `4` | `5` |
| selected record | already initialized `0x12a403e8` | returned `0x12a403e8` |

The native selector has exactly two nonstack writes in this case. The acquire
helper `0x121687dc` clears the old current slot, selects and publishes this
record, consumes its first bitmap slot, and returns `0x12a479b0`. No fresh slab
initialization helper executes in these probes.

The public model adds `select_singleton_available_slab` and
`refill_singleton_available_slab_and_pop`. The latter reproduces the observed
four-slot batch and wrapper pop:

```text
allocation order: 0x12a479b0, 0x12a479e0, 0x12a47a10, 0x12a47a40
list write indexes: 3, 2, 1, 0
return: 0x12a479b0; published count after pop: 3
slab counter: 0x34 -> 0x30
leaf bitmap: 0x3fffffffffeffe00 -> 0x3fffffffffefe000
```

Direct Unicorn execution of `0x12165d44` and `0x12187ecc` is compared with the
Python primitives on separate copies of the trusted checkpoint. Return values
and final bytes across all 4,256 checkpoint pages match. The native refill has
25 nonstack writes, including the transient lock acquire/release; the Python
model matches final memory and does not model concurrency or those transient
lock writes. An existing-current-slab regression also matches native execution
and returns `0x1296bb80`.

Empty trees, larger trees, tagged singleton links, an active current slab,
nonempty target bins, wrong-class records, and batches requiring another slab
are rejected without checkpoint mutation. This is deliberately limited to the
verified initialized tree shape, not a fresh allocator.

The new evidence is
[evidence/vm9_allocator_available_slab_20261003.json](evidence/vm9_allocator_available_slab_20261003.json).

## Metadata field width

Native `LDR W8, [X30, #0x58]` reads the base offset as 32 bits. The earlier
Python implementation read 64 bits. A one-variable test writes `0xaabbccdd`
to the adjacent upper word at `0x121d929c`: native still returns
`0x12a479b0`, while the old model returns `0xaabbccdd12a479b0`. Reading the
field with `read_u32` repairs that discrepancy; the corrected refill still
matches every checkpoint page.

## Object identity and history boundary

The full forced callback replay completed 13 callbacks before the reference
trace differed at relative Seg2 event `146`: actual `R1=0x12a479b0`, expected
`R1=0x1296ba60`. The intervention deliberately changes allocator state, so
this pointer difference alone does not prove a missing VM operation.

The paired control uses count `3`, list `0x12282680`, index `2`, and returns
`0x1296ba60`. Its 204 writes versus the forced callback's 273 demonstrate the
different allocation paths. The diagnostic runner explicitly frees
`0x1296ba60` before callback 1, whose `malloc(0x2c)` then reclaims it. Those
explicit transition frees are probe setup, not independently recovered fresh
history. Native `free` is void; residual `x0` observations carry no return-value
semantics.

Fresh arena/slab initialization, general tree removal, the true constructor and
cleanup history, callback registration, and fresh-input Medusa generation
remain open. Current Python signing and the no-JVM Rust download chain are
still unavailable; this batch performs no new online request.

## Normal malloc/free publication (2026-10-03)

The Python owner now models the normal initialized-thread small-object paths,
including all allocation/free accounting. Class selection for malloc comes
from the request-size byte table. Free derives the object's class from region
page metadata, then publishes it to `list[count]` and increments the count.
The following nonempty-bin malloc reclaims that same address.

Native differential verification covers classes 0, 1, 2 and 3, zero-size
malloc, and the signed count-floor update. Ten native stages match the exact
nonstack write sequence and all 4,256 checkpoint pages. Twelve unsupported
branches are rejected without mutation. A second captured checkpoint adds nine
matching allocation/free/reallocation stages, for 19 stages across two states.
The raw class-width table and native
accounting also correct this note's earlier class-3 width from `0x60` to `0x30`.

A captured Seg2 interception replaces 44 malloc/free calls, including four
transition setup operations, and matches the native control's ordered pointer
sequence through 45 callbacks. Both executions stop at the already recorded
mixed-capture event `12085` (`R2=0x2f8`, old trace `0x2f6`); this is not a new
allocator defect. Diagnostic transition frees and native constructors remain.
See [ALLOCATOR_FAST_PATHS.md](ALLOCATOR_FAST_PATHS.md) and
[evidence/vm9_allocator_fast_paths_20261003.json](evidence/vm9_allocator_fast_paths_20261003.json).
