# VM9 callback-8 allocator audit

This note records the current blocker in the independent VM9 path. It is
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
are class `3` and block width `0x60`. The arena object points at the bin table
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
size from the class-count table and the next-bin shift, then either allocates a
new slab node or consumes an existing slab record. In the existing-slab path:

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

## Controlled new-slab native replay (2026-10-03)

The next probe forced the class-3 free-list count at `0x12282090` from `3`
to `0` and cleared the class-3 slab pointer slot at `0x12240950` immediately
before Seg2 callback 1. The native code then took the empty-bin path:

```text
0x1217f450 -> 0x12187ecc -> 0x1216970c -> 0x121687dc
```

This run did not copy the historical slab page. The allocator created a new
captured record at `0x12a403e8`, with the post-call header word
`0x3000000003` and bitmap word `0x3fffffffffefe000`, and returned the object
`0x12a479b0`. The native constructor wrote 32 bytes to that object. The run
recorded 273 native writes across 10 pages and stopped after the first callback
for inspection.

The old slab remained at counter `0x18` and bitmap
`0xffffff0000000000`; the class slot was repointed to `0x12a403e8`, while the
target bin ended with head `0x2` and count `0x3`. This is direct evidence that
the empty-bin branch can allocate a new slab record in the captured heap.
It still does not identify a generic slab base formula, region initialization,
allocation/free history, callback registration, or fresh-input body state.

The sanitized evidence is
[evidence/vm9_allocator_new_slab_native_replay_20261003.json](evidence/vm9_allocator_new_slab_native_replay_20261003.json).

This result remains a controlled checkpoint replay. The public allocator model
must continue to reject fresh empty-bin allocation until those missing inputs
are independently generated.

## Full controlled replay boundary

Repeating the same probe without stopping after callback 1 completed 13 native
callbacks. The first VM mismatch then occurred at relative Seg2 event `146`:
`R1=0x12a479b0` from the new slab, while the trace requires
`R1=0x1296ba60` from the current free-list state. The run therefore proves
that the new slab object remains live across later callbacks, but it cannot
stand in for the object identity selected by this captured trace.

This is a useful boundary: the missing behavior is now the allocator's object
selection and allocation/free history after the new slab transition, rather
than failure to execute the empty-bin primitive itself. The full run still
does not establish a fresh-input allocator or a current online Medusa body.

The paired control run keeps the class-3 bin non-empty: count `3`, list
`0x12282680`, selected index `2`, and returned object `0x1296ba60`. The forced
run instead returns the new object `0x12a479b0`. This A/B pair directly ties
the first VM mismatch to allocator object identity and records the control
branch's 204 native writes versus 273 writes on the new-slab branch.

The allocator entry trace also captures the relevant history: the transition
frees `0x1296ba60`, then callback 1 performs `malloc(0x2c)` and reclaims that
same slot. The forced run bypasses this reuse by zeroing the bin count and
slab slot. This is the concrete state sequence that a fresh allocator model
must reproduce before the VM body can be compared.
