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

## Controlled intervention

For the current checkpoint, forcing only `[0x12282060 + 0x30]` to zero did
not reproduce the historical address; the refill path returned `0x1296b9a0`.
Copying the complete `0x12282000` bin page from the historical checkpoint
also returned `0x1296b9a0`. This rules out a single count field or a single bin
page as the missing parameter. The refill cursor, slab/bitmap state, or the
preceding allocation/free history is also different.

## Consequence

The current Medusa implementation cannot be called an independent parameterized
signer yet. Adding `Perseus`, freezing the timestamp, or changing ordinary HTTP
headers cannot repair this divergence; the mismatch occurs before the next
real callback page is injected.

The next proof is to model the allocator's size-class table, slab cursor,
bitmap/free-list words, and allocation/free sequence from a fresh chain, then
rerun the full VM9 trace with a new input vector. A historical replay that
injects captured pages remains diagnostic evidence only.
