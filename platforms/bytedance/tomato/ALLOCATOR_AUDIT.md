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
