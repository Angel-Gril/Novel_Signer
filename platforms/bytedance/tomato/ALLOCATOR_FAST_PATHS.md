# VM9 Python allocator fast paths

The public Python checkpoint model reproduces the normal initialized-thread
small-object malloc/free paths, including their accounting. This is a component
of current Medusa research; it does not initialize a fresh allocator or generate
a current online signature.

## Native boundaries

| operation | wrapper | implementation | observed branch |
| --- | --- | --- | --- |
| malloc | `0x1210bb08` | `0x1217f00c` | nonempty bin at `0x1217f0e8` |
| free | `0x1210bac0` | `0x12181990` | small-object publication at `0x12181ad8` |

The captured thread state is `0x12296000`; its `+0x10` field points to the bin
table at `0x12282000`. The Python primitives accept that initialized state as
an explicit input. TLS lookup and thread/arena creation remain outside them.

## Allocation rule

Native malloc treats a zero-size request as one byte. For the supported small
requests, the tables derive the class and accounting width:

```text
effective_size = request_size or 1
class_id = read8(0x12196a80 + ((effective_size - 1) >> 3))
class_width = read64(0x12196c80 + class_id * 8)
bin = bins + class_id * 0x20
count_after = read32(bin + 0x30) - 1
object = read64(read64(bin + 0x38) + count_after * 8)
```

The fast path decrements the bin count, updates the signed floor at `bin+0x28`
when needed, increments the class allocation counter at `bin+0x20`, increments
the shared cleanup counter at `bins+0x18`, and adds the class width to the
allocated-byte counter at `thread+0x18`. The normal path leaves the object's
payload intact; debug and fill branches are unsupported.

## Free publication rule

Free determines the class from the object's region page metadata:

```text
region_base = object & ~read64(0x121d9ec0)
page_index = (object - region_base) >> 12
page_bias = read64(0x121d9eb0)
entry_address = region_base + (page_index - page_bias) * 8 + 0x68
entry = read64(entry_address)
class_id = (entry >> 4) & 0xff
```

The supported page has low flag bits `01`; the page index lies between the
captured bias and page limit. The class determines the bin and its capacity.
An ordinary free performs exactly four nonstack writes, in this order:

1. Add the class width to `[thread+0x20]`, the freed-byte counter.
2. Store the object at `list[count_before]`.
3. Increment `[bin+0x30]`, the free-list count.
4. Increment `[bins+0x18]`, the shared cleanup counter.

For object `0x1296ba60`, region `0x12940000` has page metadata `0x2031` at
`0x129401b0`, giving class `3`. Free publishes it at list index `3` and changes
the count from `3` to `4`. A subsequent `malloc(0x2c)` decrements the count and
reclaims that object from the last list entry.

The class-3 width is `0x30`, as verified in both the raw native table and the
checkpoint, and by native byte accounting. This corrects the older audit's
`0x60` statement. Native free is void: retained physical `x0` values are not
return values.

## Python call boundary

The following is a checkpoint component example; `pages` must be a trusted
initialized page map with 4,096-byte mutable pages keyed by `address >> 12`.

```python
from vm9_allocator import allocate_small_object_fast, publish_small_object_free

publication = publish_small_object_free(
    pages,
    thread_state_address=0x12296000,
    object_address=0x1296BA60,
)
allocation = allocate_small_object_fast(
    pages,
    thread_state_address=0x12296000,
    request_size=0x2C,
)
assert allocation.free_list.object_address == publication.object_address
```

The caller still establishes object ownership and the actual allocation/free
history. Calling free on an arbitrary pointer is not a method of discovering
that history.

## Verification and limits

Ten direct ARM64 execution stages cover classes 0, 1, 2 and 3, three immediate
free/reallocate pairs, zero-size malloc, and a signed floor update. The Python
result matches the native malloc return pointer, exact ordered nonstack write
address/size/value triples, and final bytes across all 4,256 checkpoint pages.
The native stack is placed outside the checkpoint for this differential check.
Twelve unsupported branch cases reject without checkpoint mutation.

A second captured input's initialized checkpoint adds nine native stages:
`malloc -> free -> malloc` for requests `0x4`, `0x18` and `0x2c`. Write order,
return pointers and all checkpoint pages match at each stage, and the last
allocation reclaims the first allocated slot. In particular, `malloc(0x18)`
returns `0x122a0c40` in this state versus `0x122a0c20` in the primary state.
The Python rule follows the actual list state rather than an expected fixed
pointer. These are 19 native stages across two captured states; both still
supply initialized allocator pages.

A separate Seg2 diagnostic replaces 44 native malloc/free wrapper calls with
Python, with no native allocator fallback. Other constructors and callbacks
still execute captured ARM64. It completes 45 callbacks and matches the native
control's ordered object sequence. Both runs stop at relative event `12085`
with `R2=0x2f8` where the older trace expects `0x2f6`. This is the previously
recorded mixed-capture artifact; it is not evidence of a new allocator failure.
The four diagnostic transition operations still include explicitly supplied
frees, so this prefix does not recover fresh caller history.

The current model rejects automatic empty-bin malloc dispatch, full-bin flush,
periodic cleanup, hooks, debug/fill modes, large objects, and initialization.
Existing-slab refill and singleton available-node acquisition are separate
checkpoint primitives. The interception does not reproduce physical scratch
registers or dead native call-frame bytes. Current Medusa generation and live
server validity remain unverified.

Sanitized provenance and results:
[evidence/vm9_allocator_fast_paths_20261003.json](evidence/vm9_allocator_fast_paths_20261003.json).
The broader allocator boundary is recorded in
[ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).
