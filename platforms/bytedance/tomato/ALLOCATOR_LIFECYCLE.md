# VM9 allocator lifecycle and same-capture validation

The Python allocator now handles empty-list refill, full-bin flush, periodic
cleanup, and actual slab initialization from mapped free extents. The paired
detail capture passes Seg1 -> native host continuation -> Seg2 -> Seg3 with
303 malloc/free calls replaced by Python. Its 779-byte output matches both
the native allocator control and the original captured output exactly.

This is a captured-state component result. Initial mapped regions, initialized
TLS/arena, trace entry registers, and other native ARM64 callbacks are still
required. It does not establish a standalone current Medusa signer or live
server acceptance.

## Implemented call boundary

The owner is [python/vm9_allocator.py](python/vm9_allocator.py). Page maps contain
trusted mutable 4,096-byte pages keyed by `address >> 12`.

| API | Behavior |
| --- | --- |
| `allocate_small_object` | Derive class from size; pop/refill; account bytes and trigger cleanup |
| `free_small_object` | Derive class from region metadata; flush full bins; publish pointer; trigger cleanup; NULL is a no-op |
| `cleanup_small_object_bins` | Sweep one class; adjust retention/shift; reset counter and advance/wrap cursor |
| `initialize_slab_bitmap` | Generate leaf/summary bitmap words from the native class descriptor |

The first three APIs stage changes in a page transaction. Unsupported paths
leave the original map unchanged. `initialize_slab_bitmap` is a direct helper;
the transaction guarantee belongs to the lifecycle APIs. The older
`allocate_small_object_fast` and `publish_small_object_free` retain their
narrower boundaries.

```python
from vm9_allocator import AllocatorConstants, allocate_small_object, free_small_object

# pages and thread_address come from a trusted initialized guest runtime.
constants = AllocatorConstants()
allocation = allocate_small_object(
    pages, thread_state_address=thread_address, request_size=0x2C,
    constants=constants,
)
free_small_object(
    pages, thread_state_address=thread_address,
    object_address=allocation.free_list.object_address, constants=constants,
)
```

## Refill, initialization and cleanup

The empty-bin batch is derived from class capacity and shift. It can consume
the current slab, select available slabs, and cross slab boundaries. Tagged
compact tree links, rotations, insertion and deletion are modeled. Overlapping
bin fields are preserved: the stride is `0x20`, while some fields extend beyond
that stride. Tree balancing follows jemalloc 3.6.0 `rb.h`; its BSD notice is
retained in [python/jemalloc-BSD-2-Clause.txt](python/jemalloc-BSD-2-Clause.txt).

With no available slots, the allocator selects and splits a mapped free extent,
writes a new slab record, page metadata and counters, and initializes the
descriptor-derived bitmap. This is actual new-slab initialization. The older
probe only selected an already initialized slab; that earlier interpretation
remains refuted in [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).

Full-bin flush and periodic cleanup return slots to slab bitmaps, maintain
trees/counters, release empty slabs, coalesce adjacent extents, and update
dirty queues and purge accounting. The sampled runtime has 36 supported small
classes, through size `0x3800`.

Purge requires `AllocatorConstants.purge_madvise_result`. The default `None`
rejects it. The isolated success oracle uses `0`; the failure oracle uses `-22`
and the guest TLS errno address. These explicit advisory syscall outcomes do
not prove Linux page zeroing semantics. Fresh OS region mapping, fresh TLS/arena
setup, whole OS region release, large cached-extent purge and custom purge
hooks remain unsupported. Concurrency and transient lock writes are not
modeled. The direct release helper is tested with its required class lock held.

## Native differential evidence

The public [lifecycle verifier](python/verify_vm9_allocator_lifecycle.py) uses
Unicorn and the private primary initialized checkpoint as the native oracle.
Its 83 cases cover nine refill/cleanup scenarios, 36 new-slab classes,
36 bitmap descriptors, and two release-purge results. Every case matches final
bytes across all 4,256 checkpoint pages. Eight unsupported cases reject without
mutation; `free(NULL)` leaves memory unchanged. A continuous 240 allocations
plus 120 frees also matches native returns and all checkpoint pages after
every operation. Identical transient write ordering is not claimed.

```text
python verify_vm9_allocator_lifecycle.py --checkpoint trusted_primary.pkl --output lifecycle_results.json
```

The checkpoint includes private native code and initialized tables and is not
supplied here. Pickle inputs must be trusted. The native scratch stack is
outside checkpoint memory. Results and hashes:
[evidence/vm9_allocator_lifecycle_20261003.json](evidence/vm9_allocator_lifecycle_20261003.json).

## Same-capture execution

All three segments use `vm9_detail_20261002_g` memory and trace. Seg2 consumes
the Python-generated Seg1 checkpoint and executes the actual host continuation,
including dynamic string construction and recursive cleanup. It uses no
trained handoff, manually supplied transition free list, or captured `NEXT#1`
region transplant.

| Stage | Matched VM events | Native callbacks | Python malloc/free calls |
| --- | ---: | ---: | ---: |
| Seg1 | 4,592 / 4,592 | 85 | 95 |
| Host continuation + Seg2 | 90,330 / 90,330 | 121 | 118 |
| Seg3 | 1,057 / 1,057 | 87 | 90 |

These runs have no native allocator fallback, callback-page injection,
callback-target replacement, Seg3 frame patch or clock-slot override. Existing
Seg1 pointer-tag normalization of two stack bytes remains in both controls.
The runner supplies captured native frame context, segment entry registers and
guest clock policy. In its isolated single-thread environment, only the
observed `FUTEX_WAKE_PRIVATE` wake-all call returns zero; other unmodeled
syscalls are rejected. Remaining callbacks execute captured ARM64 in Unicorn.

Seg1/Seg2 have no nonstack page differences between Python and native controls.
Seg3 has 15 differing bytes across five non-output pages, plus call-stack
differences. Native copy stores for those bytes were observed at callbacks 9
and 87. These bytes are retained, not patched; whole-memory equivalence is
not claimed. The final 779-byte body matches native and captured `MEDCOPY`
output, SHA-256
`1cf99c1513819043bb7c8e0a21891274005907d3219cc12445bb5c514b1ee6a9`.

The exercise also found an interpreter bug: virtual R28 was used as the
physical ARM64 x28 slot-array address. OP17/sub52 overwrote callback pointer
`0x12641b28`, ending at `0x1d`. The interpreter now accepts an explicit
`register_backing_base`; virtual R28 cannot supply it implicitly. Native
divmod/commit handlers verify 12 pairs covering optional backing, sign
extension, upper-bit truncation and zero divisors. The pointer stays intact.
See [python/verify_vm9_divmod_backing.py](python/verify_vm9_divmod_backing.py) and
[evidence/vm9_allocator_same_capture_20261003.json](evidence/vm9_allocator_same_capture_20261003.json).

## Remaining boundary

Next work must derive fresh TLS/arena and callback/constructor state, remove
native/frame dependencies, and validate a new request without captured
initialization. Current Python Medusa, the no-JVM Rust download chain, live
nonempty search, full-header server matrix and timestamp experiments remain
separate unfinished acceptance work.
