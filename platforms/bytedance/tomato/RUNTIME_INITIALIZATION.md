# VM9 TLS, arena, cache and string initialization

Python now generates a fresh allocator thread state, arena and thread cache
from the observed build's global configuration. The string constructor at
`0x12508344` generates its object and payload from the supplied source.
The implementations use neither an existing TSD/arena image as their output
template nor a captured constructor object/string payload.

This is a component result inside an initialized guest runtime. Global boot
configuration, arena-zero storage, TLS key generation tables, loaded vtables
and other native callbacks still come from private captures. Python does not
yet allocate a new OS region for a fresh arena. Current parameterized Medusa
and online server acceptance remain unfinished.

## Owners and call contract

[python/vm9_allocator.py](python/vm9_allocator.py) owns TLS and allocator state.
[python/vm9_objects.py](python/vm9_objects.py) owns the string constructor.
Both use mutable 4,096-byte guest pages indexed by `address >> 12`.
The constructor calls `allocate(staged_pages, requested_size)`; that adapter
must mutate only the supplied pages and return a guest pointer or NULL.
The normal adapter uses the Python allocator. Unsupported operations roll
back the page transaction, including allocator changes made inside a
constructor. External adapter effects cannot be rolled back by this contract.

| Function | Result and boundary |
| --- | --- |
| `pthread_getspecific` | Generation-checked value; clears stale values; invalid keys return NULL |
| `pthread_setspecific` | Stores generation/value; returns 0 or native invalid-key result 22 |
| `base_allocate` | Takes and splits a mapped base extent; preserves allocation payload and padding |
| `create_arena` | Generates mutexes, counters, sentinels, extent trees, stats arrays and 36 small-bin controls |
| `allocate_arena_small` | Direct allocation without an initialized thread cache; supports optional zeroing |
| `create_tcache` | Allocates/zeros backing storage in arena zero, associates the chosen arena, generates 45 bin lists |
| `initialize_thread_state` | Creates and publishes native state-0 TSD, before the state transition |
| `choose_thread_arena` | Chooses the least occupied arena or creates the first empty table slot |
| `prepare_thread_allocator` | TLS -> TSD -> state 1 -> arena -> tcache publication, before user allocation |
| `construct_string_object` | Generates the 24-byte object and source-derived payload; returns native X0 payload pointer |

These are observed-build research APIs. Global boot, concurrent/recursive
TSD initialization, contended mutexes, arena table expansion and fresh OS
mapping are outside their supported boundary. Creating nine empty large-class
cache bins does not implement large-object malloc/free.

## Derivation and checks

The local libc sample retains function symbols. Symbol values plus the ELF
load base identify the actual pthread/jemalloc functions; their ARM64 bodies
and independently executed memory effects provide the oracle. The captured
libc byte range begins at a different address from that ELF load base.

TLS validity uses a signed 32-bit key bound and an active odd generation.
The current value alone cannot establish key validity. Base extent trees use
link offset `0x48`, with keys `(size, address)`; the same compact tree owner
now accepts this offset while retaining its previous default. Allocation size
is rounded to 64 bytes, whereas extent search uses class-rounded size.

Arena construction writes the fields observed in the native constructor,
including 40-byte mutexes and differently placed extent-tree links. Prefilling
the destination with nonzero bytes proves that unspecified padding is
preserved rather than indiscriminately zeroed. Fresh TSD has the same padding
requirement. Cache creation has 45 bins, although only 36 are small classes;
the list pointers and capacities are generated from runtime configuration.

The string constructor supports NULL source, empty strings, supplied UTF-8
bytes, cross-page input/object placement and allocation failure. For a
nonnull source it stores capacity `strlen + 1`, length `strlen`, allocates
capacity and copies the terminating NUL. On NULL source it reads the build's
empty descriptor, allocates eight bytes and writes the first NUL. A NULL
allocation preserves the native branch-specific field behavior. Source scans
are explicitly bounded; missing pages and unterminated inputs reject without
mutating the caller's pages.

## Reproducible component evidence

[python/verify_vm9_initialization.py](python/verify_vm9_initialization.py)
compares 85 native differential cases against all 4,256 guest pages. Cases
include stale/inactive/invalid TLS keys, cross-page TLS, base extent consumption
and multiple native-built tree shapes, nonzero arena/TSD prefills, all 36
direct new-slab zeroing classes, cache association, new TSD publication, arena
choice, the combined initialization boundary and string construction.
Eleven invalid/unsupported cases reject without mutation.

```text
python verify_vm9_initialization.py --capture-dir trusted_capture --output initialization.json
```

The local capture directory must contain `vm9_libc.bin`, `vm9_m0.bin`,
`vm9_m1.bin`, `vm9_m2.bin` and `vm9_copy2.bin`. It is private and unpublished.
The combined initialization oracle runs actual malloc from empty TLS and
stops after tcache publication, before the first user-object refill. This
boundary proves initialization; it does not claim the complete fresh malloc
call returns in Python. The verifier uses real ARM64 constructors; its
allocation-failure cases inject NULL only at the native malloc boundary.
Source hashes, case results and limitations are retained in
[evidence/vm9_runtime_initialization_20261003.json](evidence/vm9_runtime_initialization_20261003.json).

The earlier 83-case allocator lifecycle regression also passes after the
offset-aware tree change. That run checks refill, cleanup, release and all
4,256 existing pages; no whole-runtime independence follows from it.

## Same-capture integration

The private integration runner resolves allocator thread state through TLS
and replaces every reached call to target string constructor `0x12508344`
with the Python owner. The detail capture completes Seg1 -> actual native
host continuation -> Seg2 -> Seg3:

| Segment | VM events | Callbacks | Python malloc/free | Python target constructors |
| --- | ---: | ---: | ---: | ---: |
| 1 | 4,592 | 85 | 95 | 1 |
| 2 including continuation | 90,330 | 121 | 118 | 3 |
| 3 | 1,057 | 87 | 90 | 3 |

All 303 allocator calls and seven target constructor calls avoid native
fallback. The final 779 bytes equal both the captured MEDCOPY and native
allocator control. Output SHA256:
`1cf99c1513819043bb7c8e0a21891274005907d3219cc12445bb5c514b1ee6a9`.
Seg1/Seg2 nonstack memory is identical. Seg3 retains the previously observed
15 differing bytes on five non-output pages. Stack bytes can also differ;
whole-memory equivalence is not claimed.

This integration still starts from the capture's existing thread/region
state. It checks TLS lookup and the new constructor in the full chain; the
separate component oracle proves empty-TLS initialization. Captured trace
entry registers, native frames, other constructors/callbacks, native host
continuation and the earlier two-byte Seg1 pointer-tag normalization remain.

## Fresh OS-region oracle and remaining work

An isolated native run from empty TLS originally stopped at mmap. With an
explicit guest policy that actually maps zero-filled anonymous pages and
records supported anonymous-VMA naming metadata, the native full malloc call
returns successfully. A second mapping address and another small size class
also pass. Unknown syscalls still reject. These runs establish a native
oracle, not an implemented Python kernel or allocator region path.

The verified request is an anonymous private `0x40000`-byte mapping, followed
by `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)`. Native code then registers
the region, generates its arena/page/slab metadata and refills the cache.
The next implementation must generate these effects and the arena lookup
cache in Python under an explicit mapping policy. It must compare complete
fresh malloc calls, allocation sequences and rejected mapping requests with
the native oracle, then replace remaining host objects/callbacks and global
boot state before claiming current standalone Medusa.

Only sanitized source, counts, hashes and evidence are published. Private
images, checkpoints, native write traces, raw requests and signature bytes
remain local. This work is confined to Tomato's ByteDance directory.
