# VM9 TLS, arena, cache and string initialization

The startup A/B global is now modeled independently of clocks:
`initialize_ab_switch(pages, image_base=..., ab_switch=2)` writes the verified
`MSC.GetABSwitch()` field at image offset `0x3d1578`;
`evaluate_ab_switch_gate` evaluates BC indices 311–313 at `+0x706c0`.
Eighteen fresh-page cases match actual bytecode execution, with three invalid
cases rejected. The old bridge's timestamp-valued A/B callback was a setup
error; its time-grid observations are not initialization requirements.
See [BRIDGE_INITIALIZATION.md](BRIDGE_INITIALIZATION.md).

To reproduce the bounded component check with the matching private library:

```text
python python/verify_vm9_startup_switch.py --library /private/libmetasec_ml_71332.so --output /private/startup-switch.json
```

This check uses no captured checkpoint or JVM. It initializes one global and
one gate; it does not build the network signer or produce current Medusa.

Python now generates a fresh allocator thread state, arena and thread cache
from the observed build's global configuration. The string constructor at
`0x12508344` generates its object and payload from the supplied source.
The implementations use neither an existing TSD/arena image as their output
template nor a captured constructor object/string payload.

This is a component result inside an initialized guest runtime. The Python
owner now has an explicit anonymous private mapping transaction and fresh
region registration path. Global boot is exposed as a state report plus a
bounded publication contract; arena-zero storage, TLS key generation tables,
lookup-cache generation, loaded vtables and other native callbacks still need
independent inputs. Current parameterized Medusa and online server acceptance
remain unfinished.

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
| `GuestOS.map_anonymous` | Creates zero-filled pages only for the observed private mapping contract |
| `register_os_region` | Registers one mapped `0x40000` region, its free extent and arena available-tree node |
| `read_global_boot_state` / `global_boot_inventory` | Reports observed global fields and the eight-component boot boundary |
| `initialize_global_boot` | Publishes the bounded arena/TLS/cache fields when all required inputs are explicit |
| `clock_callback` | Writes a caller-supplied guest timespec and the wrapper result slot |
| `publish_callback_descriptor` | Publishes the two fields consumed by the active descriptor trampoline |
| `construct_string_object` | Generates the 24-byte object and source-derived payload; returns native X0 payload pointer |

These are observed-build research APIs. Concurrent/recursive TSD
initialization, contended mutexes, arena table expansion and whole-region
unmap/release remain outside the supported boundary. Creating nine empty
large-class cache bins does not implement large-object malloc/free.

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
boundary proves the TLS/TSD/tcache component. The separate region verifier
now proves a complete first refill when an explicit thread/arena/tcache state
and `GuestOS` owner are supplied; it is still not a full empty-TLS global-boot
replacement. The verifier uses real ARM64 constructors; its allocation-failure
cases inject NULL only at the native malloc boundary.
Source hashes, case results and limitations are retained in
[evidence/vm9_runtime_initialization_20261003.json](evidence/vm9_runtime_initialization_20261003.json).
The current-source region/callback addendum is
[evidence/vm9_runtime_region_callbacks_20261003.json](evidence/vm9_runtime_region_callbacks_20261003.json).

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

## Fresh OS-region registration and remaining work

An isolated native run from empty TLS originally stopped at mmap. With an
explicit guest policy that actually maps zero-filled anonymous pages and
records supported anonymous-VMA naming metadata, the native full malloc call
returns successfully. A second mapping address and another small size class
also pass. Unknown syscalls still reject. The public `GuestOS` owner now
creates the same zero-filled page range under an isolated fixed-address
policy. `register_os_region` stages the mapping and allocator writes together,
then inserts the region's free extent at the arena available-tree root.
Starting from the trusted initialization checkpoint, the public verifier
creates a new arena, registers `0x13600000..0x13640000`, and allocates the
first class-3 object at `0x13602000`; metadata becomes
`0x31/0x1031/0x2031/0x3bff0` exactly as the native empty-TLS oracle. Invalid
mapping requests and a post-registration allocation failure leave both pages
and mapping ownership unchanged.

The verified request is an anonymous private `0x40000`-byte mapping, followed
by `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)`. The Python model now covers
page creation, header, free-page endpoints, tree registration and the first
slab split. It still does not generate the arena lookup cache, mutex/global
boot image, callback tables or the remaining constructor/object graph. Those
must be replaced with parameterized rules before claiming a current
standalone Medusa.

The sanitized component result is
[evidence/vm9_os_region_register_20261003.json](evidence/vm9_os_region_register_20261003.json).

## Parameterized callback boundaries

The callback evidence closes two narrow native boundaries. `clock_callback`
models the observed wrapper sequence `ldp x8,x0,[wrapper]; blr x8; str
x0,[wrapper,#0x10]`; the timespec destination is read from `wrapper+0x08` and
the caller supplies the clock result. `publish_callback_descriptor` writes
only descriptor fields `+0x00` and `+0x08`, which the active trampoline loads
with `ldp x1,x8,[x0]` before `mov x0,x8; br x1`. Unsupported clock IDs,
invalid nanoseconds and the packed callback-object x8 composition reject
without mutation. The object graph, destructor path and exact packed-word
writer remain open.

The sanitized result is
[evidence/vm9_callbacks_parameterized_20261003.json](evidence/vm9_callbacks_parameterized_20261003.json).

Only sanitized source, counts, hashes and evidence are published. Private
images, checkpoints, native write traces, raw requests and signature bytes
remain local. This work is confined to Tomato's ByteDance directory.
