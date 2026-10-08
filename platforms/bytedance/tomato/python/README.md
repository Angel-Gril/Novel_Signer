# Tomato Python material

2026-10-08 B reader components: `vm9_alternative_startup.read_reader_varuint32`
restores +0x324870 (258 fresh controls/seven rollback checks).
`run_reader_sections` restores +0x324188 envelope/order/partial state and section
0 (generic custom), 3, 7, 8 and 12 (202 controls/12 rollback checks, including
eight actual ELF sections from independent Python XOR). Callbacks are explicit
pure status services; actual node/AST allocation, type/import/special custom,
wrapper cleanup and a complete Python reader/factory remain open. See
[startup/reader report](../REQUEST_JNI_STARTUP_WORKERS.md#62-section-状态与部分-handler2026-10-08-utc).

```powershell
python -B platforms/bytedance/tomato/python/verify_vm9_alternative_sections_20261008.py --library "$env:TOMATO_LIBMETASEC" --libc "$env:TOMATO_MATCHING_LIBC" --output <reader-section-evidence.json>
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
