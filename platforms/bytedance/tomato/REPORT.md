# Tomato reverse-engineering report

## Scope and version

The live checks used the Tomato Android client profile `v7.1.3.32` (`aid=1967`) and the current `libmetasec_ml` VM bridge available in the isolated workspace. The original development directory was not used for these trials.

## What is established

The complete content path is reproducible with the current Java/Unidbg bridge:

```text
device_register
  → registerkey
  → directory
  → reader/full
  → AES-CBC chapter decode
```

The directory response contained 611 chapter entries. The reader response was HTTP 200 with `crypt_status=0`; decrypting it with the key returned by the registerkey exchange produced 6,496 bytes of HTML. The decoded chapter hash is recorded in `evidence/EVIDENCE_INDEX.json`.

The registerkey request uses a fixed application content-encryption constant and returns a per-session chapter key. The published report records only the key version and output hashes; the per-session key, device identifiers, UUIDs, tickets, and complete headers remain private trial data.

## Pure algorithms already separated from the VM

The following are implemented and have sample-level or vector-level checks:

- `X-Khronos`: seconds timestamp;
- `X-Neptune`: soft timestamp field; it was removed by the open bridge and is not a hard reading-interface dependency;
- `X-Gorgon`: current 0404 form has the 0x8404 prefix and a one-way KSA/PRGA path;
- `X-Ladon`: Speck-like 34-round block transform;
- `X-Argus`: the Tomato variant uses SHA-256/AES details different from the common Douyin implementation; the live reading matrix did not require it;
- `X-Helios`: the 34-round VM was translated to Python and its key-table/header samples matched captured vectors;
- registerkey and chapter AES-CBC/decompression routines.

## Medusa status

There are two materially different claims:

1. The old 12a2a000 snapshot has a pure-Python body interpreter. It can accept a query string and reproduce its 225-byte body vectors. This is useful for studying field layout and VM semantics.
2. The current `v04.09.09.01-bugfixS` VM9 path can be run by the Java/Unidbg bridge. It produces short (228-byte raw) and long (803–804-byte raw) branches that were accepted by the live reading endpoints. The current VM9 body has also been reconstructed from A/B traces (777/779 bytes), but the reconstruction is trace-assisted. Independent execution still reaches native target `0x125081ac`, whose constructor calls allocator target `0x12607fd0`; after that boundary the standalone comparator lacks the returned object and diverges.

The latest checkpoint audit separates three results that must not be merged: the historical Seg3 replay still reaches `1057/1057` events with 87 callbacks when the captured `event0_cb66_vm9_*` image and callback 9/64/66 pages are used; the unmodified newer full-Seg2 checkpoint diverges at trace 758 after callback 8 (`0x1296b940` versus `0x1296ba60`); and a controlled transplant of the callback-8 slab fields lets that captured Seg2 trace complete at `90161/90161` events with 121 callbacks. These are reproducible diagnostic replays, not evidence of a general current-version parameterized signer. See [VM9_PROGRESS.md](VM9_PROGRESS.md) for the exact matrix.

Consequently, this repository does not call current Medusa “pure Python parameterized” and does not enable it in the default Rust build. The exact next proof is an independent constructor/allocator implementation followed by fresh current-version vectors and the same live endpoint matrix. The callback-8 allocator branch is documented in [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).

The independent VM9 notes corrected two Seg1 runner mistakes. The actual entry
base `0x1235a6f0` removed a false trace-120 branch; using Seg1's own native
stack frame then removed a false callback-20 libc abort caused by applying the
Seg2 frame. The corrected ARM64 replay completed all `4592/4592` Seg1 events
and 85 callbacks on the captured sample, and its checkpoint matched the first
10 Seg2 callbacks. This narrows the state handoff work but does not change the
current Medusa parameterization status. See [VM9_PROGRESS.md](VM9_PROGRESS.md)
and the [sanitized frame probe](evidence/vm9_seg1_frame_probe_20260930.json).
The first full Seg2 continuation from that checkpoint reached callback 45; the
apparent `0x2f8` versus `0x2f6` mismatch was later identified as a mixed-capture
artifact. The paired trace and memory image both use `0x2f8`; the older `0x2f6`
value belongs to a different checkpoint.

A fresh same-run capture was then replayed with full host handoff snapshots.
Seg1 reached `4592/4592` events and 85 callbacks, Seg2 reached
`90153/90153` events and 121 callbacks without callback-page injection or an
allocator-field transplant, and Seg3 reached callback 86 before the first
unexplained clock-result slot. A real Unidbg write watch then observed callback
function `0x12545f60` store `x0=0` to `0xe4ffe630` at PC `0x12545f70`; the
captured instruction is `str x0, [x19, #0x10]`. The slot is therefore the
native callback result field, rather than an unexplained host transplant. The
earlier explicit-slot-zero replay models this real store and completes Seg3 at
`1057/1057` events and 87 callbacks. These are still captured-state
diagnostics and do not establish a fresh-input pure-Python signer. See
[evidence/vm9_handoff_probe_20260930.json](evidence/vm9_handoff_probe_20260930.json)
and [evidence/vm9_clockslot_native_write_20260930.json](evidence/vm9_clockslot_native_write_20260930.json).

Instruction-level tracing then identified the offline mismatch: callback 86
calls `clock_gettime(1)` and computes `(current_ns - saved_start_ns) / 1000`,
while the offline runner had supplied a wall-clock timespec to clock ID 1.
Matching the bridge's frozen monotonic value (`123456789000000` ns) let Seg3
complete `1057/1057` events and 87 callbacks without any clock-result-slot
override or callback-page injection. This closes the clock discrepancy for
one captured request, but the replay still uses captured full-memory handoffs
and native ARM64 images. See
[evidence/vm9_clock_model_replay_20261001.json](evidence/vm9_clock_model_replay_20261001.json).

The second captured URL then closed a separate constructor-input mistake in
the diagnostic runner. Native constructor `0x12508344` uses nonzero `x1` as a
string pointer, calling the length helper at `0x12607f40`, allocating through
`0x12607fd0`, and copying through `0x12607f60`. The previous replay supplied
`0x1296ba90`, which is an allocator dynamic-area address. Replaying with the
same-capture static pointer `0x1232fe64` removed the old trace-13 divergence
and completed Seg2 at `90385/90385` events with 121 native callbacks.

The resulting checkpoint matched the captured `NEXT#2` page set except for
153 bytes in two synthetic stack pages. Seg3 still failed when started with
no handoff, at callback 9; loading the captured `NEXT#2/vm9_m0.bin` state let
the same checkpoint complete Seg3 at `1057/1057` events and 87 callbacks,
without a clock-slot override or callback-page injection. This narrows the
remaining dependency to the host/native handoff boundary for this sample, but
it is still trace-assisted evidence. It does not establish a fresh-input
pure-Python current-Medusa signer or enable the no-JVM Rust implementation.
See [evidence/vm9_static_constructor_x1_20261001.json](evidence/vm9_static_constructor_x1_20261001.json).

The `90385/90385` result is reproducible only with its paired Seg1 checkpoint
and `NEXT#1` handoff. A later continuation experiment that returned callback
`0x12548a4c` through the native dispatcher and copied all register backing
slots into the Python VM produced `R2=0` at the first boundary; the trace
expects `0x122a0d00`. That experiment is refuted as a register model. The
stable replay completes without it, and the boundary slot `e4ffc9a0` must be
treated as native/host state. See
[evidence/vm9_dispatcher_slot_refutation_20261001.json](evidence/vm9_dispatcher_slot_refutation_20261001.json).

The opcode assumption that caused the second-input failure is now closed. The
handler at `+0x16e8f0` is OP29/sub34, a signed `BLEZ` branch. For an encoded
instruction, the source register is selected from the high and low register
fields, the branch immediate is assembled from the five VM bit fields, and the
next BCP is `BCP + 4 + imm*4` only when the signed source value is non-positive.
There is no instruction-specific fixed jump. In the second independent capture,
`0x1800811d` decoded to source `R2` and immediate `208`; native execution moved
BCP from `0x123ceadc` to `0x123cee20`, exactly matching
`0x123ceadc + 4 + 208*4`.

The clean paired recheck reached `90385/90385` Seg2 events and 121 callbacks,
then `1057/1057` Seg3 events and 87 callbacks, with `NEXT#1`/`NEXT#2` handoffs
and no callback-page injection, allocator-field transplant, clock-slot override,
or dispatcher backing-slot injection. This is strong evidence that OP29 is now
generic across the two captured inputs. It remains trace-assisted: the replay
still consumes captured host handoffs and native ARM64 images, so current
pure-Python Medusa parameterization and the no-JVM Rust signer remain open. The
sanitized details are in
[evidence/vm9_op29_generic_20261001.json](evidence/vm9_op29_generic_20261001.json).

The bridge-level parameter and time checks are now separated from that open proof. Repeating the same URL, frozen timestamp, and emulated PID produced the same Medusa digest. Changing the URL, timestamp, or emulated PID changed the Medusa digest or branch length, so those values are real bridge inputs rather than ignored placeholders. Five frozen timestamp trials signed successfully and returned HTTP 200 from the detail endpoint. This closes the timestamp-freeze question for the Java/Unidbg bridge; it does not make the current VM a pure-Python signer. The sanitized matrix is in [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json).

The local bridge performance sweep measured 23.165 seconds before the current optimization and 10.546 seconds after it for the same input, with the same Medusa digest. This is a bridge runtime result only. It does not change the no-JVM capability boundary.

## Captured handoff reduction

The paired second-input VM9 replay was reduced without mixing capture files. The
Seg1 checkpoint to `NEXT#1` comparison contains 14 changed pages but only 560
changed bytes. Applying those deltas, and removing the stale synthetic
`0xe4ffcaa0=0x122a0c20` write from the diagnostic runner, completes Seg2 at
`90385/90385` events and 121 callbacks without loading the full `NEXT#1` image.

For the following boundary, the paired Seg2 checkpoint differs from `NEXT#2` on
four pages. Seg3 nevertheless completes with one four-byte patch at
`0x12641b28` (`0x1d` to `0x1250c59c`) and no other `NEXT#2` pages. The result is
`1057/1057` events, 87 callbacks, and two clock syscalls with no callback-page
injection, allocator-field transplant, or clock-slot override.

This is a useful boundary proof: the full handoff images are not semantically
required for this captured request. It remains a captured-state diagnostic,
because the Seg1 checkpoint, native ARM64 images, and native callback execution
are still supplied from the capture. It does not close current pure-Python
Medusa parameterization or the no-JVM Rust implementation. See
[evidence/vm9_minimal_handoff_pair_20261001.json](evidence/vm9_minimal_handoff_pair_20261001.json).

## Six/seven gods and “16/24 gods”

“God” in the historical notes means a request header, not a VM layer. The six hard historical names are Gorgon, Ladon, Argus, Khronos, Helios, and Medusa; Neptune is an additional soft field in seven-header descriptions. Perseus is a separate VM header and is tracked independently.

The current material proves a Medusa selector of `state & 0x0f`, so there are 16 selector values in the VM dispatch space. The available old notes and samples cover only selected variants. The names `jadx_out16` and `jadx_out24` are analysis-directory names, not evidence of 16 or 24 completed algorithms. No reliable 24-variant result is claimed here.

## Evidence use

Use the paired matrix entries when arguing about a required header. A single successful request only proves that one complete request worked. The `drop_medusa` versus `drop_perseus` pairs prove that Medusa is a hard dependency for these reading endpoints while Perseus was optional in this time window. Use the registerkey key-version, `crypt_status`, decoded length, and decoded hash together to prove that the response was decrypted rather than served as a plaintext cache.
