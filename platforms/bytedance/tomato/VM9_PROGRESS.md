# Current VM9 progress checkpoint

This file records the current state of the independent VM9 work. It is a
checkpoint, not a completion claim.

## Reproduced diagnostic path

The historical `seg3_verified_final_20260929.txt` path can be reproduced with
the captured `event0_cb66_vm9_*` memory image and the real callback pages for
callbacks 9, 64, and 66. The fresh replay reached:

```text
SUMMARY events=1057/1057 callbacks=87 syscalls=3
```

This proves that the VM bytecode trace, the selected native callback execution,
and the recorded page injections are internally consistent for that captured
sample. It remains trace-assisted because the callback pages and native ARM64
execution are supplied externally.

## Current checkpoint mismatch

The newer `mem_after_seg2_full_diag_20260929.pkl` checkpoint does not reproduce
that path. It diverges at trace 758 after callback 8:

| Path | callback 8 allocator result | callback 8 writes |
| --- | ---: | ---: |
| reproduced historical path | `0x1296b940` | 80 |
| new full-Seg2 checkpoint | `0x1296ba60` | 33 |

The native callback therefore selects a different allocator/free-list branch.
The divergence is before callback 9's real-page injection and is not fixed by
adding Perseus, changing the timestamp, or replaying the same callback pages.

The follow-up allocator audit narrowed the branch further. For callback 8 the
requested size maps to size class `3` and bin `0x12282060`. The historical
checkpoint has count `0` and returns `0x1296b940` through the refill path; the
new checkpoint has count `4` and returns `0x1296ba60` from free-list index `2`.
Forcing only the count to zero, or copying the complete `0x12282000` bin page,
still returned `0x1296b9a0`. Native disassembly and a controlled transplant
then isolated the missing state to the slab counter `[0x1294110c]` and bitmap
word `[0x12941128]`; with those two fields plus the count corrected, callback 8
returned `0x1296b940`.

## Seg1 entry-base and native-frame corrections

The first independent Seg1 runner used the nested-frame jump-base field that
belongs to the later segments. That made the first apparent branch at trace
120 look like a VM or allocator mismatch. Re-running with the actual Seg1
entry base `0x1235a6f0` removed that false divergence. A second mismatch was
then isolated to the native callback context: the diagnostic runner still used
Seg2's `SP=0xe4ffbd70` and `X29=0xe4ffbe90` for Seg1, while the captured Seg1
frame has `SP=0xe4ffb320` and `X29=0xe4ffb440`. With the wrong frame, callback
19 overwrote its argument area and callback 20 reached libc's explicit
`Invalid address 0xe4ffb848 passed to free` abort. Returning zero from
`exit_group` in the early syscall probe had hidden that abort and produced an
irrelevant unmapped read and `accept4` loop.

With the Seg1 frame corrected, the real ARM64 callback runner completed the
captured Seg1 trace: `4592/4592` VM events, 85 callbacks, and one `madvise`
syscall. No callback-page injection was needed for this Seg1 run. The resulting
checkpoint advanced into Seg2 and matched its first 10 native callbacks. The
sanitized diagnostic record is
[evidence/vm9_seg1_frame_probe_20260930.json](evidence/vm9_seg1_frame_probe_20260930.json).

An earlier continuation reached callback 45 and appeared to diverge at VM
trace `12085` (`[0xe4ffcd00]` was `0x2f8` while the older checkpoint expected
`0x2f6`). Pairing the trace with its same-capture memory files showed that this
was a mixed-capture artifact: the paired trace also expects `0x2f8`. The old
`0x2f6` value came from a different capture/checkpoint and must not be copied
into the corrected run.

This is a diagnostic correction, not a completion claim. The runner still
executes captured ARM64 native code against captured memory, and its Seg1
`X22` frame value is inferred from the frame offset rather than directly
observed. The next independent proof must carry the corrected state through
Seg2 and Seg3 without captured-field transplants, then repeat with a fresh
input before treating it as a parameterized signer.

Applying that fixed checkpoint transplant at callback 8 allowed the full
captured Seg2 replay to complete at `90161/90161` events with `121` callbacks.
This closes the captured branch diagnostic, not the independent parameterization
requirement. See [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).

## Same-run full handoff capture (2026-09-30)

A fresh Unidbg capture was taken with a frozen clock and deterministic emulated
random source. Seg1 was replayed from that capture at `4592/4592` events and
85 callbacks. Full memory snapshots taken at the real host transitions were
then supplied to the offline runner:

- Seg2 reached `90153/90153` events and 121 callbacks from the real `NEXT#1`
  handoff, with no callback-page injection or allocator-field transplant.
- Seg3 reached 1,028 of 1,057 events and callback 86 from the real `NEXT#2`
  handoff. It stopped at the clock-dependent callback boundary; the current
  syscall model does not yet reproduce the VM state that follows that native
  clock wrapper.

This is stronger evidence about the segment and host handoff boundaries, but it
still consumes captured full-memory handoffs from one run. It is therefore a
trace-assisted diagnostic and not a fresh-input, pure-Python Medusa proof. The
sanitized record is
[evidence/vm9_handoff_probe_20260930.json](evidence/vm9_handoff_probe_20260930.json).

## Meaning for the deliverables

- Seg2 has complete diagnostic runs (`90161/90161` with the historical branch
  transplant and `90153/90153` from a fresh same-run host handoff), but it is
  not an independent pure-Python parameterization.
- Seg3 now reaches the clock boundary at callback 86 for a fresh same-run
  handoff, while the older page-assisted replay remains complete only for its
  captured sample. Neither is a general current-version signer.
- The old 225-byte Python Medusa implementation remains valid only for its old
  snapshot vectors.
- The no-JVM Rust crate must continue to return an explicit unavailable error
  for current Medusa until the allocator/constructor boundary is reproduced
  from fresh inputs.

## Next experiment

The next useful experiment is to model the allocator's slab acquisition and
bitmap updates from a fresh chain, then rerun Seg2 and Seg3 with a new input
vector without transplanting captured fields. A successful replay must then be
checked against a new live directory/reader matrix; matching the old captured
body alone is insufficient.
