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
still returned `0x1296b9a0`. The refill cursor/slab/bitmap state therefore
also differs. See [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md).

## Meaning for the deliverables

- Seg2 has a complete diagnostic run (`90161/90161` events), but it is not an
  independent pure-Python parameterization.
- Seg3 has a complete trace-assisted replay for one captured sample, but it is
  not a general current-version signer.
- The old 225-byte Python Medusa implementation remains valid only for its old
  snapshot vectors.
- The no-JVM Rust crate must continue to return an explicit unavailable error
  for current Medusa until the allocator/constructor boundary is reproduced
  from fresh inputs.

## Next experiment

The next useful experiment is to model the callback-8 allocator state from the
new full-Seg2 checkpoint and rerun the full 1057-event trace with a fresh input
vector. A successful replay must then be checked against a new live
directory/reader matrix; matching the old captured body alone is insufficient.
