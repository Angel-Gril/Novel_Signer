# Tomato Python material

`fq_crypto.py`, `helios_vm.py`, and `medusa_f13.py` contain the pure primitives and sample checks extracted during the analysis.

`medusa_body.py` and `medusa_body_legacy_snapshot.py` are deliberately labelled as the old 225-byte snapshot implementation. The current online VM produces different branches and is only available through the Java/Unidbg bridge in the original isolated workspace. Do not import this module into a current downloader and infer online compatibility from a local 225-byte match.

`vm_full.py` is the sanitized current-VM diagnostic interpreter used to replay
captured VM9 traces. It requires the private `libmetasec_ml_71332.so` supplied
outside this repository (`TOMATO_LIBMETASEC` may point to it) and captured
memory/trace inputs. It is not a current online signer: the constructor,
allocator, and host handoff path still depend on captured state.

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
`clock_callback` writes a supplied guest timespec and wrapper result, while
`publish_callback_descriptor` writes the two fields consumed by the active
descriptor trampoline. The packed callback-object composition and remaining
native object graph are explicit unsupported boundaries.
The module accepts trusted local checkpoint pages. See
[ALLOCATOR_LIFECYCLE.md](../ALLOCATOR_LIFECYCLE.md) for usage, 83 native
differential cases, 360 sequential operations and the same-capture chain.

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
