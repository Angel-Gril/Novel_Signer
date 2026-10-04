# Tomato / Fanqie (ByteDance)

This directory is limited to the `com.dragon.read` / Tomato material. Douyin and Qidian are documented in their own directories.

Read in this order:

1. [REPORT.md](REPORT.md) — algorithm and confidence summary;
2. [API_CALLS.md](API_CALLS.md) — the request chain and response evidence;
3. [SIGNATURE.md](SIGNATURE.md) — header dependencies, six/seven-god terminology, and the 16-selector result;
4. [SEARCH.md](SEARCH.md) — static search model and the still-empty live responses;
5. [COMPLETE_ANALYSIS_AND_USAGE.md](COMPLETE_ANALYSIS_AND_USAGE.md) — consolidated status, interface/analysis/usage guide, evidence rules, and product boundary;
6. [VM9_PROGRESS.md](VM9_PROGRESS.md) — the current independent-execution checkpoint and blocker;
7. [ALLOCATOR_AUDIT.md](ALLOCATOR_AUDIT.md) — callback-8 allocator/refill evidence;
8. [ALLOCATOR_LIFECYCLE.md](ALLOCATOR_LIFECYCLE.md) — empty bins, real mapped-slab initialization, cleanup and same-capture validation;
9. [RUNTIME_INITIALIZATION.md](RUNTIME_INITIALIZATION.md) — generated TLS/TSD/arena/cache and input-driven constructor evidence;
10. [SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md) — default A/B constructor graph, callback pair binding, JNI cleanup, and fresh-memory evidence;
11. [rust/README.md](rust/README.md) — what the no-JVM Rust crate can and cannot do today.

The Python folder contains the verified primitives and the old Medusa snapshot interpreter. It is labelled carefully because a successful old snapshot replay is not proof of current online compatibility.

Latest constructor work restores configuration-tree lookup/insertion,
the complete 136/320-byte constructor bodies and both lazy getters.
Fresh differences and same-run checks include cold TLS/key/destructor
registration, scoped writer cleanup and observable stack padding. Guard/OS
boundaries remain explicit; the complete Python prelude and 88-byte
initialization are still open. See
[SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md).

The configuration cipher work now restores the mode-0 decrypt callback and
advances parser to step 725, with fresh component and same-run cold-state
differences. Read [CIPHER_CALLBACK.md](CIPHER_CALLBACK.md) for the memory ABI,
reproduction commands and evidence limits. Complete Python startup, Rust
current-interface signing and a usable search/download webpage remain open.

The separate stream/reference path is also restored and verified. Read
[STREAM_REFERENCE.md](STREAM_REFERENCE.md) for RC4 state, X5 call convention,
reference ownership and the next fill/resize boundary.


The bounded root factory/caller now runs from fresh ELF/TLS/reference inputs
without a native entry prelude. Eight controls compare all32 terminal slots,
heap, main image, TLS/generation and ordered effects; full factory counts are
206/93. Read [ROOT_INITIALIZATION.md](ROOT_INITIALIZATION.md) for the exact
input and allocator/OS boundary. Complete current Medusa and the final
search/download product remain open.
