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

Latest constructor work restores the 136/320-byte prefixes, cold TLS/key and
destructor registration, and the single-mutex scoped writer path with fresh
native differences and same-run checks. Configuration-tree population and
complete 136/88-byte initialization remain open; see
[SIGNER_CONSTRUCTION.md](SIGNER_CONSTRUCTION.md).
