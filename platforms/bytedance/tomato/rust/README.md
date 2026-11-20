# No-JVM Rust integration

This is a deliberately small, default-buildable Rust crate. It keeps verified pure-Rust pieces separate from the current VM boundary:

- `signature::legacy_headers` exposes known Gorgon/Ladon/Argus/Khronos primitives as auxiliary
  headers; they are not a current server-compatible header set;
- `crypto::build_register_content_with_iv` carries the registerkey envelope vector;
- `api::{SEARCH_TAB_PATH, SEARCH_PAGE_PATH, search_params}` records the statically recovered search model and both observed search paths;
- `status::current_medusa` returns an explicit error instead of generating a guessed current header.
- `signature::current_headers` returns the same explicit unavailable boundary for the full
  Helios + current Medusa header set.

The current online reading server still requires Helios + current Medusa. The available Java/Unidbg bridge can produce accepted current samples, but the current VM9 constructor/allocator path has not yet been independently parameterized. This crate therefore compiles on Windows without dynarmic, MinGW, a JVM, or an Android artifact while that work remains open. Enabling the empty `current-vm` feature does not change that status; it is reserved for a future reviewed implementation.

The crate is an integration boundary and evidence-preserving scaffold, not a claim that a no-JVM current downloader is already complete.
