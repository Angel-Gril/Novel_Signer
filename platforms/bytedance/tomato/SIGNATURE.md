# Tomato signature report

## Header inventory

| Header | Finding in the current reading matrix | Confidence |
| --- | --- | --- |
| `X-Khronos` | retain; timestamp window input | live paired matrix |
| `X-Helios` | required | live paired matrix + vector checks |
| `X-Medusa` | required | live paired matrix + current bridge |
| `X-Gorgon` | removable from these reading requests | live paired matrix |
| `X-Ladon` | removable from these reading requests | live paired matrix |
| `X-Argus` | removable from these reading requests | live paired matrix |
| `X-Perseus` | removable in the tested time window; keep as an optional future risk-control field | live paired matrix |
| `X-Neptune` | not a hard dependency in the open bridge path | static/open-source behavior |

## Current Medusa branches

Historical bridge captures produced both of these raw sizes under frozen timestamps:

- 228 bytes (304 base64 characters);
- 801–804 bytes (1,068–1,072 base64 characters).

Both captured families were accepted by the tested detail/directory/reader endpoints when their timestamp and `_rticket` were fresh. The old bridge accidentally passed that timestamp to `MSC.GetABSwitch()` as well. Its adjacent-time failures and observed 200-second grid are misconfigured bridge controls, not native time constraints or server rejection.

The 802-byte size was added by the 2026-10-01 diagnostic capture. That new
sample was not submitted to the server; the earlier accepted long samples were
803–804 bytes. Captured branch sizes and live acceptance are separate evidence.

Fresh 2026-10-03 detail requests separately accepted 801-byte and 802-byte
Medusa samples with code 0. Their response metrics and hashes are in
`evidence/vm9_handle_initialization_20261003.json`; the original 2026-10-01
sample retains its untested status.

The new same-URL controls locate the local crash after missing signer-handle
publication and the old app-manager fallback. The bridge still fails explicitly
when no signer is published. The A/B correction restores APK default `2`
independently of clocks; former +999/+1000 ms and old failing inputs now
succeed. Corrected controls produce 800–802-byte Medusa, and an unrounded
fresh 802-byte detail sample is accepted. See `BRIDGE_INITIALIZATION.md`.

The measured fresh bridge also emits short native forms: four decoded bytes
for Argus (equal to the Khronos seconds as u32 little-endian), and four for
Ladon. Their presence does not prove the separate long-form algorithms are
validated by current search. Reading-header removability remains scoped to
the paired reading matrix.

Historical accepted requests remain transport evidence, but their A/B input was coupled to the timestamp. New controls keep A/B at `2` while varying time, and a repeated URL/time/PID/A-B tuple produces the same digest. These describe the bridge input surface and do not replace independent no-JVM implementation proof.

## VM selector count

The Medusa material contains a selector equivalent to `state & 0x0f`. That is direct evidence for 16 selector values in the VM dispatch space. It does not mean that all 16 have been independently reconstructed. There is no independent 24-variant result in the available material. Directory names such as `jadx_out16` or `jadx_out24` are not algorithm evidence.

## Independent-proof boundary

The old pure-Python body interpreter is a 225-byte snapshot implementation. The current VM9 body is currently a Java/Unidbg bridge plus trace-assisted replay. The Rust crate therefore exposes an explicit unavailable error for a current no-JVM Medusa signer instead of emitting a guessed header.
