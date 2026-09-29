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

The current signer produced both of these raw sizes under frozen timestamps:

- 228 bytes (304 base64 characters);
- 803–804 bytes (1,072 base64 characters).

Both branch families were accepted by the tested detail/directory/reader endpoints when their timestamp and `_rticket` were fresh. Some adjacent frozen millisecond values crash the local Unidbg harness before an HTTP request is sent; a 200-second grid was stable in the recorded sweep. This is a local VM execution issue, not evidence of server rejection.

The current bridge matrix also confirms that the URL, frozen timestamp, and emulated PID affect the Medusa result, while repeating the same triple is deterministic. Five frozen timestamp trials reached the detail endpoint with HTTP 200. These observations describe the bridge's input surface; they do not replace the independent no-JVM implementation proof.

## VM selector count

The Medusa material contains a selector equivalent to `state & 0x0f`. That is direct evidence for 16 selector values in the VM dispatch space. It does not mean that all 16 have been independently reconstructed. There is no independent 24-variant result in the available material. Directory names such as `jadx_out16` or `jadx_out24` are not algorithm evidence.

## Independent-proof boundary

The old pure-Python body interpreter is a 225-byte snapshot implementation. The current VM9 body is currently a Java/Unidbg bridge plus trace-assisted replay. The Rust crate therefore exposes an explicit unavailable error for a current no-JVM Medusa signer instead of emitting a guessed header.
