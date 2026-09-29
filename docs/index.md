# Novel Signer research

This site is the reviewable index for the platform-separated reports.

## Findings

| Platform | Evidence level | Current result |
| --- | --- | --- |
| Tomato / ByteDance | Live chain verified; current Medusa parameterization incomplete | `device_register → registerkey → directory → reader/full → AES-CBC` succeeds with the Java/Unidbg bridge. |
| Douyin / ByteDance | Static/community analysis | Four-god algorithms are documented; Helios/Medusa for 23.3.0+ were not independently verified here. |
| Qidian | No usable sample in this workspace | No claim is made about Qidian endpoints or signatures. |

Open the [full platform reports](../platforms/), the [sanitized evidence index](../platforms/bytedance/tomato/EVIDENCE_INDEX.json), and the [Rust integration status](../platforms/bytedance/tomato/rust/README.md).
