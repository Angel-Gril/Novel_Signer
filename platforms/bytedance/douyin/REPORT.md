# Douyin / Aweme (ByteDance)

## Material available in this workspace

The local `douyin-algorithm` material is a public/community static implementation for `com.ss.android.ugc.aweme` 23.2.0. It documents the last four-header generation:

```text
X-Khronos, X-Gorgon, X-Argus, X-Ladon
```

The repository itself marks these four algorithms complete for 23.2.0 and marks Helios/Medusa as incomplete from 23.3.0 onward. The material includes Argus protobuf definitions, Simon/SM3 helpers, Ladon, Gorgon support code, and build files.

## Confidence boundary

No current Douyin APK, current signed request sample, live endpoint matrix, or server-accepted response was available in this workspace. The four-header code is therefore recorded as static/community evidence, not as a current online API claim. The Tomato reports remain separate because the Tomato variant changes Argus details and has a different tested server surface.

## How to continue

To promote this directory from static to live evidence, collect one exact app version, capture a request with its complete query/body/header tuple, identify the endpoint and response semantics, then run one-variable removal matrices. Store only redacted status/length/hash summaries in `EVIDENCE_INDEX.json`.
