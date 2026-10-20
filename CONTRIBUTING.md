# Contributing

## Before you start

This repository is an **evidence archive**. A change is valuable when it either:

- adds a reproducible check with an explicit evidence label, or
- corrects an over-claim (downgrades a label, documents a failing control, narrows a boundary).

New claims without controls, captures or a linked report will not be merged.

## Evidence labels (required)

Every report or README claim must carry exactly one label:

| Label | Use when |
| --- | --- |
| `Live verified` | a fresh request was accepted by the server and the response was measured |
| `Sample verified` | a captured input/output or trace was reproduced, but not independent for the current online version |
| `Static only` | supported by decompilation or public source, with no live acceptance result |

An HTTP 200 with an empty body is **not** a success. Record it as a failed application result.

## Public-data rules

`scripts/scan_public.py` runs in CI and must pass. Do not commit:

- device identifiers, `*_device.json`, `*_token*`, `*_ticket*`
- complete request headers, raw responses, cookies or session material
- APK / AAB / `.so` / native libraries
- keystores, `.p12`, `.jks`
- traces, dumps, raw binaries

Evidence files may contain endpoint names, parameter names, status/length/hash summaries and
local trial labels. Hashes identify a trial output; they must not be reusable authentication
material.

## Local checks

```bash
python scripts/check_python.py
python scripts/scan_public.py
cargo test --manifest-path platforms/bytedance/tomato/rust/Cargo.toml --locked
```

All three run in CI (`verify` workflow). Pull requests that fail them will not be merged.

## Layout rules

- Keep platforms separate: `platforms/bytedance/tomato`, `platforms/bytedance/douyin`,
  `platforms/qidian`. Do not mix parameters or algorithms across platforms.
- Do not move `platforms/**` or `scripts/**`: CI `working-directory` and the README links
  depend on those paths.
- New long-form research entries go to `docs/RESEARCH_LOG.md`; the README stays a landing page.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat(tomato): add reader AST callback parity for section 9
fix(douyin): correct claim label on signing inventory
docs: move checkpoint log out of README
chore(ci): upload build-rust artifacts
```

## Pull requests

1. One topic per PR.
2. State the evidence label in the description.
3. Attach the command output that supports the claim.
4. Update `docs/RESEARCH_LOG.md` when adding a new checkpoint.
