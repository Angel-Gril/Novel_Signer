## What changed

<!-- One or two sentences: what does this PR do and why -->

## Evidence label (required for research claims)

- [ ] Live verified
- [ ] Sample verified
- [ ] Static only
- [ ] Not applicable (scripts / docs / CI only)

## Type

- [ ] New reproducible result (`feat`)
- [ ] Correction of a claim or its evidence label (`fix`)
- [ ] Scripts / CI (`chore`)
- [ ] Documentation (`docs`)

## Scope

- [ ] `platforms/bytedance/tomato`
- [ ] `platforms/bytedance/douyin`
- [ ] `platforms/qidian`
- [ ] `scripts/`
- [ ] `.github/`
- [ ] `docs/`

## Verification

```text
(paste the output of check_python.py / scan_public.py / cargo test)
```

- [ ] `python scripts/check_python.py` passes
- [ ] `python scripts/scan_public.py` passes
- [ ] `cargo test --locked` passes (when Rust changed)
- [ ] New evidence contains no device identifiers, tokens, raw responses, APKs or native libraries
- [ ] Checkpoint recorded in `docs/RESEARCH_LOG.md` (when applicable)

## Checklist

- [ ] One topic per PR
- [ ] `platforms/**` and `scripts/**` were not moved (CI paths depend on them)
- [ ] The "still incomplete" boundary is stated explicitly
