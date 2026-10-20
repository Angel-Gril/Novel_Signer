# Changelog

Repository-structure changes are listed here. Research checkpoints are recorded separately in
[`docs/RESEARCH_LOG.md`](docs/RESEARCH_LOG.md) — that log is the authoritative record of what
was reproduced, with the exact control/negative counts.

## [Unreleased]

### Changed

- README rewritten as a landing page: platform status table, repository layout, quick start,
  evidence model and documentation index.
- The chronological checkpoint log (previously ~350 lines inside the README) moved verbatim to
  `docs/RESEARCH_LOG.md`; links and numbers are unchanged.

### Added

- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`.
- `.gitattributes` and `.editorconfig` for consistent encoding and line endings.
- Issue forms (bug report / research claim) and a pull-request template that require an
  evidence label.
- CI hardening: explicit `permissions`, `concurrency`, and artifact upload for the Rust build;
  tagged builds publish artifacts as a GitHub Release.

### Unchanged

- `platforms/**`, `scripts/**` and their CI `working-directory` paths.
- Evidence JSON files and their contents.
