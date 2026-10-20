# Security policy

## Scope

This repository publishes **redacted** reverse-engineering evidence: endpoint names,
parameter names, status/length/hash summaries and local trial labels.

It must never contain material that is directly reusable as authentication, or that
identifies a real device or account.

## What to report privately

Use [Security Advisory](https://github.com/Angel-Gril/Novel_Signer/security/advisories/new)
if you find any of the following **committed to the repository**:

- device identifiers, tokens, tickets, cookies or session material
- complete request headers or raw server responses
- APKs, native libraries (`.so`), keystores or signing material
- traces, dumps or raw binaries
- personal data of a third party

Do **not** open a normal issue for these — open an advisory, or contact the maintainer and
wait for redaction.

## Response time

| Stage | Target |
| --- | --- |
| Acknowledgement | 3 business days |
| Redaction / removal | as soon as confirmed |
| History rewrite (if required) | coordinated after removal |

## Repository safety rules

1. `scripts/scan_public.py` runs on every push and pull request; it must stay green.
2. `.gitignore` blocks the risky classes (`*.apk`, `*.aab`, `*.so`, `*_token*`, `*_ticket*`,
   `*.trace`, `*.dump`, `*.bin`, `*.raw`, keystores).
3. Evidence files record hashes instead of payloads.
4. Reports state the evidence label, so an unverified claim cannot silently become a product
   contract.
