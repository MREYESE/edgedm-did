# Deployment record

> This record covers a test-only identity. It is non-production, not governance-approved, not connector-onboarded, and not legally verified.

## Deployment

- Implementation Issue: [#1 — Deploy the EDGE/DM test did:web identity](https://github.com/MREYESE/edgedm-did/issues/1)
- Merged pull request: [#2 — feat: publish EDGE/DM test did:web identity](https://github.com/MREYESE/edgedm-did/pull/2)
- Merge commit: [`ae8478358f426a42d5b44fe195938a3b745f06a3`](https://github.com/MREYESE/edgedm-did/commit/ae8478358f426a42d5b44fe195938a3b745f06a3)
- Pages workflow: [run 29814572648](https://github.com/MREYESE/edgedm-did/actions/runs/29814572648)
- Deployment status: successful
- Live validation date: `2026-07-21T08:32:14Z`

## Public identity

- DID: `did:web:mreyese.github.io:edgedm-did`
- Site: `https://mreyese.github.io/edgedm-did/`
- DID document: `https://mreyese.github.io/edgedm-did/did.json`
- Verification method: `did:web:mreyese.github.io:edgedm-did#key-1`
- Public-key type: `Ed25519` / `JsonWebKey2020`
- Public-key fingerprint: `sha256:0917373f24ab5cc0b452262a817dc07dee2b47bdae0cd46c603cd4cfe3d04df1`

## Validation record

The implementation passed `make validate`, 21 unit tests via `make test`, external-key consistency via `make check`, Python compilation, Git diff checks, generator idempotence, deployable-file security scans, and local HTTP fetches. GitHub Actions CI and the Pages validate/deploy jobs passed.

Post-deployment validation fetched the page and DID document over HTTPS with HTTP 200, observed no redirects, validated the remote DID semantics, confirmed `application/json; charset=utf-8`, and compared the remote document byte-for-byte with `site/did.json`.
