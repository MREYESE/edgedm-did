# EDGE/DM test `did:web` identity

> **Warning**
> This repository publishes a test-only DID. Do not use its locally managed private key for production credentials or regulated trust decisions.

This project publishes a small, auditable `did:web` identity through GitHub Pages for dataspace interoperability testing. It is non-production, not governance-approved, not connector-onboarded, and not legally verified.

## Public identity

- DID: `did:web:mreyese.github.io:edgedm-did`
- Resolution URL: `https://mreyese.github.io/edgedm-did/did.json`
- Site: `https://mreyese.github.io/edgedm-did/`
- Verification method: `did:web:mreyese.github.io:edgedm-did#key-1`

Because the DID contains the path segment `edgedm-did`, its document is served from `/edgedm-did/did.json`. This project does not publish or advertise a root `/.well-known/did.json` document.

For compatibility testing, Pages also exposes an exact copy at `https://mreyese.github.io/edgedm-did/.well-known/did.json`. This nested copy is not the canonical resolution URL for the path-based DID and does not represent `did:web:mreyese.github.io` or `did:web:edgedm.eu`.

## Repository structure

- `site/` — the complete static Pages artifact and public identity documents.
- `scripts/` — dependency-free generation and validation tools.
- `tests/` — standard-library unit tests with synthetic public fixtures.
- `docs/` — architecture, key-management, and operations guidance.
- `.github/workflows/` — pull-request CI and default-branch Pages deployment.

## Local workflow

Requirements are Python 3 and OpenSSL. Generate or reuse the external test key and update public artifacts:

```bash
umask 077
make generate
make check
```

The generator stores private material outside the repository under `${XDG_DATA_HOME:-$HOME/.local/share}/edgedm-did/keys`. It never silently replaces an existing key. `make check-key` proves that the committed public JWK and fingerprint still derive from that external private key.

Run individual checks or preview the site:

```bash
make validate
make test
make serve
```

The preview listens at `http://127.0.0.1:8765/`. No runtime dependency, package manager, cookie, analytics, external font, or third-party library is used.

## Deployment

Pull requests run validation and tests without deploying. Changes merged to `main` trigger the Pages workflow, which validates again and uploads only `site/`. A manual workflow dispatch is also available. See [operations](docs/operations.md) for post-deployment checks and rollback.

## Security boundary

Only the Ed25519 public JWK and its SHA-256 fingerprint are public. The private key remains on the operator’s machine, outside Git, and is never stored as a GitHub Actions secret. Review [key management](docs/key-management.md) and [security policy](SECURITY.md) before operating the identity.

## Rotation and deactivation

Rotation requires creating a replacement Ed25519 key, regenerating the public artifacts, validating them, and deploying through review. The DID remains the same while its verification material changes, so relying systems must be coordinated. Deactivation is represented operationally by removing verification capabilities or the published document through a reviewed change; GitHub Pages has no DID-specific deactivation registry.

## Limitations and future production migration

This test workflow relies on a locally managed file key and repository-hosted static content. It does not provide regulated custody, governance approval, connector onboarding, legal verification, credential issuance, service discovery, or guaranteed compatibility with every resolver. A production migration should use governed ownership, documented recovery, KMS/HSM-backed custody, controlled rotation, monitoring, and explicit relying-party coordination; it should not reuse this test key.
