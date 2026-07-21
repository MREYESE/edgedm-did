# Architecture

The publication path is deliberately small:

```text
Git repository
→ GitHub Actions validation
→ Pages artifact
→ GitHub Pages HTTPS endpoint
→ did:web resolver
```

The repository is the public source of truth. CI validates syntax, DID semantics, public-key encoding, metadata consistency, and deployable-file safety. The deployment workflow repeats those checks, packages only `site/`, and publishes that artifact through GitHub Pages over HTTPS.

## Resolution mapping

The identity is path-based:

```text
did:web:mreyese.github.io:edgedm-did
→
https://mreyese.github.io/edgedm-did/did.json
```

Under the `did:web` method, the first method-specific segment is the host and subsequent colon-delimited segments become URL path segments. Consequently, `edgedm-did` is part of the URL path. The root-host form using `/.well-known/did.json` applies only when a DID has no path segment and is intentionally not used here.

The DID document exposes one `JsonWebKey2020` Ed25519 verification method for authentication and assertions. It exposes no service endpoint, key-agreement method, timestamp, or deployment metadata. Operational metadata lives separately in `identity-metadata.json`.
