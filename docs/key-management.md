# Test key management

This identity uses a local Ed25519 test key. It is not suitable for production credentials, regulated trust, or durable organizational identity.

## Storage and permissions

The generator resolves its external key directory as `${XDG_DATA_HOME:-$HOME/.local/share}/edgedm-did/keys`. The directory is mode `0700`, the private PEM is mode `0600`, and the derived public PEM may be mode `0644`. The path is outside the repository. Neither PEM is committed; only the public JWK and fingerprint are published.

Run `python3 scripts/generate_identity.py`. If no private key exists, the script creates one atomically with OpenSSL. If one exists, it is reused and validated as Ed25519. The script refuses malformed keys, unsafe permissions, unexpected SubjectPublicKeyInfo DER, or silent replacement.

## Public derivation

OpenSSL derives the SubjectPublicKeyInfo object. The generator validates the Ed25519 algorithm identifier `1.3.101.112`, the DER structure, and the 32-byte raw public key. The JWK `x` is unpadded Base64URL of those bytes. The published fingerprint is `sha256:` followed by the lowercase SHA-256 hex digest of the same raw bytes.

Use `make check-key` to compare committed public artifacts with the external private key without modifying either. The private bytes are never printed.

## Backup and recovery

If continuity of this test DID matters, keep an encrypted offline backup with access controls and a tested recovery procedure. Do not place it in Git, GitHub Secrets, shared chat, tickets, or temporary directories. A lost unbacked key cannot be reconstructed from the public JWK.

## Rotation

1. Coordinate a maintenance window and notify every relying test system.
2. Securely archive or destroy the old key according to the test policy.
3. Move the old files out of the active key directory without placing them in the repository.
4. Generate a new key and public artifacts, review the changed JWK and fingerprint, and run `make check`.
5. Deploy through a pull request and verify the live HTTPS document.

Changing the key changes the verification material associated with the existing DID. Relying systems that cache or pin it must be coordinated, and previously issued test material may stop verifying under current-document semantics.

## Compromise response and production migration

On suspected disclosure, stop using the key, avoid posting it in an Issue, rotate immediately, identify affected test assertions, and document the public incident outcome. Production use requires governed KMS/HSM custody, separation of duties, audit logging, recovery, approved algorithms and lifecycles, and formal ownership. Never migrate this test private key into production.
