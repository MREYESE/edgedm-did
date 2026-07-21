#!/usr/bin/env python3
"""Safely generate public artifacts for the EDGE/DM test DID."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

DID = "did:web:mreyese.github.io:edgedm-did"
VM_ID = f"{DID}#key-1"
SITE_URL = "https://mreyese.github.io/edgedm-did/"
DID_DOCUMENT_URL = f"{SITE_URL}did.json"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class IdentityError(RuntimeError):
    """Raised for safe, user-facing identity generation failures."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def key_paths() -> tuple[Path, Path, Path]:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    key_dir = base / "edgedm-did" / "keys"
    return key_dir, key_dir / "ed25519-private.pem", key_dir / "ed25519-public.pem"


def run_openssl(arguments: list[str]) -> bytes:
    executable = shutil.which("openssl")
    if not executable:
        raise IdentityError("OpenSSL is unavailable; install it before managing the identity")
    try:
        result = subprocess.run(
            [executable, *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.decode("utf-8", errors="replace").strip()
        raise IdentityError(f"OpenSSL could not process the Ed25519 key: {message}") from exc
    return result.stdout


def raw_public_key(private_key: Path) -> bytes:
    if not private_key.is_file():
        raise IdentityError(f"Private key does not exist: {private_key}")
    der = run_openssl(["pkey", "-in", str(private_key), "-pubout", "-outform", "DER"])
    expected_length = len(ED25519_SPKI_PREFIX) + 32
    if len(der) != expected_length or not der.startswith(ED25519_SPKI_PREFIX):
        raise IdentityError(
            "Private key is not Ed25519 or its SubjectPublicKeyInfo DER structure is unexpected"
        )
    raw = der[len(ED25519_SPKI_PREFIX) :]
    if len(raw) != 32:
        raise IdentityError("Derived Ed25519 public key is not exactly 32 bytes")
    return raw


def ensure_external_location(root: Path, key_dir: Path) -> None:
    try:
        key_dir.resolve().relative_to(root.resolve())
    except ValueError:
        return
    raise IdentityError("Refusing to store private key material inside the repository")


def create_private_key(key_dir: Path, private_key: Path) -> None:
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)
    if private_key.exists():
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ed25519-private-", dir=key_dir)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        run_openssl(["genpkey", "-algorithm", "Ed25519", "-out", str(temporary)])
        if private_key.exists():
            raise IdentityError("Private key appeared during generation; refusing to replace it")
        os.replace(temporary, private_key)
        os.chmod(private_key, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def ensure_private_permissions(private_key: Path) -> None:
    mode = stat.S_IMODE(private_key.stat().st_mode)
    if mode != 0o600:
        raise IdentityError(f"Private key permissions must be 0600, found {mode:04o}")


def write_public_pem(private_key: Path, public_key: Path) -> None:
    pem = run_openssl(["pkey", "-in", str(private_key), "-pubout"])
    atomic_write(public_key, pem, mode=0o644, reject_private=True)


def contains_private_material(data: bytes) -> bool:
    marker = b"PRIVATE" + b" KEY-----"
    if marker in data:
        return True
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False

    def has_private_d(item: Any) -> bool:
        if isinstance(item, dict):
            return "d" in item or any(has_private_d(child) for child in item.values())
        if isinstance(item, list):
            return any(has_private_d(child) for child in item)
        return False

    return has_private_d(value)


def atomic_write(path: Path, data: bytes, *, mode: int = 0o644, reject_private: bool = False) -> None:
    if reject_private and contains_private_material(data):
        raise IdentityError(f"Refusing to write private material to {path}")
    if path.exists() and reject_private and contains_private_material(path.read_bytes()):
        raise IdentityError(f"Refusing to replace target containing private material: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == data:
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except OSError as exc:
        raise IdentityError(f"Could not atomically write {path}: {exc}") from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def public_values(raw: bytes) -> tuple[str, str]:
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    fingerprint = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    return encoded, fingerprint


def documents(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    encoded, fingerprint = public_values(raw)
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": DID,
        "verificationMethod": [
            {
                "id": VM_ID,
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": encoded},
            }
        ],
        "authentication": [VM_ID],
        "assertionMethod": [VM_ID],
    }
    metadata = {
        "did": DID,
        "didDocumentUrl": DID_DOCUMENT_URL,
        "siteUrl": SITE_URL,
        "verificationMethod": VM_ID,
        "keyType": "Ed25519",
        "verificationMethodType": "JsonWebKey2020",
        "publicKeyFingerprintSha256": fingerprint,
        "environment": "test",
        "status": "active-for-testing",
        "productionApproved": False,
        "governanceApproved": False,
        "connectorOnboarded": False,
    }
    return did_document, metadata


def stable_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def check_committed(root: Path, raw: bytes) -> None:
    did_path = root / "site" / "did.json"
    metadata_path = root / "site" / "identity-metadata.json"
    expected_did, expected_metadata = documents(raw)
    try:
        actual_did = json.loads(did_path.read_text(encoding="utf-8"))
        actual_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityError(f"Could not read committed public identity artifacts: {exc}") from exc
    if actual_did != expected_did:
        raise IdentityError("site/did.json does not match the external Ed25519 private key")
    if actual_metadata != expected_metadata:
        raise IdentityError("site/identity-metadata.json does not match the external key and DID")


def show_summary(raw: bytes, private_key: Path) -> None:
    encoded, fingerprint = public_values(raw)
    print(f"DID: {DID}")
    print(f"Verification method: {VM_ID}")
    print("Public key type: Ed25519")
    print(f"Public key SHA-256 fingerprint: {fingerprint}")
    print(f"Public key Base64URL: {encoded}")
    print(f"Site URL: {SITE_URL}")
    print(f"DID document URL: {DID_DOCUMENT_URL}")
    print(f"Private key path: {private_key}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check public artifacts without changes")
    mode.add_argument("--show-public-summary", action="store_true", help="show public identity details")
    args = parser.parse_args()
    root = repository_root()
    key_dir, private_key, public_key = key_paths()
    ensure_external_location(root, key_dir)
    try:
        if not args.check and not args.show_public_summary:
            create_private_key(key_dir, private_key)
        if not private_key.exists():
            raise IdentityError(f"Private key does not exist: {private_key}")
        ensure_private_permissions(private_key)
        raw = raw_public_key(private_key)
        if args.check:
            check_committed(root, raw)
        elif args.show_public_summary:
            show_summary(raw, private_key)
        else:
            write_public_pem(private_key, public_key)
            did_document, metadata = documents(raw)
            atomic_write(root / "site" / "did.json", stable_json(did_document), reject_private=True)
            atomic_write(
                root / "site" / "identity-metadata.json",
                stable_json(metadata),
                reject_private=True,
            )
            print("Generated public DID artifacts from the external Ed25519 key.")
        return 0
    except IdentityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
