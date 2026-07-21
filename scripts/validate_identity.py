#!/usr/bin/env python3
"""Validate the local or deployed EDGE/DM test DID identity."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

DID = "did:web:mreyese.github.io:edgedm-did"
VM_ID = f"{DID}#key-1"
SITE_URL = "https://mreyese.github.io/edgedm-did/"
DID_DOCUMENT_URL = f"{SITE_URL}did.json"
COMPATIBILITY_DID_PATH = Path(".well-known/did.json")
COMPATIBILITY_DID_URL = f"{SITE_URL}.well-known/did.json"
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
REQUIRED_FILES = {
    ".nojekyll", "404.html", "app.js", "did.json", "identity-metadata.json",
    "index.html", "robots.txt", "styles.css",
}
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
PLACEHOLDER = re.compile(r"(?:<actual|placeholder|change[-_ ]?me|replace[-_ ]?me)", re.I)
SECRET = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{20,})")
LOCAL_PATH = re.compile(r"(?:/home/[^/\s]+/|/Users/[^/\s]+/|[A-Za-z]:\\Users\\)")
INTERNAL_ENDPOINT = re.compile(
    r"https?://(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|[^/\s]+\.(?:internal|local))(?:[/:]|$)",
    re.I,
)


class ValidationError(ValueError):
    """A deterministic identity validation failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path) -> Any:
    require(path.is_file(), f"missing required file: {path.name}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{path.name} is not valid UTF-8") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path.name} is malformed JSON: {exc}") from exc


def find_member(item: Any, name: str) -> bool:
    if isinstance(item, dict):
        return name in item or any(find_member(value, name) for value in item.values())
    if isinstance(item, list):
        return any(find_member(value, name) for value in item)
    return False


def validate_document(document: Any) -> bytes:
    require(isinstance(document, dict), "DID document root must be an object")
    require(document.get("id") == DID, "incorrect root DID")
    contexts = document.get("@context")
    require(isinstance(contexts, list) and DID_CONTEXT in contexts, "missing DID v1 context")
    methods = document.get("verificationMethod")
    require(isinstance(methods, list) and len(methods) == 1, "expected exactly one verification method")
    method = methods[0]
    require(isinstance(method, dict), "verification method must be an object")
    require(method.get("id") == VM_ID, "incorrect verification-method ID")
    require(method.get("controller") == DID, "incorrect verification-method controller")
    require(method.get("type") == "JsonWebKey2020", "incorrect verification-method type")
    jwk = method.get("publicKeyJwk")
    require(isinstance(jwk, dict), "publicKeyJwk must be an object")
    require(jwk.get("kty") == "OKP", "publicKeyJwk.kty must be OKP")
    require(jwk.get("crv") == "Ed25519", "publicKeyJwk.crv must be Ed25519")
    encoded = jwk.get("x")
    require(isinstance(encoded, str) and bool(encoded), "publicKeyJwk.x must be a non-empty string")
    require("=" not in encoded, "publicKeyJwk.x must be unpadded Base64URL")
    require(bool(BASE64URL.fullmatch(encoded)), "publicKeyJwk.x has an invalid Base64URL alphabet")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidationError("publicKeyJwk.x is not decodable Base64URL") from exc
    require(len(raw) == 32, "Ed25519 public key must decode to exactly 32 bytes")
    require(not find_member(document, "d"), "private JWK member d is forbidden")
    method_ids = {entry.get("id") for entry in methods if isinstance(entry, dict)}
    for relationship in ("authentication", "assertionMethod"):
        references = document.get(relationship)
        require(isinstance(references, list) and references, f"missing {relationship}")
        require(VM_ID in references, f"{relationship} does not reference the expected method")
        for reference in references:
            require(isinstance(reference, str) and reference in method_ids, f"broken {relationship} reference")
            require(reference.startswith("did:"), f"{relationship} contains a non-absolute DID URL")
    for value in (document["id"], method["id"], method["controller"]):
        require(isinstance(value, str) and value.startswith("did:"), "DID URLs must be absolute")
    return raw


def validate_metadata(metadata: Any, raw: bytes) -> None:
    require(isinstance(metadata, dict), "identity metadata root must be an object")
    expected = {
        "did": DID,
        "didDocumentUrl": DID_DOCUMENT_URL,
        "siteUrl": SITE_URL,
        "verificationMethod": VM_ID,
        "keyType": "Ed25519",
        "verificationMethodType": "JsonWebKey2020",
        "publicKeyFingerprintSha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "environment": "test",
        "status": "active-for-testing",
        "productionApproved": False,
        "governanceApproved": False,
        "connectorOnboarded": False,
    }
    require(metadata == expected, "metadata is malformed or does not match the DID document")


def validate_site(site_dir: Path) -> None:
    require(site_dir.is_dir(), f"site directory does not exist: {site_dir}")
    present = {path.name for path in site_dir.iterdir() if path.is_file()}
    missing = sorted(REQUIRED_FILES - present)
    require(not missing, f"missing required site file: {', '.join(missing)}")
    for path in site_dir.rglob("*"):
        require(not path.is_symlink(), f"symbolic link is forbidden under site: {path}")
        if not path.is_file():
            continue
        data = path.read_bytes()
        require(b"PRIVATE" + b" KEY-----" not in data, f"private PEM marker found in {path.name}")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError(f"{path.name} is not valid UTF-8") from exc
        if path.name != ".nojekyll":
            require(text.endswith("\n"), f"{path.name} must have a final newline")
        require(not PLACEHOLDER.search(text), f"placeholder value found in {path.name}")
        require(not SECRET.search(text), f"obvious secret or token found in {path.name}")
        require(not LOCAL_PATH.search(text), f"absolute local filesystem path found in {path.name}")
        require(not INTERNAL_ENDPOINT.search(text), f"internal endpoint found in {path.name}")
    require((site_dir / ".nojekyll").read_bytes() == b"", ".nojekyll must be empty")
    document = load_json(site_dir / "did.json")
    raw = validate_document(document)
    compatibility_path = site_dir / COMPATIBILITY_DID_PATH
    compatibility_document = load_json(compatibility_path)
    validate_document(compatibility_document)
    require(
        compatibility_path.read_bytes() == (site_dir / "did.json").read_bytes(),
        ".well-known/did.json must exactly match did.json",
    )
    metadata = load_json(site_dir / "identity-metadata.json")
    validate_metadata(metadata, raw)
    index = (site_dir / "index.html").read_text(encoding="utf-8")
    require(DID in index, "index.html does not contain the exact DID")
    require(DID_DOCUMENT_URL in index, "index.html does not contain the exact DID document URL")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname != "mreyese.github.io":
            raise ValidationError(f"refusing redirect to unexpected host: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> tuple[bytes, str, Any, int]:
    opener = urllib.request.build_opener(SafeRedirectHandler())
    request = urllib.request.Request(url, headers={"User-Agent": "edgedm-did-validator/1.0"})
    try:
        with opener.open(request, timeout=20) as response:
            return response.read(), response.geturl(), response.headers, response.status
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        raise ValidationError(f"could not fetch {url}: {exc}") from exc


def validate_remote(site_dir: Path) -> None:
    validate_site(site_dir)
    remote_did, final_did_url, did_headers, did_status = fetch(DID_DOCUMENT_URL)
    require(final_did_url == DID_DOCUMENT_URL, f"unexpected final DID URL: {final_did_url}")
    try:
        remote_document = json.loads(remote_did.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("remote DID document is not valid UTF-8 JSON") from exc
    validate_document(remote_document)
    local_did = (site_dir / "did.json").read_bytes()
    require(remote_did == local_did, "remote DID document does not exactly match the local document")
    compatibility_did, final_compatibility_url, compatibility_headers, compatibility_status = fetch(
        COMPATIBILITY_DID_URL
    )
    require(
        final_compatibility_url == COMPATIBILITY_DID_URL,
        f"unexpected final compatibility URL: {final_compatibility_url}",
    )
    require(
        compatibility_did == remote_did,
        "remote .well-known compatibility copy does not exactly match the canonical document",
    )
    page, final_site_url, page_headers, page_status = fetch(SITE_URL)
    require(final_site_url == SITE_URL, f"unexpected final site URL: {final_site_url}")
    page_text = page.decode("utf-8")
    require(DID in page_text and DID_DOCUMENT_URL in page_text, "remote page lacks expected identity content")
    print(f"Remote DID URL: {final_did_url}; redirects: none")
    print(f"Remote DID: HTTP {did_status}; Content-Type: {did_headers.get('Content-Type', '(absent)')}")
    print(f"Remote DID CORS: {did_headers.get('Access-Control-Allow-Origin', '(absent)')}")
    print(
        f"Remote compatibility copy: HTTP {compatibility_status}; "
        f"Content-Type: {compatibility_headers.get('Content-Type', '(absent)')}"
    )
    print(f"Remote site URL: {final_site_url}; redirects: none")
    print(f"Remote page: HTTP {page_status}; Content-Type: {page_headers.get('Content-Type', '(absent)')}")
    print("Remote DID document exactly matches the committed local document.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-dir", default="site", type=Path)
    parser.add_argument("--remote", action="store_true")
    args = parser.parse_args()
    try:
        if args.remote:
            validate_remote(args.site_dir)
        else:
            validate_site(args.site_dir)
            print(f"Validated deployable identity site: {args.site_dir}")
        return 0
    except (ValidationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
