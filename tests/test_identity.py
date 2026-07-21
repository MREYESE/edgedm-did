from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.validate_identity import (
    DID,
    DID_CONTEXT,
    DID_DOCUMENT_URL,
    SITE_URL,
    VM_ID,
    ValidationError,
    validate_site,
)


class IdentityValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.site = Path(self.temporary.name) / "site"
        self.site.mkdir()
        self.raw = bytes(range(32))
        self.document = self.valid_document()
        self.metadata = self.valid_metadata()
        self.write_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def valid_document(self) -> dict:
        encoded = base64.urlsafe_b64encode(self.raw).rstrip(b"=").decode("ascii")
        return {
            "@context": [DID_CONTEXT, "https://w3id.org/security/suites/jws-2020/v1"],
            "id": DID,
            "verificationMethod": [{
                "id": VM_ID,
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": encoded},
            }],
            "authentication": [VM_ID],
            "assertionMethod": [VM_ID],
        }

    def valid_metadata(self) -> dict:
        return {
            "did": DID,
            "didDocumentUrl": DID_DOCUMENT_URL,
            "siteUrl": SITE_URL,
            "verificationMethod": VM_ID,
            "keyType": "Ed25519",
            "verificationMethodType": "JsonWebKey2020",
            "publicKeyFingerprintSha256": f"sha256:{hashlib.sha256(self.raw).hexdigest()}",
            "environment": "test",
            "status": "active-for-testing",
            "productionApproved": False,
            "governanceApproved": False,
            "connectorOnboarded": False,
        }

    def write_fixture(self) -> None:
        files = {
            ".nojekyll": "",
            "404.html": "Not found\n",
            "app.js": "'use strict';\n",
            "did.json": json.dumps(self.document, indent=2) + "\n",
            "identity-metadata.json": json.dumps(self.metadata, indent=2) + "\n",
            "index.html": f"<html>{DID} {DID_DOCUMENT_URL}</html>\n",
            "robots.txt": "User-agent: *\nDisallow: /\n",
            "styles.css": "body { color: #111; }\n",
        }
        for name, content in files.items():
            (self.site / name).write_text(content, encoding="utf-8")

    def rewrite(self) -> None:
        (self.site / "did.json").write_text(json.dumps(self.document) + "\n", encoding="utf-8")
        (self.site / "identity-metadata.json").write_text(
            json.dumps(self.metadata) + "\n", encoding="utf-8"
        )

    def assert_invalid(self, expected: str) -> None:
        self.rewrite()
        with self.assertRaisesRegex(ValidationError, expected):
            validate_site(self.site)

    def test_valid_generated_did(self) -> None:
        validate_site(self.site)

    def test_incorrect_root_did(self) -> None:
        self.document["id"] = "did:web:example.invalid"
        self.assert_invalid("incorrect root DID")

    def test_incorrect_controller(self) -> None:
        self.document["verificationMethod"][0]["controller"] = "did:web:example.invalid"
        self.assert_invalid("incorrect verification-method controller")

    def test_incorrect_verification_method_id(self) -> None:
        self.document["verificationMethod"][0]["id"] = f"{DID}#wrong"
        self.assert_invalid("incorrect verification-method ID")

    def test_malformed_json(self) -> None:
        (self.site / "did.json").write_text("{bad json\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "malformed JSON"):
            validate_site(self.site)

    def test_missing_context(self) -> None:
        self.document["@context"] = []
        self.assert_invalid("missing DID v1 context")

    def test_padded_base64url(self) -> None:
        self.document["verificationMethod"][0]["publicKeyJwk"]["x"] += "="
        self.assert_invalid("unpadded Base64URL")

    def test_invalid_base64url_alphabet(self) -> None:
        self.document["verificationMethod"][0]["publicKeyJwk"]["x"] = "*invalid*"
        self.assert_invalid("invalid Base64URL alphabet")

    def test_public_key_shorter_than_32_bytes(self) -> None:
        value = base64.urlsafe_b64encode(bytes(31)).rstrip(b"=").decode("ascii")
        self.document["verificationMethod"][0]["publicKeyJwk"]["x"] = value
        self.assert_invalid("exactly 32 bytes")

    def test_public_key_longer_than_32_bytes(self) -> None:
        value = base64.urlsafe_b64encode(bytes(33)).rstrip(b"=").decode("ascii")
        self.document["verificationMethod"][0]["publicKeyJwk"]["x"] = value
        self.assert_invalid("exactly 32 bytes")

    def test_private_jwk_d_member(self) -> None:
        self.document["verificationMethod"][0]["publicKeyJwk"]["d"] = "forbidden"
        self.assert_invalid("private JWK member d")

    def test_missing_authentication(self) -> None:
        del self.document["authentication"]
        self.assert_invalid("missing authentication")

    def test_broken_authentication_reference(self) -> None:
        self.document["authentication"] = [f"{DID}#missing"]
        self.assert_invalid("does not reference the expected method")

    def test_missing_assertion_method(self) -> None:
        del self.document["assertionMethod"]
        self.assert_invalid("missing assertionMethod")

    def test_broken_assertion_method_reference(self) -> None:
        self.document["assertionMethod"] = [f"{DID}#missing"]
        self.assert_invalid("does not reference the expected method")

    def test_malformed_metadata(self) -> None:
        self.metadata = {"did": DID}
        self.assert_invalid("metadata is malformed")

    def test_fingerprint_mismatch(self) -> None:
        self.metadata["publicKeyFingerprintSha256"] = "sha256:" + "0" * 64
        self.assert_invalid("metadata is malformed")

    def test_placeholder_detection(self) -> None:
        (self.site / "app.js").write_text("const value = 'change" + "me';\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "placeholder"):
            validate_site(self.site)

    def test_private_pem_marker_detection(self) -> None:
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        (self.site / "app.js").write_text(marker + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "private PEM marker"):
            validate_site(self.site)

    def test_local_absolute_path_detection(self) -> None:
        local_path = "/" + "home/example/private\n"
        (self.site / "app.js").write_text(local_path, encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "absolute local filesystem path"):
            validate_site(self.site)

    def test_missing_site_file(self) -> None:
        (self.site / "robots.txt").unlink()
        with self.assertRaisesRegex(ValidationError, "missing required site file"):
            validate_site(self.site)


if __name__ == "__main__":
    unittest.main()
