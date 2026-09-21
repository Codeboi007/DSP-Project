"""The secure message package - what the sender hands to the receiver.

A package is plain JSON so it can travel over email or chat. It carries
everything needed to decrypt *except* the secret itself: ciphertext, salt, IV,
and the metadata describing how the key was derived.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

FORMAT = "pico-package"
VERSION = 1

# Fields that must never appear in a package. Checked on build so a bug can
# never leak key material into a file the user is about to send.
FORBIDDEN = {"key", "key_b64", "password", "secret", "passphrase", "private_pem"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build(*, algorithm: str, ciphertext: str, sender: str = "", recipient: str = "",
          params: dict | None = None, kdf: dict | None = None,
          note: str = "", signature: dict | None = None) -> dict:
    """Assemble a package dict."""
    package = {
        "format": FORMAT,
        "version": VERSION,
        "algorithm": algorithm,
        "created": _now(),
        "sender": sender or "anonymous",
        "recipient": recipient or "anyone with the secret",
        "ciphertext": ciphertext,
        "params": params or {},
        "kdf": kdf or {},
        "note": note,
    }
    if signature:
        package["signature"] = signature
    _assert_clean(package)
    package["checksum"] = checksum(package)
    return package


def _assert_clean(package: dict) -> None:
    """Refuse to build a package that contains key material."""
    def walk(node, path="") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in FORBIDDEN:
                    raise ValueError(
                        "Refusing to build a package containing '" + path + key +
                        "' - key material must never leave the sender's machine."
                    )
                walk(value, path + key + ".")
        elif isinstance(node, list):
            for item in node:
                walk(item, path)
    walk(package)


def checksum(package: dict) -> str:
    """SHA-256 over the package with the checksum field removed."""
    body = {k: v for k, v in package.items() if k != "checksum"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]


def verify_checksum(package: dict) -> bool:
    stored = package.get("checksum")
    return bool(stored) and stored == checksum(package)


def to_json(package: dict, indent: int = 2) -> str:
    return json.dumps(package, indent=indent, sort_keys=False)


def parse(text: str | dict) -> dict:
    """Load and validate a package from JSON text or a dict."""
    if isinstance(text, dict):
        package = text
    else:
        try:
            package = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("This is not valid JSON: " + str(exc.msg)) from exc

    if not isinstance(package, dict):
        raise ValueError("A package must be a JSON object.")
    if package.get("format") != FORMAT:
        raise ValueError("Missing the 'pico-package' marker - is this a PICO package?")
    if package.get("version", 0) > VERSION:
        raise ValueError(
            "This package was made by a newer version of PICO (v" +
            str(package.get("version")) + ")."
        )
    for field in ("algorithm", "ciphertext"):
        if not package.get(field):
            raise ValueError("The package is missing its '" + field + "' field.")
    return package


def describe(package: dict) -> dict:
    """A human-readable summary shown to the receiver before they decrypt."""
    algorithm = package.get("algorithm", "?")
    params = package.get("params", {}) or {}
    kdf = package.get("kdf", {}) or {}

    needs = []
    if kdf.get("kdf"):
        kind = kdf.get("kind", "password")
        needs.append("the shared " + kind + " used by the sender")
    if algorithm.startswith("rsa"):
        needs.append("the matching RSA private key")
    if algorithm in ("caesar", "vigenere", "playfair"):
        needs.append("the " + algorithm + " key")
    if not needs:
        needs.append("the key used to encrypt")

    return {
        "algorithm": algorithm,
        "created": package.get("created", "unknown"),
        "sender": package.get("sender", "anonymous"),
        "recipient": package.get("recipient", "unspecified"),
        "note": package.get("note", ""),
        "ciphertext_chars": len(package.get("ciphertext", "")),
        "has_salt": bool(kdf.get("salt")),
        "has_iv": bool(params.get("iv")),
        "authenticated": bool(params.get("tag")),
        "signed": bool(package.get("signature")),
        "checksum_ok": verify_checksum(package),
        "you_need": needs,
        "carries": sorted(
            [k for k in ("ciphertext",) ] +
            (["salt"] if kdf.get("salt") else []) +
            (["iv"] if params.get("iv") else []) +
            (["tag"] if params.get("tag") else []) +
            (["wrapped_key"] if params.get("wrapped_key") else [])
        ),
        "never_carries": ["the password", "the derived key", "any private key"],
    }
