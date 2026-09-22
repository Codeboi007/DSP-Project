"""Key derivation - turning a human secret into real key material.

The raw password / phrase / mobile number is never used as a key directly.
It always goes through a KDF with a random salt.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_ITERATIONS = 390_000  # OWASP guidance for PBKDF2-HMAC-SHA256
SALT_BYTES = 16
KDFS = ("pbkdf2", "scrypt", "hkdf")


def random_salt(size: int = SALT_BYTES) -> bytes:
    return os.urandom(size)


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def normalise_secret(secret: str, kind: str = "password") -> str:
    """Tidy up the personal input before it reaches the KDF.

    ``mobile`` keeps digits only, so that '+91 98765 43210' and '9876543210'
    derive the same key on both sides of a conversation.
    """
    secret = (secret or "").strip()
    if kind == "mobile":
        digits = "".join(ch for ch in secret if ch.isdigit())
        if not digits:
            raise ValueError("No digits found in the mobile number.")
        return digits[-10:] if len(digits) > 10 else digits
    if kind == "phrase":
        return " ".join(secret.split()).lower()
    return secret


def derive_key(
    secret: str,
    salt: bytes | None = None,
    *,
    length: int = 32,
    kdf: str = "pbkdf2",
    iterations: int = DEFAULT_ITERATIONS,
    kind: str = "password",
    info: bytes = b"pico-message-key",
) -> dict:
    """Derive ``length`` bytes of key material from a personal secret."""
    if kdf not in KDFS:
        raise ValueError(f"Unknown KDF '{kdf}'. Choose one of {', '.join(KDFS)}.")
    if length not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24 or 32 bytes.")

    material = normalise_secret(secret, kind)
    if not material:
        raise ValueError("The secret cannot be empty.")
    salt = salt or random_salt()
    raw = material.encode("utf-8")

    if kdf == "pbkdf2":
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=length, salt=salt,
            iterations=iterations,
        ).derive(raw)
        params = {"iterations": iterations, "hash": "SHA256"}
    elif kdf == "scrypt":
        key = Scrypt(salt=salt, length=length, n=2 ** 14, r=8, p=1).derive(raw)
        params = {"n": 2 ** 14, "r": 8, "p": 1}
    else:  # hkdf - fast, for material that is already high-entropy
        key = HKDF(
            algorithm=hashes.SHA256(), length=length, salt=salt, info=info,
        ).derive(raw)
        params = {"hash": "SHA256", "info": info.decode("utf-8")}

    return {
        "key": key,
        "key_b64": b64e(key),
        "salt": salt,
        "salt_b64": b64e(salt),
        "kdf": kdf,
        "length": length,
        "params": params,
        "fingerprint": hashlib.sha256(key).hexdigest()[:16],
    }


def random_key(length: int = 32) -> dict:
    """A key straight from the OS CSPRNG, with no password behind it."""
    key = secrets.token_bytes(length)
    return {
        "key": key,
        "key_b64": b64e(key),
        "length": length,
        "source": "os-csprng",
        "fingerprint": hashlib.sha256(key).hexdigest()[:16],
    }


def explain(kdf: str = "pbkdf2") -> dict:
    blurbs = {
        "pbkdf2": (
            "PBKDF2 hashes the password together with a random salt, then feeds "
            f"the result back into itself {DEFAULT_ITERATIONS:,} times. The salt "
            "stops precomputed rainbow tables; the iteration count makes each "
            "guess expensive for an attacker."
        ),
        "scrypt": (
            "scrypt is deliberately memory-hungry as well as slow, which makes "
            "large-scale GPU and ASIC cracking far more costly than PBKDF2 does."
        ),
        "hkdf": (
            "HKDF extracts and then expands existing high-entropy material into "
            "one or more keys. It is fast, so it is the wrong choice for a "
            "human-chosen password - use it on a shared secret such as the "
            "output of Diffie-Hellman."
        ),
    }
    return {
        "kdf": kdf,
        "summary": blurbs.get(kdf, ""),
        "why_not_raw": (
            "A password used directly as a key inherits all of the password's "
            "weaknesses: wrong length, low entropy, and reuse across messages."
        ),
    }
