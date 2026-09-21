"""RSA - public-key encryption and digital signatures.

Key generation, OAEP encryption and PSS signing all come from PyCA
``cryptography``. PICO handles the PEM plumbing and the hybrid envelope.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pico.keys.derive import b64d, b64e

SIZES = (2048, 3072, 4096)


def generate_keypair(bits: int = 2048, passphrase: str | None = None) -> dict:
    """Generate an RSA key pair and return both halves as PEM text."""
    if bits < 2048:
        raise ValueError("RSA keys below 2048 bits are not considered safe.")
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public = private.public_key()

    if passphrase:
        enc: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        )
    else:
        enc = serialization.NoEncryption()

    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    ).decode("ascii")
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return {
        "bits": bits,
        "public_pem": public_pem,
        "private_pem": private_pem,
        "protected": bool(passphrase),
        "fingerprint": fingerprint(public_pem),
        "max_plaintext_bytes": max_plaintext_bytes(bits),
    }


def fingerprint(public_pem: str) -> str:
    """Short SHA-256 fingerprint, shown so users can compare keys by eye."""
    digest = hashlib.sha256(public_pem.strip().encode("ascii")).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 16, 4))


def max_plaintext_bytes(bits: int) -> int:
    """OAEP with SHA-256 costs 2*32 + 2 bytes of overhead."""
    return bits // 8 - 2 * 32 - 2


def load_public(public_pem: str):
    try:
        return serialization.load_pem_public_key(public_pem.strip().encode("ascii"))
    except Exception as exc:
        raise ValueError("That does not look like a valid RSA public key (PEM).") from exc


def load_private(private_pem: str, passphrase: str | None = None):
    try:
        return serialization.load_pem_private_key(
            private_pem.strip().encode("ascii"),
            password=passphrase.encode("utf-8") if passphrase else None,
        )
    except TypeError as exc:
        raise ValueError("This private key is passphrase-protected.") from exc
    except ValueError as exc:
        raise ValueError(
            "Could not read the private key - wrong passphrase or malformed PEM."
        ) from exc


_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def encrypt(plaintext: str, public_pem: str) -> dict:
    """Direct RSA-OAEP encryption. Only for short messages."""
    key = load_public(public_pem)
    data = plaintext.encode("utf-8")
    limit = max_plaintext_bytes(key.key_size)
    if len(data) > limit:
        raise ValueError(
            f"RSA-OAEP can only wrap {limit} bytes with this key, and the "
            f"message is {len(data)}. Use the hybrid RSA+AES mode instead."
        )
    return {
        "algorithm": f"RSA-{key.key_size}-OAEP",
        "ciphertext_b64": b64e(key.encrypt(data, _OAEP)),
        "recipient_fingerprint": fingerprint(public_pem),
    }


def decrypt(ciphertext_b64: str, private_pem: str, passphrase: str | None = None) -> str:
    key = load_private(private_pem, passphrase)
    try:
        return key.decrypt(b64d(ciphertext_b64), _OAEP).decode("utf-8")
    except Exception as exc:
        raise ValueError(
            "RSA decryption failed - this message was not encrypted for this key."
        ) from exc


def wrap_key(key_bytes: bytes, public_pem: str) -> str:
    """Encrypt an AES key under the recipient's public key (hybrid mode)."""
    return b64e(load_public(public_pem).encrypt(key_bytes, _OAEP))


def unwrap_key(wrapped_b64: str, private_pem: str, passphrase: str | None = None) -> bytes:
    key = load_private(private_pem, passphrase)
    try:
        return key.decrypt(b64d(wrapped_b64), _OAEP)
    except Exception as exc:
        raise ValueError(
            "Could not unwrap the session key - wrong private key."
        ) from exc


def sign(message: str, private_pem: str, passphrase: str | None = None) -> str:
    key = load_private(private_pem, passphrase)
    return b64e(key.sign(message.encode("utf-8"), _PSS, hashes.SHA256()))


def verify(message: str, signature_b64: str, public_pem: str) -> bool:
    try:
        load_public(public_pem).verify(
            b64d(signature_b64), message.encode("utf-8"), _PSS, hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def explain(bits: int = 2048) -> dict:
    return {
        "algorithm": f"RSA-{bits}",
        "summary": (
            "RSA rests on the difficulty of factoring a large number n = p*q. "
            "The public key (n, e) can encrypt; only the private key (n, d) "
            "can undo it, because d is the inverse of e modulo phi(n)."
        ),
        "formula": "c = m^e mod n     m = c^d mod n",
        "steps": [
            {"name": "Pick primes", "what": f"Choose two random primes p and q of about {bits // 2} bits each."},
            {"name": "Modulus", "what": "n = p * q. This is public and gives the key its size."},
            {"name": "Totient", "what": "phi(n) = (p-1)(q-1) - kept secret."},
            {"name": "Exponents", "what": "Public e = 65537; private d satisfies e*d = 1 mod phi(n)."},
            {"name": "Padding", "what": "OAEP adds randomness so the same message never encrypts twice the same way."},
        ],
        "limits": (
            f"Only {max_plaintext_bytes(bits)} bytes fit in one RSA-OAEP block, "
            "which is why real systems encrypt a random AES key with RSA and "
            "the actual message with AES. PICO calls that hybrid mode."
        ),
        "signature_note": (
            "Signing runs the private key over a SHA-256 hash of the message "
            "using PSS padding. Anyone with the public key can verify it, but "
            "only the private key holder can produce it."
        ),
    }
