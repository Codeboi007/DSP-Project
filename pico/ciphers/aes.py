"""AES - the modern symmetric workhorse.

All maths is done by the PyCA ``cryptography`` package. PICO only chooses the
mode, manages the IV/nonce, and packages the result.

Modes offered:
  GCM - authenticated encryption (recommended; detects tampering)
  CBC - classic mode with PKCS#7 padding (no integrity protection on its own)
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pico.keys.derive import b64d, b64e

MODES = ("gcm", "cbc")
GCM_NONCE_BYTES = 12
CBC_IV_BYTES = 16


def _check_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError(
            f"AES needs a 16, 24 or 32 byte key; got {len(key)} bytes."
        )


def encrypt(plaintext: str, key: bytes, *, mode: str = "gcm",
            iv: bytes | None = None, aad: bytes | None = None) -> dict:
    """Encrypt ``plaintext`` and return the ciphertext plus its parameters."""
    _check_key(key)
    mode = mode.lower()
    data = plaintext.encode("utf-8")

    if mode == "gcm":
        nonce = iv or os.urandom(GCM_NONCE_BYTES)
        if len(nonce) != GCM_NONCE_BYTES:
            raise ValueError("AES-GCM expects a 12 byte nonce.")
        sealed = AESGCM(key).encrypt(nonce, data, aad)
        # The library appends the 16 byte tag; split it out so the package is
        # explicit about what each field is.
        ciphertext, tag = sealed[:-16], sealed[-16:]
        return {
            "algorithm": f"AES-{len(key) * 8}-GCM",
            "mode": "gcm",
            "ciphertext_b64": b64e(ciphertext),
            "iv_b64": b64e(nonce),
            "tag_b64": b64e(tag),
            "aad_b64": b64e(aad) if aad else None,
            "authenticated": True,
        }

    if mode == "cbc":
        iv = iv or os.urandom(CBC_IV_BYTES)
        if len(iv) != CBC_IV_BYTES:
            raise ValueError("AES-CBC expects a 16 byte IV.")
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return {
            "algorithm": f"AES-{len(key) * 8}-CBC",
            "mode": "cbc",
            "ciphertext_b64": b64e(ciphertext),
            "iv_b64": b64e(iv),
            "tag_b64": None,
            "aad_b64": None,
            "authenticated": False,
            "padding": "PKCS7",
        }

    raise ValueError(f"Unknown AES mode '{mode}'. Choose gcm or cbc.")


def decrypt(ciphertext_b64: str, key: bytes, iv_b64: str, *, mode: str = "gcm",
            tag_b64: str | None = None, aad_b64: str | None = None) -> str:
    _check_key(key)
    mode = mode.lower()
    ciphertext = b64d(ciphertext_b64)
    iv = b64d(iv_b64)
    aad = b64d(aad_b64) if aad_b64 else None

    if mode == "gcm":
        if not tag_b64:
            raise ValueError("AES-GCM decryption needs the authentication tag.")
        try:
            data = AESGCM(key).decrypt(iv, ciphertext + b64d(tag_b64), aad)
        except InvalidTag as exc:
            raise ValueError(
                "Authentication failed: the key is wrong or the message was "
                "modified in transit."
            ) from exc
        return data.decode("utf-8")

    if mode == "cbc":
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            data = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise ValueError(
                "Could not unpad the plaintext - the key or IV is wrong. "
                "(CBC cannot tell you whether the message was tampered with.)"
            ) from exc
        return data.decode("utf-8", errors="strict")

    raise ValueError(f"Unknown AES mode '{mode}'. Choose gcm or cbc.")


def explain(mode: str = "gcm", key_bits: int = 256) -> dict:
    rounds = {128: 10, 192: 12, 256: 14}.get(key_bits, 14)
    return {
        "algorithm": f"AES-{key_bits}-{mode.upper()}",
        "summary": (
            f"AES works on 16-byte blocks and runs {rounds} rounds for a "
            f"{key_bits}-bit key. Each round mixes the block with SubBytes, "
            "ShiftRows, MixColumns and AddRoundKey."
        ),
        "rounds": rounds,
        "block_size": "128 bits (16 bytes)",
        "round_steps": [
            {"name": "SubBytes",
             "what": "Each byte is replaced using the S-box lookup table (confusion)."},
            {"name": "ShiftRows",
             "what": "Rows of the 4x4 state are rotated left by 0, 1, 2 and 3 bytes."},
            {"name": "MixColumns",
             "what": "Each column is multiplied by a fixed matrix in GF(2^8) (diffusion). Skipped in the final round."},
            {"name": "AddRoundKey",
             "what": "The state is XORed with the round key from the key schedule."},
        ],
        "mode_note": (
            "GCM is authenticated: the 16-byte tag proves the ciphertext was "
            "not altered. Decryption fails loudly if it was."
            if mode == "gcm" else
            "CBC chains each block into the next using XOR, so an IV is needed "
            "to randomise the first block. CBC alone provides no integrity "
            "check - a flipped ciphertext bit silently flips a plaintext bit."
        ),
        "iv_note": (
            "Never reuse a nonce with the same key in GCM - doing so leaks the "
            "XOR of the plaintexts and can expose the authentication subkey."
            if mode == "gcm" else
            "The IV must be unpredictable and fresh for every message."
        ),
    }
