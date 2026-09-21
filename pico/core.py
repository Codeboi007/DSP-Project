"""The routing layer.

Everything the CLI and the web app can do goes through here. This module
decides *what* to call and how to package the result; the cipher modules
decide *how* to compute it. The two concerns stay separate on purpose.
"""

from __future__ import annotations

import secrets

from pico.ciphers import aes, caesar, dh, playfair, rsa, vigenere
from pico.education import cryptanalysis
from pico.envelope import package as envelope
from pico.keys import derive
from pico.security import checks

ALGORITHMS = {
    "caesar": {
        "label": "Caesar",
        "family": "classical",
        "key_hint": "A number from 1 to 25 (the shift).",
        "strength": "broken",
        "blurb": "Rotate every letter by a fixed amount. 25 possible keys.",
    },
    "vigenere": {
        "label": "Vigenere",
        "family": "classical",
        "key_hint": "A keyword, letters only - e.g. LEMON.",
        "strength": "broken",
        "blurb": "A Caesar shift that changes with every letter of a keyword.",
    },
    "playfair": {
        "label": "Playfair",
        "family": "classical",
        "key_hint": "A keyword that fills the 5x5 square.",
        "strength": "broken",
        "blurb": "Encrypts letter pairs using a 5x5 key square. I and J share a cell.",
    },
    "aes": {
        "label": "AES",
        "family": "modern",
        "key_hint": "Derived from your secret, or a random 256-bit key.",
        "strength": "strong",
        "blurb": "The symmetric standard. GCM mode also detects tampering.",
    },
    "rsa": {
        "label": "RSA",
        "family": "modern",
        "key_hint": "The recipient's public key (PEM).",
        "strength": "strong",
        "blurb": "Public-key encryption. Encrypt with their public key, they decrypt with their private one.",
    },
    "hybrid": {
        "label": "RSA + AES",
        "family": "modern",
        "key_hint": "The recipient's public key (PEM). No size limit on the message.",
        "strength": "strong",
        "blurb": "How real systems do it: RSA wraps a random AES key, AES encrypts the message.",
    },
}

CLASSICAL = {"caesar", "vigenere", "playfair"}


class PicoError(ValueError):
    """A problem the user can fix, phrased for the user."""


def _parse_shift(key: str) -> int:
    try:
        return caesar.normalise_shift(int(str(key).strip()))
    except (TypeError, ValueError) as exc:
        raise PicoError("The Caesar key must be a whole number, e.g. 3.") from exc


def list_algorithms() -> list[dict]:
    return [dict(id=key, **value) for key, value in ALGORITHMS.items()]


# --------------------------------------------------------------------------
# Encryption
# --------------------------------------------------------------------------

def encrypt(algorithm: str, message: str, *, key: str = "", secret: str = "",
            secret_kind: str = "password", kdf: str = "pbkdf2",
            aes_mode: str = "gcm", key_bits: int = 256, public_pem: str = "",
            sender: str = "", recipient: str = "", note: str = "",
            explain: bool = False, sign_private_pem: str = "",
            sign_passphrase: str = "", iv_history: list[str] | None = None) -> dict:
    """Encrypt ``message`` and return a package, an audit and (optionally) a trace."""
    algorithm = (algorithm or "").lower().strip()
    if algorithm not in ALGORITHMS:
        raise PicoError("Unknown algorithm '" + algorithm + "'. Try: " +
                        ", ".join(ALGORITHMS))
    if message is None or message == "":
        raise PicoError("There is no message to encrypt.")

    explanation = None
    key_info: dict = {}

    if algorithm == "caesar":
        shift = _parse_shift(key or "3")
        ciphertext = caesar.encrypt(message, shift)
        params = {"shift": shift}
        kdf_meta: dict = {}
        if explain:
            explanation = caesar.explain(message, shift)
        audit = checks.audit(algorithm="caesar", message=message)

    elif algorithm == "vigenere":
        if not key:
            raise PicoError("Vigenere needs a keyword.")
        ciphertext = vigenere.encrypt(message, key)
        params = {"key_length": len(vigenere.clean_key(key))}
        kdf_meta = {}
        if explain:
            explanation = vigenere.explain(message, key)
        audit = checks.audit(algorithm="vigenere", message=message)

    elif algorithm == "playfair":
        if not key:
            raise PicoError("Playfair needs a keyword to build the square.")
        ciphertext = playfair.encrypt(message, key)
        params = {"padding": "X", "j_folded_into_i": True}
        kdf_meta = {}
        if explain:
            explanation = playfair.explain(message, key)
        audit = checks.audit(algorithm="playfair", message=message)

    elif algorithm == "aes":
        key_bytes, kdf_meta, key_info = _aes_key(
            key=key, secret=secret, secret_kind=secret_kind, kdf=kdf,
            key_bits=key_bits)
        result = aes.encrypt(message, key_bytes, mode=aes_mode)
        ciphertext = result["ciphertext_b64"]
        params = {"mode": result["mode"], "iv": result["iv_b64"],
                  "tag": result["tag_b64"], "cipher": result["algorithm"]}
        if explain:
            explanation = aes.explain(aes_mode, len(key_bytes) * 8)
        audit = checks.audit(algorithm="aes", secret=secret, secret_kind=secret_kind,
                             message=message, mode=aes_mode,
                             key_bits=len(key_bytes) * 8, iv_b64=result["iv_b64"],
                             iv_history=iv_history)

    elif algorithm == "rsa":
        if not public_pem:
            raise PicoError("RSA needs the recipient's public key in PEM form.")
        result = rsa.encrypt(message, public_pem)
        ciphertext = result["ciphertext_b64"]
        params = {"padding": "OAEP-SHA256",
                  "recipient_fingerprint": result["recipient_fingerprint"]}
        kdf_meta = {}
        bits = rsa.load_public(public_pem).key_size
        key_info = {"recipient_fingerprint": result["recipient_fingerprint"],
                    "bits": bits}
        if explain:
            explanation = rsa.explain(bits)
        audit = checks.audit(algorithm="rsa", message=message, key_bits=bits)

    else:  # hybrid
        if not public_pem:
            raise PicoError("Hybrid mode needs the recipient's public key (PEM).")
        session_key = secrets.token_bytes(32)
        sealed = aes.encrypt(message, session_key, mode="gcm")
        wrapped = rsa.wrap_key(session_key, public_pem)
        bits = rsa.load_public(public_pem).key_size
        ciphertext = sealed["ciphertext_b64"]
        params = {"mode": "gcm", "iv": sealed["iv_b64"], "tag": sealed["tag_b64"],
                  "cipher": "AES-256-GCM", "wrapped_key": wrapped,
                  "wrap": "RSA-" + str(bits) + "-OAEP",
                  "recipient_fingerprint": rsa.fingerprint(public_pem)}
        kdf_meta = {}
        key_info = {"session_key_bits": 256, "wrapped_with": "RSA-" + str(bits),
                    "recipient_fingerprint": params["recipient_fingerprint"]}
        if explain:
            explanation = {
                "algorithm": "Hybrid RSA + AES",
                "summary": (
                    "A fresh 256-bit AES key is generated for this one message. "
                    "AES-GCM encrypts the message with it, then RSA-OAEP wraps "
                    "that key with the recipient's public key. The recipient "
                    "unwraps the key with their private key and decrypts."
                ),
                "steps": [
                    {"name": "Session key", "what": "32 random bytes from the OS CSPRNG."},
                    {"name": "Encrypt", "what": "AES-256-GCM over the whole message, any length."},
                    {"name": "Wrap", "what": "RSA-OAEP encrypts those 32 bytes for the recipient."},
                    {"name": "Discard", "what": "The session key is thrown away; only the wrapped copy travels."},
                ],
                "why": "RSA is slow and size-limited; AES is fast and unlimited. "
                       "Hybrid encryption uses each for what it is good at.",
            }
        audit = checks.audit(algorithm="rsa", message=message, key_bits=bits)

    signature = None
    if sign_private_pem:
        signature = {
            "algorithm": "RSA-PSS-SHA256",
            "value": rsa.sign(ciphertext, sign_private_pem, sign_passphrase or None),
            "signer_note": "Signed over the ciphertext.",
        }

    pkg = envelope.build(
        algorithm=algorithm, ciphertext=ciphertext, sender=sender,
        recipient=recipient, params=params, kdf=kdf_meta, note=note,
        signature=signature)

    return {
        "ok": True,
        "algorithm": algorithm,
        "ciphertext": ciphertext,
        "package": pkg,
        "package_json": envelope.to_json(pkg),
        "audit": audit,
        "explanation": explanation,
        "key_info": key_info,
        "describe": envelope.describe(pkg),
    }


def _aes_key(*, key: str, secret: str, secret_kind: str, kdf: str,
             key_bits: int) -> tuple[bytes, dict, dict]:
    """Resolve the AES key from either a raw base64 key or a personal secret."""
    length = {128: 16, 192: 24, 256: 32}.get(int(key_bits), 32)
    if secret:
        derived = derive.derive_key(secret, length=length, kdf=kdf, kind=secret_kind)
        meta = {
            "kdf": derived["kdf"],
            "salt": derived["salt_b64"],
            "length": derived["length"],
            "kind": secret_kind,
            "params": derived["params"],
        }
        info = {"source": "derived", "kdf": derived["kdf"],
                "fingerprint": derived["fingerprint"], "bits": length * 8}
        return derived["key"], meta, info
    if key:
        try:
            raw = derive.b64d(key.strip())
        except Exception as exc:
            raise PicoError("The raw key must be base64 text.") from exc
        if len(raw) not in (16, 24, 32):
            raise PicoError(
                "A raw AES key must decode to 16, 24 or 32 bytes; that one is " +
                str(len(raw)) + ".")
        return raw, {}, {"source": "raw", "bits": len(raw) * 8}
    raise PicoError("AES needs either a personal secret to derive from, or a raw key.")


# --------------------------------------------------------------------------
# Decryption
# --------------------------------------------------------------------------

def decrypt(package: str | dict, *, secret: str = "", key: str = "",
            private_pem: str = "", passphrase: str = "",
            verify_public_pem: str = "", explain: bool = False) -> dict:
    """Open a package and recover the plaintext."""
    pkg = envelope.parse(package)
    algorithm = pkg["algorithm"].lower()
    params = pkg.get("params", {}) or {}
    kdf_meta = pkg.get("kdf", {}) or {}
    ciphertext = pkg["ciphertext"]

    notices: list[dict] = []
    if not envelope.verify_checksum(pkg):
        notices.append(checks.finding(
            checks.WARNING, "PKG001", "Package checksum does not match",
            "The package was edited after it was created. That may be harmless "
            "(someone reformatted the JSON) or it may mean tampering.", ""))

    if algorithm == "caesar":
        shift = params.get("shift")
        if shift is None:
            shift = _parse_shift(key or "3")
        plaintext = caesar.decrypt(ciphertext, int(shift))
        explanation = caesar.explain(plaintext, int(shift)) if explain else None

    elif algorithm == "vigenere":
        if not key:
            raise PicoError("This package needs the Vigenere keyword.")
        plaintext = vigenere.decrypt(ciphertext, key)
        explanation = vigenere.explain(plaintext, key) if explain else None

    elif algorithm == "playfair":
        if not key:
            raise PicoError("This package needs the Playfair keyword.")
        plaintext = playfair.decrypt(ciphertext, key)
        explanation = playfair.explain(plaintext, key) if explain else None

    elif algorithm == "aes":
        key_bytes = _aes_key_for_decrypt(secret, key, kdf_meta)
        plaintext = aes.decrypt(
            ciphertext, key_bytes, params.get("iv", ""),
            mode=params.get("mode", "gcm"), tag_b64=params.get("tag"))
        explanation = aes.explain(params.get("mode", "gcm"),
                                  len(key_bytes) * 8) if explain else None

    elif algorithm == "rsa":
        if not private_pem:
            raise PicoError("This package needs your RSA private key to open.")
        plaintext = rsa.decrypt(ciphertext, private_pem, passphrase or None)
        explanation = rsa.explain() if explain else None

    elif algorithm == "hybrid":
        if not private_pem:
            raise PicoError("This package needs your RSA private key to unwrap "
                            "the session key.")
        wrapped = params.get("wrapped_key")
        if not wrapped:
            raise PicoError("The package is missing its wrapped session key.")
        session_key = rsa.unwrap_key(wrapped, private_pem, passphrase or None)
        plaintext = aes.decrypt(ciphertext, session_key, params.get("iv", ""),
                                mode="gcm", tag_b64=params.get("tag"))
        explanation = aes.explain("gcm", 256) if explain else None

    else:
        raise PicoError("This package uses an algorithm PICO does not know: " +
                        algorithm)

    signature_status = None
    if pkg.get("signature"):
        if verify_public_pem:
            valid = rsa.verify(ciphertext, pkg["signature"]["value"], verify_public_pem)
            signature_status = {
                "checked": True, "valid": valid,
                "message": ("Signature verified - this came from the holder of "
                            "that private key.") if valid else
                           ("Signature does NOT match. Do not trust the sender "
                            "identity on this package."),
            }
            if not valid:
                notices.append(checks.finding(
                    checks.CRITICAL, "SIG001", "Signature verification failed",
                    "The signature does not match this ciphertext and public key.", ""))
        else:
            signature_status = {
                "checked": False, "valid": None,
                "message": "This package is signed. Supply the sender's public "
                           "key to verify it.",
            }

    return {
        "ok": True,
        "algorithm": algorithm,
        "plaintext": plaintext,
        "describe": envelope.describe(pkg),
        "notices": notices,
        "signature": signature_status,
        "explanation": explanation,
        "authenticated": bool(params.get("tag")),
    }


def _aes_key_for_decrypt(secret: str, key: str, kdf_meta: dict) -> bytes:
    if secret:
        if not kdf_meta.get("salt"):
            raise PicoError("The package carries no salt, so a password cannot "
                            "reproduce the key. Supply the raw key instead.")
        return derive.derive_key(
            secret,
            derive.b64d(kdf_meta["salt"]),
            length=kdf_meta.get("length", 32),
            kdf=kdf_meta.get("kdf", "pbkdf2"),
            iterations=(kdf_meta.get("params") or {}).get(
                "iterations", derive.DEFAULT_ITERATIONS),
            kind=kdf_meta.get("kind", "password"),
        )["key"]
    if key:
        try:
            raw = derive.b64d(key.strip())
        except Exception as exc:
            raise PicoError("The raw key must be base64 text.") from exc
        if len(raw) not in (16, 24, 32):
            raise PicoError("A raw AES key must decode to 16, 24 or 32 bytes.")
        return raw
    raise PicoError("This package needs the shared secret, or the raw AES key.")


# --------------------------------------------------------------------------
# Keys, analysis and explanations
# --------------------------------------------------------------------------

def generate_keys(kind: str = "aes", *, bits: int = 2048, secret: str = "",
                  secret_kind: str = "password", kdf: str = "pbkdf2",
                  key_bits: int = 256, passphrase: str = "") -> dict:
    kind = (kind or "aes").lower()
    if kind == "rsa":
        pair = rsa.generate_keypair(bits, passphrase or None)
        pair["audit"] = checks.audit(algorithm="rsa", key_bits=bits)
        return pair
    if kind == "derive":
        if not secret:
            raise PicoError("Supply the secret you want the key derived from.")
        length = {128: 16, 192: 24, 256: 32}.get(int(key_bits), 32)
        result = derive.derive_key(secret, length=length, kdf=kdf, kind=secret_kind)
        # This is a demonstration of derivation, not a key hand-out: show the
        # salt, the parameters and a fingerprint, never the key material.
        result.pop("key")
        result.pop("key_b64")
        result.pop("salt")
        result["audit"] = checks.audit(secret=secret, secret_kind=secret_kind)
        result["explain"] = derive.explain(kdf)
        return result
    if kind == "aes":
        length = {128: 16, 192: 24, 256: 32}.get(int(key_bits), 32)
        result = derive.random_key(length)
        result.pop("key")
        result["bits"] = length * 8
        result["audit"] = checks.audit(algorithm="aes", mode="gcm",
                                       key_bits=length * 8)
        return result
    raise PicoError("Unknown key kind '" + kind + "'. Try aes, rsa or derive.")


def analyse(ciphertext: str, algorithm: str = "caesar") -> dict:
    """Run the cryptanalysis demos against a ciphertext."""
    algorithm = (algorithm or "caesar").lower()
    if algorithm == "caesar":
        return cryptanalysis.attack_caesar(ciphertext)
    if algorithm == "vigenere":
        return cryptanalysis.attack_vigenere(ciphertext)
    if algorithm == "aes":
        return cryptanalysis.attack_aes(ciphertext)
    raise PicoError("No cryptanalysis demo for '" + algorithm + "'.")


def explain_algorithm(algorithm: str, **kwargs) -> dict:
    algorithm = (algorithm or "").lower()
    samples = {
        "caesar": lambda: caesar.explain(kwargs.get("message") or "HELLO", 3),
        "vigenere": lambda: vigenere.explain(kwargs.get("message") or "ATTACKATDAWN",
                                             kwargs.get("key") or "LEMON"),
        "playfair": lambda: playfair.explain(kwargs.get("message") or "HIDETHEGOLD",
                                             kwargs.get("key") or "MONARCHY"),
        "aes": lambda: aes.explain(kwargs.get("mode") or "gcm",
                                   int(kwargs.get("key_bits") or 256)),
        "rsa": lambda: rsa.explain(int(kwargs.get("bits") or 2048)),
        "dh": lambda: dh.explain(),
        "kdf": lambda: derive.explain(kwargs.get("kdf") or "pbkdf2"),
    }
    if algorithm not in samples:
        raise PicoError("Nothing to explain for '" + algorithm + "'.")
    return samples[algorithm]()
