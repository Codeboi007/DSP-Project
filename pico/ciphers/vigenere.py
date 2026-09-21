"""Vigenere cipher - a Caesar shift whose key changes every letter."""

from __future__ import annotations

import string

ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = len(ALPHABET)


def clean_key(key: str) -> str:
    """Keep only letters, upper-cased. Raises if nothing usable is left."""
    cleaned = "".join(ch for ch in key.upper() if ch in ALPHABET)
    if not cleaned:
        raise ValueError("Vigenere key must contain at least one letter A-Z.")
    return cleaned


def _apply(text: str, key: str, sign: int) -> str:
    key = clean_key(key)
    out = []
    k = 0  # only advances on letters, so spacing does not desync the key
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            shift = ord(key[k % len(key)]) - 65
            out.append(chr((ord(ch) - base + sign * shift) % ALPHABET_SIZE + base))
            k += 1
        else:
            out.append(ch)
    return "".join(out)


def encrypt(plaintext: str, key: str) -> str:
    return _apply(plaintext, key, 1)


def decrypt(ciphertext: str, key: str) -> str:
    return _apply(ciphertext, key, -1)


def keystream(text: str, key: str) -> str:
    """The repeating key lined up against the letters of ``text``."""
    key = clean_key(key)
    out = []
    k = 0
    for ch in text:
        if ch.isalpha():
            out.append(key[k % len(key)])
            k += 1
        else:
            out.append(" ")
    return "".join(out)


def tabula_recta() -> list[list[str]]:
    """The 26x26 Vigenere square, for the web UI visualiser."""
    return [
        [ALPHABET[(row + col) % ALPHABET_SIZE] for col in range(ALPHABET_SIZE)]
        for row in range(ALPHABET_SIZE)
    ]


def explain(plaintext: str, key: str, limit: int = 8) -> dict:
    key = clean_key(key)
    steps = []
    k = 0
    for ch in plaintext[:limit]:
        if not ch.isalpha():
            steps.append({
                "input": ch, "key": "-", "math": "passthrough", "output": ch,
            })
            continue
        base = 65 if ch.isupper() else 97
        idx = ord(ch) - base
        kch = key[k % len(key)]
        shift = ord(kch) - 65
        new = (idx + shift) % ALPHABET_SIZE
        steps.append({
            "input": ch,
            "key": kch,
            "math": f"({idx} + {shift}) mod 26 = {new}",
            "output": chr(new + base),
        })
        k += 1
    return {
        "algorithm": "Vigenere",
        "summary": (
            f"The key '{key}' repeats across the message. Each letter gets its "
            "own Caesar shift, so the same plaintext letter can encrypt to "
            "different ciphertext letters."
        ),
        "formula": "E(x_i) = (x_i + k_(i mod m)) mod 26",
        "key_space": f"26^{len(key)}",
        "keystream": keystream(plaintext[:limit], key),
        "steps": steps,
        "truncated": len(plaintext) > limit,
    }
