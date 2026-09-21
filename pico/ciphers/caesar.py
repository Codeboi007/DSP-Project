"""Caesar cipher - the classic shift substitution.

Implemented from scratch (no library) because the point of the classical
ciphers in PICO is to show the mechanics, not to provide real security.
"""

from __future__ import annotations

import string
from collections import Counter

ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = len(ALPHABET)

# English letter frequencies (percent), used by the cryptanalysis demo.
ENGLISH_FREQ = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702, "F": 2.228,
    "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153, "K": 0.772, "L": 4.025,
    "M": 2.406, "N": 6.749, "O": 7.507, "P": 1.929, "Q": 0.095, "R": 5.987,
    "S": 6.327, "T": 9.056, "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150,
    "Y": 1.974, "Z": 0.074,
}


def normalise_shift(shift: int) -> int:
    """Wrap any integer into the 0..25 range."""
    return int(shift) % ALPHABET_SIZE


def shift_text(text: str, shift: int) -> str:
    """Shift every letter by ``shift``; non-letters pass through untouched."""
    shift = normalise_shift(shift)
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr((ord(ch) - 65 + shift) % ALPHABET_SIZE + 65))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 + shift) % ALPHABET_SIZE + 97))
        else:
            out.append(ch)
    return "".join(out)


def encrypt(plaintext: str, shift: int) -> str:
    return shift_text(plaintext, shift)


def decrypt(ciphertext: str, shift: int) -> str:
    return shift_text(ciphertext, -normalise_shift(shift))


def explain(plaintext: str, shift: int, limit: int = 8) -> dict:
    """Per-character trace of the encryption, for Educational Mode."""
    shift = normalise_shift(shift)
    steps = []
    for ch in plaintext[:limit]:
        if not ch.isalpha():
            steps.append({
                "input": ch, "index": None, "math": "passthrough",
                "result_index": None, "output": ch,
            })
            continue
        base = 65 if ch.isupper() else 97
        idx = ord(ch) - base
        new = (idx + shift) % ALPHABET_SIZE
        steps.append({
            "input": ch,
            "index": idx,
            "math": f"({idx} + {shift}) mod 26 = {new}",
            "result_index": new,
            "output": chr(new + base),
        })
    return {
        "algorithm": "Caesar",
        "summary": (
            f"Every letter is rotated {shift} position(s) forward through the "
            f"26-letter alphabet. Decryption rotates {shift} back."
        ),
        "formula": "E(x) = (x + k) mod 26     D(x) = (x - k) mod 26",
        "key_space": 25,
        "steps": steps,
        "truncated": len(plaintext) > limit,
    }


def chi_squared(text: str) -> float:
    """Goodness-of-fit against English letter frequencies (lower = better)."""
    letters = [c for c in text.upper() if c in ALPHABET]
    if not letters:
        return float("inf")
    counts = Counter(letters)
    total = len(letters)
    score = 0.0
    for letter in ALPHABET:
        expected = total * ENGLISH_FREQ[letter] / 100.0
        observed = counts.get(letter, 0)
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def brute_force(ciphertext: str) -> list[dict]:
    """Try all 26 shifts and rank them by English-likeness."""
    results = []
    for k in range(ALPHABET_SIZE):
        candidate = decrypt(ciphertext, k)
        results.append({
            "shift": k,
            "plaintext": candidate,
            "score": round(chi_squared(candidate), 2),
        })
    results.sort(key=lambda r: r["score"])
    for rank, item in enumerate(results, start=1):
        item["rank"] = rank
    return results


def frequency_analysis(text: str) -> list[dict]:
    """Letter histogram of ``text`` next to expected English frequencies."""
    letters = [c for c in text.upper() if c in ALPHABET]
    total = len(letters) or 1
    counts = Counter(letters)
    return [
        {
            "letter": letter,
            "count": counts.get(letter, 0),
            "percent": round(counts.get(letter, 0) * 100.0 / total, 2),
            "english": ENGLISH_FREQ[letter],
        }
        for letter in ALPHABET
    ]
