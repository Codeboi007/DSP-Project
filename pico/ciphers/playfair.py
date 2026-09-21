"""Playfair cipher - digraph substitution over a 5x5 key square.

Convention used here (the common one): I and J share a cell, and 'X' is the
padding letter for repeated pairs and for an odd-length message.
"""

from __future__ import annotations

import string

ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # no J
PAD = "X"
ALT_PAD = "Q"  # used when the letter to pad is already an X


def build_square(key: str) -> list[list[str]]:
    """Fill a 5x5 grid with the key letters first, then the rest of A-Z."""
    seen: list[str] = []
    for ch in (key or "").upper():
        if ch == "J":
            ch = "I"
        if ch in ALPHABET and ch not in seen:
            seen.append(ch)
    for ch in ALPHABET:
        if ch not in seen:
            seen.append(ch)
    return [seen[row * 5:(row + 1) * 5] for row in range(5)]


def _positions(square: list[list[str]]) -> dict[str, tuple[int, int]]:
    return {ch: (r, c) for r, row in enumerate(square) for c, ch in enumerate(row)}


def prepare_text(text: str) -> str:
    """Strip to letters, fold J into I."""
    return "".join("I" if ch == "J" else ch for ch in text.upper() if ch in string.ascii_uppercase)


def digraphs(text: str) -> list[str]:
    """Split into letter pairs, inserting padding so no pair is a double."""
    letters = prepare_text(text)
    pairs: list[str] = []
    i = 0
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else None
        if b is None:
            pairs.append(a + (PAD if a != PAD else ALT_PAD))
            i += 1
        elif a == b:
            pairs.append(a + (PAD if a != PAD else ALT_PAD))
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def _transform(pairs: list[str], square: list[list[str]], sign: int) -> list[dict]:
    pos = _positions(square)
    out = []
    for pair in pairs:
        (r1, c1), (r2, c2) = pos[pair[0]], pos[pair[1]]
        if r1 == r2:
            rule = "same row -> shift right" if sign > 0 else "same row -> shift left"
            n1 = square[r1][(c1 + sign) % 5]
            n2 = square[r2][(c2 + sign) % 5]
        elif c1 == c2:
            rule = "same column -> shift down" if sign > 0 else "same column -> shift up"
            n1 = square[(r1 + sign) % 5][c1]
            n2 = square[(r2 + sign) % 5][c2]
        else:
            rule = "rectangle -> swap columns"
            n1 = square[r1][c2]
            n2 = square[r2][c1]
        out.append({"pair": pair, "rule": rule, "result": n1 + n2,
                    "cells": [[r1, c1], [r2, c2]]})
    return out


def encrypt(plaintext: str, key: str) -> str:
    square = build_square(key)
    steps = _transform(digraphs(plaintext), square, 1)
    return "".join(s["result"] for s in steps)


def decrypt(ciphertext: str, key: str) -> str:
    square = build_square(key)
    letters = prepare_text(ciphertext)
    if len(letters) % 2:
        raise ValueError("Playfair ciphertext must have an even number of letters.")
    pairs = [letters[i:i + 2] for i in range(0, len(letters), 2)]
    steps = _transform(pairs, square, -1)
    return "".join(s["result"] for s in steps)


def explain(plaintext: str, key: str, limit: int = 6) -> dict:
    square = build_square(key)
    pairs = digraphs(plaintext)
    steps = _transform(pairs, square, 1)
    return {
        "algorithm": "Playfair",
        "summary": (
            "The message is split into letter pairs and each pair is looked up "
            "in a 5x5 key square. Pairs in the same row shift right, pairs in "
            "the same column shift down, and any other pair swaps columns."
        ),
        "formula": "row rule | column rule | rectangle rule",
        "key_space": "25! arrangements of the square",
        "square": square,
        "digraphs": pairs[:limit],
        "steps": steps[:limit],
        "note": "J is folded into I, and X pads doubles and odd endings.",
        "truncated": len(steps) > limit,
    }
