"""Diffie-Hellman - agreeing on a shared secret over an open channel.

Two flavours:
  * ``toy`` - small numbers, every step printable, for the classroom demo
  * ``real`` - RFC 3526 2048-bit MODP group via PyCA ``cryptography``
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pico.keys.derive import b64e

# A small safe prime, big enough to show the mechanics and far too small to use.
TOY_P = 2_147_483_647  # 2^31 - 1, a Mersenne prime
TOY_G = 5


def toy_exchange(private_a: int | None = None, private_b: int | None = None,
                 p: int = TOY_P, g: int = TOY_G) -> dict:
    """Run a full DH exchange with numbers small enough to read."""
    a = private_a if private_a is not None else secrets.randbelow(p - 2) + 2
    b = private_b if private_b is not None else secrets.randbelow(p - 2) + 2
    A = pow(g, a, p)
    B = pow(g, b, p)
    shared_a = pow(B, a, p)
    shared_b = pow(A, b, p)
    return {
        "mode": "toy",
        "p": p,
        "g": g,
        "alice_private": a,
        "bob_private": b,
        "alice_public": A,
        "bob_public": B,
        "alice_shared": shared_a,
        "bob_shared": shared_b,
        "agreed": shared_a == shared_b,
        "steps": [
            f"Public parameters agreed in the open: p = {p}, g = {g}",
            f"Alice keeps a = {a} secret and sends A = g^a mod p = {A}",
            f"Bob keeps b = {b} secret and sends B = g^b mod p = {B}",
            f"Alice computes B^a mod p = {shared_a}",
            f"Bob computes A^b mod p = {shared_b}",
            "Both sides now hold the same number, which never crossed the wire.",
        ],
        "warning": (
            "These numbers are tiny - an attacker can solve the discrete "
            "logarithm instantly. Use the 2048-bit group for anything real."
        ),
    }


def real_exchange(key_bytes: int = 32) -> dict:
    """A genuine 2048-bit MODP exchange, with HKDF applied to the result."""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    alice = parameters.generate_private_key()
    bob = parameters.generate_private_key()

    shared_a = alice.exchange(bob.public_key())
    shared_b = bob.exchange(alice.public_key())

    def kdf(raw: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=key_bytes, salt=None,
            info=b"pico-dh-session-key",
        ).derive(raw)

    key_a, key_b = kdf(shared_a), kdf(shared_b)
    numbers = parameters.parameter_numbers()

    def pub_pem(key) -> str:
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    return {
        "mode": "real",
        "group": "2048-bit MODP (generated)",
        "generator": numbers.g,
        "prime_bits": numbers.p.bit_length(),
        "alice_public_pem": pub_pem(alice),
        "bob_public_pem": pub_pem(bob),
        "raw_secret_bytes": len(shared_a),
        "session_key_b64": b64e(key_a),
        "agreed": key_a == key_b,
        "note": (
            "The raw DH output is not uniform, so it is run through HKDF-SHA256 "
            "before being used as an AES key."
        ),
    }


def explain() -> dict:
    return {
        "algorithm": "Diffie-Hellman",
        "summary": (
            "Two parties agree on a shared secret while an eavesdropper watches "
            "every message. It works because computing g^a mod p is easy but "
            "recovering a from it (the discrete logarithm) is not."
        ),
        "formula": "(g^b mod p)^a mod p = g^(ab) mod p = (g^a mod p)^b mod p",
        "eavesdropper": (
            "Eve sees p, g, g^a and g^b. To get g^(ab) she would have to solve "
            "the discrete logarithm problem for a 2048-bit prime."
        ),
        "caveat": (
            "Plain DH authenticates nobody. Without signatures an active "
            "attacker can run a separate exchange with each side - the classic "
            "man-in-the-middle attack."
        ),
    }
