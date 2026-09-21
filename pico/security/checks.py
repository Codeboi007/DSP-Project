"""The advisory layer - PICO's opinions about your configuration.

Nothing here blocks an operation. Every check returns a finding with a level
so the CLI and the web UI can show it before the user commits.
"""

from __future__ import annotations

import math
import re
from collections import Counter

CRITICAL, WARNING, INFO, OK = "critical", "warning", "info", "ok"
_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2, OK: 3}

CLASSICAL = {"caesar", "playfair", "vigenere"}

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "111111", "letmein",
    "admin", "welcome", "monkey", "dragon", "iloveyou", "password1", "1234",
    "secret", "root", "test", "guest", "pass", "hello", "login", "master",
}


def finding(level: str, code: str, title: str, detail: str, fix: str = "") -> dict:
    return {"level": level, "code": code, "title": title, "detail": detail, "fix": fix}


def shannon_entropy_bits(secret: str) -> float:
    """Rough entropy estimate: charset size ^ length, in bits."""
    if not secret:
        return 0.0
    pools = 0
    if re.search(r"[a-z]", secret):
        pools += 26
    if re.search(r"[A-Z]", secret):
        pools += 26
    if re.search(r"[0-9]", secret):
        pools += 10
    if re.search(r"[^A-Za-z0-9]", secret):
        pools += 32
    pools = max(pools, 1)
    return round(len(secret) * math.log2(pools), 1)


def check_secret(secret: str, kind: str = "password") -> list[dict]:
    """Assess the personal input a key will be derived from."""
    out: list[dict] = []
    if not secret:
        return [finding(CRITICAL, "SEC001", "No secret supplied",
                        "There is nothing to derive a key from.",
                        "Enter a password or passphrase.")]

    lowered = secret.lower().strip()
    bits = shannon_entropy_bits(secret)

    if kind == "mobile":
        out.append(finding(
            WARNING, "SEC010", "A phone number is public information",
            "Mobile numbers are short, structured and often known to others. "
            "There are only about 10^10 of them, so an attacker can try every "
            "one. PBKDF2 slows that down but does not fix it.",
            "Add a shared word to the number, or use a passphrase instead."))
    if lowered in COMMON_PASSWORDS:
        out.append(finding(
            CRITICAL, "SEC002", "This is one of the most-guessed passwords",
            "This secret appears in every password cracking wordlist.",
            "Pick something that is not in a dictionary."))
    if len(secret) < 8 and kind != "mobile":
        out.append(finding(
            CRITICAL if len(secret) < 5 else WARNING, "SEC003",
            "Secret is only " + str(len(secret)) + " characters",
            "Short secrets fall to brute force regardless of the KDF.",
            "Use at least 12 characters, or three or four random words."))
    if secret.isdigit() and kind != "mobile":
        out.append(finding(
            WARNING, "SEC004", "Digits only",
            "A digits-only secret has about 3.3 bits of entropy per character.",
            "Mix in letters and symbols, or lengthen it substantially."))
    if len(set(secret)) <= 2 and len(secret) > 2:
        out.append(finding(
            CRITICAL, "SEC005", "Almost no variety",
            "The secret uses only " + str(len(set(secret))) + " distinct characters.",
            "Use a varied passphrase."))
    if re.search(r"(.)\1{3,}", secret):
        out.append(finding(
            WARNING, "SEC006", "Long run of a repeated character",
            "Repetition adds length without adding entropy.", ""))
    if re.search(r"(?:0123|1234|2345|abcd|qwer|asdf)", lowered):
        out.append(finding(
            WARNING, "SEC007", "Contains a keyboard or counting sequence",
            "Sequences are the first thing a cracking tool tries.", ""))

    level = INFO if bits >= 60 else (WARNING if bits >= 40 else CRITICAL)
    detail = {
        INFO: "Comfortable for a derived key.",
        WARNING: "Usable, but an attacker with a GPU farm would enjoy this.",
        CRITICAL: "Well below what a key should be built from.",
    }[level]
    out.append(finding(
        level, "SEC008", "Estimated entropy: " + str(bits) + " bits", detail,
        "" if level == INFO else "Longer and more varied beats clever substitutions."))
    return out


def check_algorithm(algorithm: str, *, message_length: int = 0,
                    mode: str | None = None, key_bits: int | None = None) -> list[dict]:
    """Assess the algorithm choice itself."""
    algorithm = (algorithm or "").lower()
    out: list[dict] = []

    classical_detail = {
        "caesar": "There are only 25 keys. A laptop tries them all instantly, and "
                  "frequency analysis recovers the shift from the ciphertext alone.",
        "vigenere": "The Kasiski examination and the index of coincidence recover the "
                    "key length, after which each position reduces to a Caesar cipher.",
        "playfair": "Digraph frequency analysis breaks Playfair with a few hundred "
                    "letters of ciphertext.",
    }

    if algorithm in CLASSICAL:
        out.append(finding(
            CRITICAL, "ALG001", algorithm.title() + " offers no real security",
            classical_detail[algorithm],
            "Use AES-256-GCM for anything you actually want kept secret. Keep "
            "the classical ciphers for learning."))
    if algorithm == "caesar":
        out.append(finding(INFO, "ALG002", "Key space: 25 shifts",
                           "Exhaustive search is trivial.", ""))
    if algorithm == "aes":
        if mode == "cbc":
            out.append(finding(
                WARNING, "ALG010", "CBC does not detect tampering",
                "Without a MAC, an attacker can flip bits in the ciphertext and "
                "flip the matching plaintext bits. CBC is also open to padding "
                "oracle attacks if error messages differ.",
                "Prefer AES-GCM, which authenticates the ciphertext."))
        else:
            out.append(finding(OK, "ALG011", "AES-GCM is authenticated encryption",
                               "Tampering is detected and decryption fails cleanly.", ""))
        if key_bits and key_bits < 256:
            out.append(finding(INFO, "ALG012", "AES-" + str(key_bits),
                               "Still safe, but AES-256 costs almost nothing extra.",
                               "Use a 32-byte key."))
    if algorithm == "rsa":
        if key_bits and key_bits < 2048:
            out.append(finding(CRITICAL, "ALG020", "RSA-" + str(key_bits) + " is too small",
                               "Keys below 2048 bits are within reach of well-funded attackers.",
                               "Generate at least 2048 bits; 3072 for long-term data."))
        elif key_bits:
            out.append(finding(OK, "ALG021", "RSA-" + str(key_bits) + " with OAEP padding",
                               "A sound choice for wrapping keys and short messages.", ""))
        if message_length > 190:
            out.append(finding(
                WARNING, "ALG022", "Message is larger than one RSA block",
                str(message_length) + " bytes will not fit in a single RSA-OAEP operation.",
                "Use hybrid mode: RSA wraps a random AES key, AES encrypts the message."))
    return out


def check_iv_reuse(history: list[str], iv_b64: str | None) -> list[dict]:
    """Flag a nonce that has already been used with the current key."""
    if not iv_b64:
        return []
    if iv_b64 in history:
        return [finding(
            CRITICAL, "IV001", "This IV/nonce has been used before",
            "Reusing a nonce with the same key is catastrophic in GCM and "
            "leaks block relationships in CBC.",
            "Let PICO generate a fresh random IV for every message.")]
    return []


def check_message(message: str) -> list[dict]:
    out = []
    if not message:
        out.append(finding(WARNING, "MSG001", "Empty message",
                           "There is nothing to encrypt.", ""))
    elif len(message) < 4:
        out.append(finding(INFO, "MSG002", "Very short message",
                           "Short ciphertexts leak their length and resist little.", ""))
    if message and len(set(message)) == 1 and len(message) > 8:
        out.append(finding(INFO, "MSG003", "Highly repetitive plaintext",
                           "Repetition is exactly what classical ciphers leak.", ""))
    return out


def audit(*, algorithm: str = "", secret: str = "", secret_kind: str = "password",
          message: str = "", mode: str | None = None, key_bits: int | None = None,
          iv_b64: str | None = None, iv_history: list[str] | None = None) -> dict:
    """Run every relevant check and summarise the result."""
    findings: list[dict] = []
    if algorithm:
        findings += check_algorithm(algorithm, message_length=len(message or ""),
                                    mode=mode, key_bits=key_bits)
    if secret:
        findings += check_secret(secret, secret_kind)
    if message is not None:
        findings += check_message(message)
    findings += check_iv_reuse(iv_history or [], iv_b64)

    findings.sort(key=lambda f: _ORDER.get(f["level"], 9))
    counts = Counter(f["level"] for f in findings)
    if counts[CRITICAL]:
        verdict, score = "unsafe", max(0, 40 - 10 * counts[CRITICAL])
    elif counts[WARNING]:
        verdict, score = "risky", max(45, 85 - 10 * counts[WARNING])
    else:
        verdict, score = "sound", 95

    headlines = {
        "unsafe": "This configuration would not protect a real secret.",
        "risky": "This will work, but there are weak points.",
        "sound": "No problems found with this configuration.",
    }

    return {
        "verdict": verdict,
        "score": score,
        "counts": {k: counts.get(k, 0) for k in (CRITICAL, WARNING, INFO, OK)},
        "findings": findings,
        "headline": headlines[verdict],
    }
