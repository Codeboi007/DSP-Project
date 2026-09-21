"""Breaking things on purpose.

These demos show *why* the classical ciphers are taught as history rather than
as tools. They only ever run against ciphertext the user supplies.
"""

from __future__ import annotations

import string
from collections import Counter

from pico.ciphers import caesar, vigenere

ALPHABET = string.ascii_uppercase
ENGLISH_IC = 0.0667  # index of coincidence for English text
RANDOM_IC = 0.0385   # for a uniform random string
LENGTH_PENALTY = 12.0  # fitness cost per key letter, to stop over-fitting
SAMPLE_LIMIT = 600     # letters used for the statistics; the key is short


def only_letters(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def index_of_coincidence(text: str) -> float:
    """Probability that two letters drawn at random from ``text`` match."""
    letters = only_letters(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    total = sum(c * (c - 1) for c in counts.values())
    return round(total / (n * (n - 1)), 4)


COMMON_WORDS = (
    "THE", "AND", "THAT", "HAVE", "FOR", "NOT", "WITH", "YOU", "THIS", "BUT",
    "HIS", "FROM", "THEY", "SAY", "HER", "SHE", "WILL", "ONE", "ALL", "WOULD",
    "THERE", "THEIR", "WHAT", "OUT", "ABOUT", "WHO", "GET", "WHICH", "WHEN",
    "MAKE", "CAN", "LIKE", "TIME", "JUST", "HIM", "KNOW", "TAKE", "INTO",
    "YEAR", "YOUR", "GOOD", "SOME", "COULD", "THEM", "SEE", "OTHER", "THAN",
    "THEN", "NOW", "LOOK", "ONLY", "COME", "ITS", "OVER", "ALSO", "BACK",
    "AFTER", "USE", "TWO", "HOW", "WORK", "FIRST", "WELL", "WAY", "EVEN",
    "WANT", "BECAUSE", "ANY", "THESE", "GIVE", "MOST", "TEXT", "KEY", "ARE",
    "WAS", "HAS", "HAD", "WERE", "BEEN", "MORE", "IS", "IT", "IN", "OF", "TO",
    "AT", "ON", "AS", "BE", "OR", "AN", "WE", "DO", "IF", "SO", "UP", "BY",
)


def word_hits(text: str) -> int:
    """How many common English words appear in the (spaceless) candidate."""
    upper = only_letters(text)
    return sum(upper.count(word) for word in COMMON_WORDS if len(word) >= 3)


def fitness(text: str) -> float:
    """Higher is more English. Frequency fit, nudged by real word sightings."""
    return 25.0 * word_hits(text) - caesar.chi_squared(text)


def _refine_key(letters: str, key: str, passes: int = 4) -> str:
    """Hill-climb each key position against the fitness of the whole plaintext.

    Per-column chi-squared is noisy when the columns are short, so this second
    pass re-scores every candidate letter using the entire decryption.
    """
    key_chars = list(key)
    best = fitness(vigenere.decrypt(letters, "".join(key_chars)))
    for _ in range(passes):
        improved = False
        for position in range(len(key_chars)):
            original = key_chars[position]
            for candidate in ALPHABET:
                if candidate == original:
                    continue
                key_chars[position] = candidate
                score = fitness(vigenere.decrypt(letters, "".join(key_chars)))
                if score > best:
                    best, original, improved = score, candidate, True
            key_chars[position] = original
        if not improved:
            break
    return "".join(key_chars)


def attack_caesar(ciphertext: str) -> dict:
    """Brute force all 25 shifts and rank them by English-likeness."""
    candidates = caesar.brute_force(ciphertext)
    best = candidates[0]
    return {
        "attack": "Exhaustive key search",
        "target": "Caesar",
        "effort": "25 decryptions - under a millisecond",
        "candidates": candidates,
        "best": best,
        "frequencies": caesar.frequency_analysis(ciphertext),
        "verdict": (
            "Recovered shift " + str(best["shift"]) + " with no key material at "
            "all. The entire key space fits on one screen."
        ),
        "lesson": (
            "A cipher whose key space can be enumerated is not a cipher, it is "
            "an encoding. Modern keys are sized so that enumeration is "
            "physically impossible."
        ),
    }


def kasiski_spacings(ciphertext: str, length: int = 3) -> list[dict]:
    """Distances between repeated substrings - the classic key-length clue."""
    letters = only_letters(ciphertext)
    seen: dict[str, list[int]] = {}
    for i in range(len(letters) - length + 1):
        seen.setdefault(letters[i:i + length], []).append(i)
    out = []
    for chunk, positions in seen.items():
        if len(positions) > 1:
            gaps = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
            out.append({"sequence": chunk, "positions": positions, "gaps": gaps})
    out.sort(key=lambda item: -len(item["positions"]))
    return out[:10]


def _column_ic(letters: str, key_length: int) -> float:
    if key_length <= 0 or len(letters) < key_length * 2:
        return 0.0
    columns = [letters[i::key_length] for i in range(key_length)]
    scores = [index_of_coincidence(col) for col in columns]
    return round(sum(scores) / len(scores), 4)


def guess_key_length(ciphertext: str, max_length: int = 12) -> list[dict]:
    letters = only_letters(ciphertext)
    rows = []
    for length in range(1, min(max_length, max(1, len(letters) // 2)) + 1):
        ic = _column_ic(letters, length)
        rows.append({
            "length": length,
            "ic": ic,
            "distance_from_english": round(abs(ic - ENGLISH_IC), 4),
        })
    rows.sort(key=lambda r: r["distance_from_english"])
    return rows


def _collapse(key: str) -> str:
    """Report ABCABC as ABC - the shorter key decrypts identically."""
    for size in range(1, len(key)):
        if len(key) % size == 0 and key == key[:size] * (len(key) // size):
            return key[:size]
    return key


def attack_vigenere(ciphertext: str, max_length: int = 12) -> dict:
    """Recover the key with the index of coincidence, then per-column chi-squared."""
    letters = only_letters(ciphertext)
    if len(letters) < 20:
        return {
            "attack": "Index of coincidence + frequency analysis",
            "target": "Vigenere",
            "error": "Need at least 20 letters of ciphertext for this to mean anything.",
            "candidates": [],
        }

    sample = letters[:SAMPLE_LIMIT]
    lengths = guess_key_length(ciphertext, max_length)

    # The index of coincidence scores multiples of the true key length almost
    # as well as the true one, and on short ciphertexts it can miss the true
    # length entirely. So do not trust the ranking: solve every candidate
    # length properly and keep whichever yields the most English-looking
    # plaintext, preferring the shortest key on a near tie.
    best_key = ""
    best_score = float("-inf")
    best_length = lengths[0]["length"]

    for row in lengths:
        length = row["length"]
        seed = []
        for i in range(length):
            column = sample[i::length]
            scores = [(caesar.chi_squared(caesar.decrypt(column, k)), k)
                      for k in range(26)]
            scores.sort()
            seed.append(ALPHABET[scores[0][1]])

        candidate = _collapse(_refine_key(sample, "".join(seed)))
        # A longer key has more freedom to manufacture coincidental English,
        # so it has to earn its extra letters.
        score = (fitness(vigenere.decrypt(sample, candidate))
                 - LENGTH_PENALTY * len(candidate))
        if score > best_score + 1e-9 or (
                abs(score - best_score) <= 1e-9 and len(candidate) < len(best_key)):
            best_key, best_score, best_length = candidate, score, length

    key = best_key

    return {
        "attack": "Index of coincidence + per-column frequency analysis",
        "target": "Vigenere",
        "effort": "A few thousand operations - instant",
        "ciphertext_ic": index_of_coincidence(ciphertext),
        "english_ic": ENGLISH_IC,
        "random_ic": RANDOM_IC,
        "key_lengths": lengths,
        "kasiski": kasiski_spacings(ciphertext),
        "recovered_key": key,
        "recovered_plaintext": vigenere.decrypt(ciphertext, key),
        "verdict": (
            "Best guess: key length " + str(len(key)) + ", key '" + key + "'."
        ),
        "tested_lengths": [row["length"] for row in lengths],
        "caveat": (
            "This needs roughly 20 letters of ciphertext per key letter. A long "
            "key on a short message leaves each column too thin to analyse, and "
            "the recovered key will be close but not exact."
        ),
        "lesson": (
            "Repeating the key is the whole weakness. Split the ciphertext by "
            "key position and every column collapses back into a Caesar cipher. "
            "A one-time pad fixes this only because the key never repeats."
        ),
    }


def attack_aes(ciphertext: str) -> dict:
    """There is no demo here, and that is the point."""
    letters = len(ciphertext)
    return {
        "attack": "Exhaustive key search",
        "target": "AES-256",
        "key_space": "2^256 = about 1.16 x 10^77 keys",
        "ciphertext_chars": letters,
        "candidates": [],
        "verdict": "No attack to run.",
        "lesson": (
            "Counting to 2^256 at a billion billion keys per second would take "
            "far longer than the age of the universe, and the energy bill would "
            "exceed the output of the sun. AES is not broken by brute force - "
            "real attacks target key management, reused nonces and side "
            "channels instead. That is what PICO's warnings are watching for."
        ),
        "what_breaks_instead": [
            "A password with 20 bits of entropy behind the key",
            "A nonce reused with the same key in GCM",
            "A CBC padding oracle in the error messages",
            "The key written to a log file or checked into git",
        ],
    }
