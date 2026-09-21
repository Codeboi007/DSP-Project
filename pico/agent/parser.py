"""Agent Mode - turning plain English into a PICO operation.

This is a deterministic, rule-based parser. It scores intent keywords, pulls
out the obvious parameters, and returns a *plan*. It never performs any
cryptography itself - the plan is handed back to ``pico.core`` to execute, and
the user confirms it first.
"""

from __future__ import annotations

import re

INTENTS = {
    "encrypt": (
        "encrypt", "encipher", "encode", "scramble", "protect", "lock",
        "secure this", "hide this", "send securely", "cipher this",
    ),
    "decrypt": (
        "decrypt", "decipher", "decode", "unlock", "unscramble", "open the",
        "read the message", "recover the message",
    ),
    "generate": (
        "generate", "create a key", "make a key", "new key", "key pair",
        "keypair", "give me a key", "produce a key",
    ),
    "analyse": (
        "break", "crack", "attack", "analyse", "analyze", "cryptanalysis",
        "frequency analysis", "brute force", "solve this",
    ),
    "explain": (
        "explain", "how does", "how do", "teach", "what is", "tell me about",
        "walk me through", "show me how",
    ),
    "exchange": (
        "diffie", "hellman", "key exchange", "agree on a key", "shared secret",
    ),
}

ALGORITHM_WORDS = {
    "aes": ("aes", "rijndael", "symmetric", "aes-256", "aes256"),
    "rsa": ("rsa", "public key", "public-key", "asymmetric", "private key"),
    "hybrid": ("hybrid", "rsa + aes", "rsa and aes", "envelope", "wrapped key"),
    "caesar": ("caesar", "shift cipher", "rot"),
    "vigenere": ("vigenere", "vigenère", "polyalphabetic"),
    "playfair": ("playfair", "digraph", "5x5", "key square"),
    "dh": ("diffie", "hellman", "dh"),
}

STRENGTH_HINTS = ("strong", "strongest", "secure", "safe", "best", "military",
                  "properly", "seriously", "real security")
LEARNING_HINTS = ("simple", "classic", "classical", "old", "learn", "teaching",
                  "demo", "example", "historical", "school")

QUOTED = re.compile(r'"([^"]{1,4000})"|“([^”]{1,4000})”|\'([^\']{4,4000})\'')
SHIFT = re.compile(r"(?:shift|rot|by)\s*(?:of\s*)?(\d{1,2})")
# An unqualified "key" needs an explicit separator, because "key pair" and
# "key exchange" are not keys. The longer words may stand on their own.
KEYWORD = re.compile(
    r"(?:keyword|password|passphrase|secret)\s*(?:is|are|=|:|of)?\s*"
    r"[\"']?([A-Za-z0-9!@#$%^&*_.+-]{2,64})[\"']?"
    r"|(?:key)\s*(?:is|=|:)\s*"
    r"[\"']?([A-Za-z0-9!@#$%^&*_.+-]{2,64})[\"']?",
    re.IGNORECASE)

# Words that follow "secret"/"keyword" but are plainly not the key itself.
NOT_A_KEY = {
    "with", "for", "and", "the", "using", "is", "to", "from", "of", "by",
    "pair", "exchange", "key", "keys", "that", "this", "it", "me", "my",
    "please", "then", "so", "in", "on", "a", "an",
}
MOBILE = re.compile(r"(?:\+?\d[\d\s-]{8,15}\d)")
RECIPIENT = re.compile(r"(?:to|for)\s+([A-Z][a-z]+)")
BITS = re.compile(r"(\d{3,4})\s*-?\s*bit")


def _score_intent(text: str) -> tuple[str, float, dict]:
    scores = {name: 0.0 for name in INTENTS}
    for name, words in INTENTS.items():
        for word in words:
            if word in text:
                scores[name] += 2.0 if " " in word else 1.0
    # "decrypt" contains "crypt"; make sure an explicit decode wins over encode.
    if "decrypt" in text or "decipher" in text:
        scores["encrypt"] = max(0.0, scores["encrypt"] - 1.0)
    if "explain" in text or "how does" in text or "what is" in text:
        scores["explain"] += 1.0

    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "encrypt", 0.25, scores

    # "encrypt this and explain it" is an encryption with the explain flag set,
    # not a request for a lecture. Treat a trailing "explain" as a modifier
    # unless the sentence actually opens with one.
    if best == "explain" and not text.lstrip().startswith(
            ("explain", "how do", "how does", "what is", "teach", "tell me",
             "walk me", "show me")):
        operational = {k: v for k, v in scores.items()
                       if k != "explain" and v > 0}
        if operational:
            best = max(operational, key=lambda k: operational[k])

    total = sum(scores.values()) or 1.0
    return best, round(min(0.99, 0.45 + 0.5 * scores[best] / total), 2), scores


def _pick_algorithm(text: str, intent: str) -> tuple[str, str]:
    for algo, words in ALGORITHM_WORDS.items():
        for word in words:
            if re.search(r"(?<![a-z])" + re.escape(word) + r"(?![a-z])", text):
                if algo == "rsa" and ("long" in text or "large" in text or
                                      "file" in text or "hybrid" in text):
                    return "hybrid", "RSA was named and the message sounds long, so hybrid RSA+AES fits."
                return algo, "'" + word + "' appears in your request."
    if intent == "analyse":
        return "caesar", "No cipher named - defaulting to the Caesar demo."
    if any(hint in text for hint in LEARNING_HINTS):
        return "caesar", "You asked for something simple to learn from."
    if any(hint in text for hint in STRENGTH_HINTS):
        return "aes", "You asked for strong protection, so AES-256-GCM."
    return "aes", "Nothing specific was named, so AES-256-GCM is the safe default."


def _extract_message(raw: str) -> str:
    match = QUOTED.search(raw)
    if match:
        return next(g for g in match.groups() if g is not None)
    lowered = raw.lower()
    for marker in (" saying ", " that reads ", " message: ", " text: ", ": "):
        index = lowered.find(marker)
        if index != -1:
            tail = raw[index + len(marker):].strip(" .:\"'")
            # A tail that starts with a connector is still instruction text.
            if len(tail) > 2 and not tail.lower().startswith(
                    ("and ", "to ", "with ", "using ", "for ", "then ", "so ")):
                return tail
    return ""


def parse(request: str) -> dict:
    """Turn a sentence into a plan the user can confirm."""
    raw = (request or "").strip()
    text = raw.lower()
    if not raw:
        return {
            "ok": False,
            "intent": None,
            "reply": "Tell me what you would like to do - for example "
                     "\"encrypt this for Bob with AES\".",
            "plan": [],
            "confidence": 0.0,
        }

    intent, confidence, scores = _score_intent(text)
    algorithm, reason = _pick_algorithm(text, intent)
    message = _extract_message(raw)

    params: dict = {"algorithm": algorithm}
    notes: list[str] = [reason]
    missing: list[str] = []

    keyword = KEYWORD.search(raw)
    if keyword:
        captured = keyword.group(1) or keyword.group(2) or ""
        if captured and captured.lower() not in NOT_A_KEY:
            params["key"] = captured
            params["secret"] = captured
            notes.append("Picked up the key/secret from your sentence.")

    shift = SHIFT.search(text)
    if shift and algorithm == "caesar":
        params["key"] = shift.group(1)
        notes.append("Using shift " + shift.group(1) + ".")

    if "mobile" in text or "phone" in text or "number" in text:
        mobile = MOBILE.search(raw)
        if mobile:
            params["secret"] = mobile.group(0)
        params["secret_kind"] = "mobile"
        notes.append("Deriving the key from a mobile number - PICO will flag "
                     "that this is public information.")

    recipient = RECIPIENT.search(raw)
    if recipient and recipient.group(1).lower() not in ("i", "it"):
        params["recipient"] = recipient.group(1)

    bits = BITS.search(text)
    if bits:
        value = int(bits.group(1))
        if algorithm in ("rsa", "hybrid") and value in (2048, 3072, 4096):
            params["bits"] = value
        elif algorithm == "aes" and value in (128, 192, 256):
            params["key_bits"] = value

    if "cbc" in text:
        params["aes_mode"] = "cbc"
        notes.append("You asked for CBC - PICO will warn that it is unauthenticated.")
    elif algorithm == "aes":
        params["aes_mode"] = "gcm"

    if "sign" in text or "signature" in text or "prove it came from" in text:
        params["sign"] = True
        notes.append("A digital signature was requested.")
    if "explain" in text or "step by step" in text or "show the steps" in text:
        params["explain"] = True

    if message:
        params["message"] = message
    elif intent in ("encrypt", "analyse"):
        missing.append("message" if intent == "encrypt" else "ciphertext")

    if intent == "encrypt":
        if algorithm == "aes" and "secret" not in params:
            missing.append("secret")
        if algorithm in ("rsa", "hybrid"):
            missing.append("public_pem")
        if algorithm in ("vigenere", "playfair") and "key" not in params:
            missing.append("key")
    if intent == "decrypt":
        missing.append("package")

    plan = _build_plan(intent, algorithm, params)

    return {
        "ok": True,
        "intent": intent,
        "confidence": confidence,
        "algorithm": algorithm,
        "params": params,
        "missing": sorted(set(missing)),
        "plan": plan,
        "notes": notes,
        "scores": {k: v for k, v in scores.items() if v},
        "reply": _reply(intent, algorithm, params, missing),
        "route": {"encrypt": "core.encrypt", "decrypt": "core.decrypt",
                  "generate": "core.generate_keys", "analyse": "core.analyse",
                  "explain": "core.explain_algorithm",
                  "exchange": "dh.real_exchange"}[intent],
        "disclaimer": "The agent only routes your request. All cryptography is "
                      "performed by the deterministic modules below it.",
    }


def _build_plan(intent: str, algorithm: str, params: dict) -> list[str]:
    if intent == "encrypt":
        steps = []
        if params.get("secret"):
            steps.append("Derive a key from your secret using PBKDF2 with a "
                         "fresh random salt")
        if algorithm in ("rsa", "hybrid"):
            steps.append("Load the recipient's public key and check its size")
        if algorithm == "hybrid":
            steps.append("Generate a one-time AES-256 session key")
        steps.append("Encrypt the message with " + _label(algorithm))
        if algorithm == "hybrid":
            steps.append("Wrap the session key with RSA-OAEP")
        if params.get("sign"):
            steps.append("Sign the ciphertext with your RSA private key")
        steps.append("Run the security checks and show any warnings")
        steps.append("Package the result as JSON for the receiver")
        return steps
    if intent == "decrypt":
        return ["Read the package and validate its format and checksum",
                "Recover the key from your secret plus the salt in the package",
                "Decrypt and verify the authentication tag",
                "Show the plaintext"]
    if intent == "generate":
        return ["Draw key material from the operating system CSPRNG",
                "Show the fingerprint so you can compare keys",
                "Warn if the chosen size is too small"]
    if intent == "analyse":
        return ["Count letter frequencies in the ciphertext",
                "Run the attack that fits " + _label(algorithm),
                "Rank the candidate plaintexts by English-likeness"]
    if intent == "explain":
        return ["Load the step-by-step description of " + _label(algorithm),
                "Show the formula and a worked example"]
    return ["Generate Diffie-Hellman parameters",
            "Exchange public values",
            "Derive the shared session key with HKDF"]


def _label(algorithm: str) -> str:
    return {"aes": "AES", "rsa": "RSA", "dh": "Diffie-Hellman",
            "hybrid": "RSA+AES"}.get(algorithm, algorithm.title())


def _reply(intent: str, algorithm: str, params: dict, missing: list[str]) -> str:
    human = {
        "encrypt": "encrypt your message with " + _label(algorithm),
        "decrypt": "open the package",
        "generate": "generate key material",
        "analyse": "attack that ciphertext (" + _label(algorithm) + ")",
        "explain": "explain how " + _label(algorithm) + " works",
        "exchange": "run a Diffie-Hellman key exchange",
    }[intent]
    line = "Understood - I will " + human + "."
    if missing:
        readable = {
            "message": "the message text", "ciphertext": "the ciphertext",
            "secret": "the shared secret or password",
            "public_pem": "the recipient's public key",
            "key": "the cipher keyword", "package": "the package JSON",
        }
        line += " I still need " + ", ".join(readable.get(m, m) for m in sorted(set(missing))) + "."
    else:
        line += " Ready when you confirm."
    return line
