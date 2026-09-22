"""pico/agent/wizard.py

Interactive guided wizard for PICO's Agent Mode.

Flow
----
1. Show what the parser understood (intent, algorithm, confidence).
2. For every missing required parameter, ask a friendly plain-English
   question — one at a time.
3. Collect a small set of optional extras (sender, recipient, explain,
   save path).
4. Print a plain-English confirmation summary and wait for [Y/n].
5. Call the appropriate pico.core function and display the result using
   the same colour style as the rest of the CLI.

No cryptography happens here.  The wizard only routes.
"""

from __future__ import annotations

import getpass
import json
import os
import sys

from pico import core
from pico.ciphers import dh as _dh

# ---------------------------------------------------------------------------
# Colour helpers (same palette as cli.py, self-contained to avoid circular
# imports — cli imports wizard, so wizard cannot import cli)
# ---------------------------------------------------------------------------

_USE_COLOUR = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()
if os.name == "nt" and _USE_COLOUR:
    os.system("")   # enable ANSI on Windows console


def _c(code: str, text: str) -> str:
    return "\033[" + code + "m" + text + "\033[0m" if _USE_COLOUR else text


def bold(t: str) -> str:   return _c("1",  t)
def dim(t: str) -> str:    return _c("2",  t)
def cyan(t: str) -> str:   return _c("96", t)
def green(t: str) -> str:  return _c("92", t)
def yellow(t: str) -> str: return _c("93", t)
def red(t: str) -> str:    return _c("91", t)
def blue(t: str) -> str:   return _c("94", t)

AGENT  = cyan("◆")          # agent "speaks"
PROMPT = green("›")          # user input marker
_W     = 66                  # ruler width


# ---------------------------------------------------------------------------
# Low-level printing helpers
# ---------------------------------------------------------------------------

def _say(*parts: str) -> None:
    """One line of agent speech."""
    print("  " + AGENT + "  " + " ".join(parts))


def _hint(text: str) -> None:
    print("     " + dim(text))


def _rule(title: str = "") -> None:
    if title:
        pad = max(0, _W - len(title) - 4)
        print("  " + dim("── " + title + " " + "─" * pad))
    else:
        print("  " + dim("─" * _W))


def _blank() -> None:
    print()


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def _ask(
    prompt: str,
    *,
    secret: bool = False,
    hint: str = "",
    multiline: bool = False,
    optional: bool = False,
    default: str = "",
) -> str:
    """Print a question and return the user's answer."""
    _blank()
    _say(bold(prompt))
    if hint:
        _hint(hint)
    if optional:
        _hint("Optional — press Enter to skip.")
    if default and not optional:
        _hint(f"Default: {default}  (press Enter to accept)")
    _blank()

    if multiline:
        _hint("Paste your text, then press Enter on a blank line to finish.")
        lines: list[str] = []
        while True:
            try:
                line = input("  " + PROMPT + "  ")
            except (EOFError, KeyboardInterrupt):
                raise KeyboardInterrupt
            if line == "" and lines:
                break
            lines.append(line)
        return "\n".join(lines).strip()

    if secret:
        try:
            return getpass.getpass("  " + PROMPT + "  ")
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt

    try:
        value = input("  " + PROMPT + "  ").strip()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt
    return value or default


# ---------------------------------------------------------------------------
# Per-parameter question catalogue
# ---------------------------------------------------------------------------

_QUESTIONS: dict[str, dict] = {
    "message": dict(
        prompt="What is the message you want to encrypt?",
        hint="",
        secret=False, multiline=False, optional=False,
    ),
    "ciphertext": dict(
        prompt="Paste the ciphertext you want to work with:",
        hint="Just the encrypted text — nothing else.",
        secret=False, multiline=False, optional=False,
    ),
    "secret": dict(
        prompt="What password or phrase should I derive the key from?",
        hint=(
            "This never leaves your machine. "
            "Only the derived key (and its salt) travel in the package."
        ),
        secret=True, multiline=False, optional=False,
    ),
    "key": dict(
        prompt="What is the cipher keyword?",
        hint="Letters only — e.g. LEMON for Vigenère or MONARCHY for Playfair.",
        secret=False, multiline=False, optional=False,
    ),
    "public_pem": dict(
        prompt="Paste the recipient's public key (PEM format):",
        hint="Starts with  -----BEGIN PUBLIC KEY-----",
        secret=False, multiline=True, optional=False,
    ),
    "private_pem": dict(
        prompt="Paste your private key (PEM format):",
        hint="Starts with  -----BEGIN RSA PRIVATE KEY-----  or  -----BEGIN PRIVATE KEY-----",
        secret=False, multiline=True, optional=False,
    ),
    "package": dict(
        prompt="Paste the package JSON you received:",
        hint="The full JSON block that was sent to you.",
        secret=False, multiline=True, optional=False,
    ),
}


# ---------------------------------------------------------------------------
# Optional extras — asked after all required fields are filled
# ---------------------------------------------------------------------------

def _collect_extras(intent: str, algorithm: str, params: dict) -> dict:
    extras: dict = {}

    if intent == "encrypt":
        if not params.get("sender"):
            v = _ask("Who is sending this?", optional=True)
            if v:
                extras["sender"] = v

        if not params.get("recipient"):
            v = _ask("Who is the recipient?", optional=True)
            if v:
                extras["recipient"] = v

        v = _ask(
            "Show a step-by-step explanation of how the algorithm works?",
            hint="y / n",
            default="n",
        )
        extras["explain"] = v.lower().startswith("y")

        v = _ask(
            "Save the encrypted package to a file?",
            hint="Enter a filename such as  message.json  — or press Enter to skip.",
            optional=True,
        )
        if v:
            extras["out"] = v.strip()

    elif intent == "decrypt":
        v = _ask(
            "Show how the decryption works?",
            hint="y / n",
            default="n",
        )
        extras["explain"] = v.lower().startswith("y")

        v = _ask(
            "Save the recovered plaintext to a file?",
            hint="Enter a filename — or press Enter to skip.",
            optional=True,
        )
        if v:
            extras["out"] = v.strip()

    elif intent == "generate":
        if algorithm == "rsa":
            v = _ask(
                "RSA key size?",
                hint="2048 / 3072 / 4096  — 2048 is standard and fast.",
                default="2048",
            )
            try:
                extras["bits"] = int(v) if v else 2048
            except ValueError:
                extras["bits"] = 2048

            v = _ask(
                "Save the key pair to a folder?",
                hint="Enter a path like  keys/  — or press Enter to skip.",
                optional=True,
            )
            if v:
                extras["out_dir"] = v.strip()
                name = _ask("Base name for the files?", default="pico")
                extras["name"] = name or "pico"

    elif intent == "exchange":
        v = _ask(
            "Which mode?",
            hint=(
                "toy  — tiny numbers, every step printed (educational)\n"
                "     real — 2048-bit MODP group (cryptographic)"
            ),
            default="toy",
        )
        extras["real"] = v.lower().startswith("r")

    return extras


# ---------------------------------------------------------------------------
# Confirmation summary
# ---------------------------------------------------------------------------

_ALGO_LABEL = {
    "aes":     "AES-256-GCM",
    "rsa":     "RSA-OAEP (SHA-256)",
    "hybrid":  "RSA + AES  (hybrid — recommended for long messages)",
    "caesar":  "Caesar cipher",
    "vigenere":"Vigenère cipher",
    "playfair":"Playfair cipher",
    "dh":      "Diffie-Hellman",
}


def _show_summary(intent: str, algorithm: str, params: dict, extras: dict) -> None:
    _blank()
    _rule("ready to execute")
    _say(bold("Here is exactly what I am about to do:"))
    _blank()

    rows: list[tuple[str, str]] = [("Operation", intent)]
    if algorithm:
        rows.append(("Algorithm", _ALGO_LABEL.get(algorithm, algorithm.upper())))

    if params.get("secret"):
        rows.append(("Key source", "derived from your password  (PBKDF2 · 390 000 rounds)"))
    elif params.get("key"):
        rows.append(("Key source", "keyword you provided"))
    elif algorithm in ("rsa", "hybrid"):
        rows.append(("Key source", "recipient's RSA public key"))

    sender = extras.get("sender") or params.get("sender") or ""
    if sender:
        rows.append(("Sender", sender))

    recipient = extras.get("recipient") or params.get("recipient") or ""
    if recipient:
        rows.append(("Recipient", recipient))

    if extras.get("explain"):
        rows.append(("Explain", "yes — step-by-step shown after"))

    if extras.get("bits") and intent == "generate":
        rows.append(("Key size", str(extras["bits"]) + " bits"))

    save = extras.get("out") or extras.get("out_dir") or ""
    if save:
        rows.append(("Save to", save))
    elif intent in ("encrypt", "generate"):
        rows.append(("Save to", dim("(not saved — you can add a path when asked)")))

    col_w = max(len(r[0]) for r in rows) + 2
    for label, value in rows:
        print("     " + cyan(label.ljust(col_w)) + value)
    _blank()


# ---------------------------------------------------------------------------
# Result display (mirrors cli.py's style)
# ---------------------------------------------------------------------------

_LEVELS = {
    "critical": (red,    "!!"),
    "warning":  (yellow, " !"),
    "info":     (blue,   " i"),
    "ok":       (green,  " +"),
}


def _show_audit(audit: dict) -> None:
    verdict_fn = {"unsafe": red, "risky": yellow, "sound": green}[audit["verdict"]]
    _rule("security check")
    print(
        "  " + verdict_fn(bold(audit["verdict"].upper())) +
        "  score " + str(audit["score"]) + "/100 — " + audit["headline"]
    )
    for item in audit["findings"]:
        style, mark = _LEVELS[item["level"]]
        print("  " + style(mark) + " " + bold(item["title"]))
        print("     " + dim(item["detail"]))
        if item.get("fix"):
            print("     " + cyan("fix: " + item["fix"]))


def _show_explanation(exp: dict | None) -> None:
    if not exp:
        return
    _rule("how it works")
    title = exp.get("algorithm") or exp.get("kdf", "")
    if title:
        print("  " + bold(title.upper() if len(title) <= 6 else title))
    print("  " + exp.get("summary", ""))
    if exp.get("formula"):
        print("  " + cyan(exp["formula"]))
    for step in exp.get("steps", [])[:8]:
        if "name" in step:
            print("   - " + bold(step["name"]) + ": " + step.get("what", ""))
        else:
            print("   - " + str(step.get("input", "")) + " → " +
                  str(step.get("output", "")) + dim("   " + str(step.get("math", ""))))
    for key in ("mode_note", "iv_note", "limits", "why", "note", "caveat"):
        if exp.get(key):
            print("  " + dim(exp[key]))


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _execute(intent: str, algorithm: str, params: dict, extras: dict) -> int:  # noqa: C901
    _blank()
    _rule("executing")
    _blank()

    try:
        # ── ENCRYPT ────────────────────────────────────────────────────────
        if intent == "encrypt":
            result = core.encrypt(
                algorithm,
                params.get("message", ""),
                key=params.get("key", ""),
                secret=params.get("secret", ""),
                secret_kind=params.get("secret_kind", "password"),
                kdf=params.get("kdf", "pbkdf2"),
                aes_mode=params.get("aes_mode", "gcm"),
                key_bits=int(params.get("key_bits", 256)),
                public_pem=params.get("public_pem", ""),
                sender=extras.get("sender", params.get("sender", "")),
                recipient=extras.get("recipient", params.get("recipient", "")),
                note=params.get("note", ""),
                explain=extras.get("explain", False),
            )
            _rule("encrypted")
            print("  algorithm : " + bold(result["algorithm"]))
            ct = result["ciphertext"]
            print("  ciphertext: " + cyan(ct[:88]) + (dim(" ...") if len(ct) > 88 else ""))
            if result.get("key_info"):
                print("  key info  : " + dim(json.dumps(result["key_info"])))
            _show_audit(result["audit"])
            _show_explanation(result.get("explanation"))
            _blank()

            out = extras.get("out")
            if out:
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(result["package_json"])
                _say(green("Package saved → " + bold(out)))
                _hint("Carries: " + ", ".join(result["describe"]["carries"]))
                _hint("Never carries: " + ", ".join(result["describe"]["never_carries"]))
            else:
                _say(dim("Tip: next time answer the save question with a filename "
                         "so Bob can open the package directly."))

        # ── DECRYPT ────────────────────────────────────────────────────────
        elif intent == "decrypt":
            result = core.decrypt(
                params.get("package", ""),
                secret=params.get("secret", ""),
                key=params.get("key", ""),
                private_pem=params.get("private_pem", ""),
                passphrase=params.get("passphrase", ""),
                explain=extras.get("explain", False),
            )
            _rule("plaintext")
            print("  " + green(result["plaintext"]))
            if result.get("authenticated"):
                print("  " + dim("The authentication tag verified — message was not altered."))
            sig = result.get("signature")
            if sig:
                fn = green if sig["valid"] else (
                    yellow if sig["valid"] is None else red)
                print("  " + fn(sig["message"]))
            for notice in result.get("notices", []):
                fn, mark = _LEVELS[notice["level"]]
                print("  " + fn(mark + " " + notice["title"]) +
                      " — " + dim(notice["detail"]))
            _show_explanation(result.get("explanation"))
            out = extras.get("out")
            if out:
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(result["plaintext"])
                _say(green("Saved → " + bold(out)))

        # ── GENERATE ───────────────────────────────────────────────────────
        elif intent == "generate":
            kind = algorithm   # "aes" | "rsa" | "derive"
            result = core.generate_keys(
                kind,
                bits=int(extras.get("bits", params.get("bits", 2048))),
                secret=params.get("secret", ""),
                secret_kind=params.get("secret_kind", "password"),
                kdf=params.get("kdf", "pbkdf2"),
                key_bits=int(params.get("key_bits", 256)),
            )
            _rule("generated")
            if kind == "rsa":
                print("  RSA-" + str(result["bits"]) +
                      "   fingerprint " + cyan(result["fingerprint"]))
                print("  max direct plaintext: " +
                      str(result["max_plaintext_bytes"]) + " bytes")
                out_dir = extras.get("out_dir")
                name    = extras.get("name", "pico")
                if out_dir:
                    os.makedirs(out_dir, exist_ok=True)
                    pub  = os.path.join(out_dir, name + "_public.pem")
                    priv = os.path.join(out_dir, name + "_private.pem")
                    for path, content in ((pub, result["public_pem"]),
                                          (priv, result["private_pem"])):
                        with open(path, "w", encoding="utf-8") as fh:
                            fh.write(content)
                    os.chmod(priv, 0o600)
                    print("  public  → " + green(pub))
                    print("  private → " + green(priv) + dim("  (keep this one)"))
                else:
                    print(result["public_pem"])
                    _say(dim("Answer the save question next time to write both files to disk."))
            elif kind == "derive":
                print("  kdf         : " + bold(result["kdf"]) +
                      "  " + dim(json.dumps(result["params"])))
                print("  salt        : " + result["salt_b64"] +
                      dim("   (store this alongside the ciphertext)"))
                print("  fingerprint : " + cyan(result["fingerprint"]))
                _say(dim(result["explain"]["summary"]))
            else:
                print("  random AES-" + str(result["bits"]) + " key")
                print("  key         : " + cyan(result["key_b64"]))
                print("  fingerprint : " + result["fingerprint"])
            _show_audit(result["audit"])

        # ── ANALYSE ────────────────────────────────────────────────────────
        elif intent == "analyse":
            result = core.analyse(
                params.get("ciphertext", ""),
                params.get("algorithm", "caesar"),
            )
            _rule("cryptanalysis: " + result["target"])
            print("  attack : " + bold(result["attack"]))
            if result.get("error"):
                print("  " + red(result["error"]))
                return 1
            algo = params.get("algorithm", "caesar")
            if algo == "caesar":
                _blank()
                for row in result["candidates"][:8]:
                    marker = green("  ← best fit") if row["rank"] == 1 else ""
                    print("   shift " + str(row["shift"]).rjust(2) +
                          "  score " + str(row["score"]).rjust(8) +
                          "  " + row["plaintext"][:44] + marker)
            elif algo == "vigenere":
                print("  index of coincidence : " + str(result["ciphertext_ic"]))
                print("  recovered key        : " + bold(green(result["recovered_key"])))
                print("  plaintext            : " + result["recovered_plaintext"][:120])
            _blank()
            print("  " + yellow(result["verdict"]))
            print("  " + dim(result["lesson"]))

        # ── EXPLAIN ────────────────────────────────────────────────────────
        elif intent == "explain":
            result = core.explain_algorithm(params.get("algorithm", "aes"))
            _show_explanation(result)

        # ── EXCHANGE (Diffie-Hellman) ──────────────────────────────────────
        elif intent == "exchange":
            if extras.get("real"):
                result = _dh.real_exchange()
                _rule("diffie-hellman (2048-bit MODP)")
                print("  prime size  : " + str(result["prime_bits"]) + " bits")
                print("  session key : " + cyan(result["session_key_b64"]))
                print("  both agree  : " +
                      (green("yes") if result["agreed"] else red("no")))
                print("  " + dim(result["note"]))
            else:
                result = _dh.toy_exchange()
                _rule("diffie-hellman (toy numbers)")
                for step in result["steps"]:
                    print("   " + step)
                _blank()
                print("  both agree: " +
                      (green("yes") if result["agreed"] else red("no")))
                print("  " + yellow(result["warning"]))

        else:
            _say(red("I don't know how to execute intent '" + intent + "'."))
            return 2

    except core.PicoError as exc:
        _blank()
        _say(red(str(exc)))
        return 2
    except ValueError as exc:
        _blank()
        _say(red(str(exc)))
        return 2

    _blank()
    _rule()
    _say(dim("Done.  Run  python -m pico.cli serve  for the interactive web console."))
    return 0


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(plan: dict) -> int:
    """Drive the full wizard loop for one parsed plan.

    Parameters
    ----------
    plan:
        The dict returned by ``pico.agent.parser.parse``.

    Returns
    -------
    int
        Exit code (0 = success, 2 = error, 130 = cancelled).
    """
    intent    = plan.get("intent") or "encrypt"
    algorithm = plan.get("algorithm", "aes")
    params    = dict(plan.get("params") or {})
    missing   = list(plan.get("missing") or [])

    # ── Show what was understood ──────────────────────────────────────────
    _blank()
    _rule("understood")
    _say(bold(plan.get("reply", "")))
    for note in (plan.get("notes") or [])[:2]:
        _hint(note)
    confidence = int((plan.get("confidence") or 0) * 100)
    print("  " + dim(f"  confidence {confidence}%   →   {plan.get('route', '-')}"))
    _blank()
    _say(dim(plan.get("disclaimer", "")))

    # ── Collect required missing parameters ───────────────────────────────
    if missing:
        _blank()
        _rule("collecting inputs")

    try:
        for field in missing:
            spec = _QUESTIONS.get(field)
            if spec is None:
                continue
            value = _ask(**spec)
            if not value:
                _blank()
                _say(red("That field is required. Aborting."))
                return 2
            params[field] = value

        # ── Collect optional extras ───────────────────────────────────────
        _blank()
        _rule("a few more details")
        extras = _collect_extras(intent, algorithm, params)

    except KeyboardInterrupt:
        _blank()
        _say(yellow("Cancelled."))
        return 130

    # ── Confirmation ──────────────────────────────────────────────────────
    _show_summary(intent, algorithm, params, extras)

    try:
        answer = input("  Proceed?  [Y/n]  " + PROMPT + "  ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        _blank()
        _say(yellow("Cancelled."))
        return 130

    if answer and not answer.startswith("y"):
        _say(yellow("Cancelled."))
        return 130

    # ── Execute ───────────────────────────────────────────────────────────
    return _execute(intent, algorithm, params, extras)
