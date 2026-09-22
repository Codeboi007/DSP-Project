"""PICO's command line interface.

    python -m pico.cli encrypt --algo aes --message "hi" --secret "pass"
    python -m pico.cli demo
    python -m pico.cli serve
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from pico import __version__, core
from pico.agent import parser as agent
from pico.agent import wizard
from pico.ciphers import dh
from pico.envelope import package as envelope

# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------

_USE_COLOUR = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()
if os.name == "nt" and _USE_COLOUR:
    os.system("")  # ask the Windows console to honour ANSI escapes


def _c(code: str, text: str) -> str:
    return "\033[" + code + "m" + text + "\033[0m" if _USE_COLOUR else text


def bold(t): return _c("1", t)
def dim(t): return _c("2", t)
def cyan(t): return _c("96", t)
def green(t): return _c("92", t)
def yellow(t): return _c("93", t)
def red(t): return _c("91", t)
def blue(t): return _c("94", t)


LEVEL_STYLE = {"critical": (red, "!!"), "warning": (yellow, " !"),
               "info": (blue, " i"), "ok": (green, " +")}

BANNER = r"""
  ____  ___ ____ ___
 |  _ \|_ _/ ___/ _ \    Personalized Interactive
 | |_) || | |  | | | |   Cryptographic Operations
 |  __/ | | |__| |_| |
 |_|   |___\____\___/    v""" + __version__ + """
"""


def rule(title: str = "") -> None:
    width = 68
    if title:
        print(dim("-- " + title + " " + "-" * max(0, width - len(title) - 4)))
    else:
        print(dim("-" * width))


def show_audit(audit: dict) -> None:
    verdict_style = {"unsafe": red, "risky": yellow, "sound": green}[audit["verdict"]]
    rule("security check")
    print("  " + verdict_style(bold(audit["verdict"].upper())) +
          "  score " + str(audit["score"]) + "/100 - " + audit["headline"])
    for item in audit["findings"]:
        style, mark = LEVEL_STYLE[item["level"]]
        print("  " + style(mark) + " " + bold(item["title"]))
        print("     " + dim(item["detail"]))
        if item["fix"]:
            print("     " + cyan("fix: " + item["fix"]))


def show_explanation(explanation: dict | None) -> None:
    if not explanation:
        return
    rule("how it works")
    title = explanation.get("algorithm") or explanation.get("kdf", "")
    if title:
        print("  " + bold(title.upper() if len(title) <= 6 else title))
    print("  " + explanation.get("summary", ""))
    if explanation.get("formula"):
        print("  " + cyan(explanation["formula"]))
    for step in explanation.get("steps", [])[:8]:
        if "name" in step:
            print("   - " + bold(step["name"]) + ": " + step.get("what", ""))
        else:
            print("   - " + str(step.get("input", "")) + " -> " +
                  str(step.get("output", "")) + dim("   " + str(step.get("math", ""))))
    for key in ("mode_note", "iv_note", "limits", "why", "note", "caveat"):
        if explanation.get(key):
            print("  " + dim(explanation[key]))


def _read_secret(args, prompt: str = "Secret: ") -> str:
    if getattr(args, "secret", None):
        return args.secret
    if getattr(args, "ask_secret", False) or sys.stdin.isatty():
        return getpass.getpass(prompt)
    return ""


def _read_source(inline: str | None, path: str | None, what: str) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    if inline:
        return inline
    raise SystemExit(red("Provide " + what + " inline or with a file path."))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_encrypt(args) -> int:
    message = _read_source(args.message, args.message_file, "a message")
    secret = ""
    if args.algo == "aes" and not args.key:
        secret = _read_secret(args)
    public_pem = ""
    if args.algo in ("rsa", "hybrid"):
        public_pem = _read_source(args.public_key, args.public_key_file,
                                  "the recipient's public key")

    result = core.encrypt(
        args.algo, message, key=args.key or "", secret=secret,
        secret_kind=args.secret_kind, kdf=args.kdf, aes_mode=args.mode,
        key_bits=args.key_bits, public_pem=public_pem, sender=args.sender,
        recipient=args.recipient, note=args.note, explain=args.explain)

    rule("encrypted")
    print("  algorithm : " + bold(result["algorithm"]))
    print("  ciphertext: " + cyan(result["ciphertext"][:120]) +
          (dim(" ...") if len(result["ciphertext"]) > 120 else ""))
    if result["key_info"]:
        print("  key       : " + dim(json.dumps(result["key_info"])))
    show_audit(result["audit"])
    show_explanation(result["explanation"])

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(result["package_json"])
        rule("package")
        print("  saved to " + green(args.out))
        print("  " + dim("Contains: " + ", ".join(result["describe"]["carries"])))
        print("  " + dim("Never contains: " +
                         ", ".join(result["describe"]["never_carries"])))
    elif args.json:
        print(result["package_json"])
    else:
        rule("package")
        print(dim("  (pass --out FILE to save, or --json to print the package)"))
    return 0


def cmd_decrypt(args) -> int:
    text = _read_source(args.package, args.package_file, "a package")
    secret = ""
    private_pem = ""
    pkg = envelope.parse(text)
    if pkg["algorithm"] in ("rsa", "hybrid"):
        private_pem = _read_source(args.private_key, args.private_key_file,
                                   "your private key")
    elif pkg["algorithm"] == "aes" and not args.key:
        secret = _read_secret(args)

    rule("package")
    info = envelope.describe(pkg)
    print("  from      : " + info["sender"] + "  ->  " + info["recipient"])
    print("  algorithm : " + bold(info["algorithm"]) + "   created " + info["created"])
    print("  checksum  : " + (green("ok") if info["checksum_ok"] else red("MISMATCH")))
    print("  you need  : " + ", ".join(info["you_need"]))

    result = core.decrypt(
        pkg, secret=secret, key=args.key or "", private_pem=private_pem,
        passphrase=args.passphrase or "", verify_public_pem=args.verify_with or "",
        explain=args.explain)

    rule("plaintext")
    print("  " + green(result["plaintext"]))
    if result["authenticated"]:
        print("  " + dim("The authentication tag verified - this message was not altered."))
    if result["signature"]:
        style = green if result["signature"]["valid"] else (
            yellow if result["signature"]["valid"] is None else red)
        print("  " + style(result["signature"]["message"]))
    for notice in result["notices"]:
        fn, mark = LEVEL_STYLE[notice["level"]]
        print("  " + fn(mark + " " + notice["title"]) + " - " + dim(notice["detail"]))
    show_explanation(result["explanation"])
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(result["plaintext"])
        print("  saved to " + green(args.out))
    return 0


def cmd_keygen(args) -> int:
    secret = args.secret or (_read_secret(args) if args.kind == "derive" else "")
    result = core.generate_keys(args.kind, bits=args.bits, secret=secret,
                                secret_kind=args.secret_kind, kdf=args.kdf,
                                key_bits=args.key_bits,
                                passphrase=args.passphrase or "")
    rule("generated")
    if args.kind == "rsa":
        print("  RSA-" + str(result["bits"]) + "   fingerprint " + cyan(result["fingerprint"]))
        print("  max direct plaintext: " + str(result["max_plaintext_bytes"]) + " bytes")
        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)
            pub = os.path.join(args.out_dir, args.name + "_public.pem")
            priv = os.path.join(args.out_dir, args.name + "_private.pem")
            with open(pub, "w", encoding="utf-8") as handle:
                handle.write(result["public_pem"])
            with open(priv, "w", encoding="utf-8") as handle:
                handle.write(result["private_pem"])
            os.chmod(priv, 0o600)
            print("  public  -> " + green(pub))
            print("  private -> " + green(priv) + dim("  (keep this one)"))
        else:
            print(result["public_pem"])
            print(dim("  (pass --out-dir DIR to save both halves to disk)"))
    elif args.kind == "derive":
        print("  kdf         : " + bold(result["kdf"]) + "  " + dim(json.dumps(result["params"])))
        print("  salt        : " + result["salt_b64"] + dim("   (store this, it is not secret)"))
        print("  fingerprint : " + cyan(result["fingerprint"]))
        print("  " + dim(result["explain"]["summary"]))
    else:
        print("  random AES-" + str(result["bits"]) + " key")
        print("  key         : " + cyan(result["key_b64"]))
        print("  fingerprint : " + result["fingerprint"])
    show_audit(result["audit"])
    return 0


def cmd_analyse(args) -> int:
    ciphertext = _read_source(args.ciphertext, args.ciphertext_file, "a ciphertext")
    result = core.analyse(ciphertext, args.algo)
    rule("cryptanalysis: " + result["target"])
    print("  attack : " + bold(result["attack"]))
    if result.get("error"):
        print("  " + red(result["error"]))
        return 1
    print("  effort : " + result.get("effort", "-"))
    if args.algo == "caesar":
        print()
        for row in result["candidates"][:8]:
            marker = green(" <- best fit") if row["rank"] == 1 else ""
            print("   shift " + str(row["shift"]).rjust(2) + "  score " +
                  str(row["score"]).rjust(8) + "  " + row["plaintext"][:44] + marker)
    elif args.algo == "vigenere":
        print("  index of coincidence: " + str(result["ciphertext_ic"]) +
              dim("   (english " + str(result["english_ic"]) +
                  ", random " + str(result["random_ic"]) + ")"))
        print("  key length guesses  : " +
              ", ".join(str(r["length"]) + " (ic " + str(r["ic"]) + ")"
                        for r in result["key_lengths"][:4]))
        print("  recovered key       : " + bold(green(result["recovered_key"])))
        print("  plaintext           : " + result["recovered_plaintext"][:120])
    else:
        print("  key space: " + result["key_space"])
        for item in result.get("what_breaks_instead", []):
            print("   - " + item)
    print()
    print("  " + yellow(result["verdict"]))
    print("  " + dim(result["lesson"]))
    return 0


def cmd_explain(args) -> int:
    explanation = core.explain_algorithm(args.algo, message=args.message,
                                         key=args.key, mode=args.mode)
    show_explanation(explanation)
    return 0


def cmd_agent(args) -> int:
    # ── Initial request ──────────────────────────────────────────────────
    if getattr(args, "request", None):
        request = " ".join(args.request)
    else:
        print(cyan(BANNER))
        print(dim("  ── PICO Agent " + "─" * 52))
        print()
        print("  " + cyan("◆") + "  " + bold("What would you like to do?") +
              dim("  (describe it in plain English)"))
        print()
        print("  " + dim("Examples:"))
        for ex in (
            "encrypt a message using AES",
            "decrypt this package",
            "generate an RSA key pair",
            "crack this Caesar cipher",
            "explain how RSA works",
            "run a Diffie-Hellman exchange",
        ):
            print("  " + dim("  •  " + ex))
        print()
        try:
            request = input("  " + green("›") + "  ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 130

    if not request:
        print("  " + yellow("Nothing to do."))
        return 0

    # ── Parse intent ─────────────────────────────────────────────────────
    plan = agent.parse(request)

    if not plan.get("ok") or (plan.get("confidence") or 0) < 0.2:
        print()
        print("  " + yellow("◆") + "  I didn't quite catch that.")
        print("  " + dim("Try phrasing it like one of the examples above."))
        return 1

    # ── Hand off to the interactive wizard ───────────────────────────────
    return wizard.run(plan)


def cmd_exchange(args) -> int:
    if args.real:
        result = dh.real_exchange()
        rule("diffie-hellman (2048-bit MODP)")
        print("  prime size    : " + str(result["prime_bits"]) + " bits")
        print("  raw secret    : " + str(result["raw_secret_bytes"]) + " bytes")
        print("  session key   : " + cyan(result["session_key_b64"]))
        print("  both agree    : " + (green("yes") if result["agreed"] else red("no")))
        print("  " + dim(result["note"]))
    else:
        result = dh.toy_exchange()
        rule("diffie-hellman (toy numbers)")
        for step in result["steps"]:
            print("   " + step)
        print()
        print("  both agree: " + (green("yes") if result["agreed"] else red("no")))
        print("  " + yellow(result["warning"]))
    return 0


def cmd_demo(args) -> int:
    """The README's Alice-and-Bob walkthrough, start to finish."""
    print(cyan(BANNER))
    password = "tuesday-blue-42"
    message = "Meet me by the old bridge at midnight. Bring the map."

    rule("step 1 - alice encrypts")
    print("  Alice's message : " + message)
    print("  Shared password : " + password + dim("   (never leaves her machine)"))
    sent = core.encrypt("aes", message, secret=password, sender="Alice",
                        recipient="Bob", note="See you tonight.", explain=True)
    print("  Cipher          : " + bold(sent["package"]["params"]["cipher"]))
    print("  Salt            : " + sent["package"]["kdf"]["salt"])
    print("  IV              : " + sent["package"]["params"]["iv"])
    print("  Ciphertext      : " + cyan(sent["ciphertext"][:64]) + dim("..."))
    show_audit(sent["audit"])

    rule("step 2 - the package travels")
    print("  " + dim("This JSON is what Bob receives. Anyone may read it."))
    preview = dict(sent["package"])
    preview["ciphertext"] = preview["ciphertext"][:40] + "..."
    print("  " + json.dumps(preview, indent=2).replace("\n", "\n  "))

    rule("step 3 - bob decrypts")
    opened = core.decrypt(sent["package"], secret=password)
    print("  Bob types the shared password and PICO re-derives the same key.")
    print("  Plaintext : " + green(opened["plaintext"]))
    print("  " + dim("The GCM tag verified, so the message was not altered."))

    rule("step 4 - an attacker tries")
    try:
        core.decrypt(sent["package"], secret="tuesday-blue-43")
    except ValueError as exc:
        print("  Wrong password -> " + red(str(exc)))

    tampered = json.loads(sent["package_json"])
    body = list(tampered["ciphertext"])
    body[5] = "A" if body[5] != "A" else "B"
    tampered["ciphertext"] = "".join(body)
    try:
        core.decrypt(tampered, secret=password)
    except ValueError as exc:
        print("  Flipped one character -> " + red(str(exc)))

    rule("step 5 - the same message with a classical cipher")
    weak = core.encrypt("caesar", message, key="7")
    print("  Caesar ciphertext : " + weak["ciphertext"][:56] + dim("..."))
    cracked = core.analyse(weak["ciphertext"], "caesar")
    print("  Attack result     : shift " + bold(str(cracked["best"]["shift"])) +
          " -> " + red(cracked["best"]["plaintext"][:56]) + dim("..."))
    print("  " + yellow("Broken in 25 guesses, with no key at all."))

    rule("step 6 - public key, no shared password")
    keys = core.generate_keys("rsa", bits=2048)
    print("  Bob's key         : RSA-2048  fingerprint " + cyan(keys["fingerprint"]))
    hybrid = core.encrypt("hybrid", message, public_pem=keys["public_pem"],
                          sender="Alice", recipient="Bob")
    print("  Wrapped key       : " + dim(hybrid["package"]["params"]["wrapped_key"][:48] + "..."))
    back = core.decrypt(hybrid["package"], private_pem=keys["private_pem"])
    print("  Bob decrypts      : " + green(back["plaintext"]))
    print("  " + dim("Alice and Bob never agreed on a password in advance."))

    rule()
    print("  Run " + bold("python -m pico.cli serve") + " for the interactive web version.")
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    print(cyan(BANNER))
    print("  Serving the PICO console on " +
          bold("http://" + args.host + ":" + str(args.port)))
    uvicorn.run("pico.web.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level="warning")
    return 0


# ---------------------------------------------------------------------------
# Argument wiring
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pico",
        description="PICO - Personalized Interactive Cryptographic Operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Start with:  python -m pico.cli demo")
    ap.add_argument("--version", action="version", version="PICO " + __version__)
    sub = ap.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a message into a package")
    enc.add_argument("--algo", default="aes", choices=list(core.ALGORITHMS))
    enc.add_argument("-m", "--message")
    enc.add_argument("--message-file")
    enc.add_argument("-k", "--key", help="cipher key (classical) or base64 AES key")
    enc.add_argument("-s", "--secret", help="personal secret to derive the key from")
    enc.add_argument("--ask-secret", action="store_true", help="prompt for the secret")
    enc.add_argument("--secret-kind", default="password",
                     choices=["password", "phrase", "mobile"])
    enc.add_argument("--kdf", default="pbkdf2", choices=["pbkdf2", "scrypt", "hkdf"])
    enc.add_argument("--mode", default="gcm", choices=["gcm", "cbc"])
    enc.add_argument("--key-bits", type=int, default=256, choices=[128, 192, 256])
    enc.add_argument("--public-key", help="recipient public key, inline PEM")
    enc.add_argument("--public-key-file")
    enc.add_argument("--sender", default="")
    enc.add_argument("--recipient", default="")
    enc.add_argument("--note", default="")
    enc.add_argument("-o", "--out", help="write the package to this file")
    enc.add_argument("--json", action="store_true", help="print the package JSON")
    enc.add_argument("--explain", action="store_true")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="open a package")
    dec.add_argument("--package", help="package JSON inline")
    dec.add_argument("-f", "--package-file")
    dec.add_argument("-k", "--key")
    dec.add_argument("-s", "--secret")
    dec.add_argument("--ask-secret", action="store_true")
    dec.add_argument("--private-key")
    dec.add_argument("--private-key-file")
    dec.add_argument("--passphrase")
    dec.add_argument("--verify-with", help="sender public key, to check a signature")
    dec.add_argument("-o", "--out")
    dec.add_argument("--explain", action="store_true")
    dec.set_defaults(func=cmd_decrypt)

    gen = sub.add_parser("keygen", help="generate keys")
    gen.add_argument("--kind", default="aes", choices=["aes", "rsa", "derive"])
    gen.add_argument("--bits", type=int, default=2048, choices=[2048, 3072, 4096])
    gen.add_argument("--key-bits", type=int, default=256, choices=[128, 192, 256])
    gen.add_argument("-s", "--secret")
    gen.add_argument("--ask-secret", action="store_true")
    gen.add_argument("--secret-kind", default="password",
                     choices=["password", "phrase", "mobile"])
    gen.add_argument("--kdf", default="pbkdf2", choices=["pbkdf2", "scrypt", "hkdf"])
    gen.add_argument("--passphrase", help="encrypt the private key with this")
    gen.add_argument("--out-dir")
    gen.add_argument("--name", default="pico")
    gen.set_defaults(func=cmd_keygen)

    ana = sub.add_parser("analyse", aliases=["analyze"], help="attack a ciphertext")
    ana.add_argument("--algo", default="caesar", choices=["caesar", "vigenere", "aes"])
    ana.add_argument("-c", "--ciphertext")
    ana.add_argument("--ciphertext-file")
    ana.set_defaults(func=cmd_analyse)

    exp = sub.add_parser("explain", help="how an algorithm works")
    exp.add_argument("--algo", default="aes",
                     choices=["caesar", "vigenere", "playfair", "aes", "rsa", "dh", "kdf"])
    exp.add_argument("-m", "--message", default="")
    exp.add_argument("-k", "--key", default="")
    exp.add_argument("--mode", default="gcm")
    exp.set_defaults(func=cmd_explain)

    agt = sub.add_parser("agent", help="describe what you want in plain English")
    agt.add_argument("request", nargs="*")
    agt.set_defaults(func=cmd_agent)

    exc = sub.add_parser("exchange", help="run a Diffie-Hellman exchange")
    exc.add_argument("--real", action="store_true", help="use a 2048-bit group")
    exc.set_defaults(func=cmd_exchange)

    dem = sub.add_parser("demo", help="the full Alice and Bob walkthrough")
    dem.set_defaults(func=cmd_demo)

    srv = sub.add_parser("serve", help="start the web console")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8000)
    srv.add_argument("--reload", action="store_true")
    srv.set_defaults(func=cmd_serve)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except core.PicoError as exc:
        print(red("  " + str(exc)))
        return 2
    except ValueError as exc:
        print(red("  " + str(exc)))
        return 2
    except FileNotFoundError as exc:
        print(red("  File not found: " + str(exc.filename)))
        return 2
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
