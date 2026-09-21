# PICO — Personalized Interactive Cryptographic Operations

> A cryptography toolkit with intelligent interaction, personalized key management, and a sender-receiver workflow — built on top of established, well-tested algorithms.

---

## Table of Contents

0. [Quick Start](#quick-start)
1. [What is PICO?](#1-what-is-pico)
2. [Why are we building this?](#2-why-are-we-building-this)
3. [Main Features](#3-main-features)
4. [How You Interact With It](#4-how-you-interact-with-it)
5. [Overall Architecture](#5-overall-architecture)
6. [Example User Workflow](#6-example-user-workflow)
7. [Planned Technologies](#7-planned-technologies)
8. [Future Scope](#8-future-scope)

---

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate         # macOS / Linux
pip install -r requirements.txt
```

**See the whole thing in one command** - Alice encrypts, Bob decrypts, an
attacker fails, and the same message falls instantly to a classical cipher:

```bash
python -m pico.cli demo
```

**The web console** (themes, live visualisers, agent mode, cryptanalysis):

```bash
python run.py                     # http://127.0.0.1:8000
```

**The CLI**, one subcommand per operation:

```bash
python -m pico.cli encrypt --algo aes -m "Meet me at dawn" -s "tuesday-blue-42" -o note.json
python -m pico.cli decrypt -f note.json -s "tuesday-blue-42"
python -m pico.cli keygen  --kind rsa --bits 2048 --out-dir keys --name bob
python -m pico.cli analyse --algo caesar -c "Xppe xp mj esp zwo mctorp"
python -m pico.cli agent   'encrypt "meet me at dawn" and send it securely to Bob using RSA'
python -m pico.cli explain --algo aes
python -m pico.cli exchange --real
```

Run `python -m pico.cli --help` for every option, and `pytest` for the test
suite.

### Project layout

```
pico/
  core.py            the routing layer - decides WHAT to call
  cli.py             the command line interface
  ciphers/           caesar, playfair, vigenere, aes, rsa, dh
  keys/derive.py     PBKDF2 / scrypt / HKDF key derivation
  security/checks.py the warnings engine
  envelope/          the JSON message package
  agent/parser.py    plain-English intent parsing (no cryptography)
  education/         step-by-step explanations and the attack demos
  web/               FastAPI app, plus the console's HTML, CSS and JS
tests/               pytest suite
```

---

## 1. What is PICO?

PICO is a software system that lets users **encrypt and decrypt messages, generate cryptographic keys, and explore how cryptography works** — all through a simple command-line interface (CLI) or a web browser.

The name stands for **Personalized Interactive Cryptographic Operations**.

PICO does **not** invent new cryptographic algorithms. Instead, it wraps well-established algorithms — like AES, RSA, Vigenère, and Caesar — with a friendly interaction layer that handles:

- Choosing the right algorithm for your needs
- Deriving safe cryptographic keys from personal inputs (like a password or mobile number)
- Packaging encrypted messages for a specific receiver
- Warning you when a configuration is weak or unsafe
- Optionally explaining how the algorithm works, step by step

Think of PICO as a **smart front-end for cryptography** — the actual math is always done by proven, standard modules.

---

## 2. Why Are We Building This?

Cryptography is a core topic in our course (VTU BAD703 — Data Security and Privacy), but most people only ever see it as theory or isolated code snippets. PICO brings it together into one practical, interactive project.

**Our goals:**

- Give users a hands-on way to experiment with classical and modern cryptographic algorithms
- Show how a real key-management workflow looks (instead of just hardcoding a key)
- Demonstrate a proper sender-receiver message exchange
- Make the system smart enough to warn users about bad security decisions
- Serve as an educational tool that explains what is happening under the hood

---

## 3. Main Features

### ?? Cryptographic Operations
- **Encryption & Decryption** using classical algorithms (Caesar, Playfair, Vigenère) and modern algorithms (AES, RSA, Diffie-Hellman)
- **Key Generation** — create secure keys on demand

### ?? Two Interaction Modes
- **Manual Mode** — you pick the algorithm and supply the parameters yourself
- **Agent Mode** — you describe what you want in plain English; the system figures out which operation to run

### ?? Personalized Key Derivation
- Derive a cryptographic key from a personal input such as a password, secret phrase, or mobile number
- The raw input is **never used directly as a key** — it is passed through a secure key-derivation process (e.g., PBKDF2 or HKDF)

### ?? Sender-Receiver Workflow
- A sender can encrypt a message and produce a **secure message package**
- A receiver imports the package, verifies required information, and decrypts the message
- Supports both symmetric (shared/derived key) and asymmetric (public/private key) scenarios

### ?? Security Warnings
- The system actively checks for weak keys, reused IVs/nonces, short key lengths, and inappropriate algorithm choices
- It will warn you before proceeding with an unsafe configuration

### ?? Educational Mode
- Optionally shows a step-by-step explanation of how the selected algorithm works
- Demonstrates basic cryptanalysis (e.g., frequency analysis on Caesar cipher) to illustrate why some algorithms are insecure

---

## 4. How You Interact With It

### Manual Mode

You choose every detail yourself.

```
> Select algorithm: AES
> Key source: derive from password
> Enter password: mySecretPass123
> Enter message: Hello, World!

[PICO] Deriving key using PBKDF2...
[PICO] Encrypting with AES-256-CBC...
[PICO] Done. Encrypted package saved to: package_20260921.json
```

### Agent Mode

You describe what you want in plain language.

```
> What do you want to do?
  "Encrypt this message and send it securely to Bob using RSA."

[PICO] Understood. I will:
  1. Generate an RSA key pair for you
  2. Encrypt the message with Bob's public key
  3. Package the ciphertext for Bob to decrypt with his private key

Proceed? (yes/no): yes
```

> **Note:** The agent layer only **understands and routes** your request. All cryptographic operations are performed by separate, deterministic modules — the agent never does the math itself.

---

## 5. Overall Architecture

```
+---------------------------------------------------------+
¦                      User Interfaces                     ¦
¦              CLI  --------------  Web UI                 ¦
+---------------------------------------------------------+
                        ¦
          +-------------?--------------+
          ¦      Interaction Layer      ¦
          ¦  +----------+ +----------+ ¦
          ¦  ¦  Manual  ¦ ¦  Agent   ¦ ¦
          ¦  ¦   Mode   ¦ ¦  Mode    ¦ ¦
          ¦  +----------+ +----------+ ¦
          +-------+------------+-------+
                  ¦            ¦
                  +------------+
                        ¦ routes to
          +-------------?--------------+
          ¦     Cryptographic Modules   ¦
          ¦  Caesar ¦ Playfair ¦ Vigenère¦
          ¦  AES    ¦ RSA      ¦ DH      ¦
          +----------------------------+
                        ¦
          +-------------?--------------+
          ¦   Key Management & Security ¦
          ¦  Key Derivation (PBKDF2)    ¦
          ¦  Security Checks & Warnings ¦
          +-----------------------------+
```

**Key design principle:** The agent/interaction layer only decides *what* to call. The cryptographic modules decide *how* to compute it. These two concerns are kept strictly separate.

---

## 6. Example User Workflow

### Scenario: Alice sends a secret message to Bob using AES

**Step 1 — Alice (Sender)**
1. Alice opens PICO and chooses "Encrypt a message"
2. She enters her shared password with Bob: `"tuesday-blue-42"`
3. PICO derives an AES-256 key from this password using PBKDF2 (with a random salt)
4. PICO encrypts the message and packages it as `message_for_bob.json`
   - This file contains: ciphertext, salt, IV, and algorithm metadata
   - It does **not** contain the password or the raw key

**Step 2 — Bob (Receiver)**
1. Bob receives `message_for_bob.json` and opens it in PICO
2. PICO reads the salt and IV from the package
3. Bob enters the shared password: `"tuesday-blue-42"`
4. PICO re-derives the same AES key and decrypts the message
5. Bob sees the original plaintext

---

### Scenario: RSA public-key exchange

1. Bob generates an RSA key pair and shares his **public key** with Alice
2. Alice encrypts her message using Bob's public key
3. Only Bob's **private key** can decrypt it
4. PICO demonstrates each step and optionally explains how RSA achieves this

---

## 7. Planned Technologies

| Component | Technology |
|---|---|
| Programming Language | Python |
| Classical Crypto | Custom implementations (for learning) |
| Modern Crypto | `cryptography` library (AES, RSA, PBKDF2, etc.) |
| Agent / NLP Layer | Rule-based parser or lightweight LLM integration |
| CLI Interface | `argparse` / `click` |
| Web Interface | Flask or FastAPI + HTML/CSS/JS |
| Message Packaging | JSON |
| Testing | `pytest` |

> The `cryptography` library (by PyCA) is used for all production-grade operations. We do not rely on self-written AES or RSA math for actual security.

---

## 8. Future Scope

- **Digital Signatures** — sign messages so the receiver can verify the sender's identity
- **Steganography** — hide encrypted messages inside image files
- **Cryptanalysis Demos** — automated attacks on weak ciphers (brute force, frequency analysis) for educational use
- **User Accounts** — save and manage personal key configurations securely
- **Group Messaging** — extend the sender-receiver model to multi-party scenarios
- **Real-time Chat** — an end-to-end encrypted chat demo using the existing modules

---

## Project Context

This project is developed as part of **VTU BAD703 — Data Security and Privacy**.

It covers the following course topics in a practical, integrated way:

- Classical cryptography (Caesar, Playfair, Vigenère)
- Symmetric cryptography (AES, DES)
- Public-key cryptography (RSA, Diffie-Hellman)
- Key management and key derivation
- Cryptanalysis fundamentals

---

*PICO does not claim to provide novel cryptographic security. It is an educational and practical tool built on top of established, peer-reviewed algorithms and libraries.*
