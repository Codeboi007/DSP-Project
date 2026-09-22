# keys/

Where PICO writes the key pairs you generate.

```bash
python -m pico.cli keygen --kind rsa --bits 2048 --out-dir keys --name bob
```

That produces two files:

| File | What it is | Who gets it |
|---|---|---|
| `bob_public.pem` | Bob's public key | Give it to anyone who wants to send Bob a message |
| `bob_private.pem` | Bob's private key | Bob only. It never leaves this machine |

Then use them:

```bash
# Alice encrypts for Bob using his public key
python -m pico.cli encrypt --algo hybrid --message-file letter.txt \
    --public-key-file keys/bob_public.pem -o letter.json

# Bob opens it with his private key
python -m pico.cli decrypt -f letter.json --private-key-file keys/bob_private.pem
```

Protect a private key with a passphrase when you generate it:

```bash
python -m pico.cli keygen --kind rsa --out-dir keys --name bob --passphrase "..."
python -m pico.cli decrypt -f letter.json --private-key-file keys/bob_private.pem \
    --passphrase "..."
```

## This folder is not committed

`.gitignore` tracks this README and ignores everything else here, so generated
`.pem` files never reach the repository. On POSIX systems PICO also sets the
private key to mode `600` (owner read/write only).

Nothing in a PICO message package ever contains a private key, a password or a
derived key — only the ciphertext and the public parameters needed to reverse
it (salt, IV, tag, wrapped session key).
