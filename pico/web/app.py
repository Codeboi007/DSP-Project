"""The PICO web console - a thin HTTP layer over ``pico.core``.

Every endpoint validates its input, calls the same routing layer the CLI uses,
and returns JSON. No cryptography happens in this file.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from pico import __version__, core
from pico.agent import parser as agent
from pico.ciphers import dh, playfair, vigenere
from pico.envelope import package as envelope
from pico.security import checks

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
TEMPLATES = HERE / "templates"

app = FastAPI(
    title="PICO",
    description="Personalized Interactive Cryptographic Operations",
    version=__version__,
    docs_url="/api/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.exception_handler(core.PicoError)
async def pico_error_handler(request: Request, exc: core.PicoError):
    return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})


def _guard(fn, *args, **kwargs):
    """Run a core call and turn its errors into clean 400s."""
    try:
        return fn(*args, **kwargs)
    except (core.PicoError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EncryptRequest(BaseModel):
    algorithm: str = "aes"
    message: str = Field(default="", max_length=200_000)
    key: str = ""
    secret: str = ""
    secret_kind: str = "password"
    kdf: str = "pbkdf2"
    aes_mode: str = "gcm"
    key_bits: int = 256
    public_pem: str = ""
    sender: str = ""
    recipient: str = ""
    note: str = ""
    explain: bool = True
    sign_private_pem: str = ""
    sign_passphrase: str = ""
    iv_history: list[str] = Field(default_factory=list)


class DecryptRequest(BaseModel):
    package: dict | str
    secret: str = ""
    key: str = ""
    private_pem: str = ""
    passphrase: str = ""
    verify_public_pem: str = ""
    explain: bool = True


class KeyRequest(BaseModel):
    kind: str = "aes"
    bits: int = 2048
    key_bits: int = 256
    secret: str = ""
    secret_kind: str = "password"
    kdf: str = "pbkdf2"
    passphrase: str = ""


class AuditRequest(BaseModel):
    algorithm: str = ""
    secret: str = ""
    secret_kind: str = "password"
    message: str = ""
    mode: str | None = None
    key_bits: int | None = None


class AnalyseRequest(BaseModel):
    ciphertext: str = Field(default="", max_length=100_000)
    algorithm: str = "caesar"


class AgentRequest(BaseModel):
    request: str = Field(default="", max_length=4000)


class ExplainRequest(BaseModel):
    algorithm: str = "aes"
    message: str = ""
    key: str = ""
    mode: str = "gcm"
    bits: int = 2048
    kdf: str = "pbkdf2"
    key_bits: int = 256


class ExchangeRequest(BaseModel):
    mode: str = "toy"


class PreviewRequest(BaseModel):
    algorithm: str = "caesar"
    message: str = Field(default="", max_length=5000)
    key: str = ""


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((TEMPLATES / "index.html").read_text(encoding="utf-8"))


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "service": "pico", "version": __version__}


@app.get("/api/algorithms")
async def algorithms() -> dict:
    return {"ok": True, "algorithms": core.list_algorithms()}


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

@app.post("/api/encrypt")
async def encrypt(body: EncryptRequest) -> dict:
    return _guard(
        core.encrypt,
        body.algorithm, body.message, key=body.key, secret=body.secret,
        secret_kind=body.secret_kind, kdf=body.kdf, aes_mode=body.aes_mode,
        key_bits=body.key_bits, public_pem=body.public_pem, sender=body.sender,
        recipient=body.recipient, note=body.note, explain=body.explain,
        sign_private_pem=body.sign_private_pem,
        sign_passphrase=body.sign_passphrase, iv_history=body.iv_history)


@app.post("/api/decrypt")
async def decrypt(body: DecryptRequest) -> dict:
    return _guard(
        core.decrypt, body.package, secret=body.secret, key=body.key,
        private_pem=body.private_pem, passphrase=body.passphrase,
        verify_public_pem=body.verify_public_pem, explain=body.explain)


@app.post("/api/keys")
async def keys(body: KeyRequest) -> dict:
    result = _guard(core.generate_keys, body.kind, bits=body.bits,
                    secret=body.secret, secret_kind=body.secret_kind,
                    kdf=body.kdf, key_bits=body.key_bits,
                    passphrase=body.passphrase)
    return {"ok": True, **result}


@app.post("/api/audit")
async def audit(body: AuditRequest) -> dict:
    result = checks.audit(algorithm=body.algorithm, secret=body.secret,
                          secret_kind=body.secret_kind, message=body.message,
                          mode=body.mode, key_bits=body.key_bits)
    result["entropy_bits"] = checks.shannon_entropy_bits(body.secret)
    return {"ok": True, **result}


@app.post("/api/analyse")
async def analyse(body: AnalyseRequest) -> dict:
    result = _guard(core.analyse, body.ciphertext, body.algorithm)
    return {"ok": True, **result}


@app.post("/api/agent")
async def agent_route(body: AgentRequest) -> dict:
    return agent.parse(body.request)


@app.post("/api/explain")
async def explain(body: ExplainRequest) -> dict:
    result = _guard(core.explain_algorithm, body.algorithm,
                    message=body.message, key=body.key, mode=body.mode,
                    bits=body.bits, kdf=body.kdf, key_bits=body.key_bits)
    return {"ok": True, **result}


@app.post("/api/exchange")
async def exchange(body: ExchangeRequest) -> dict:
    result = dh.real_exchange() if body.mode == "real" else dh.toy_exchange()
    return {"ok": True, **result}


@app.post("/api/package/inspect")
async def inspect(body: DecryptRequest) -> dict:
    pkg = _guard(envelope.parse, body.package)
    return {"ok": True, "package": pkg, "describe": envelope.describe(pkg)}


# ---------------------------------------------------------------------------
# Visualiser data
# ---------------------------------------------------------------------------

@app.get("/api/visual/vigenere")
async def visual_vigenere() -> dict:
    return {"ok": True, "table": vigenere.tabula_recta()}


@app.get("/api/visual/playfair")
async def visual_playfair(key: str = "MONARCHY") -> dict:
    return {"ok": True, "square": playfair.build_square(key),
            "key": key.upper()}


@app.post("/api/preview")
async def preview(body: PreviewRequest) -> dict:
    """A live, un-packaged encryption used by the visualisers as you type."""
    algorithm = body.algorithm.lower()
    if algorithm not in ("caesar", "vigenere", "playfair"):
        raise HTTPException(status_code=400,
                            detail="Preview is only available for the classical ciphers.")
    try:
        if algorithm == "caesar":
            shift = int(body.key or 3)
            from pico.ciphers import caesar
            return {"ok": True, "ciphertext": caesar.encrypt(body.message, shift),
                    "explain": caesar.explain(body.message, shift, limit=14)}
        if algorithm == "vigenere":
            key = body.key or "LEMON"
            return {"ok": True, "ciphertext": vigenere.encrypt(body.message, key),
                    "explain": vigenere.explain(body.message, key, limit=14),
                    "keystream": vigenere.keystream(body.message, key)}
        key = body.key or "MONARCHY"
        return {"ok": True, "ciphertext": playfair.encrypt(body.message, key),
                "explain": playfair.explain(body.message, key, limit=12)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
