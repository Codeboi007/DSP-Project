"""The HTTP layer, exercised through FastAPI's TestClient."""

import json

import pytest
from fastapi.testclient import TestClient

from pico.web.app import app

MESSAGE = "Meet me by the old bridge at midnight."
PASSWORD = "tuesday-blue-42"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def keypair(client):
    return client.post("/api/keys", json={"kind": "rsa", "bits": 2048}).json()


class TestPages:
    def test_index_serves_the_console(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "PICO" in response.text
        assert "globe-canvas" in response.text

    def test_static_assets(self, client):
        for path in ("/static/css/pico.css", "/static/js/app.js",
                     "/static/js/api.js", "/static/js/ui.js",
                     "/static/js/viz.js", "/static/js/globe.js"):
            assert client.get(path).status_code == 200

    def test_health(self, client):
        body = client.get("/api/health").json()
        assert body["ok"] is True and body["service"] == "pico"

    def test_algorithms(self, client):
        body = client.get("/api/algorithms").json()
        assert len(body["algorithms"]) == 6


class TestEncryptEndpoint:
    def test_aes_round_trip(self, client):
        sent = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": MESSAGE, "secret": PASSWORD,
            "sender": "Alice", "recipient": "Bob",
        }).json()
        assert sent["ok"] is True

        opened = client.post("/api/decrypt", json={
            "package": sent["package"], "secret": PASSWORD,
        }).json()
        assert opened["plaintext"] == MESSAGE
        assert opened["authenticated"] is True

    def test_wrong_secret_returns_400(self, client):
        sent = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": MESSAGE, "secret": PASSWORD,
        }).json()
        response = client.post("/api/decrypt", json={
            "package": sent["package"], "secret": "nope",
        })
        assert response.status_code == 400
        assert "Authentication failed" in response.json()["detail"]

    def test_package_as_a_json_string(self, client):
        sent = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": MESSAGE, "secret": PASSWORD,
        }).json()
        opened = client.post("/api/decrypt", json={
            "package": json.dumps(sent["package"]), "secret": PASSWORD,
        }).json()
        assert opened["plaintext"] == MESSAGE

    def test_hybrid_round_trip(self, client, keypair):
        sent = client.post("/api/encrypt", json={
            "algorithm": "hybrid", "message": "x" * 2000,
            "public_pem": keypair["public_pem"],
        }).json()
        opened = client.post("/api/decrypt", json={
            "package": sent["package"], "private_pem": keypair["private_pem"],
        }).json()
        assert opened["plaintext"] == "x" * 2000

    def test_signature_verification(self, client, keypair):
        sent = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": MESSAGE, "secret": PASSWORD,
            "sign_private_pem": keypair["private_pem"],
        }).json()
        opened = client.post("/api/decrypt", json={
            "package": sent["package"], "secret": PASSWORD,
            "verify_public_pem": keypair["public_pem"],
        }).json()
        assert opened["signature"]["valid"] is True

    @pytest.mark.parametrize("algorithm,key", [
        ("caesar", "7"), ("vigenere", "LEMON"), ("playfair", "MONARCHY"),
    ])
    def test_classical_round_trip(self, client, algorithm, key):
        sent = client.post("/api/encrypt", json={
            "algorithm": algorithm, "message": "attack at dawn", "key": key,
        }).json()
        opened = client.post("/api/decrypt", json={
            "package": sent["package"], "key": key,
        }).json()
        assert opened["plaintext"].upper().startswith("ATTACK")

    def test_bad_algorithm_returns_400(self, client):
        response = client.post("/api/encrypt",
                               json={"algorithm": "enigma", "message": "hi"})
        assert response.status_code == 400

    def test_missing_key_returns_400(self, client):
        response = client.post("/api/encrypt",
                               json={"algorithm": "aes", "message": "hi"})
        assert response.status_code == 400

    def test_malformed_package_returns_400(self, client):
        response = client.post("/api/decrypt", json={"package": "not json"})
        assert response.status_code == 400

    def test_oversized_message_is_rejected_by_validation(self, client):
        response = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": "x" * 200_001, "secret": PASSWORD,
        })
        assert response.status_code == 422


class TestOtherEndpoints:
    def test_audit_reports_entropy(self, client):
        body = client.post("/api/audit", json={
            "algorithm": "aes", "secret": "123", "message": "hi",
            "mode": "cbc", "key_bits": 128,
        }).json()
        assert body["verdict"] == "unsafe"
        assert "entropy_bits" in body

    def test_keys_aes(self, client):
        body = client.post("/api/keys", json={"kind": "aes", "key_bits": 256}).json()
        assert body["bits"] == 256 and body["key_b64"]

    def test_keys_derive_never_returns_the_key(self, client):
        body = client.post("/api/keys", json={
            "kind": "derive", "secret": PASSWORD,
        }).json()
        assert "key_b64" not in body and "key" not in body
        assert body["salt_b64"]

    def test_analyse_caesar(self, client):
        body = client.post("/api/analyse", json={
            "ciphertext": "Buubdl bu ebxo", "algorithm": "caesar",
        }).json()
        assert body["best"]["shift"] == 1
        assert len(body["frequencies"]) == 26

    def test_analyse_unsupported_algorithm(self, client):
        response = client.post("/api/analyse", json={
            "ciphertext": "abc", "algorithm": "playfair",
        })
        assert response.status_code == 400

    def test_agent(self, client):
        body = client.post("/api/agent", json={
            "request": 'encrypt "hi bob" with aes and explain it',
        }).json()
        assert body["intent"] == "encrypt"
        assert body["route"] == "core.encrypt"

    def test_explain(self, client):
        body = client.post("/api/explain", json={"algorithm": "rsa"}).json()
        assert body["steps"] and "factoring" in body["summary"]

    def test_exchange_toy_and_real(self, client):
        assert client.post("/api/exchange", json={"mode": "toy"}).json()["agreed"]
        assert client.post("/api/exchange", json={"mode": "real"}).json()["agreed"]

    def test_inspect_does_not_decrypt(self, client):
        sent = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": MESSAGE, "secret": PASSWORD,
        }).json()
        body = client.post("/api/package/inspect",
                           json={"package": sent["package"]}).json()
        assert body["describe"]["checksum_ok"] is True
        assert "plaintext" not in body

    def test_visual_endpoints(self, client):
        table = client.get("/api/visual/vigenere").json()["table"]
        assert len(table) == 26

        square = client.get("/api/visual/playfair?key=MONARCHY").json()["square"]
        assert square[0] == list("MONAR")

    def test_preview(self, client):
        body = client.post("/api/preview", json={
            "algorithm": "caesar", "message": "HELLO", "key": "3",
        }).json()
        assert body["ciphertext"] == "KHOOR"

    def test_preview_rejects_modern_algorithms(self, client):
        response = client.post("/api/preview",
                               json={"algorithm": "aes", "message": "hi"})
        assert response.status_code == 400

    def test_preview_reports_a_bad_key(self, client):
        response = client.post("/api/preview", json={
            "algorithm": "vigenere", "message": "hi", "key": "123",
        })
        assert response.status_code == 400


class TestNoSecretsLeak:
    def test_no_endpoint_echoes_the_password(self, client, keypair):
        calls = [
            ("/api/encrypt", {"algorithm": "aes", "message": MESSAGE,
                              "secret": PASSWORD}),
            ("/api/audit", {"algorithm": "aes", "secret": PASSWORD,
                            "message": MESSAGE}),
            ("/api/keys", {"kind": "derive", "secret": PASSWORD}),
        ]
        for path, body in calls:
            text = client.post(path, json=body).text
            assert PASSWORD not in text, path

    def test_private_key_never_comes_back_from_encrypt(self, client, keypair):
        text = client.post("/api/encrypt", json={
            "algorithm": "aes", "message": MESSAGE, "secret": PASSWORD,
            "sign_private_pem": keypair["private_pem"],
        }).text
        assert "PRIVATE KEY" not in text
