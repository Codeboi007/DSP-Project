"""The routing layer, the package format, the advisor and the agent."""

import json

import pytest

from pico import core
from pico.agent import parser as agent
from pico.education import cryptanalysis
from pico.envelope import package as envelope
from pico.security import checks

MESSAGE = "Meet me by the old bridge at midnight. Bring the map."
PASSWORD = "tuesday-blue-42"


@pytest.fixture(scope="module")
def keypair():
    return core.generate_keys("rsa", bits=2048)


class TestEncryptDecrypt:
    def test_aes_round_trip(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD, sender="Alice",
                            recipient="Bob")
        assert core.decrypt(sent["package"], secret=PASSWORD)["plaintext"] == MESSAGE

    def test_aes_cbc_round_trip(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD, aes_mode="cbc")
        assert core.decrypt(sent["package"], secret=PASSWORD)["plaintext"] == MESSAGE

    def test_wrong_password_fails(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD)
        with pytest.raises(ValueError):
            core.decrypt(sent["package"], secret="wrong password")

    def test_raw_key_round_trip(self):
        key = core.generate_keys("aes")["key_b64"]
        sent = core.encrypt("aes", MESSAGE, key=key)
        assert core.decrypt(sent["package"], key=key)["plaintext"] == MESSAGE

    @pytest.mark.parametrize("algorithm,key", [
        ("caesar", "7"), ("vigenere", "LEMON"), ("playfair", "MONARCHY"),
    ])
    def test_classical_round_trip(self, algorithm, key):
        sent = core.encrypt(algorithm, "attack at dawn", key=key)
        opened = core.decrypt(sent["package"], key=key)["plaintext"]
        assert opened.upper().startswith("ATTACK")

    def test_caesar_shift_travels_in_the_package(self):
        sent = core.encrypt("caesar", "hello", key="11")
        assert sent["package"]["params"]["shift"] == 11
        assert core.decrypt(sent["package"])["plaintext"] == "hello"

    def test_rsa_round_trip(self, keypair):
        sent = core.encrypt("rsa", "short message", public_pem=keypair["public_pem"])
        opened = core.decrypt(sent["package"], private_pem=keypair["private_pem"])
        assert opened["plaintext"] == "short message"

    def test_hybrid_handles_a_long_message(self, keypair):
        long_message = "x" * 5000
        sent = core.encrypt("hybrid", long_message, public_pem=keypair["public_pem"])
        opened = core.decrypt(sent["package"], private_pem=keypair["private_pem"])
        assert opened["plaintext"] == long_message

    def test_hybrid_uses_a_fresh_session_key(self, keypair):
        a = core.encrypt("hybrid", "hi", public_pem=keypair["public_pem"])
        b = core.encrypt("hybrid", "hi", public_pem=keypair["public_pem"])
        assert a["package"]["params"]["wrapped_key"] != b["package"]["params"]["wrapped_key"]

    def test_signed_package_verifies(self, keypair):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD,
                            sign_private_pem=keypair["private_pem"])
        opened = core.decrypt(sent["package"], secret=PASSWORD,
                              verify_public_pem=keypair["public_pem"])
        assert opened["signature"]["valid"] is True

    def test_signature_flagged_when_unverifiable(self, keypair):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD,
                            sign_private_pem=keypair["private_pem"])
        opened = core.decrypt(sent["package"], secret=PASSWORD)
        assert opened["signature"]["checked"] is False

    def test_tampered_signature_is_caught(self, keypair):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD,
                            sign_private_pem=keypair["private_pem"])
        other = core.generate_keys("rsa", bits=2048)
        opened = core.decrypt(sent["package"], secret=PASSWORD,
                              verify_public_pem=other["public_pem"])
        assert opened["signature"]["valid"] is False
        assert any(n["code"] == "SIG001" for n in opened["notices"])

    def test_unknown_algorithm(self):
        with pytest.raises(core.PicoError, match="Unknown algorithm"):
            core.encrypt("enigma", "hi")

    def test_empty_message(self):
        with pytest.raises(core.PicoError, match="no message"):
            core.encrypt("aes", "", secret=PASSWORD)

    def test_aes_without_any_key(self):
        with pytest.raises(core.PicoError, match="personal secret"):
            core.encrypt("aes", "hi")

    def test_rsa_without_a_public_key(self):
        with pytest.raises(core.PicoError, match="public key"):
            core.encrypt("rsa", "hi")

    def test_explanations_are_optional(self):
        assert core.encrypt("aes", "hi", secret=PASSWORD)["explanation"] is None
        assert core.encrypt("aes", "hi", secret=PASSWORD,
                            explain=True)["explanation"] is not None

    def test_iv_reuse_is_flagged(self):
        first = core.encrypt("aes", "hi", secret=PASSWORD)
        reused = first["package"]["params"]["iv"]
        audit = checks.audit(algorithm="aes", iv_b64=reused, iv_history=[reused])
        assert any(f["code"] == "IV001" for f in audit["findings"])


class TestPackage:
    def test_package_never_carries_key_material(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD)
        blob = json.dumps(sent["package"]).lower()
        assert PASSWORD not in blob
        assert "key_b64" not in blob
        # "password" appears only as the kdf's 'kind' label, never as a value
        assert sent["package"]["kdf"]["kind"] == "password"
        assert "derived" not in blob

    def test_builder_refuses_key_material(self):
        with pytest.raises(ValueError, match="key material"):
            envelope.build(algorithm="aes", ciphertext="x",
                           params={"key_b64": "leaked"})

    def test_checksum_detects_edits(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD)
        package = dict(sent["package"])
        assert envelope.verify_checksum(package) is True
        package["sender"] = "Mallory"
        assert envelope.verify_checksum(package) is False

    def test_edited_package_produces_a_notice(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD)
        package = dict(sent["package"])
        package["note"] = "changed in transit"
        opened = core.decrypt(package, secret=PASSWORD)
        assert any(n["code"] == "PKG001" for n in opened["notices"])

    def test_parse_rejects_junk(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            envelope.parse("{oh no")

    def test_parse_rejects_a_foreign_format(self):
        with pytest.raises(ValueError, match="pico-package"):
            envelope.parse('{"hello": "world"}')

    def test_parse_rejects_a_future_version(self):
        with pytest.raises(ValueError, match="newer version"):
            envelope.parse(json.dumps({
                "format": "pico-package", "version": 99,
                "algorithm": "aes", "ciphertext": "x",
            }))

    def test_parse_requires_a_ciphertext(self):
        with pytest.raises(ValueError, match="ciphertext"):
            envelope.parse(json.dumps({
                "format": "pico-package", "version": 1, "algorithm": "aes",
            }))

    def test_describe_lists_what_the_receiver_needs(self):
        sent = core.encrypt("aes", MESSAGE, secret=PASSWORD)
        described = envelope.describe(sent["package"])
        assert described["has_salt"] and described["has_iv"]
        assert described["authenticated"] is True
        assert "the shared password" in " ".join(described["you_need"])


class TestSecurityAdvisor:
    def test_classical_ciphers_are_called_out(self):
        for algorithm in ("caesar", "vigenere", "playfair"):
            audit = checks.audit(algorithm=algorithm, message="hi there")
            assert audit["verdict"] == "unsafe"
            assert any(f["code"] == "ALG001" for f in audit["findings"])

    def test_good_configuration_is_sound(self):
        audit = checks.audit(algorithm="aes", mode="gcm", key_bits=256,
                             secret="correct horse battery staple 7",
                             message="a normal length message")
        assert audit["verdict"] == "sound"

    def test_common_password_is_critical(self):
        audit = checks.audit(algorithm="aes", secret="password", message="hi")
        assert any(f["code"] == "SEC002" for f in audit["findings"])

    def test_mobile_number_is_flagged(self):
        audit = checks.audit(algorithm="aes", secret="9876543210",
                             secret_kind="mobile", message="hi")
        assert any(f["code"] == "SEC010" for f in audit["findings"])

    def test_cbc_is_flagged_as_unauthenticated(self):
        audit = checks.audit(algorithm="aes", mode="cbc", key_bits=256,
                             secret="a reasonable passphrase here", message="hi")
        assert any(f["code"] == "ALG010" for f in audit["findings"])

    def test_short_rsa_is_critical(self):
        audit = checks.audit(algorithm="rsa", key_bits=1024)
        assert any(f["code"] == "ALG020" for f in audit["findings"])

    def test_oversized_rsa_message_suggests_hybrid(self):
        audit = checks.audit(algorithm="rsa", key_bits=2048, message="x" * 500)
        assert any(f["code"] == "ALG022" for f in audit["findings"])

    def test_entropy_estimate_grows_with_variety(self):
        assert checks.shannon_entropy_bits("aaaaaaaa") < \
            checks.shannon_entropy_bits("aA1!aA1!")

    def test_score_never_leaves_the_scale(self):
        for audit in (checks.audit(algorithm="caesar", secret="a", message=""),
                      checks.audit(algorithm="aes", mode="gcm", key_bits=256,
                                   secret="a long and varied passphrase!", message="hello")):
            assert 0 <= audit["score"] <= 100


class TestCryptanalysis:
    def test_caesar_is_recovered(self):
        plaintext = "the treasure is buried under the old oak tree by the river"
        from pico.ciphers import caesar
        result = cryptanalysis.attack_caesar(caesar.encrypt(plaintext, 19))
        assert result["best"]["shift"] == 19
        assert result["best"]["plaintext"] == plaintext

    @pytest.mark.parametrize("key", ["lemon", "liberty", "key", "vtu", "cipher"])
    def test_vigenere_key_is_recovered(self, key):
        from pico.ciphers import vigenere
        plaintext = ("we hold these truths to be self evident that all men are "
                     "created equal and are endowed with certain rights among "
                     "these are life and liberty")
        result = cryptanalysis.attack_vigenere(vigenere.encrypt(plaintext, key))
        assert result["recovered_key"] == key.upper()
        assert result["recovered_plaintext"] == plaintext

    def test_a_repeated_key_is_reported_in_its_shortest_form(self):
        from pico.ciphers import vigenere
        plaintext = ("the treasure is buried under the old oak tree by the river "
                     "where the water runs fastest after the spring rains")
        # ZZ and Z produce identical ciphertext, so the short form is the answer.
        result = cryptanalysis.attack_vigenere(vigenere.encrypt(plaintext, "zz"))
        assert result["recovered_key"] == "Z"
        assert result["recovered_plaintext"] == plaintext

    def test_a_long_key_on_a_short_message_is_out_of_reach(self):
        from pico.ciphers import vigenere
        # Roughly 20 letters per key letter are needed; this gives about 11.
        result = cryptanalysis.attack_vigenere(
            vigenere.encrypt("we hold these truths to be self evident that all "
                             "men are created equal", "cryptogram"))
        assert result["recovered_key"] != "CRYPTOGRAM"
        assert "caveat" in result

    def test_short_ciphertext_is_refused(self):
        result = cryptanalysis.attack_vigenere("abc")
        assert "error" in result

    def test_index_of_coincidence_separates_english_from_random(self):
        english = cryptanalysis.index_of_coincidence(
            "this is a reasonably long piece of ordinary english prose used for "
            "measuring the index of coincidence accurately")
        from pico.ciphers import vigenere
        scrambled = cryptanalysis.index_of_coincidence(
            vigenere.encrypt("this is a reasonably long piece of ordinary english "
                             "prose used for measuring the index of coincidence "
                             "accurately", "unpredictablekey"))
        assert english > scrambled

    def test_aes_has_no_attack_to_run(self):
        result = cryptanalysis.attack_aes("anything")
        assert result["candidates"] == []
        assert "what_breaks_instead" in result


class TestAgent:
    def test_empty_request(self):
        assert agent.parse("")["ok"] is False

    @pytest.mark.parametrize("request_text,intent", [
        ("encrypt this for Bob", "encrypt"),
        ("decrypt the package Bob sent me", "decrypt"),
        ("generate a new rsa key pair", "generate"),
        ("break this caesar ciphertext", "analyse"),
        ("explain how AES works", "explain"),
        ("agree on a shared secret with diffie hellman", "exchange"),
    ])
    def test_intents(self, request_text, intent):
        assert agent.parse(request_text)["intent"] == intent

    def test_algorithm_word_boundaries(self):
        # "caesar" contains the letters "aes" - it must not match AES.
        assert agent.parse("break this caesar ciphertext")["algorithm"] == "caesar"

    def test_quoted_message_is_extracted(self):
        plan = agent.parse('encrypt "meet me at dawn" with aes')
        assert plan["params"]["message"] == "meet me at dawn"

    def test_message_is_not_invented_from_instructions(self):
        plan = agent.parse("Encrypt this message and send it securely to Bob using RSA")
        assert "message" not in plan["params"]
        assert "message" in plan["missing"]

    def test_key_pair_is_not_read_as_a_key(self):
        assert "key" not in agent.parse("generate a 4096-bit rsa key pair")["params"]

    def test_explicit_key_is_picked_up(self):
        plan = agent.parse("encrypt with vigenere, keyword LEMON")
        assert plan["params"]["key"] == "LEMON"

    def test_shift_is_picked_up(self):
        plan = agent.parse('encrypt "hi" with a caesar shift of 7')
        assert plan["params"]["key"] == "7"

    def test_explain_is_a_modifier_not_an_intent(self):
        plan = agent.parse('encrypt "hi bob" with aes and explain it')
        assert plan["intent"] == "encrypt"
        assert plan["params"]["explain"] is True

    def test_long_rsa_message_routes_to_hybrid(self):
        plan = agent.parse("send a long report to Carol using rsa, it is a large file")
        assert plan["algorithm"] == "hybrid"

    def test_mobile_number_is_recognised(self):
        plan = agent.parse("encrypt my note using my mobile number 9876543210")
        assert plan["params"]["secret_kind"] == "mobile"
        assert plan["params"]["secret"] == "9876543210"

    def test_cbc_request_is_honoured_and_noted(self):
        plan = agent.parse("encrypt with aes in cbc mode")
        assert plan["params"]["aes_mode"] == "cbc"
        assert any("unauthenticated" in note for note in plan["notes"])

    def test_plan_has_steps_and_a_route(self):
        plan = agent.parse('encrypt "hi" with aes, password swordfish123')
        assert plan["plan"] and plan["route"] == "core.encrypt"

    def test_agent_performs_no_cryptography(self):
        plan = agent.parse('encrypt "top secret" with aes')
        assert "ciphertext" not in plan
        assert "only routes" in plan["disclaimer"]


class TestGenerateAndExplain:
    def test_aes_key_generation_hides_the_raw_key_object(self):
        result = core.generate_keys("aes")
        assert "key" not in result
        assert result["key_b64"]

    def test_derive_hides_the_key_entirely(self):
        result = core.generate_keys("derive", secret="tuesday-blue-42")
        # Deriving is a demonstration, not a key hand-out.
        assert "key" not in result and "key_b64" not in result
        assert result["salt_b64"] and result["fingerprint"]

    def test_derive_requires_a_secret(self):
        with pytest.raises(core.PicoError, match="secret"):
            core.generate_keys("derive")

    def test_unknown_key_kind(self):
        with pytest.raises(core.PicoError, match="Unknown key kind"):
            core.generate_keys("elliptic")

    @pytest.mark.parametrize("topic", ["caesar", "vigenere", "playfair", "aes",
                                       "rsa", "dh", "kdf"])
    def test_every_topic_explains(self, topic):
        explanation = core.explain_algorithm(topic)
        assert explanation["summary"]

    def test_unknown_topic(self):
        with pytest.raises(core.PicoError):
            core.explain_algorithm("enigma")

    def test_algorithm_catalogue(self):
        catalogue = core.list_algorithms()
        assert len(catalogue) == 6
        assert all({"id", "label", "family", "strength"} <= set(a) for a in catalogue)
