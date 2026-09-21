"""AES, RSA, Diffie-Hellman and key derivation."""

import pytest

from pico.ciphers import aes, dh, rsa
from pico.keys import derive


@pytest.fixture(scope="module")
def key32():
    return derive.derive_key("a strong test passphrase")["key"]


@pytest.fixture(scope="module")
def keypair():
    return rsa.generate_keypair(2048)


class TestDerive:
    def test_same_salt_gives_the_same_key(self):
        first = derive.derive_key("tuesday-blue-42")
        second = derive.derive_key("tuesday-blue-42", first["salt"])
        assert first["key"] == second["key"]

    def test_different_salts_give_different_keys(self):
        a = derive.derive_key("tuesday-blue-42")
        b = derive.derive_key("tuesday-blue-42")
        assert a["salt"] != b["salt"]
        assert a["key"] != b["key"]

    def test_every_kdf_produces_the_requested_length(self):
        for kdf in derive.KDFS:
            for length in (16, 24, 32):
                result = derive.derive_key("secret", length=length, kdf=kdf)
                assert len(result["key"]) == length

    def test_mobile_numbers_are_normalised(self):
        salt = derive.random_salt()
        a = derive.derive_key("+91 98765 43210", salt, kind="mobile")
        b = derive.derive_key("9876543210", salt, kind="mobile")
        assert a["key"] == b["key"]

    def test_phrase_normalisation_folds_case_and_spacing(self):
        salt = derive.random_salt()
        a = derive.derive_key("Three  Random Words", salt, kind="phrase")
        b = derive.derive_key("three random words", salt, kind="phrase")
        assert a["key"] == b["key"]

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError):
            derive.derive_key("")

    def test_unknown_kdf_rejected(self):
        with pytest.raises(ValueError):
            derive.derive_key("secret", kdf="md5")

    def test_bad_length_rejected(self):
        with pytest.raises(ValueError):
            derive.derive_key("secret", length=13)

    def test_random_key_is_random(self):
        assert derive.random_key()["key"] != derive.random_key()["key"]


class TestAes:
    MESSAGE = "Meet me by the old bridge — bring the map. ✓"

    @pytest.mark.parametrize("mode", ["gcm", "cbc"])
    def test_round_trip(self, key32, mode):
        sealed = aes.encrypt(self.MESSAGE, key32, mode=mode)
        opened = aes.decrypt(sealed["ciphertext_b64"], key32, sealed["iv_b64"],
                             mode=mode, tag_b64=sealed["tag_b64"])
        assert opened == self.MESSAGE

    def test_fresh_iv_every_time(self, key32):
        first = aes.encrypt("same message", key32)
        second = aes.encrypt("same message", key32)
        assert first["iv_b64"] != second["iv_b64"]
        assert first["ciphertext_b64"] != second["ciphertext_b64"]

    def test_gcm_rejects_a_wrong_key(self, key32):
        sealed = aes.encrypt("secret", key32)
        other = derive.random_key()["key"]
        with pytest.raises(ValueError, match="Authentication failed"):
            aes.decrypt(sealed["ciphertext_b64"], other, sealed["iv_b64"],
                        tag_b64=sealed["tag_b64"])

    def test_gcm_detects_tampering(self, key32):
        sealed = aes.encrypt("transfer 100 rupees", key32)
        raw = bytearray(derive.b64d(sealed["ciphertext_b64"]))
        raw[0] ^= 0x01
        with pytest.raises(ValueError, match="Authentication failed"):
            aes.decrypt(derive.b64e(bytes(raw)), key32, sealed["iv_b64"],
                        tag_b64=sealed["tag_b64"])

    def test_gcm_needs_its_tag(self, key32):
        sealed = aes.encrypt("secret", key32)
        with pytest.raises(ValueError, match="authentication tag"):
            aes.decrypt(sealed["ciphertext_b64"], key32, sealed["iv_b64"])

    def test_cbc_is_not_authenticated(self, key32):
        sealed = aes.encrypt("secret", key32, mode="cbc")
        assert sealed["authenticated"] is False
        assert sealed["tag_b64"] is None

    def test_empty_message_round_trips(self, key32):
        sealed = aes.encrypt("", key32)
        assert aes.decrypt(sealed["ciphertext_b64"], key32, sealed["iv_b64"],
                           tag_b64=sealed["tag_b64"]) == ""

    def test_bad_key_size_rejected(self):
        with pytest.raises(ValueError, match="16, 24 or 32"):
            aes.encrypt("hi", b"too short")

    def test_unknown_mode_rejected(self, key32):
        with pytest.raises(ValueError, match="Unknown AES mode"):
            aes.encrypt("hi", key32, mode="ecb")

    def test_all_three_key_sizes(self):
        for length in (16, 24, 32):
            key = derive.random_key(length)["key"]
            sealed = aes.encrypt("hello", key)
            assert str(length * 8) in sealed["algorithm"]
            assert aes.decrypt(sealed["ciphertext_b64"], key, sealed["iv_b64"],
                               tag_b64=sealed["tag_b64"]) == "hello"


class TestRsa:
    def test_round_trip(self, keypair):
        sealed = rsa.encrypt("hi bob", keypair["public_pem"])
        assert rsa.decrypt(sealed["ciphertext_b64"], keypair["private_pem"]) == "hi bob"

    def test_oaep_is_randomised(self, keypair):
        a = rsa.encrypt("hi", keypair["public_pem"])["ciphertext_b64"]
        b = rsa.encrypt("hi", keypair["public_pem"])["ciphertext_b64"]
        assert a != b

    def test_message_too_long_is_refused(self, keypair):
        with pytest.raises(ValueError, match="hybrid"):
            rsa.encrypt("x" * 400, keypair["public_pem"])

    def test_wrong_private_key_fails(self, keypair):
        sealed = rsa.encrypt("hi", keypair["public_pem"])
        other = rsa.generate_keypair(2048)
        with pytest.raises(ValueError, match="not encrypted for this key"):
            rsa.decrypt(sealed["ciphertext_b64"], other["private_pem"])

    def test_small_keys_refused(self):
        with pytest.raises(ValueError, match="2048"):
            rsa.generate_keypair(1024)

    def test_key_wrapping(self, keypair):
        session = derive.random_key()["key"]
        wrapped = rsa.wrap_key(session, keypair["public_pem"])
        assert rsa.unwrap_key(wrapped, keypair["private_pem"]) == session

    def test_signature_round_trip(self, keypair):
        signature = rsa.sign("the message", keypair["private_pem"])
        assert rsa.verify("the message", signature, keypair["public_pem"]) is True

    def test_signature_rejects_a_changed_message(self, keypair):
        signature = rsa.sign("pay 100", keypair["private_pem"])
        assert rsa.verify("pay 900", signature, keypair["public_pem"]) is False

    def test_signature_rejects_a_different_signer(self, keypair):
        signature = rsa.sign("hi", keypair["private_pem"])
        other = rsa.generate_keypair(2048)
        assert rsa.verify("hi", signature, other["public_pem"]) is False

    def test_passphrase_protection(self):
        pair = rsa.generate_keypair(2048, passphrase="open sesame")
        assert pair["protected"] is True
        with pytest.raises(ValueError, match="passphrase-protected"):
            rsa.load_private(pair["private_pem"])
        assert rsa.load_private(pair["private_pem"], "open sesame") is not None

    def test_malformed_pem_rejected(self):
        with pytest.raises(ValueError, match="valid RSA public key"):
            rsa.load_public("not a key")

    def test_fingerprint_is_stable(self, keypair):
        assert rsa.fingerprint(keypair["public_pem"]) == keypair["fingerprint"]


class TestDiffieHellman:
    def test_toy_exchange_agrees(self):
        result = dh.toy_exchange(6, 15)
        assert result["agreed"] is True
        assert result["alice_shared"] == result["bob_shared"]

    def test_toy_maths_is_correct(self):
        result = dh.toy_exchange(6, 15)
        expected = pow(result["g"], 6 * 15, result["p"])
        assert result["alice_shared"] == expected

    def test_toy_is_random_without_arguments(self):
        assert dh.toy_exchange()["alice_private"] != dh.toy_exchange()["alice_private"]

    def test_real_exchange_agrees(self):
        result = dh.real_exchange()
        assert result["agreed"] is True
        assert result["prime_bits"] == 2048
        assert len(derive.b64d(result["session_key_b64"])) == 32
