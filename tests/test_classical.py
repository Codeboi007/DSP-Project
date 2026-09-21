"""The classical ciphers, checked against textbook vectors."""

import pytest

from pico.ciphers import caesar, playfair, vigenere


class TestCaesar:
    def test_known_vector(self):
        assert caesar.encrypt("Hello, World!", 3) == "Khoor, Zruog!"

    def test_round_trip(self):
        text = "The quick brown fox jumps over the lazy dog."
        for shift in range(26):
            assert caesar.decrypt(caesar.encrypt(text, shift), shift) == text

    def test_case_and_punctuation_survive(self):
        assert caesar.encrypt("aA zZ 1!", 1) == "bB aA 1!"

    def test_shift_wraps(self):
        assert caesar.encrypt("abc", 26) == "abc"
        assert caesar.encrypt("abc", 27) == caesar.encrypt("abc", 1)
        assert caesar.encrypt("abc", -1) == caesar.encrypt("abc", 25)

    def test_brute_force_finds_the_shift(self):
        plaintext = "the treasure is buried under the old oak tree at midnight"
        cipher = caesar.encrypt(plaintext, 19)
        assert caesar.brute_force(cipher)[0]["plaintext"] == plaintext

    def test_frequency_analysis_sums_to_100(self):
        rows = caesar.frequency_analysis("hello world")
        assert len(rows) == 26
        assert abs(sum(row["percent"] for row in rows) - 100) < 0.5

    def test_explain_traces_each_letter(self):
        trace = caesar.explain("AB", 3)
        assert trace["steps"][0]["output"] == "D"
        assert trace["steps"][1]["math"] == "(1 + 3) mod 26 = 4"


class TestVigenere:
    def test_known_vector(self):
        assert vigenere.encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"

    def test_round_trip_with_spacing(self):
        text = "Attack at dawn, bring the map!"
        assert vigenere.decrypt(vigenere.encrypt(text, "lemon"), "lemon") == text

    def test_key_only_advances_on_letters(self):
        # Spaces must not consume key letters, or the two sides desync.
        assert vigenere.encrypt("AB", "LE") == vigenere.encrypt("A B", "LE").replace(" ", "")

    def test_key_is_normalised(self):
        assert vigenere.encrypt("ATTACK", "lemon") == vigenere.encrypt("ATTACK", "L E M O N!")

    def test_empty_key_rejected(self):
        with pytest.raises(ValueError):
            vigenere.encrypt("ATTACK", "123")

    def test_tabula_recta_shape(self):
        table = vigenere.tabula_recta()
        assert len(table) == 26 and len(table[0]) == 26
        assert table[0][0] == "A" and table[1][0] == "B" and table[25][25] == "Y"


class TestPlayfair:
    KEY = "playfair example"

    def test_known_vector(self):
        assert playfair.encrypt("hide the gold in the tree stump", self.KEY) == \
            "BMODZBXDNABEKUDMUIXMMOUVIF"

    def test_round_trip(self):
        # The padding that made the pairs even stays in the recovered text -
        # Playfair cannot tell a padding X from a real one.
        cipher = playfair.encrypt("hide the gold", self.KEY)
        assert playfair.decrypt(cipher, self.KEY) == "HIDETHEGOLDX"

    def test_square_starts_with_the_key(self):
        square = playfair.build_square("MONARCHY")
        assert square[0] == list("MONAR")
        assert square[1][0] == "C"

    def test_square_has_25_unique_letters_and_no_j(self):
        letters = [c for row in playfair.build_square("keyword") for c in row]
        assert len(letters) == 25
        assert len(set(letters)) == 25
        assert "J" not in letters

    def test_doubles_are_padded(self):
        assert playfair.digraphs("BALLOON") == ["BA", "LX", "LO", "ON"]

    def test_odd_length_is_padded(self):
        assert playfair.digraphs("ODD")[-1] == "DX"

    def test_x_pair_uses_the_alternate_pad(self):
        # "XX" cannot be padded with another X or it never terminates.
        assert playfair.digraphs("XX") == ["XQ", "XQ"]

    def test_odd_ciphertext_rejected(self):
        with pytest.raises(ValueError):
            playfair.decrypt("ABC", self.KEY)
