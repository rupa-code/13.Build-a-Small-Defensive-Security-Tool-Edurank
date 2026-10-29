"""Test cases for hashing_demo.py
Run from the project folder:  python -m unittest discover -s tests -v
"""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import hashing_demo as hd  # noqa: E402

FAST = 1000  # low PBKDF2 iterations so tests run quickly


def temp_file(data: bytes) -> str:
    fh = tempfile.NamedTemporaryFile("wb", delete=False)
    fh.write(data)
    fh.close()
    return fh.name


class TestKnownVectors(unittest.TestCase):
    """Official test values for the hash functions."""

    def test_abc(self):
        self.assertEqual(hd.digest(b"abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hd.digest(b"abc", "sha1"), "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(hd.digest(b"abc", "sha256"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_empty_input(self):
        self.assertEqual(hd.digest(b"", "sha256"),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_unsupported_algorithm(self):
        with self.assertRaises(ValueError):
            hd.digest(b"abc", "crc32")

    @unittest.skipUnless(shutil.which("sha256sum"), "sha256sum not installed")
    def test_matches_system_sha256sum(self):
        path = temp_file(os.urandom(5000))
        self.addCleanup(os.remove, path)
        system = subprocess.run(["sha256sum", path], capture_output=True, text=True).stdout.split()[0]
        self.assertEqual(hd.file_digest(path), system)


class TestHashProperties(unittest.TestCase):
    def test_same_input_same_hash(self):
        self.assertEqual(hd.digest(b"hello"), hd.digest(b"hello"))

    def test_different_input_different_hash(self):
        self.assertNotEqual(hd.digest(b"hello"), hd.digest(b"hellp"))

    def test_fixed_output_length(self):
        for algo, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
            self.assertEqual(len(hd.digest(b"x", algo)), length)
            self.assertEqual(len(hd.digest(b"x" * 100000, algo)), length)

    def test_file_chunking_matches_direct_hash(self):
        data = os.urandom(200_000)            # bigger than one 64 KB chunk
        path = temp_file(data)
        self.addCleanup(os.remove, path)
        self.assertEqual(hd.file_digest(path), hd.digest(data))
        self.assertEqual(hd.file_digest(path, chunk_size=1000), hd.digest(data))

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            hd.file_digest("no_such_file.bin")


class TestAvalanche(unittest.TestCase):
    def test_bit_difference_identical_is_zero(self):
        h = hd.digest(b"abc")
        self.assertEqual(hd.bit_difference(h, h), (0, 256))

    def test_bit_difference_rejects_unequal_lengths(self):
        with self.assertRaises(ValueError):
            hd.bit_difference("ab", "abcd")

    def test_one_character_change_flips_about_half_the_bits(self):
        r = hd.avalanche("Transfer 100 rupees to Asha", "Transfer 900 rupees to Asha")
        self.assertEqual(r["total_bits"], 256)
        self.assertTrue(80 <= r["changed_bits"] <= 176, r["changed_bits"])

    def test_average_over_many_messages_is_near_50_percent(self):
        total = 0
        n = 200
        for i in range(n):
            r = hd.avalanche(f"message number {i}", f"message number {i}!")
            total += r["percent"]
        self.assertTrue(45 <= total / n <= 55, total / n)


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.path = temp_file(b"Pay: 100 rupees\n")
        self.addCleanup(os.remove, self.path)
        self.good = hd.file_digest(self.path)

    def test_untouched_file_verifies(self):
        self.assertTrue(hd.verify_file(self.path, self.good))

    def test_uppercase_or_spaced_expected_hash_still_works(self):
        self.assertTrue(hd.verify_file(self.path, "  " + self.good.upper() + "\n"))

    def test_tampered_file_fails(self):
        with open(self.path, "wb") as fh:
            fh.write(b"Pay: 900 rupees\n")
        self.assertFalse(hd.verify_file(self.path, self.good))

    def test_limit_plain_hash_can_be_recomputed_by_attacker(self):
        """A plain hash does not prove who made the file."""
        with open(self.path, "wb") as fh:
            fh.write(b"Pay: 900 rupees\n")
        forged = hd.file_digest(self.path)
        self.assertTrue(hd.verify_file(self.path, forged))


class TestHmac(unittest.TestCase):
    KEY = b"test-key"

    def test_valid_tag_verifies(self):
        tag = hd.hmac_tag(self.KEY, b"data")
        self.assertTrue(hd.hmac_verify(self.KEY, b"data", tag))

    def test_tampered_data_rejected(self):
        tag = hd.hmac_tag(self.KEY, b"data")
        self.assertFalse(hd.hmac_verify(self.KEY, b"data!", tag))

    def test_wrong_key_rejected(self):
        forged = hd.hmac_tag(b"attacker", b"data")
        self.assertFalse(hd.hmac_verify(self.KEY, b"data", forged))

    def test_known_rfc4231_vector(self):
        # RFC 4231 test case 2
        tag = hd.hmac_tag(b"Jefe", b"what do ya want for nothing?")
        self.assertEqual(tag, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")


class TestPasswords(unittest.TestCase):
    def test_unsalted_same_password_same_hash(self):
        self.assertEqual(hd.hash_password_unsalted("sunshine1"), hd.hash_password_unsalted("sunshine1"))

    def test_salted_same_password_different_hash(self):
        s1, h1 = hd.hash_password_salted("sunshine1", iterations=FAST)
        s2, h2 = hd.hash_password_salted("sunshine1", iterations=FAST)
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)

    def test_salt_is_16_bytes(self):
        salt, _ = hd.hash_password_salted("x", iterations=FAST)
        self.assertEqual(len(bytes.fromhex(salt)), 16)

    def test_given_salt_is_deterministic(self):
        salt = bytes(range(16))
        self.assertEqual(hd.hash_password_salted("pw", salt, FAST),
                         hd.hash_password_salted("pw", salt, FAST))

    def test_verify_password(self):
        salt, h = hd.hash_password_salted("right", iterations=FAST)
        self.assertTrue(hd.verify_password("right", salt, h, FAST))
        self.assertFalse(hd.verify_password("wrong", salt, h, FAST))

    def test_more_iterations_changes_hash(self):
        salt = bytes(range(16))
        self.assertNotEqual(hd.hash_password_salted("pw", salt, 1000)[1],
                            hd.hash_password_salted("pw", salt, 2000)[1])


class TestCommandLineAndDemo(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = hd.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_text_hash(self):
        code, out, _ = self.run_cli("--text", "abc")
        self.assertEqual(code, 0)
        self.assertIn("ba7816bf8f01cfea", out)

    def test_other_algorithm(self):
        _, out, _ = self.run_cli("--text", "abc", "--algo", "md5")
        self.assertIn("900150983cd24fb0d6963f7d28e17f72", out)

    def test_verify_match_and_mismatch(self):
        good = hd.digest(b"abc")
        code, out, _ = self.run_cli("--text", "abc", "--verify", good)
        self.assertEqual((code, "MATCH" in out), (0, True))
        code, out, _ = self.run_cli("--text", "abc", "--verify", "0" * 64)
        self.assertEqual((code, "MISMATCH" in out), (1, True))

    def test_missing_file_exit_2(self):
        code, _, err = self.run_cli("--file", "nope.bin")
        self.assertEqual(code, 2)
        self.assertIn("Error", err)

    def test_verify_without_input_exit_2(self):
        code, _, _ = self.run_cli("--verify", "abc")
        self.assertEqual(code, 2)

    def test_bad_algorithm_rejected_by_argparse(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                hd.main(["--text", "abc", "--algo", "crc32"])
        self.assertEqual(ctx.exception.code, 2)

    def test_full_demo_runs_and_shows_key_points(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            hd.run_demo(iterations=FAST)
        text = out.getvalue()
        for phrase in ("DEMO 1", "DEMO 6", "tampering detected", "REJECTED", "IDENTICAL"):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
