#!/usr/bin/env python3
"""
Hashing Demo  (Task 12 - Explore a Cryptography Concept)

A safe, small demonstration of cryptographic HASHING using only Python's
standard library. It shows what a hash is, what it can protect, and - just as
important - what it cannot protect.

Run everything:      python hashing_demo.py
Hash some text:      python hashing_demo.py --text "abc"
Hash a file:         python hashing_demo.py --file notes.txt --algo sha256
Verify a file:       python hashing_demo.py --file notes.txt --verify <expected_hash>

Exit codes (hash/verify mode): 0 = ok / match, 1 = hash mismatch, 2 = error.
All data used in the demo is made up (synthetic).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
import tempfile
import time

ALGORITHMS = ("md5", "sha1", "sha256")
PBKDF2_ITERATIONS = 600_000      # OWASP 2023 guidance for PBKDF2-HMAC-SHA256


# --------------------------------------------------------------------------
# Building blocks
# --------------------------------------------------------------------------
def digest(data: bytes, algo: str = "sha256") -> str:
    """Hash bytes and return the hex digest."""
    if algo not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algo}'. Choose from {ALGORITHMS}")
    return hashlib.new(algo, data).hexdigest()


def file_digest(path: str, algo: str = "sha256", chunk_size: int = 65536) -> str:
    """Hash a file in chunks (works for big files too)."""
    if algo not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algo}'. Choose from {ALGORITHMS}")
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk_size), b""):
            h.update(block)
    return h.hexdigest()


def bit_difference(hex_a: str, hex_b: str) -> tuple[int, int]:
    """Return (number of different bits, total bits) between two hex digests."""
    if len(hex_a) != len(hex_b):
        raise ValueError("Digests must be the same length")
    diff = int(hex_a, 16) ^ int(hex_b, 16)
    return bin(diff).count("1"), len(hex_a) * 4


def verify_file(path: str, expected_hex: str, algo: str = "sha256") -> bool:
    """True if the file's hash equals the expected hash (constant-time compare)."""
    actual = file_digest(path, algo)
    return hmac.compare_digest(actual, expected_hex.strip().lower())


def hmac_tag(key: bytes, data: bytes) -> str:
    """Keyed hash (HMAC-SHA256): only someone with the key can make a valid tag."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, data: bytes, tag: str) -> bool:
    return hmac.compare_digest(hmac_tag(key, data), tag.strip().lower())


def hash_password_unsalted(password: str) -> str:
    """BAD practice, shown on purpose: plain fast hash, no salt."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_password_salted(password: str, salt: bytes | None = None,
                         iterations: int = PBKDF2_ITERATIONS) -> tuple[str, str]:
    """Better practice: random salt + slow key-derivation (PBKDF2-HMAC-SHA256)."""
    salt = os.urandom(16) if salt is None else salt
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt.hex(), derived.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str,
                    iterations: int = PBKDF2_ITERATIONS) -> bool:
    _, candidate = hash_password_salted(password, bytes.fromhex(salt_hex), iterations)
    return hmac.compare_digest(candidate, hash_hex)


def avalanche(msg_a: str, msg_b: str, algo: str = "sha256") -> dict:
    """Compare the hashes of two messages and count how many bits changed."""
    ha, hb = digest(msg_a.encode(), algo), digest(msg_b.encode(), algo)
    changed, total = bit_difference(ha, hb)
    return {"hash_a": ha, "hash_b": hb, "changed_bits": changed, "total_bits": total,
            "percent": round(100 * changed / total, 1)}


# --------------------------------------------------------------------------
# The demonstration
# --------------------------------------------------------------------------
def title(n: int, text: str) -> None:
    print(f"\n{'=' * 70}\nDEMO {n}: {text}\n{'=' * 70}")


def run_demo(iterations: int = PBKDF2_ITERATIONS) -> None:
    print("HASHING DEMO - synthetic data only")

    # 1 ---------------------------------------------------------------
    title(1, "A hash is a fixed-size fingerprint")
    for text in ("abc", "Hello, World!"):
        print(f'\nInput: "{text}"')
        for algo in ALGORITHMS:
            print(f"  {algo:<7}{digest(text.encode(), algo)}")
    long_hash = digest(b"a" * 1_000_000)
    print(f"\nInput: 1,000,000 letters 'a'\n  sha256 {long_hash}")
    print("-> Tiny or huge input, the sha256 output is always 64 hex characters.")
    print("-> Same input always gives the same hash.")

    # 2 ---------------------------------------------------------------
    title(2, "Avalanche effect: change one character")
    r = avalanche("Transfer 100 rupees to Asha", "Transfer 900 rupees to Asha")
    print('A: "Transfer 100 rupees to Asha"\nB: "Transfer 900 rupees to Asha"')
    print(f"  sha256(A) = {r['hash_a']}\n  sha256(B) = {r['hash_b']}")
    print(f"-> {r['changed_bits']} of {r['total_bits']} bits changed ({r['percent']}%).")
    print("-> One tiny edit completely changes the hash, so edits are easy to spot.")

    # 3 ---------------------------------------------------------------
    title(3, "Integrity check on a file (what hashing CAN do)")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "invoice.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Invoice 001\nPay: 100 rupees\nTo: Asha\n")
        good = file_digest(path)
        print(f"Original file hash : {good}")
        print(f"Verify original    : {'MATCH' if verify_file(path, good) else 'MISMATCH'}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Invoice 001\nPay: 900 rupees\nTo: Asha\n")
        print(f"Verify after edit  : {'MATCH' if verify_file(path, good) else 'MISMATCH  <- tampering detected'}")

        # 4 -----------------------------------------------------------
        title(4, "Limit 1: a plain hash does NOT prove WHO made the file")
        forged = file_digest(path)
        print("An attacker edits the file AND publishes a new hash next to it.")
        print(f"Attacker's new hash: {forged}")
        print(f"Verify vs new hash : {'MATCH  <- looks valid, but it is forged!' if verify_file(path, forged) else 'MISMATCH'}")

        print("\nFix: use a keyed hash (HMAC) with a secret key.")
        key = b"demo-secret-key-not-real"
        data_ok = b"Invoice 001\nPay: 100 rupees\nTo: Asha\n"
        data_bad = b"Invoice 001\nPay: 900 rupees\nTo: Asha\n"
        tag = hmac_tag(key, data_ok)
        print(f"Real HMAC tag      : {tag}")
        print(f"Tampered data      : {'valid' if hmac_verify(key, data_bad, tag) else 'REJECTED'}")
        attacker_tag = hmac_tag(b"attacker-guess", data_bad)
        print(f"Forged tag, no key : {'valid' if hmac_verify(key, data_bad, attacker_tag) else 'REJECTED'}")
        print("-> Without the secret key, the attacker cannot make a valid tag.")

    # 5 ---------------------------------------------------------------
    title(5, "Limit 2: fast unsalted hashes are weak for passwords")
    users = {"user_a": "sunshine1", "user_b": "sunshine1", "user_c": "T7#kd9!Lm2qW"}
    stored = {u: hash_password_unsalted(p) for u, p in users.items()}
    print("Stored with plain SHA-256 (no salt):")
    for u, h in stored.items():
        print(f"  {u}: {h}")
    print("-> user_a and user_b have IDENTICAL hashes, so anyone can see they share a password.")
    tiny_table = {hash_password_unsalted(w): w for w in
                  ("123456", "password", "sunshine1", "welcome", "qwerty")}
    print("\nA tiny made-up table of common passwords, pre-hashed:")
    for u, h in stored.items():
        hit = tiny_table.get(h)
        print(f"  {u}: {'FOUND in table -> ' + hit if hit else 'not in table'}")
    print("-> Weak passwords are found by simple lookup. Strong ones are not.")

    print(f"\nBetter: random salt + slow PBKDF2 ({iterations:,} iterations):")
    start = time.perf_counter()
    s1, h1 = hash_password_salted("sunshine1", iterations=iterations)
    s2, h2 = hash_password_salted("sunshine1", iterations=iterations)
    elapsed = time.perf_counter() - start
    print(f"  user_a: salt={s1[:8]}...  hash={h1[:32]}...")
    print(f"  user_b: salt={s2[:8]}...  hash={h2[:32]}...")
    print(f"-> Same password, different hashes. Right password verifies: "
          f"{verify_password('sunshine1', s1, h1, iterations)}; wrong: "
          f"{verify_password('wrong-guess', s1, h1, iterations)}")
    print(f"-> Two hashes took {elapsed:.2f}s - slow on purpose to make guessing expensive.")

    # 6 ---------------------------------------------------------------
    title(6, "Summary: what hashing can and cannot protect")
    print("CAN:    detect changes (integrity); store passwords safely (with salt + slow hash);")
    print("        fingerprint files; with HMAC, prove a message came from a key holder.")
    print("CANNOT: keep data secret or be 'decrypted' (a hash is one-way, it is not encryption);")
    print("        prove who made a file (needs HMAC or a digital signature);")
    print("        protect weak, guessable passwords; or keep old algorithms safe")
    print("        (MD5 and SHA-1 have known collisions - use SHA-256 or better).")


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Hashing demo and small hash tool.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--text", help="hash this text")
    src.add_argument("--file", help="hash this file")
    p.add_argument("--algo", choices=ALGORITHMS, default="sha256", help="default: sha256")
    p.add_argument("--verify", metavar="HASH", help="compare the result with this expected hash")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.text is None and args.file is None:
        if args.verify:
            print("Error: --verify needs --text or --file", file=sys.stderr)
            return 2
        run_demo()
        return 0
    try:
        result = (digest(args.text.encode(), args.algo) if args.text is not None
                  else file_digest(args.file, args.algo))
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(result)
    if args.verify:
        ok = hmac.compare_digest(result, args.verify.strip().lower())
        print("MATCH" if ok else "MISMATCH")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
