#!/usr/bin/env python3
"""
Self-tests for the Reddit Vault tools.  Run before trusting any result:

    python3 -m unittest -v test_vault.py        (from this directory)
    python3 test_vault.py

Covers the published PBKDF2 and independently generated scrypt Web3
Secret Storage vectors (password "testpassword"), Keccak-256 vs NIST
SHA3-256 confusion, the
AES-128 FIPS-197 vector, EIP-55 vectors, secp256k1 address derivation,
the redditBackupData wrapper, wrong-password MAC failure, and the
CLI tools end-to-end (inspector redaction, decrypt without reveal).
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultlib  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# --- Published vectors: ethereum.org, Web3 Secret Storage Definition -----
EXPECTED_ADDRESS = "0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b"
EXPECTED_SECRET = bytes.fromhex(
    "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")

PBKDF2_VECTOR = {
    "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {"iv": "6087dab2f9fdbbfaddc31a909735c1e6"},
        "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf": "pbkdf2",
        "kdfparams": {"c": 262144, "dklen": 32, "prf": "hmac-sha256",
                      "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
        "mac": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
    },
    "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version": 3,
}

# NOTE on the spec's own scrypt example: the keystore printed in the
# Web3 Secret Storage definition (ciphertext dd8a1132..., MAC 337aeb...)
# is internally consistent -- its published derived key really does
# decrypt it -- but that derived key is reproduced only by feeding
# scrypt the salt as an *ASCII hex string*, not as the hex-decoded bytes
# used by standard implementations (including Python's hashlib and PyCA's
# independent implementation). Do not "fix" vaultlib to match this anomaly.
# The vector below therefore keeps the spec's salt/IV/secret/password
# but was generated with PyCA `cryptography` (independent scrypt +
# AES-CTR implementations) using standard hex-decoded salt bytes, which
# hashlib.scrypt reproduces exactly.
SCRYPT_VECTOR = {
    "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {"iv": "740770fce12ce862af21264dab25f1da"},
        "ciphertext": "1b368ffb2db0fcec8802eceba0b2820ae1069ef3815ac97ca1031371748f6e18",
        "kdf": "scrypt",
        "kdfparams": {"dklen": 32, "n": 262144, "p": 1, "r": 8,
                      "salt": "25710c2ccd7c610b24d068af83b959b7a0e5f40641f0c82daeb1345766191034"},
        "mac": "61de4bf77db2f8e07e01232c045e5b455997efeb22bb8ea08a66ff5a252182a6",
    },
    "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "version": 3,
}


def _ks(obj) -> vaultlib.Keystore:
    import base64
    if isinstance(obj, (bytes, str)):
        data = obj.encode() if isinstance(obj, str) else obj
        return vaultlib.parse_vault_bytes(data)
    wrapped = {"redditBackupData": base64.b64encode(json.dumps(obj).encode()).decode()}
    return vaultlib.parse_vault_bytes(json.dumps(wrapped).encode())


class TestPrimitives(unittest.TestCase):
    def test_keccak_vectors(self):
        self.assertEqual(vaultlib.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(vaultlib.keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_keccak_is_not_nist_sha3(self):
        import hashlib
        self.assertNotEqual(vaultlib.keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_keccak_rate_boundaries(self):
        # Independent PyCryptodome oracle; 135 bytes exercises the special
        # one-byte 0x81 padding case at the end of the 136-byte Keccak rate.
        vectors = {
            135: "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62",
            136: "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e",
            137: "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db",
        }
        for length, expected in vectors.items():
            data = bytes(i % 251 for i in range(length))
            self.assertEqual(vaultlib.keccak256(data).hex(), expected)

    def test_aes_fips197(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        round_keys = vaultlib._aes128_expand_key(key)  # noqa: SLF001
        self.assertEqual(vaultlib._aes128_encrypt_block(round_keys, plaintext).hex(),  # noqa: SLF001
                         "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_eip55_vectors(self):
        # Reference vectors straight from EIP-55.
        cases = {
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb": "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb": "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        }
        for lower, checksummed in cases.items():
            self.assertEqual(vaultlib.to_checksum_address(lower), checksummed)

    def test_privkey_one_address(self):
        self.assertEqual(vaultlib.private_key_to_address((1).to_bytes(32, "big")),
                         "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")


class TestKeystoreVectors(unittest.TestCase):
    def test_pbkdf2_vector_decrypts(self):
        ks = _ks(PBKDF2_VECTOR)
        self.assertEqual(vaultlib.decrypt_keystore(ks, "testpassword"), EXPECTED_SECRET)

    def test_scrypt_vector_decrypts(self):
        ks = _ks(SCRYPT_VECTOR)
        self.assertEqual(vaultlib.decrypt_keystore(ks, "testpassword"), EXPECTED_SECRET)

    def test_decrypted_key_derives_spec_address(self):
        self.assertEqual(vaultlib.private_key_to_address(EXPECTED_SECRET), EXPECTED_ADDRESS)

    def test_wrong_password_fails_mac(self):
        ks = _ks(PBKDF2_VECTOR)
        with self.assertRaises(vaultlib.VaultError):
            vaultlib.decrypt_keystore(ks, "wrongpassword")

    def test_capital_crypto_variant(self):
        variant = json.loads(json.dumps(SCRYPT_VECTOR))
        variant["Crypto"] = variant.pop("crypto")
        ks = _ks(variant)
        self.assertEqual(vaultlib.decrypt_keystore(ks, "testpassword"), EXPECTED_SECRET)

    def test_outer_wrapper_public_address(self):
        wrapped = {
            "address": EXPECTED_ADDRESS,
            "redditBackupData": base64.b64encode(json.dumps(SCRYPT_VECTOR).encode()).decode(),
        }
        ks = vaultlib.parse_vault_bytes(json.dumps(wrapped).encode())
        self.assertEqual(ks.address, EXPECTED_ADDRESS)

    def test_roundtrip_phrase_and_wrapper(self):
        phrase = b"sampleword " * 11 + b"sampleword"
        obj = vaultlib.encrypt_keystore(phrase, "unit-test-pw", n=1024)
        ks = _ks(obj)
        plaintext = vaultlib.decrypt_keystore(ks, "unit-test-pw")
        self.assertEqual(plaintext, phrase)
        info = vaultlib.classify_plaintext(plaintext)
        self.assertEqual(info["kind"], "recovery_phrase")
        self.assertEqual(info["word_count"], 12)
        # Classification must not leak the secret itself.
        self.assertNotIn("abandon", json.dumps(info))

    def test_malformed_kdfparams_reported_without_crashing(self):
        malformed = json.loads(json.dumps(SCRYPT_VECTOR))
        del malformed["crypto"]["kdfparams"]
        ks = _ks(malformed)
        errors, _warnings = ks.validate()
        self.assertTrue(any("kdfparams" in error for error in errors))

    def test_extreme_scrypt_rejected_by_resource_limit(self):
        extreme = json.loads(json.dumps(SCRYPT_VECTOR))
        extreme["crypto"]["kdfparams"]["n"] = 1 << 30
        ks = _ks(extreme)
        errors, _warnings = ks.validate()
        self.assertTrue(any("safety limit" in error for error in errors))

    def test_video_magic_rejected(self):
        fake_mp4 = b"\x00\x00\x00\x18ftypisom" + b"\x00" * 64
        with self.assertRaises(vaultlib.VaultError):
            vaultlib.parse_vault_bytes(fake_mp4)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.demo = os.path.join(self.tmp.name, "demo-key.redditvault")
        keystore = vaultlib.encrypt_keystore(
            EXPECTED_SECRET, "demo-password-not-real", address=EXPECTED_ADDRESS,
            n=4096, salt=b"s" * 32, iv=b"i" * 16,
        )
        inner = json.dumps(keystore).encode()
        wrapped = {"redditBackupData": base64.b64encode(inner).decode()}
        with open(self.demo, "w", encoding="utf-8") as fh:
            json.dump(wrapped, fh)

    def _run(self, script, *args):
        return subprocess.run([sys.executable, os.path.join(HERE, script), *args],
                              capture_output=True, text=True, cwd=HERE)

    class _TTY(io.StringIO):
        def isatty(self):
            return True

    def _decrypt(self, password, *args, input_text=""):
        import decrypt_vault
        stdout, stderr = self._TTY(), io.StringIO()
        fake_stdin = self._TTY(input_text)
        with patch("getpass.getpass", return_value=password), patch("sys.stdin", fake_stdin), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = decrypt_vault.main([self.demo, *args])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_inspect_demo_is_redacted(self):
        result = self._run("inspect_vault.py", self.demo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALID version-3 keystore", result.stdout)
        # The demo key must never appear in inspector output.
        self.assertNotIn(EXPECTED_SECRET.hex(), result.stdout)

    def test_decrypt_without_reveal_hides_secret(self):
        rc, stdout, stderr = self._decrypt("demo-password-not-real")
        self.assertEqual(rc, 0, stderr)
        self.assertIn("PASSWORD ACCEPTED", stdout)
        self.assertIn("Address match:   YES", stdout)
        self.assertNotIn(EXPECTED_SECRET.hex(), stdout)

    def test_decrypt_wrong_password(self):
        rc, _stdout, stderr = self._decrypt("nope")
        self.assertEqual(rc, 1)
        self.assertIn("MAC verification failed", stderr)

    def test_reveal_requires_confirmation(self):
        rc, stdout, _stderr = self._decrypt(
            "demo-password-not-real", "--reveal", input_text="NO\n")
        self.assertEqual(rc, 1)
        self.assertNotIn(EXPECTED_SECRET.hex(), stdout)

    def test_out_writes_private_file_without_printing_secret(self):
        import stat
        output_path = os.path.join(self.tmp.name, "recovered.txt")
        rc, stdout, stderr = self._decrypt(
            "demo-password-not-real", "--reveal", "--out", output_path,
            input_text="REVEAL\n",
        )
        self.assertEqual(rc, 0, stderr)
        self.assertNotIn(EXPECTED_SECRET.hex(), stdout)
        with open(output_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read().strip(), "0x" + EXPECTED_SECRET.hex())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(output_path).st_mode), 0o600)

    def test_check_address_refuses_private_key(self):
        result = self._run("check_address.py", "0x" + EXPECTED_SECRET.hex())
        self.assertEqual(result.returncode, 2)
        self.assertIn("PRIVATE KEY", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
