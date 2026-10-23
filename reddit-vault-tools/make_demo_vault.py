#!/usr/bin/env python3
"""
Create DEMO .redditvault files from publicly known test secrets, so you
can practise the inspect -> decrypt flow before touching a real backup.

The key is a published Web3 Secret Storage test vector; the phrase-shaped
string is synthetic and not a valid BIP-39 mnemonic. Both are public and
permanently insecure -- never import, fund, or reuse them.
Demo password for every generated file:  demo-password-not-real

    python3 make_demo_vault.py            # writes ./demo-*.redditvault
    python3 inspect_vault.py demo-key.redditvault
    python3 decrypt_vault.py demo-key.redditvault
    python3 decrypt_vault.py demo-phrase.redditvault --reveal

*.redditvault is git-ignored in this directory so a demo (or worse, a
real backup) cannot be committed by accident.
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultlib  # noqa: E402

DEMO_PASSWORD = "demo-password-not-real"  # printed in README too; not a secret

# Web3 Secret Storage spec test vector (ethereum.org): password in the spec
# is "testpassword"; here we re-encrypt the same publicly known key under
# the demo password above so one password opens both demo files.
TEST_PRIVATE_KEY = bytes.fromhex(
    "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
TEST_ADDRESS = vaultlib.private_key_to_address(TEST_PRIVATE_KEY)

# Phrase-shaped text for exercising classification only. This is not a
# valid BIP-39 mnemonic and must never be imported into or funded as a wallet.
TEST_PHRASE = "sampleword " * 11 + "sampleword"


def _wrap(keystore: dict) -> str:
    inner = json.dumps(keystore)
    return json.dumps({
        "redditBackupData": base64.b64encode(inner.encode()).decode(),
    }, indent=2)


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    targets = {
        "demo-key.redditvault": vaultlib.encrypt_keystore(
            TEST_PRIVATE_KEY, DEMO_PASSWORD, address=TEST_ADDRESS, n=4096),
        "demo-phrase.redditvault": vaultlib.encrypt_keystore(
            TEST_PHRASE.encode(), DEMO_PASSWORD, n=4096),
    }
    for name, keystore in targets.items():
        path = os.path.join(here, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_wrap(keystore) + "\n")
        print(f"wrote {path}  (demo password: {DEMO_PASSWORD})")
    print(f"demo key address: {vaultlib.to_checksum_address(TEST_ADDRESS)}")
    print("These public demo secrets are permanently insecure and must "
          "never be imported, reused, or funded. Practise freely, then use "
          "the same commands on your real file, locally.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
