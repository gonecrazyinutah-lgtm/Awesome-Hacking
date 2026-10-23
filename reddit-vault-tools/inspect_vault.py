#!/usr/bin/env python3
"""
Inspect a .redditvault backup WITHOUT a password and WITHOUT network access.

What this can tell you (all public / structural):
  * whether the file has a plausible version-3 (Web3 Secret Storage)
    structure, optionally wrapped in a base64 ``redditBackupData`` field;
  * the public Ethereum address, if the file carries one;
  * cipher / KDF parameters and a rough decryption cost (scrypt memory);
  * structural problems (truncation, bad hex, wrong version, a real video
    container masquerading under a wallet filename, ...).

What this can NEVER tell you:
  * the password, the recovery phrase, or the private key;
  * whether any particular password is correct (that needs the MAC check
    in decrypt_vault.py, run locally with the password you type).

The output is deliberately redacted (ciphertext / salt / IV / MAC are
truncated). It still includes a filename, public address (if present), and
file fingerprint; share it only if you are comfortable disclosing those
details. Do not upload the .redditvault file itself anywhere -- whoever
holds it can attack the password offline.

Usage:
    python3 inspect_vault.py path/to/backup.redditvault
    python3 inspect_vault.py path/to/backup.redditvault --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultlib  # noqa: E402


def _trunc(hex_str: str, keep: int = 8) -> str:
    if len(hex_str) <= keep * 2:
        return hex_str
    return f"{hex_str[:keep]}...{hex_str[-4:]} ({len(hex_str) // 2} bytes)"


def build_report(path: str) -> dict:
    data = vaultlib.read_vault_file(path)
    report: dict = {
        "file": os.path.basename(path),
        "size_bytes": len(data),
        # A fingerprint of the *encrypted* file: lets you tell copies apart
        # and prove two helpers are looking at the same file.  It reveals
        # nothing about the password or the secret inside.
        "file_sha256": hashlib.sha256(data).hexdigest(),
    }
    ks = vaultlib.parse_vault_bytes(data)
    errors, warnings = ks.validate()
    try:
        kdfparams = ks.kdfparams
    except vaultlib.VaultError:
        kdfparams = {}

    report["layers_unwrapped"] = ks.layers or ["(top-level JSON keystore)"]
    report["version"] = 3
    report["keystore_id"] = ks.keystore_id
    report["cipher"] = ks.cipher
    report["kdf"] = ks.kdf
    try:
        ciphertext = ks.ciphertext
        report["ciphertext"] = _trunc(ciphertext.hex())
        report["ciphertext_bytes"] = len(ciphertext)
        report["iv"] = _trunc(ks.iv.hex())
        report["mac"] = _trunc(ks.mac.hex())
    except vaultlib.VaultError as exc:
        errors = list(errors) + [str(exc)]
        ciphertext = b""

    if ks.kdf == "scrypt":
        try:
            n, r, p = (int(kdfparams[k]) for k in ("n", "r", "p"))
            report["kdfparams"] = {
                "n": n, "r": r, "p": p,
                "dklen": int(kdfparams["dklen"]),
                "salt": _trunc(str(kdfparams["salt"])),
            }
            memory_mib = (128 * n * r + (1 << 20) - 1) // (1 << 20)
            if memory_mib > 1024:
                memory_text = "above this tool's 1024 MiB safety limit"
            else:
                memory_text = f"~{memory_mib} MiB"
            report["scrypt_working_memory_approx"] = memory_text
            report["scrypt_note"] = (
                "scrypt is deliberately expensive and slows password "
                "guessing; a forgotten password has no cryptographic "
                "shortcut. This is an approximate per-derivation memory "
                "estimate, not a time guarantee."
            )
        except (KeyError, TypeError, ValueError):
            pass
    elif ks.kdf == "pbkdf2":
        report["kdfparams"] = {
            "c": kdfparams.get("c"), "dklen": kdfparams.get("dklen"),
            "prf": kdfparams.get("prf"), "salt": _trunc(str(kdfparams.get("salt", ""))),
        }

    if ks.address:
        try:
            report["address"] = vaultlib.to_checksum_address(ks.address)
            report["address_note"] = (
                "Public information. Sharing it does not give anyone access "
                "to the wallet, but it can link activity to this address."
            )
        except vaultlib.VaultError:
            report["address"] = None
            report["address_note"] = "Malformed address field; value omitted from this report."
    else:
        report["address"] = None
        report["address_note"] = (
            "This keystore carries no address field. If the decrypted payload "
            "is a private key, its address can be derived locally; this tool "
            "does not derive an address from a recovery phrase."
        )

    if ciphertext:
        if len(ciphertext) == 32:
            report["payload_size_hint"] = (
                "Ciphertext is exactly 32 bytes -- consistent with an "
                "encrypted private key (AES-CTR has no padding, so "
                "ciphertext length equals plaintext length)."
            )
        elif 40 <= len(ciphertext) <= 250:
            report["payload_size_hint"] = (
                f"Ciphertext is {len(ciphertext)} bytes -- too long for a "
                "bare private key, consistent with encrypted text such as "
                "a recovery phrase (Reddit's original backup design). "
                "Only a successful MAC-verified decryption can confirm this."
            )
        else:
            report["payload_size_hint"] = (
                f"Ciphertext is {len(ciphertext)} bytes (AES-CTR preserves "
                "length). Its content type cannot be known before decryption."
            )

    report["structural_errors"] = errors
    report["warnings"] = warnings
    report["verdict"] = (
        "VALID version-3 keystore structure" if not errors
        else "Problems found -- see structural_errors"
    )
    return report


def print_human(report: dict) -> None:
    print(f"File:            {report['file']}  ({report['size_bytes']} bytes)")
    print(f"SHA-256 (file):  {report['file_sha256']}")
    print(f"Layers:          {' -> '.join(report.get('layers_unwrapped', []))}")
    print(f"Verdict:         {report['verdict']}")
    print(f"Version:         {report.get('version')} (Web3 Secret Storage)")
    if report.get("keystore_id"):
        print(f"Keystore id:     {report['keystore_id']}")
    print(f"Cipher:          {report.get('cipher')}  (key = derived_key[0:16], IV below)")
    print(f"  IV:            {report.get('iv')}")
    print(f"  Ciphertext:    {report.get('ciphertext')}")
    print(f"KDF:             {report.get('kdf')}  {report.get('kdfparams')}")
    if report.get("scrypt_working_memory_approx"):
        print(f"  scrypt memory: {report['scrypt_working_memory_approx']} per guess")
    print(f"MAC:             {report.get('mac')}  (keccak-256 of derived_key[16:32] + ciphertext)")
    print(f"Address:         {report.get('address')}")
    print(f"                 {report.get('address_note')}")
    if report.get("payload_size_hint"):
        print(f"Payload hint:    {report['payload_size_hint']}")
    for warning in report.get("warnings", []):
        print(f"WARNING:         {warning}")
    for error in report.get("structural_errors", []):
        print(f"ERROR:           {error}")
    print()
    print("No password was used and nothing was decrypted. This report")
    print("omits the ciphertext and secrets, but includes the filename,")
    print("public address (if present), and file fingerprint. Share only")
    print("if you are comfortable with those details; never share the")
    print(".redditvault file, password, recovery phrase, or private key.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("file", help="path to the .redditvault backup")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON (still redacted)")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 2
    try:
        report = build_report(args.file)
    except (vaultlib.VaultError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)
    return 0 if not report["structural_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
