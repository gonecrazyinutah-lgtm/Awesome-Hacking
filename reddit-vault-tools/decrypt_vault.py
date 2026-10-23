#!/usr/bin/env python3
"""
Decrypt a .redditvault backup LOCALLY, with the password only you type.

Safety contract (the whole point of this tool):

* The decrypt path is fully offline: this file and ``vaultlib.py`` make no
  network calls. ``check_address.py`` has a separate, explicit ``--fetch``
  option; it is not used here.
* The password is read with getpass (no echo, not written to disk or logs,
  never accepted on the command line or environment where shell history,
  process listings, or child processes could leak it). If the terminal
  cannot hide input, the tool refuses to continue.
* The MAC is verified BEFORE decryption.  A mismatch means "wrong
  password OR corrupted file" and nothing further happens.
* By default the secret is NOT printed.  You learn only: did the password
  work, what kind of secret is inside (private key / recovery phrase /
  text / JSON), and -- if it is a key -- the public address it controls,
  plus whether that matches the address stored in the file.
* Printing the secret requires BOTH ``--reveal`` and typing REVEAL at a
  second prompt.  Writing it to disk requires ``--out FILE`` as well and
  creates the file with mode 0600, refusing to overwrite.

There is deliberately NO password-guessing / dictionary / brute-force
mode.  scrypt makes each guess expensive by design; if the backup
password is lost, check a password manager, older devices, backup copies,
and Reddit's current official guidance -- not cracking loops here.

Usage:
    python3 decrypt_vault.py path/to/backup.redditvault
    python3 decrypt_vault.py path/to/backup.redditvault --reveal
    python3 decrypt_vault.py path/to/backup.redditvault --reveal --out recovered.txt
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultlib  # noqa: E402


def _read_password() -> str:
    # getpass may fall back to visible stdin input if no controlling TTY is
    # available. Promote that warning to an exception rather than risking a
    # password echo in a terminal transcript or redirected command output.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass("Vault backup password (input hidden, not saved to disk): ")


def _secret_as_text(plaintext: bytes, info: dict) -> str:
    if info["kind"] == "private_key":
        return "0x" + plaintext.hex()
    return plaintext.decode("utf-8", errors="strict").strip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Decrypt a .redditvault backup locally.")
    parser.add_argument("file", help="path to the .redditvault backup")
    parser.add_argument("--reveal", action="store_true",
                        help="allow secret output (requires typing REVEAL)")
    parser.add_argument("--out", metavar="FILE",
                        help="with --reveal: write secret to FILE instead of printing (mode 0600, no overwrite)")
    args = parser.parse_args(argv)

    if args.out and not args.reveal:
        print("error: --out requires --reveal (writing a secret must be an explicit reveal)",
              file=sys.stderr)
        return 2
    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 2

    try:
        keystore = vaultlib.parse_vault_bytes(vaultlib.read_vault_file(args.file))
        errors, _warnings = keystore.validate()
        if errors:
            for error in errors:
                print(f"structural error: {error}", file=sys.stderr)
            print("Refusing to attempt decryption of a structurally invalid file.",
                  file=sys.stderr)
            return 2
    except (vaultlib.VaultError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        password = _read_password()
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        print("error: could not read a hidden password from a secure terminal; "
              "nothing was attempted", file=sys.stderr)
        return 2
    if not password:
        print("error: empty password -- nothing attempted.", file=sys.stderr)
        return 2
    try:
        plaintext = vaultlib.decrypt_keystore(keystore, password)
    except vaultlib.VaultError as exc:
        print(f"DECRYPTION FAILED: {exc}", file=sys.stderr)
        if str(exc).startswith("MAC verification failed"):
            print("A wrong password and a damaged file look identical here, "
                  "by design. Do not keep hammering guesses in bulk -- check "
                  "caps lock / keyboard layout, password-manager entries, "
                  "and whether you have a second backup copy to compare with "
                  "inspect_vault.py (compare the file SHA-256).", file=sys.stderr)
        else:
            print("Nothing was decrypted. This is a format or runtime-resource "
                  "error, not evidence that the password is wrong. Check the "
                  "structural report and available memory.", file=sys.stderr)
        return 1
    finally:
        password = None  # drop our reference promptly (best effort in Python)

    # ---- MAC verified. From here on, plaintext exists only in memory. ----
    info = vaultlib.classify_plaintext(plaintext)
    print("PASSWORD ACCEPTED -- MAC verified, file decrypted in memory.")
    print(f"Secret type:     {info['kind']}  ({info['length_bytes']} bytes)")
    if info["kind"] == "recovery_phrase":
        print(f"Recovery-phrase-like text: {info['word_count']} words (not shown)")
        print("                 Reddit Vault phrases are typically 12 words; this")
        print("                 tool checks only shape/count, not phrase validity.")
        print("                 Reddit's in-app Vault feature was removed on")
        print("                 2026-01-01. Check Reddit's current official support")
        print("                 guidance, then use a reputable compatible wallet on")
        print("                 a trusted device. Never enter it into a website.")
    if "derived_address" in info:
        derived = vaultlib.to_checksum_address(info["derived_address"])
        print(f"Derived address: {derived}")
        if keystore.address:
            stored = vaultlib.to_checksum_address(keystore.address)
            match = derived.lower() == stored.lower()
            print(f"File address:    {stored}")
            print(f"Address match:   {'YES -- decryption is the key for the file address' if match else 'NO -- WARNING: secret does not control the stored address'}")
            if not match:
                print("The decrypted private key does not control the address "
                      "stored in this file. Check the backup's integrity and "
                      "wallet identity before using this key or moving funds.",
                      file=sys.stderr)
        else:
            print("(File carried no address field; derived address above is "
                  "the account this key controls.)")
    if info["kind"] == "json":
        print(f"JSON payload keys: {info.get('json_keys')}")
    if info["kind"] in ("text", "binary"):
        print("Payload is not a bare private key or a word phrase. Treat "
              "whatever --reveal shows as a master secret all the same.")

    if not args.reveal:
        print()
        print("Secret was NOT displayed. Re-run with --reveal only when you")
        print("are somewhere private, with no screen sharing / recording,")
        print("ready to write it down offline. Screenshots and cloud")
        print("notes defeat the encryption you just relied on.")
        return 0

    if sys.stdin.isatty() and sys.stdout.isatty():
        typed = input("Type REVEAL to display the secret: ").strip()
        if typed != "REVEAL":
            print("Confirmation did not match -- secret not shown.", file=sys.stderr)
            return 1
    else:
        print("error: --reveal requires an interactive terminal for both "
              "confirmation and display; secret was not shown", file=sys.stderr)
        return 2

    try:
        secret_text = _secret_as_text(plaintext, info)
    except UnicodeDecodeError:
        secret_text = "0x" + plaintext.hex()
        print("(payload is not UTF-8 text; showing hex)")

    if args.out:
        if os.path.exists(args.out):
            print(f"error: refusing to overwrite existing file: {args.out}", file=sys.stderr)
            return 2
        fd = None
        created = False
        try:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = None  # fdopen owns and closes the descriptor from here
                fh.write(secret_text + "\n")
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            if created:
                try:
                    os.unlink(args.out)  # best-effort cleanup of a partial plaintext file
                except OSError:
                    pass
            print(f"error: could not write secret file: {exc}", file=sys.stderr)
            return 2
        if os.name == "nt":
            print(f"Secret written to {args.out}. Windows ACLs control access; "
                  "keep this file on an encrypted, private volume and remove "
                  "it when no longer needed. The secret was not printed.")
        else:
            print(f"Secret written to {args.out} (mode 0600). Keep it offline "
                  "and remove it when no longer needed; secure deletion is "
                  "not guaranteed on SSDs or synced filesystems. The secret "
                  "was not printed.")
        return 0

    print()
    print("================ SECRET -- DO NOT SHARE ================")
    print(secret_text)
    print("=========================================================")
    print("Anyone with this can take everything in the wallet, forever.")
    print("Do not paste it into websites, chats, tickets, or 'recovery' forms.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
