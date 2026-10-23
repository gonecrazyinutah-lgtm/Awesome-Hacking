# Reddit Vault backup tools (local-only)

These small Python tools inspect the **structure** of a `.redditvault` backup and, if you choose, test its password and decrypt it on your own computer. They do not crack passwords, modify the backup, or upload data.

> **Your real backup is not in this repository.** Do not copy it here, commit it, attach it to an issue, or send it to anyone. Run the commands below against its existing path on your own machine. This helper has not verified any particular user's file.

## Safety first

- `inspect_vault.py` needs no password and makes **no network requests**. Its report redacts the ciphertext, IV, salt, and MAC, but does include the public wallet address (if present), the file's SHA-256 fingerprint, and basic format parameters. Share the report only if you are comfortable disclosing those details. Never share the backup itself.
- `decrypt_vault.py` is also offline. It asks for the backup password through a hidden terminal prompt, verifies the MAC **before** decrypting, and does not display the recovery phrase/private key by default. A MAC failure means either the password is wrong **or** the file is damaged; it cannot distinguish the two.
- To display a secret you must add `--reveal`, type `REVEAL`, and have an interactive terminal for both input and output. Do that only on a private, trusted computer with no screen sharing, recording, shell transcript, or redirected output. `--out FILE` instead writes a plaintext copy after the same confirmation and does **not** print the secret; on POSIX it is created with mode `0600`, while Windows access is controlled by its ACLs. Avoid writing secrets to cloud-synced folders. Secure deletion is not guaranteed on SSDs or synced filesystems.
- Python cannot promise to erase all copies of a password or plaintext from memory. Close the process after use, and keep your operating system and machine trusted.
- `check_address.py` is offline by default. Its optional `--fetch` sends the **public address and your IP address** to public RPC services to query native balances / transaction counts. It does not query or report NFT/token holdings; use the linked explorer's token/NFT tabs. A zero native balance does **not** mean the wallet is empty.
- There is no brute-force or wordlist mode. If the password is forgotten, check your password manager, notes, older devices, and backup copies; do not upload the file to an online "recovery" site.

This is a small, transparent, dependency-free helper, **not audited wallet software**. The AES-128-CTR and Ethereum Keccak-256 implementations are pure Python and tested against standard vectors. Reddit announced removal of its in-app Vault feature effective January 1, 2026; check Reddit's current official support guidance and use only a reputable, compatible wallet/tool you already trust. Do not move funds until you have independently confirmed which wallet/address the recovered secret controls.

## Requirements

- Python **3.10 or newer**.
- No `pip install`, browser, server, or account is required.
- `inspect_vault.py` and `decrypt_vault.py` make no network requests. Only `check_address.py --fetch` uses the network.

Run these commands from this directory (or use the full path to each script):

### 1. Inspect without decrypting

```sh
python3 inspect_vault.py "/path/to/your/backup.redditvault"
```

On Windows, for example:

```powershell
py -3 .\inspect_vault.py "C:\Users\you\Downloads\backup.redditvault"
```

A `VALID version-3 keystore structure` result means the JSON fields and parameters are structurally plausible. It **does not** prove the password is correct, the encrypted content is authentic, or the file is definitely a Reddit backup; only a successful MAC check can establish that the password matches this ciphertext. If the script cannot recognize the format, stop there rather than renaming, converting, or uploading the file.

Ciphertext length is only a clue: AES-CTR does not add padding, so 32 encrypted bytes are consistent with a private key, while a longer payload can be consistent with text such as a recovery phrase. The content type is confirmed only after successful local decryption. An embedded Ethereum address is public; some formats intentionally omit it.

### 2. Test the password locally (secret stays hidden)

```sh
python3 decrypt_vault.py "/path/to/your/backup.redditvault"
```

Type the password you set for that backup at the hidden prompt. With the correct password, the tool reports whether the plaintext resembles a private key, recovery phrase, JSON, or other text. For a 32-byte private key it also derives the public Ethereum address and compares it to an address stored in the file. It does **not** show the secret unless you separately request that.

To explicitly display it in a private terminal:

```sh
python3 decrypt_vault.py "/path/to/your/backup.redditvault" --reveal
```

Read the warnings and type `REVEAL` only if you genuinely want the secret shown on screen. If you need a file instead, `--out` also requires `--reveal` and still requires the interactive confirmation:

```sh
python3 decrypt_vault.py "/path/to/your/backup.redditvault" --reveal --out "./recovered-secret.txt"
```

That file is plaintext and gives anyone who can read it control of the wallet. Keep it offline, private, and temporary.

### 3. Check a public address (optional)

If the keystore contains an address, print the offline explorer links without decrypting:

```sh
python3 check_address.py --from-vault "/path/to/your/backup.redditvault"
```

Or supply a known **public address** directly:

```sh
python3 check_address.py 0xYourPublicAddress
```

These commands do not contact the explorers. To query public RPC services for native balance and transaction counts, explicitly add `--fetch`; this reveals the address and your IP to those services:

```sh
python3 check_address.py 0xYourPublicAddress --fetch
```

Never supply a private key or recovery phrase to this command, an explorer, or a web page.

## Practise on public test data first

The demo key is a public test vector and the phrase-shaped string is synthetic; both are permanently insecure and must never receive or hold funds. The generator writes two ignored `.redditvault` files inside this folder; they are excluded by `.gitignore`.

```sh
python3 make_demo_vault.py
python3 inspect_vault.py demo-key.redditvault
python3 decrypt_vault.py demo-key.redditvault
```

Demo password: `demo-password-not-real`.

The demo private key is the Web3 Secret Storage specification's public test vector. The phrase-shaped demo string (`sampleword` repeated 12 times) is intentionally **not** a valid BIP-39 mnemonic; it only exercises the classifier.

## Self-tests

From this directory:

```sh
python3 -m unittest -v test_vault.py
```

The tests cover Keccak vs NIST SHA3, AES-128, EIP-55 checksums, Ethereum address derivation, the PBKDF2 reference vector, an independently generated scrypt vector, wrapper parsing, wrong-password rejection, redacted reporting, and the hidden-by-default decrypt flow. The scrypt example in the Web3 Secret Storage page appears to have a fixture inconsistency: its printed derived key is reproduced when the salt is passed as ASCII hex, not the decoded salt bytes used by standard implementations. The tests use a separately generated fixture with the normal decoded-salt behavior rather than teaching the code to match that anomaly.

## Format notes and references

This parser recognizes a version-3 Web3 Secret Storage object (`version: 3`, `aes-128-ctr`, scrypt or PBKDF2) directly or inside a base64 `redditBackupData` JSON field. It does not guess at other encodings.

- [Ethereum.org: Web3 Secret Storage v3](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage/)
- [FileInfo: `.redditvault` file description](https://fileinfo.com/extension/redditvault) (third-party file-format reference)
- [Reddit notice: in-app Vault removal effective January 1, 2026](https://support.reddithelp.com/hc/en-us/articles/41045533082644-Changelog-September-9-2025)
- [Reddit Help Center search for current Vault recovery/export guidance](https://support.reddithelp.com/hc/en-us/search?query=Vault%20recovery)
