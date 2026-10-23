#!/usr/bin/env python3
"""
Shared, dependency-free primitives for inspecting (and, with the owner's
password, decrypting) a Reddit Vault ``.redditvault`` backup.

Design constraints -- read before modifying:

* **Standard library only.**  A recovery tool that must be run around wallet
  secrets should not require ``pip install`` of unaudited packages on the
  machine that holds those secrets.  Keccak-256, AES-128-CTR and secp256k1
  address derivation are implemented here in pure Python.  The files are
  tiny (a 32-byte key or a short recovery phrase), so pure-Python speed is
  irrelevant.
* **No network code lives in this module.**  Nothing here can phone home.
* **No secret is ever printed, logged, or written by this module.**  Callers
  decide what to reveal, and the CLI tools default to revealing nothing.

Format notes (Web3 Secret Storage, version 3 -- ethereum.org):

    derived_key = KDF(password, salt)              # scrypt or pbkdf2
    mac         = KECCAK256(derived_key[16:32] + ciphertext)
    plaintext   = AES-128-CTR(key=derived_key[0:16], iv=iv, ciphertext)

Note on Reddit's wrapper: a ``.redditvault`` file is JSON.  It commonly
wraps the backup in a base64 field (seen as ``redditBackupData``) whose
decoded payload is, or contains, the version-3 object above
(``crypto``/``Crypto`` + ``version: 3``).  In Reddit's original product the
encrypted payload protects the wallet *recovery phrase*; in a plain
Ethereum keystore it protects a 32-byte private key.  This library does
NOT assume which one it is -- the plaintext type is classified only after
a successful MAC check, because that is the first moment anyone can know.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
from dataclasses import dataclass, field

__all__ = [
    "VaultError",
    "Keystore",
    "parse_vault_bytes",
    "read_vault_file",
    "parse_vault_text",
    "unwrap_reddit_backup",
    "keccak256",
    "aes128_ctr_crypt",
    "derive_key",
    "verify_mac",
    "decrypt_keystore",
    "encrypt_keystore",
    "private_key_to_address",
    "to_checksum_address",
    "classify_plaintext",
]


class VaultError(ValueError):
    """Raised for any structural, validation, or MAC failure."""


# Defensive resource ceilings for untrusted files. Standard Reddit / Web3
# scrypt settings (N=262144, r=8, p=1) need about 256 MiB and are accepted.
# Larger work factors can be legitimate, but this small offline helper
# refuses them rather than allowing a crafted file to exhaust the machine.
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = 1024 * 1024
MAX_SCRYPT_MEMORY_BYTES = 1024 * 1024 * 1024
MAX_SCRYPT_PARALLELISM = 16
MAX_DERIVED_KEY_BYTES = 1024
MAX_PBKDF2_ITERATIONS = 20_000_000


# --------------------------------------------------------------------------
# Keccak-256 (original Keccak padding 0x01, *not* NIST SHA3's 0x06)
# --------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets r[x][y], flattened as [x + 5*y].
_KECCAK_ROT = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]

# Pi permutation for the rho+pi step, flattened as [x + 5*y].
_KECCAK_PI = [
    0, 10, 20, 5, 15,
    16, 1, 11, 21, 6,
    7, 17, 2, 12, 22,
    23, 8, 18, 3, 13,
    14, 24, 9, 19, 4,
]


def _rotl64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list) -> None:
    for rc in _KECCAK_RC:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                idx = x + 5 * y
                moved[_KECCAK_PI[idx]] = _rotl64(state[idx], _KECCAK_ROT[idx])
        # chi
        for y in range(5):
            row = moved[5 * y:5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5] & _MASK64) & row[(x + 2) % 5])
        # iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of *data* (Ethereum's hash)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("keccak256 expects bytes")
    rate = 136  # 1088-bit rate for 256-bit output / 512-bit capacity
    state = [0] * 25
    # pad10*1 with Keccak domain byte 0x01. If one byte remains in
    # the block, the first and final padding bits share that byte (0x81).
    padded = bytearray(data)
    padding_length = rate - (len(padded) % rate)
    if padding_length == 1:
        padded.append(0x81)
    else:
        padded.append(0x01)
        padded.extend(b"\x00" * (padding_length - 2))
        padded.append(0x80)
    for block_start in range(0, len(padded), rate):
        block = padded[block_start:block_start + rate]
        for lane in range(rate // 8):
            state[lane] ^= struct.unpack_from("<Q", block, lane * 8)[0]
        _keccak_f1600(state)
    out = bytearray()
    while len(out) < 32:
        for lane in range(rate // 8):
            out.extend(struct.pack("<Q", state[lane]))
            if len(out) >= 32:
                break
        if len(out) < 32:
            _keccak_f1600(state)
    return bytes(out[:32])


# --------------------------------------------------------------------------
# AES-128 (encrypt direction only -- CTR mode uses it for both directions)
# --------------------------------------------------------------------------

_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _aes128_expand_key(key: bytes) -> list:
    if len(key) != 16:
        raise VaultError("AES-128 key must be exactly 16 bytes")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _AES_RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    # Flatten into 11 round keys of 16 bytes (column-major state layout).
    round_keys = []
    for rnd in range(11):
        rk = bytearray(16)
        for col in range(4):
            for row in range(4):
                rk[col * 4 + row] = words[rnd * 4 + col][row]
        round_keys.append(bytes(rk))
    return round_keys


def _aes128_encrypt_block(round_keys: list, block: bytes) -> bytes:
    if len(block) != 16:
        raise VaultError("AES block must be exactly 16 bytes")
    state = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 10):
        state = [_AES_SBOX[b] for b in state]
        # ShiftRows on column-major state: row r is state[r::4] rotated by r.
        shifted = [0] * 16
        for row in range(4):
            for col in range(4):
                shifted[col * 4 + row] = state[((col + row) % 4) * 4 + row]
        state = shifted
        # MixColumns
        mixed = [0] * 16
        for col in range(4):
            a = state[col * 4:col * 4 + 4]
            mixed[col * 4 + 0] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
            mixed[col * 4 + 1] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
            mixed[col * 4 + 2] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
            mixed[col * 4 + 3] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])
        state = [b ^ k for b, k in zip(mixed, round_keys[rnd])]
    state = [_AES_SBOX[b] for b in state]
    shifted = [0] * 16
    for row in range(4):
        for col in range(4):
            shifted[col * 4 + row] = state[((col + row) % 4) * 4 + row]
    state = [b ^ k for b, k in zip(shifted, round_keys[10])]
    return bytes(state)


def aes128_ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR encrypt/decrypt (symmetric). Counter is the 128-bit IV,
    incremented big-endian per block, as in Web3 Secret Storage."""
    if len(iv) != 16:
        raise VaultError("AES-CTR IV must be exactly 16 bytes")
    round_keys = _aes128_expand_key(key)
    counter = int.from_bytes(iv, "big")
    out = bytearray()
    for off in range(0, len(data), 16):
        keystream = _aes128_encrypt_block(round_keys, counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        out.extend(b ^ k for b, k in zip(chunk, keystream))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


# --------------------------------------------------------------------------
# secp256k1 -> Ethereum address (+ EIP-55 checksum)
# --------------------------------------------------------------------------

_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _SECP256K1_P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _SECP256K1_P) % _SECP256K1_P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % _SECP256K1_P, -1, _SECP256K1_P) % _SECP256K1_P
    x3 = (slope * slope - x1 - x2) % _SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % _SECP256K1_P
    return (x3, y3)


def private_key_to_address(private_key: bytes) -> str:
    """Derive the (lowercase, 0x-prefixed) Ethereum address for a 32-byte key."""
    if len(private_key) != 32:
        raise VaultError("private key must be exactly 32 bytes")
    secret = int.from_bytes(private_key, "big")
    if not 1 <= secret < _SECP256K1_N:
        raise VaultError("private key is outside the valid secp256k1 range")
    point = None
    addend = _SECP256K1_G
    k = secret
    while k:
        if k & 1:
            point = _ec_add(point, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    x, y = point
    public = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + keccak256(public)[-20:].hex()


def to_checksum_address(address: str) -> str:
    """EIP-55 mixed-case checksum encoding of a 20-byte hex address."""
    body = address.lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{40}", body):
        raise VaultError("address must be 40 hexadecimal characters, optionally prefixed by 0x")
    digest = keccak256(body.encode("ascii")).hex()
    out = "".join(
        ch.upper() if ch in "abcdef" and int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(body)
    )
    return "0x" + out


# --------------------------------------------------------------------------
# Parsing / unwrapping
# --------------------------------------------------------------------------

_WRAPPER_KEYS = {"redditbackupdata", "reddit_backup_data", "backupdata", "data"}


def _get_case_insensitive(obj: dict, name: str):
    for key, value in obj.items():
        if isinstance(key, str) and key.lower() == name.lower():
            return value
    return None


def _looks_like_keystore(obj) -> bool:
    if not isinstance(obj, dict):
        return False
    crypto = _get_case_insensitive(obj, "crypto")
    version = _get_case_insensitive(obj, "version")
    return isinstance(crypto, dict) and str(version) == "3"


def _try_b64_decode(text: str):
    cleaned = re.sub(r"\s+", "", text)
    if len(cleaned) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned):
        return None
    try:
        normalised = cleaned.replace("-", "+").replace("_", "/")
        normalised += "=" * (-len(normalised) % 4)
        return base64.b64decode(normalised, validate=True)
    except (binascii.Error, ValueError):
        return None


def unwrap_reddit_backup(obj, _depth: int = 0):
    """Peel ``redditBackupData`` / base64 layers until a keystore dict remains.

    Returns ``(keystore_obj, layers)`` where *layers* describes each peel.
    Raises :class:`VaultError` with a precise message if no version-3
    keystore object can be found.
    """
    layers = []
    current = obj
    depth = _depth
    while True:
        if depth > 6:
            raise VaultError("too many nested backup layers (>6) -- file structure is not recognised")
        if isinstance(current, str):
            decoded = _try_b64_decode(current)
            if decoded is not None:
                try:
                    current = json.loads(decoded.decode("utf-8-sig"))
                    layers.append("base64 -> JSON")
                    depth += 1
                    continue
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            try:
                current = json.loads(current)
                layers.append("JSON string -> object")
                depth += 1
                continue
            except json.JSONDecodeError:
                break
        if isinstance(current, dict):
            if _looks_like_keystore(current):
                return current, layers
            wrapper_value = None
            wrapper_key = None
            for key, value in current.items():
                if isinstance(key, str) and key.lower().replace("-", "_") in _WRAPPER_KEYS:
                    wrapper_value, wrapper_key = value, key
                    break
            if wrapper_key is not None:
                layers.append(f"field {wrapper_key!r}")
                current = wrapper_value
                depth += 1
                continue
            # Some exports nest the keystore one level down under any key.
            nested = [v for v in current.values() if _looks_like_keystore(v)]
            if len(nested) == 1:
                layers.append("nested keystore object")
                current = nested[0]
                depth += 1
                continue
        break
    raise VaultError(
        "no version-3 keystore found: expected a JSON object with "
        "'crypto' and 'version': 3, optionally wrapped in a base64 "
        "'redditBackupData' field"
    )


def _hex_field(value, name: str) -> bytes:
    if not isinstance(value, str):
        raise VaultError(f"field {name!r} must be a hex string")
    cleaned = value.lower().removeprefix("0x")
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-f]+", cleaned):
        raise VaultError(f"field {name!r} is not valid even-length hex")
    return bytes.fromhex(cleaned)


def _int_parameter(params: dict, name: str) -> int:
    value = params.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise VaultError(f"KDF parameter {name!r} must be an integer")
    return value


def _validate_kdf_params(kdf: str, params) -> tuple:
    """Return KDF-specific ``(errors, warnings)`` without doing any work."""
    errors, warnings = [], []
    if not isinstance(params, dict):
        return ["missing 'kdfparams' object"], warnings
    if kdf == "scrypt":
        try:
            n = _int_parameter(params, "n")
            r = _int_parameter(params, "r")
            p = _int_parameter(params, "p")
            dklen = _int_parameter(params, "dklen")
            salt = _hex_field(params.get("salt"), "kdfparams.salt")
        except VaultError as exc:
            return [str(exc)], warnings
        if n <= 1 or (n & (n - 1)) != 0:
            errors.append(f"scrypt n={n} is not a power of two > 1")
        if r < 1:
            errors.append("scrypt r must be >= 1")
        if p < 1:
            errors.append("scrypt p must be >= 1")
        if p > MAX_SCRYPT_PARALLELISM:
            errors.append(f"scrypt p={p} exceeds this tool's safety limit ({MAX_SCRYPT_PARALLELISM})")
        if dklen < 32:
            errors.append(f"scrypt dklen={dklen} is < 32")
        if dklen > MAX_DERIVED_KEY_BYTES:
            errors.append(f"scrypt dklen={dklen} exceeds this tool's safety limit ({MAX_DERIVED_KEY_BYTES})")
        if len(salt) < 16:
            warnings.append(f"scrypt salt is short ({len(salt)} bytes)")
        if n > 1 and r > 0:
            memory = 128 * n * r
            if memory > MAX_SCRYPT_MEMORY_BYTES:
                errors.append(
                    "scrypt working-memory requirement exceeds this tool's "
                    f"{MAX_SCRYPT_MEMORY_BYTES // (1024 ** 3)} GiB safety limit"
                )
            elif memory > 512 * 1024 * 1024:
                warnings.append(f"scrypt requires about {memory / 2**20:.0f} MiB of working memory")
            work = n * r * p
            if work > 1 << 27:
                warnings.append("scrypt work factor is unusually high and may take a long time")
    elif kdf == "pbkdf2":
        try:
            c = _int_parameter(params, "c")
            dklen = _int_parameter(params, "dklen")
            _hex_field(params.get("salt"), "kdfparams.salt")
        except VaultError as exc:
            return [str(exc)], warnings
        prf = str(params.get("prf", "")).lower()
        if prf != "hmac-sha256":
            errors.append(f"unsupported pbkdf2 prf {prf!r} (expected 'hmac-sha256')")
        if c < 1:
            errors.append("pbkdf2 iteration count c must be >= 1")
        if c > MAX_PBKDF2_ITERATIONS:
            errors.append(
                f"pbkdf2 c={c} exceeds this tool's safety limit "
                f"({MAX_PBKDF2_ITERATIONS})"
            )
        if dklen < 32:
            errors.append(f"pbkdf2 dklen={dklen} is < 32")
        if dklen > MAX_DERIVED_KEY_BYTES:
            errors.append(f"pbkdf2 dklen={dklen} exceeds this tool's safety limit ({MAX_DERIVED_KEY_BYTES})")
    else:
        errors.append(f"unsupported kdf {kdf!r} (expected 'scrypt' or 'pbkdf2')")
    return errors, warnings


@dataclass
class Keystore:
    raw: dict                       # the unwrapped keystore object
    layers: list = field(default_factory=list)
    address: str | None = None      # lowercase, 0x-prefixed, if present
    keystore_id: str | None = None

    # -- typed accessors over raw["crypto"] ------------------------------
    @property
    def crypto(self) -> dict:
        crypto = _get_case_insensitive(self.raw, "crypto")
        if not isinstance(crypto, dict):
            raise VaultError("missing 'crypto' object")
        return crypto

    @property
    def cipher(self) -> str:
        return str(_get_case_insensitive(self.crypto, "cipher") or "").lower()

    @property
    def iv(self) -> bytes:
        params = _get_case_insensitive(self.crypto, "cipherparams")
        if not isinstance(params, dict):
            raise VaultError("missing 'cipherparams' object")
        return _hex_field(_get_case_insensitive(params, "iv"), "cipherparams.iv")

    @property
    def ciphertext(self) -> bytes:
        return _hex_field(_get_case_insensitive(self.crypto, "ciphertext"), "ciphertext")

    @property
    def kdf(self) -> str:
        return str(_get_case_insensitive(self.crypto, "kdf") or "").lower()

    @property
    def kdfparams(self) -> dict:
        params = _get_case_insensitive(self.crypto, "kdfparams")
        if not isinstance(params, dict):
            raise VaultError("missing 'kdfparams' object")
        return params

    @property
    def mac(self) -> bytes:
        return _hex_field(_get_case_insensitive(self.crypto, "mac"), "mac")

    def validate(self) -> tuple:
        """Return ``(errors, warnings)`` without needing any password."""
        errors, warnings = [], []

        def check(fn, label):
            try:
                return fn()
            except VaultError as exc:
                errors.append(f"{label}: {exc}")
                return None

        if str(_get_case_insensitive(self.raw, "version")) != "3":
            errors.append("version is not 3")
        cipher = check(lambda: self.cipher, "cipher")
        if cipher is not None and cipher != "aes-128-ctr":
            errors.append(f"unsupported cipher {cipher!r} (expected 'aes-128-ctr')")
        iv = check(lambda: self.iv, "iv")
        if iv is not None and len(iv) != 16:
            errors.append(f"IV must be 16 bytes, got {len(iv)}")
        ciphertext = check(lambda: self.ciphertext, "ciphertext")
        if ciphertext is not None and len(ciphertext) == 0:
            errors.append("ciphertext is empty")
        if ciphertext is not None and len(ciphertext) > MAX_CIPHERTEXT_BYTES:
            errors.append(
                f"ciphertext exceeds this tool's {MAX_CIPHERTEXT_BYTES // (1024 * 1024)} MiB limit"
            )
        mac = check(lambda: self.mac, "mac")
        if mac is not None and len(mac) != 32:
            errors.append(f"MAC must be 32 bytes (keccak-256), got {len(mac)}")

        kdf = check(lambda: self.kdf, "kdf")
        params = check(lambda: self.kdfparams, "kdfparams")
        if kdf is not None and params is not None:
            kdf_errors, kdf_warnings = _validate_kdf_params(kdf, params)
            errors.extend(kdf_errors)
            warnings.extend(kdf_warnings)

        if self.address is not None and not re.fullmatch(r"0x[0-9a-f]{40}", self.address):
            errors.append("address field is not a 20-byte Ethereum address (value omitted)")
        return errors, warnings


def _normalise_loaded(obj, layers) -> Keystore:
    keystore_obj, peel = unwrap_reddit_backup(obj)
    address = _get_case_insensitive(keystore_obj, "address")
    # Some wrappers keep public metadata beside (not inside) the encoded
    # keystore. Prefer the keystore's own address, and use a top-level value
    # only when the inner object has no address field.
    if address is None and isinstance(obj, dict):
        address = _get_case_insensitive(obj, "address")
    if isinstance(address, str):
        addr = address.lower()
        if not addr.startswith("0x"):
            addr = "0x" + addr
    else:
        addr = None
    kid = _get_case_insensitive(keystore_obj, "id")
    valid_id = (
        str(kid) if isinstance(kid, str) and re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", kid
        ) else None
    )
    return Keystore(
        raw=keystore_obj,
        layers=list(layers) + peel,
        address=addr,
        keystore_id=valid_id,
    )


_VIDEO_MAGICS = (
    (4, b"ftyp"),          # ISO-BMFF / MP4 / MOV: bytes 4..8 == 'ftyp'
    (0, b"\x1a\x45\xdf\xa3"),  # WebM / Matroska EBML
    (0, b"\x00\x00\x01\xba"),  # MPEG-PS
    (0, b"\x00\x00\x01\xb3"),  # MPEG video
    (0, b"FLV"),           # Flash video
)


def detect_container(data: bytes) -> str | None:
    """Return a video-container name if *data* starts with known magic."""
    if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return "an AVI (RIFF) video-container signature"
    for offset, magic in _VIDEO_MAGICS:
        if data[offset:offset + len(magic)] == magic:
            return "a recognised video container signature (ftyp/EBML/MPEG/FLV)"
    return None


def read_vault_file(path) -> bytes:
    """Read a small backup, refusing large files before loading them all."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise VaultError(
            f"file exceeds this tool's {MAX_INPUT_BYTES // (1024 * 1024)} MiB "
            "input limit; a .redditvault backup should be small JSON text"
        )
    return data


def parse_vault_bytes(data: bytes) -> Keystore:
    """Parse raw file bytes into a :class:`Keystore`, unwrapping layers."""
    if not data:
        raise VaultError("file is empty (0 bytes)")
    if len(data) > MAX_INPUT_BYTES:
        raise VaultError(
            f"file is {len(data)} bytes; this tool refuses inputs above "
            f"{MAX_INPUT_BYTES // (1024 * 1024)} MiB to avoid loading an "
            "unexpected video or other large file into memory"
        )
    container = detect_container(data)
    if container:
        raise VaultError(
            f"file starts with {container}. A .redditvault backup is small "
            "JSON text. Either this really is a video (and not a wallet "
            "backup), or a JSON backup was embedded/renamed -- do not try "
            "to 'play' or transcode it; inspect a copy as text first."
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise VaultError(
            "file is not UTF-8 text. A .redditvault backup is JSON text; "
            f"this file may be binary, compressed, or truncated ({exc})"
        ) from exc
    return parse_vault_text(text)


def parse_vault_text(text: str) -> Keystore:
    stripped = text.strip().strip("\x00").strip()
    if not stripped:
        raise VaultError("file contains only whitespace")
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        # Whole-file base64 (no JSON wrapper)?
        decoded = _try_b64_decode(stripped)
        if decoded is not None:
            try:
                obj = json.loads(decoded.decode("utf-8-sig"))
                return _normalise_loaded(obj, ["whole file: base64 -> JSON"])
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
        raise VaultError(
            "file is not valid JSON and is not base64-encoded JSON. "
            "A .redditvault backup should parse as JSON (possibly after "
            "decoding its redditBackupData field)."
        )
    return _normalise_loaded(obj, [])


# --------------------------------------------------------------------------
# Key derivation, MAC verification, decryption / encryption
# --------------------------------------------------------------------------

def derive_key(keystore: Keystore, password: str) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be str")
    pw = password.encode("utf-8")
    params = keystore.kdfparams
    errors, _warnings = _validate_kdf_params(keystore.kdf, params)
    if errors:
        raise VaultError("invalid KDF parameters: " + "; ".join(errors))
    if keystore.kdf == "scrypt":
        n, r, p, dklen = (params[k] for k in ("n", "r", "p", "dklen"))
        salt = _hex_field(params.get("salt"), "kdfparams.salt")
        # OpenSSL's default limit is commonly too low for standard Ethereum
        # wallets (N=262144, r=8 needs roughly 256 MiB). Permit the validated
        # working set plus overhead, but never exceed our 1 GiB policy limit.
        needed = 128 * n * r + 128 * r * p + 256 * r + (1 << 20)
        maxmem = min(MAX_SCRYPT_MEMORY_BYTES, max(needed, 1 << 28))
        try:
            return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=dklen,
                                  maxmem=maxmem)
        except (ValueError, MemoryError) as exc:
            raise VaultError(
                "scrypt could not run with this machine's available memory "
                "or cryptographic runtime limits; this is a resource error, "
                "not evidence that the password is wrong"
            ) from exc
    if keystore.kdf == "pbkdf2":
        c, dklen = params["c"], params["dklen"]
        salt = _hex_field(params.get("salt"), "kdfparams.salt")
        return hashlib.pbkdf2_hmac("sha256", pw, salt, c, dklen)
    raise VaultError(f"unsupported kdf {keystore.kdf!r}")


def verify_mac(keystore: Keystore, derived_key: bytes) -> bool:
    if len(derived_key) < 32:
        raise VaultError("derived key must be at least 32 bytes")
    expected = keccak256(derived_key[16:32] + keystore.ciphertext)
    return hmac.compare_digest(expected, keystore.mac)


def decrypt_keystore(keystore: Keystore, password: str) -> bytes:
    """Decrypt and return the plaintext bytes.

    Raises :class:`VaultError` if the MAC does not verify -- which means
    the password is wrong *or* the file is corrupted/tampered with.  The
    two cases are indistinguishable by design, and callers must say so.
    """
    errors, _warnings = keystore.validate()
    if errors:
        raise VaultError("invalid keystore: " + "; ".join(errors))
    if keystore.cipher != "aes-128-ctr":
        raise VaultError(f"unsupported cipher {keystore.cipher!r}")
    derived = derive_key(keystore, password)
    if not verify_mac(keystore, derived):
        raise VaultError(
            "MAC verification failed: the password does not match this "
            "file, or the file is corrupted/tampered with. Nothing was "
            "decrypted."
        )
    return aes128_ctr_crypt(derived[0:16], keystore.iv, keystore.ciphertext)


def encrypt_keystore(plaintext: bytes, password: str, *, address: str | None = None,
                     n: int = 4096, r: int = 8, p: int = 1,
                     salt: bytes | None = None, iv: bytes | None = None,
                     keystore_id: str = "00000000-0000-4000-8000-000000000000") -> dict:
    """Build a version-3 keystore dict.  Used only for demo/test fixtures
    with publicly known secrets -- never for a real wallet in these tools."""
    import os
    salt = salt if salt is not None else os.urandom(32)
    iv = iv if iv is not None else os.urandom(16)
    probe = Keystore(raw={"crypto": {
        "cipher": "aes-128-ctr", "cipherparams": {"iv": iv.hex()},
        "ciphertext": "", "kdf": "scrypt",
        "kdfparams": {"dklen": 32, "n": n, "r": r, "p": p, "salt": salt.hex()},
        "mac": ""}, "version": 3})
    derived = derive_key(probe, password)
    ciphertext = aes128_ctr_crypt(derived[0:16], iv, plaintext)
    mac = keccak256(derived[16:32] + ciphertext).hex()
    obj: dict = {
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": iv.hex()},
            "ciphertext": ciphertext.hex(),
            "kdf": "scrypt",
            "kdfparams": {"dklen": 32, "n": n, "p": p, "r": r, "salt": salt.hex()},
            "mac": mac,
        },
        "id": keystore_id,
        "version": 3,
    }
    if address:
        obj["address"] = address.lower().removeprefix("0x")
    return obj


def classify_plaintext(plaintext: bytes) -> dict:
    """Describe decrypted plaintext *without* returning the secret itself.

    Returns a dict whose ``kind`` is one of ``private_key``,
    ``recovery_phrase``, ``hex_private_key``, ``json``, ``text`` or
    ``binary``.  Only non-secret metadata is included (lengths, word
    count, whether a derived address matches).  The caller adds the
    secret back only under an explicit reveal step.
    """
    info: dict = {"length_bytes": len(plaintext), "kind": "binary"}
    if len(plaintext) == 32:
        try:
            info["kind"] = "private_key"
            info["derived_address"] = private_key_to_address(plaintext)
            return info
        except VaultError:
            pass  # 32 random-looking bytes that are not a valid key
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return info
    stripped = text.strip()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", stripped):
        key_bytes = bytes.fromhex(stripped.removeprefix("0x").removeprefix("0X"))
        try:
            info["kind"] = "hex_private_key"
            info["derived_address"] = private_key_to_address(key_bytes)
            return info
        except VaultError:
            pass
    words = stripped.split()
    if 12 <= len(words) <= 24 and all(re.fullmatch(r"[a-z]+", w) for w in words):
        info["kind"] = "recovery_phrase"
        info["word_count"] = len(words)
        return info
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                info["kind"] = "json"
                info["json_keys"] = sorted(str(k) for k in obj.keys())
                return info
        except json.JSONDecodeError:
            pass
    if stripped and all(ch.isprintable() or ch in "\n\t" for ch in stripped):
        info["kind"] = "text"
    return info
