#!/usr/bin/env python3
"""
Look up a wallet ADDRESS (public information) -- never a secret.

Default mode is fully offline: it validates the address, prints its
EIP-55 checksummed form, and prints block-explorer links you can open
yourself.  With ``--fetch`` it additionally asks public RPC endpoints for
the native balance and transaction count on Ethereum / Polygon /
Arbitrum One / Arbitrum Nova.

Privacy note for --fetch: an RPC provider learns "this IP asked about
this address". The address is public, but if that linkage bothers you,
skip --fetch and use the explorer links from a browser/VPN you trust.

What a native-balance check can and cannot say:
  * Reddit Collectible Avatars are NFTs (Polygon) and Community Points
    lived on Arbitrum Nova (sunset by Reddit in 2023).  ERC-20 / ERC-721
    holdings do NOT show up in a native balance -- an account can hold
    avatars while showing 0 ETH/MATIC.  Use the explorer token/NFT tabs.
  * This tool therefore never declares a wallet "empty".

Usage:
    python3 check_address.py 0xYourPublicAddress
    python3 check_address.py --from-vault path/to/backup.redditvault
    python3 check_address.py 0xYourPublicAddress --fetch
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultlib  # noqa: E402

CHAINS = {
    "ethereum": {
        "rpc": "https://ethereum.publicnode.com",
        "symbol": "ETH", "explorer": "https://etherscan.io/address/",
    },
    "polygon": {
        "rpc": "https://polygon.publicnode.com",
        "symbol": "POL/MATIC", "explorer": "https://polygonscan.com/address/",
    },
    "arbitrum": {
        "rpc": "https://arbitrum-one.publicnode.com",
        "symbol": "ETH", "explorer": "https://arbiscan.io/address/",
    },
    "arbitrum-nova": {
        "rpc": "https://nova.arbitrum.io/rpc",
        "symbol": "ETH", "explorer": "https://nova.arbiscan.io/address/",
    },
}


def _rpc(url: str, method: str, params: list) -> str:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    request = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "reddit-vault-tools/1.0"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 (fixed https hosts)
        payload = json.loads(response.read().decode())
    if "error" in payload:
        raise RuntimeError(str(payload["error"]))
    return payload["result"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check a public wallet address.")
    parser.add_argument("address", nargs="?", help="public 0x address")
    parser.add_argument("--from-vault", metavar="FILE",
                        help="read the address from a .redditvault file instead (no password needed)")
    parser.add_argument("--fetch", action="store_true",
                        help="query public RPC endpoints (reveals address + your IP to them)")
    args = parser.parse_args(argv)

    raw = args.address
    if args.from_vault:
        try:
            keystore = vaultlib.parse_vault_bytes(vaultlib.read_vault_file(args.from_vault))
        except (vaultlib.VaultError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not keystore.address:
            print("error: this backup carries no address field. This helper "
                  "does not derive addresses from recovery phrases; use a "
                  "reputable wallet locally to identify the public address, "
                  "or supply a public address you already know. Never paste "
                  "the phrase into this command.", file=sys.stderr)
            return 2
        raw = keystore.address
    if not raw:
        parser.error("give an address or --from-vault FILE")

    candidate = raw.strip()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", candidate):
        print("error: that looks like a 64-hex-character PRIVATE KEY, not an "
              "address. Never paste it into tools, chats, or websites. An "
              "address is 40 hex characters (0x + 40).", file=sys.stderr)
        return 2
    try:
        address = vaultlib.to_checksum_address(candidate)
    except vaultlib.VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Address (EIP-55): {address}")
    for name, chain in CHAINS.items():
        print(f"  {name:<14} {chain['explorer']}{address}")

    if not args.fetch:
        print("\nOffline mode: no network requests were made. Add --fetch "
              "to query public RPCs for native balance / tx count, and use "
              "the explorer token & NFT tabs for avatars / points.")
        return 0

    print("\nFetching (public RPCs now see this address + your IP)...")
    for name, chain in CHAINS.items():
        try:
            balance_hex = _rpc(chain["rpc"], "eth_getBalance", [address, "latest"])
            nonce_hex = _rpc(chain["rpc"], "eth_getTransactionCount", [address, "latest"])
            balance = int(balance_hex, 16) / 10**18
            print(f"  {name:<14} balance: {balance:.6f} {chain['symbol']}   "
                  f"outgoing txs (nonce): {int(nonce_hex, 16)}")
        except Exception as exc:  # network is best-effort by design
            print(f"  {name:<14} lookup failed: {exc}")
    print("\nReminder: 0 native balance does not mean empty -- check the "
          "ERC-20 / ERC-721 (NFT) tabs on the explorers above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
