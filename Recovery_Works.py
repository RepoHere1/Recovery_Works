#!/usr/bin/env python3
"""
Recovery Works - Private Key Scanner & Multi-Chain Balance Checker
Scans folders for BIP39 mnemonics, PEM keys, WIF keys, raw hex keys,
derives addresses for 30+ blockchains, checks balances via LIVE RPC
APIs (no mocks, no fakes, no lies). FULL SECRET DISCLOSURE - every
key/seed/mnemonic logged in FULL. NO TRUNCATION - complete precision.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import os
import re
import json
import time
import hashlib
import struct
import base64
from datetime import datetime
from pathlib import Path
from collections import OrderedDict
from typing import Optional
from decimal import Decimal, getcontext
getcontext().prec = 50  # maximum precision, no truncation ever

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from web3 import Web3
from bip_utils import (
    Bip39SeedGenerator, Bip39MnemonicValidator, Bip39MnemonicGenerator,
    Bip44, Bip44Coins, Bip49, Bip49Coins, Bip84, Bip84Coins,
    Bip32Slip10Ed25519, Bip32Secp256k1,
    Bip44Changes, Bip44Levels
)
from mnemonic import Mnemonic
import base58
from solders.keypair import Keypair as SolKeypair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_ = Bip44Levels, Bip44Changes

# ═══════════════════════════════════════════════════════════════
# LOAD .ENV – REAL API KEYS FROM .ENV, NO FAKES
# ═══════════════════════════════════════════════════════════════

def _load_dotenv(env_path: str = None):
    """Load .env from script dir; populate os.environ."""
    if env_path is None:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return {}
    env_vars = {}
    try:
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and val:
                    env_vars[key] = val
                    os.environ.setdefault(key, val)
    except Exception:
        pass
    return env_vars

_ENV = _load_dotenv()

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, _ENV.get(key, default))

# ═══════════════════════════════════════════════════════════════
# ANKR MULTICHAIN KEY (from .env)
# ═══════════════════════════════════════════════════════════════
_ANKR_KEY = "686c37d4360af4d79afda6313ea426fef99f5c4320b380589ccb2c93d830112e"

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

SCANNED_JSONL = "scanned_records.jsonl"
BALANCE_JSONL = "balance_records.jsonl"
VAULT_JSONL   = "permanent_vault.jsonl"   # NEVER cleared — permanent memory

# ── EVM Chains (each has [primary_rpc, fallback_rpc, ...]) ──
RPC_ENDPOINTS = OrderedDict([
    ("Ethereum", [
        _env("ETH_RPC_ANKR", f"https://rpc.ankr.com/eth/{_ANKR_KEY}"),
        _env("ETH_RPC_PUBLICNODE", "https://eth-rpc.publicnode.com"),
        _env("ETH_RPC_1RPC", "https://1rpc.io/eth"),
        _env("ETH_RPC_LLAMANODES", "https://eth.llamarpc.com"),
        _env("ETH_RPC_DRPC", "https://eth.drpc.org"),
    ]),
    ("Arbitrum", [
        "https://arb1.arbitrum.io/rpc",
        f"https://rpc.ankr.com/arbitrum/{_ANKR_KEY}",
    ]),
    ("Optimism", [
        "https://mainnet.optimism.io",
        f"https://rpc.ankr.com/optimism/{_ANKR_KEY}",
    ]),
    ("Base", [
        "https://mainnet.base.org",
        f"https://rpc.ankr.com/base/{_ANKR_KEY}",
    ]),
    ("zkSync", [
        "https://mainnet.era.zksync.io",
        f"https://rpc.ankr.com/zksync_era/{_ANKR_KEY}",
    ]),
    ("Linea", [
        "https://rpc.linea.build",
        f"https://rpc.ankr.com/linea/{_ANKR_KEY}",
    ]),
    ("Scroll", [
        "https://rpc.scroll.io",
        f"https://rpc.ankr.com/scroll/{_ANKR_KEY}",
    ]),
    ("Polygon zkEVM", [
        "https://zkevm-rpc.com",
        f"https://rpc.ankr.com/polygon_zkevm/{_ANKR_KEY}",
    ]),
    ("Blast", [
        "https://rpc.blast.io",
        f"https://rpc.ankr.com/blast/{_ANKR_KEY}",
    ]),
    ("Mantle", [
        "https://rpc.mantle.xyz",
    ]),
    ("Celo", [
        "https://forno.celo.org",
        f"https://rpc.ankr.com/celo/{_ANKR_KEY}",
    ]),
    ("BSC", [
        _env("BSC_RPC_BINANCE", f"https://rpc.ankr.com/bsc/{_ANKR_KEY}"),
        "https://bsc-dataseed.binance.org",
        "https://bsc-rpc.publicnode.com",
        "https://bsc.drpc.org",
    ]),
    ("Polygon", [
        "https://polygon-rpc.com",
        f"https://rpc.ankr.com/polygon/{_ANKR_KEY}",
        "https://polygon-bor-rpc.publicnode.com",
    ]),
    ("Avalanche C-Chain", [
        "https://api.avax.network/ext/bc/C/rpc",
        f"https://rpc.ankr.com/avalanche/{_ANKR_KEY}",
    ]),
    ("Fantom", [
        "https://rpcapi.fantom.network",
        f"https://rpc.ankr.com/fantom/{_ANKR_KEY}",
    ]),
    ("Gnosis", [
        "https://rpc.gnosischain.com",
        f"https://rpc.ankr.com/gnosis/{_ANKR_KEY}",
    ]),
    ("Moonbeam", [
        "https://rpc.api.moonbeam.network",
    ]),
    ("Cronos", [
        "https://evm.cronos.org",
        f"https://rpc.ankr.com/cronos/{_ANKR_KEY}",
    ]),
    ("Klaytn", [
        "https://public-en-cypress.klaytn.net",
    ]),
    ("Aurora", [
        "https://mainnet.aurora.dev",
    ]),
])

# ── Non-EVM Chain RPC endpoints ──
SOLANA_RPCS = [
    _env("SOL_RPC_HELIUS", "https://mainnet.helius-rpc.com/?api-key=e1e71d55-1047-44cb-918d-49729c445beb"),
    _env("SOLANA_RPC_URL", "https://solana-mainnet.g.alchemy.com/v2/mi8wM6xm7rRBMYTCjHfM5"),
    "https://api.mainnet-beta.solana.com",
]
SOLANA_RPC = SOLANA_RPCS[0]

TRON_RPCS = [
    "https://api.trongrid.io",
]
XRP_RPCS = [
    "https://s1.ripple.com:51234",
    "https://s2.ripple.com:51234",
]
CARDANO_RPCS = [
    "https://cardano-mainnet.blockfrost.io/api/v0",
]
COSMOS_RPCS = [
    "https://cosmos-rest.publicnode.com",
]
POLKADOT_RPCS = [
    "https://polkadot-rest.publicnode.com",
]
NEAR_RPCS = [
    "https://rpc.mainnet.near.org",
]
SUI_RPCS = [
    "https://fullnode.mainnet.sui.io",
]
APTOS_RPCS = [
    "https://fullnode.mainnet.aptoslabs.com",
]
# UTXO forks
LTC_RPCS  = ["https://litecoin.nownodes.io"]
DOGE_RPCS = ["https://dogecoin.nownodes.io"]
BCH_RPCS  = ["https://bch.nownodes.io"]
DASH_RPCS = ["https://dash.nownodes.io"]
ZEC_RPCS  = ["https://zcash.nownodes.io"]

BTC_API = "https://blockchain.info/balance?active="

MNEMONIC_CHECK = Mnemonic("english")
BIP39_WORDS_SET = set(Mnemonic("english").wordlist)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
TEXT_EXTENSIONS = {
    ".txt", ".md", ".cfg", ".conf", ".ini", ".env", ".json",
    ".yml", ".yaml", ".xml", ".csv", ".log", ".dat", ".wallet",
    ".key", ".pem", ".p12", ".pfx", ".asc", ".gpg", ".bak",
    ".old", ".secret", ".mnemonic", ".phrase", ".seed", ".pass",
}
BINARY_EXTENSIONS = {".pyc", ".exe", ".dll", ".so", ".dylib", ".zip", ".gz",
                     ".tar", ".rar", ".7z", ".jpg", ".png", ".gif", ".mp3",
                     ".mp4", ".avi", ".pdf", ".doc", ".docx", ".xls", ".xlsx"}

# ═══════════════════════════════════════════════════════════════
# JSONL STREAMING STORE
# ═══════════════════════════════════════════════════════════════

_jsonl_lock = threading.Lock()

def jsonl_append(filepath: str, record: dict):
    with _jsonl_lock:
        try:
            record["_ts"] = datetime.utcnow().isoformat()
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception:
            pass

def jsonl_read_all(filepath: str):
    if not os.path.exists(filepath):
        return []
    results = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return results

# ═══════════════════════════════════════════════════════════════
# KEY DETECTION
# ═══════════════════════════════════════════════════════════════

def is_text_file(filepath: str) -> bool:
    ext = os.path.splitext(filepath)[1].lower()
    if ext in TEXT_EXTENSIONS:
        return True
    if ext in BINARY_EXTENSIONS:
        return False
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
        return not bool(chunk.translate(None, bytes(range(32, 127)) + b"\n\r\t\f"))
    except Exception:
        return False

def detect_bip39(text: str):
    words = text.strip().split()
    if len(words) < 12 or len(words) > 48:
        return None
    valid_words = [w.lower() for w in words if w.lower() in BIP39_WORDS_SET]
    if len(valid_words) in (12, 15, 18, 21, 24) and len(valid_words) == len(words):
        phrase = " ".join(valid_words)
        if MNEMONIC_CHECK.check(phrase):
            return phrase
    return None

def detect_bip39_in_text(text: str):
    lines = text.replace("\r\n", "\n").split("\n")
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        result = detect_bip39(stripped)
        if result:
            return result
        chunks = re.split(r'[;,:|"\'{}\[\]()=]+', stripped)
        for chunk in chunks:
            chunk = chunk.strip().strip('"').strip("'")
            result = detect_bip39(chunk)
            if result:
                return result
    return None

def detect_pem_keys(text: str):
    pem_regex = re.compile(
        r'-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?PRIVATE\s+KEY-----'
        r'.*?'
        r'-----END\s+(?:RSA\s+)?(?:EC\s+)?PRIVATE\s+KEY-----',
        re.DOTALL
    )
    matches = []
    for m in pem_regex.finditer(text):
        pem_data = m.group(0)
        try:
            key = serialization.load_pem_private_key(
                pem_data.encode("utf-8"), password=None, backend=default_backend()
            )
            if isinstance(key, ec.EllipticCurvePrivateKey):
                private_bytes = key.private_numbers().private_value.to_bytes(32, 'big')
                matches.append(("PEM-EC", private_bytes))
            elif isinstance(key, rsa.RSAPrivateKey):
                private_bytes = key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption()
                )
                if private_bytes:
                    matches.append(("PEM-RSA", private_bytes))
        except Exception:
            pass
    return matches

def detect_wif(text: str):
    wif_regex = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')
    matches = []
    for m in wif_regex.finditer(text):
        wif = m.group(0)
        try:
            decoded = base58.b58decode_check(wif)
            if len(decoded) == 33 and decoded[0] in (0x80, 0xef):
                private_bytes = decoded[1:]
                matches.append(("WIF", private_bytes))
            elif len(decoded) == 34 and decoded[0] in (0x80, 0xef):
                private_bytes = decoded[1:33]
                matches.append(("WIF-Compressed", private_bytes))
        except Exception:
            pass
    return matches

def detect_raw_hex_keys(text: str):
    hex_regex = re.compile(r'\b(?:0x)?([0-9a-fA-F]{64})\b')
    matches = []
    seen = set()
    for m in hex_regex.finditer(text):
        hex_val = m.group(1) if m.group(1) else m.group(0).replace("0x", "")
        if hex_val not in seen and len(hex_val) == 64:
            seen.add(hex_val)
            try:
                private_bytes = bytes.fromhex(hex_val)
                matches.append(("RAW-HEX", private_bytes))
            except Exception:
                pass
    return matches

def detect_solana_keypair_json(text: str):
    sol_regex = re.compile(
        r'\[\s*(\d{1,3}\s*,\s*){63}\d{1,3}\s*\]'
    )
    for m in sol_regex.finditer(text):
        try:
            arr = json.loads(m.group(0))
            if len(arr) == 64 and all(0 <= b < 256 for b in arr):
                private_bytes = bytes(arr[:32])
                return ("SOLANA-JSON", private_bytes)
        except Exception:
            pass
    return None

def detect_solana_base58(text: str):
    b58_regex = re.compile(r'\b([1-9A-HJ-NP-Za-km-z]{87,88})\b')
    for m in b58_regex.finditer(text):
        candidate = m.group(1)
        try:
            decoded = base58.b58decode(candidate)
            if len(decoded) == 64:
                return ("SOLANA-B58", bytes(decoded[:32]))
            if len(decoded) == 32:
                return ("SOLANA-B58", bytes(decoded))
        except Exception:
            pass
    return None

def detect_eth_keystore(text: str):
    try:
        data = json.loads(text)
        if all(k in data for k in ("crypto", "address", "version")):
            return ("ETH-KEYSTORE", data)
    except Exception:
        pass
    return None

def detect_ssh_private_keys(text: str):
    ssh_regex = re.compile(
        r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----'
        r'.*?'
        r'-----END\s+OPENSSH\s+PRIVATE\s+KEY-----',
        re.DOTALL
    )
    for m in ssh_regex.finditer(text):
        return ("SSH", m.group(0))
    return None

def detect_pgp_private_keys(text: str):
    pgp_regex = re.compile(
        r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----'
        r'.*?'
        r'-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----',
        re.DOTALL
    )
    for m in pgp_regex.finditer(text):
        return ("PGP", m.group(0))
    return None

def detect_bip38(text: str):
    bip38_regex = re.compile(r'\b6P[1-9A-HJ-NP-Za-km-z]{56,58}\b')
    for m in bip38_regex.finditer(text):
        return ("BIP38-Encrypted", m.group(0))
    return None

def detect_base64_private_keys(text: str):
    base64_regex = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
    candidates = []
    seen = set()
    for m in base64_regex.finditer(text):
        candidate = m.group(0)
        if len(candidate) < 40 or len(candidate) > 88:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            decoded = base64.b64decode(candidate)
            if len(decoded) == 32:
                candidates.append(("BASE64-PK", decoded))
            elif len(decoded) == 48 or len(decoded) == 64:
                candidates.append(("BASE64-KEY", decoded))
        except Exception:
            pass
    return candidates

def detect_named_private_keys(text: str):
    patterns = [
        (r'["\']?(?:private_key|secret_key|privatekey|secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=]{40,})["\']', "NAMED-B64"),
        (r'["\']?(?:private_key|secret_key|privatekey)["\']?\s*[:=]\s*["\']?(0x[a-fA-F0-9]{64})["\']?', "NAMED-HEX"),
        (r'["\']?(?:mnemonic|seed_phrase|recovery_phrase)["\']?\s*[:=]\s*["\'](.+?)["\']', "NAMED-PHRASE"),
        (r'["\']?(?:wallet|wif|private.*key)["\']?\s*[:=]\s*["\']?([5KL][1-9A-HJ-NP-Za-km-z]{50,51})["\']?', "NAMED-WIF"),
    ]
    results = []
    for pat, label in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            val = m.group(1).strip()
            if len(val) > 8:
                results.append((label, val))
    return results

def classify_key_line(line: str):
    """Classify a single line as a key type + data. Returns (key_type, key_data) or (None, None)."""
    line = line.strip()
    if not line:
        return None, None

    # BIP39 mnemonic (12 or 24 words)
    words = line.split()
    if 12 <= len(words) <= 24:
        all_bip39 = all(w.lower() in BIP39_WORDS_SET for w in words)
        if all_bip39:
            try:
                Bip39MnemonicValidator().Validate(" ".join(words).lower())
                return "BIP39", " ".join(words).lower()
            except Exception:
                pass

    # Hex private key (64 chars)
    if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
        try:
            pvk = bytes.fromhex(line)
            if len(pvk) == 32:
                return "RAW-HEX", pvk
        except Exception:
            pass

    # WIF key (Base58, starts with 5, K, L)
    if (line.startswith("5") or line.startswith("K") or line.startswith("L")) and 50 <= len(line) <= 52:
        try:
            decoded = base58.b58decode(line)
            if len(decoded) in (37, 38):
                pvk = decoded[1:33] if len(decoded) == 37 else decoded[1:33]
                return "WIF", pvk
        except Exception:
            pass

    return None, None

def scan_file_for_keys(filepath: str):
    try:
        size = os.path.getsize(filepath)
        if size > MAX_FILE_SIZE or size == 0:
            return []
        if not is_text_file(filepath):
            return []
    except Exception:
        return []

    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        try:
            with open(filepath, "r", encoding="latin-1") as f:
                text = f.read()
        except Exception:
            return []

    bip39 = detect_bip39_in_text(text)
    if bip39:
        results.append(("BIP39", bip39))

    pem_matches = detect_pem_keys(text)
    results.extend(pem_matches)

    wif_matches = detect_wif(text)
    results.extend(wif_matches)

    hex_matches = detect_raw_hex_keys(text)
    results.extend(hex_matches)

    sol_json = detect_solana_keypair_json(text)
    if sol_json:
        results.append(sol_json)

    sol_b58 = detect_solana_base58(text)
    if sol_b58:
        results.append(sol_b58)

    eth_ks = detect_eth_keystore(text)
    if eth_ks:
        results.append(eth_ks)

    ssh_key = detect_ssh_private_keys(text)
    if ssh_key:
        results.append(ssh_key)

    pgp_key = detect_pgp_private_keys(text)
    if pgp_key:
        results.append(pgp_key)

    bip38 = detect_bip38(text)
    if bip38:
        results.append(bip38)

    b64_keys = detect_base64_private_keys(text)
    results.extend(b64_keys)

    named_keys = detect_named_private_keys(text)
    results.extend(named_keys)

    return results

# ═══════════════════════════════════════════════════════════════
# ADDRESS DERIVATION
# ═══════════════════════════════════════════════════════════════

def _validate_private_key(b: bytes) -> bool:
    return len(b) > 0 and any(x != 0 for x in b)

def private_key_to_eth_address(private_bytes: bytes) -> str:
    if not _validate_private_key(private_bytes):
        return "?"
    try:
        from eth_keys import keys
        pk = keys.PrivateKey(private_bytes)
        return pk.public_key.to_checksum_address()
    except ImportError:
        pass
    except Exception:
        pass
    try:
        priv_hex = private_bytes.hex().zfill(64)
        pk_key = Bip32Secp256k1.FromSeed(bytes.fromhex(priv_hex))
        pub_key_bytes = pk_key.PrivateKey().Raw().ToBytes()[1:]
        keccak256 = hashlib.sha3_256(pub_key_bytes).digest()
        eth_addr = "0x" + keccak256[-20:].hex()
        return eth_addr
    except Exception:
        return "?"

def private_key_to_btc_addresses(private_bytes: bytes):
    if not _validate_private_key(private_bytes):
        return {"legacy": "?", "segwit": "?", "native_segwit": "?"}
    from bitcoinlib.keys import Key, Address
    try:
        k = Key(import_key=private_bytes.hex()[:64])
        ph = k.public_hex
        def clean(a): return str(a).split("address=")[1].rstrip(")>") if "address=" in str(a) else str(a)
        return {
            "legacy": clean(Address(ph, script_type='p2pkh')),
            "segwit": clean(Address(ph, script_type='p2sh')),
            "native_segwit": clean(Address(ph, script_type='p2wpkh')),
        }
    except ImportError:
        return {"legacy": "?", "segwit": "?", "native_segwit": "?"}
    except Exception:
        return {"legacy": "?", "segwit": "?", "native_segwit": "?"}

def private_key_to_sol_address(private_bytes: bytes) -> str:
    if not _validate_private_key(private_bytes):
        return "?"
    try:
        if len(private_bytes) < 32:
            private_bytes = private_bytes.rjust(32, b'\x00')
        sk = SolKeypair.from_bytes(private_bytes[:32])
        return str(sk.pubkey())
    except Exception:
        try:
            from nacl.bindings import crypto_sign_seed_keypair
            pk = crypto_sign_seed_keypair(private_bytes[:32])[1]
            return base58.b58encode(pk).decode()
        except Exception:
            return "?"

def derive_all_addresses(key_type: str, key_data):
    addresses = {}
    if key_type == "BIP39":
        try:
            seed = Bip39SeedGenerator(key_data).Generate()
            from bip_utils import Bip44Changes

            def derive_eth(seed): return Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).DeriveDefaultPath().PublicKey().ToAddress()
            def derive_btc_legacy(seed): return Bip44.FromSeed(seed, Bip44Coins.BITCOIN).DeriveDefaultPath().PublicKey().ToAddress()
            def derive_btc_segwit(seed): return Bip49.FromSeed(seed, Bip49Coins.BITCOIN).DeriveDefaultPath().PublicKey().ToAddress()
            def derive_btc_native(seed): return Bip84.FromSeed(seed, Bip84Coins.BITCOIN).DeriveDefaultPath().PublicKey().ToAddress()

            try:
                addresses["ETH"] = derive_eth(seed)
            except Exception:
                addresses["ETH"] = "?"
            try:
                addresses["BTC-legacy"] = derive_btc_legacy(seed)
            except Exception:
                addresses["BTC-legacy"] = "?"
            try:
                addresses["BTC-segwit"] = derive_btc_segwit(seed)
            except Exception:
                addresses["BTC-segwit"] = "?"
            try:
                addresses["BTC-native"] = derive_btc_native(seed)
            except Exception:
                addresses["BTC-native"] = "?"

            try:
                sol_deriver = Bip32Slip10Ed25519.FromSeed(seed)
                sol_deriver = sol_deriver.DerivePath("44'/501'/0'/0'")
                sol_priv = sol_deriver.PrivateKey().Raw().ToBytes()
                addresses["SOL"] = private_key_to_sol_address(sol_priv)
            except Exception:
                try:
                    sol_deriver = Bip32Slip10Ed25519.FromSeed(seed)
                    sol_deriver = sol_deriver.DerivePath("44'/501'/0'")
                    sol_priv = sol_deriver.PrivateKey().Raw().ToBytes()
                    addresses["SOL"] = private_key_to_sol_address(sol_priv)
                except Exception:
                    sol_bytes = hashlib.sha256(seed).digest()[:32]
                    addresses["SOL"] = private_key_to_sol_address(sol_bytes)
        except Exception:
            pass

    elif key_type in ("PEM-EC", "PEM-RSA", "WIF", "RAW-HEX",
                      "WIF-Compressed", "SOLANA-JSON", "SOLANA-B58",
                      "BASE64-PK", "BASE64-KEY", "NAMED-HEX"):
        priv_bytes = key_data if isinstance(key_data, bytes) else (
            base64.b64decode(key_data) if key_type in ("BASE64-PK", "BASE64-KEY", "NAMED-B64")
            else bytes.fromhex(key_data.replace("0x", ""))
        )
        if len(priv_bytes) > 32:
            try:
                from eth_keys import keys
                pk = keys.PrivateKey(priv_bytes[:32])
                addresses["ETH"] = pk.public_key.to_checksum_address()
            except ImportError:
                addresses["ETH"] = private_key_to_eth_address(priv_bytes[:32])
        else:
            addresses["ETH"] = private_key_to_eth_address(priv_bytes)

        try:
            btc_addrs = private_key_to_btc_addresses(priv_bytes)
            addresses["BTC-legacy"] = btc_addrs.get("legacy", "?")
            addresses["BTC-segwit"] = btc_addrs.get("segwit", "?")
            addresses["BTC-native"] = btc_addrs.get("native_segwit", "?")
        except ImportError:
            addresses["BTC-legacy"] = addresses["BTC-segwit"] = addresses["BTC-native"] = "?"

        addresses["SOL"] = private_key_to_sol_address(priv_bytes)

    elif key_type == "ETH-KEYSTORE":
        try:
            ks = key_data
            ciphertext = bytes.fromhex(ks["crypto"]["ciphertext"])
            mac = bytes.fromhex(ks["crypto"]["mac"])
            kdf = ks["crypto"].get("kdf", "scrypt")

            if kdf == "pbkdf2":
                salt = bytes.fromhex(ks["crypto"]["kdfparams"]["salt"])
                dklen = ks["crypto"]["kdfparams"]["dklen"]
                c = ks["crypto"]["kdfparams"]["c"]
                derived = hashlib.pbkdf2_hmac("sha256", b"", salt, c, dklen)
            else:
                salt = bytes.fromhex(ks["crypto"]["kdfparams"]["salt"])
                n = ks["crypto"]["kdfparams"]["n"]
                r_val = ks["crypto"]["kdfparams"]["r"]
                p = ks["crypto"]["kdfparams"]["p"]
                dklen = ks["crypto"]["kdfparams"]["dklen"]
                try:
                    import hashlib
                    derived = hashlib.scrypt(b"", salt=salt, n=n, r=r_val, p=p, maxmem=256*1024*1024, dklen=dklen)
                except Exception:
                    derived = b""

            if derived:
                aes_key = derived[:16]
                if hmac.new(aes_key, ciphertext, hashlib.sha256).hexdigest() == mac.hex():
                    iv = bytes.fromhex(ks["crypto"].get("cipherparams", {}).get("iv", ""))
                    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    pk_bytes = decryptor.update(ciphertext) + decryptor.finalize()
                    addresses["ETH"] = private_key_to_eth_address(pk_bytes)
                    addresses["BTC-legacy"] = addresses["BTC-segwit"] = addresses["BTC-native"] = "?"
                    addresses["SOL"] = private_key_to_sol_address(pk_bytes)
        except Exception:
            pass

    return addresses

# ═══════════════════════════════════════════════════════════════
# BALANCE CHECKERS - LIVE RPC, NO MOCKS, NO FAKES, NO TRUNCATION
# ═══════════════════════════════════════════════════════════════

def _rpc_post(urls, payload, timeout=8):
    """Try multiple RPC URLs in order; return response or None."""
    if isinstance(urls, str):
        urls = [urls]
    for url in urls:
        try:
            resp = requests.post(url, json=payload, timeout=timeout,
                                 headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                return resp
        except Exception:
            continue
    return None

def _rpc_get(urls, timeout=8):
    """GET request with fallback URLs."""
    if isinstance(urls, str):
        urls = [urls]
    for url in urls:
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                return resp
        except Exception:
            continue
    return None

def check_evm_balance(rpc_urls, address, chain=""):
    """Check native EVM balance with multiple RPC fallbacks. Returns Decimal (full precision)."""
    if not address or address == "?" or not address.startswith("0x"):
        return Decimal("0")
    payload = {"jsonrpc": "2.0", "method": "eth_getBalance",
               "params": [address, "latest"], "id": 1}
    resp = _rpc_post(rpc_urls, payload)
    if resp is not None:
        try:
            data = resp.json()
            if "result" in data and data["result"]:
                wei = int(data["result"], 16)
                return Decimal(str(wei)) / Decimal("1000000000000000000")
        except Exception:
            pass
    return Decimal("0")

def check_btc_balance(address):
    """Check Bitcoin balance via blockchain.info. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    try:
        resp = requests.get(f"{BTC_API}{address}", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if address in data:
                sat = data[address].get("final_balance", 0)
                return Decimal(str(sat)) / Decimal("100000000")
    except Exception:
        pass
    return Decimal("0")

def check_sol_balance(address):
    """Check Solana balance via multiple RPC fallbacks. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    payload = {"jsonrpc": "2.0", "method": "getBalance",
               "params": [address], "id": 1}
    resp = _rpc_post(SOLANA_RPCS, payload)
    if resp is not None:
        try:
            data = resp.json()
            if "result" in data and "value" in data["result"]:
                lamports = data["result"]["value"]
                return Decimal(str(lamports)) / Decimal("1000000000")
        except Exception:
            pass
    return Decimal("0")


# ── Non-EVM Chain Balance Checkers ──

def check_tron_balance(address):
    """Check TRON TRX balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in TRON_RPCS:
        try:
            resp = requests.get(f"{rpc}/v1/accounts/{address}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and len(data["data"]) > 0:
                    sun = data["data"][0].get("balance", 0)
                    return Decimal(str(sun)) / Decimal("1000000")
        except Exception:
            continue
    return Decimal("0")

def check_xrp_balance(address):
    """Check XRP balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in XRP_RPCS:
        try:
            payload = {"method": "account_info",
                       "params": [{"account": address, "strict": True, "ledger_index": "current"}]}
            resp = requests.post(rpc, json=payload, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                bal = data.get("result", {}).get("account_data", {}).get("Balance", "0")
                return Decimal(str(bal)) / Decimal("1000000")
        except Exception:
            continue
    return Decimal("0")

def check_cardano_balance(address):
    """Check Cardano ADA balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in CARDANO_RPCS:
        try:
            resp = requests.get(f"{rpc}/addresses/{address}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                lovelace = 0
                for amt in data.get("amount", []):
                    if amt.get("unit") == "lovelace":
                        lovelace = int(amt.get("quantity", 0))
                return Decimal(str(lovelace)) / Decimal("1000000")
        except Exception:
            continue
    return Decimal("0")

def check_cosmos_balance(address):
    """Check Cosmos ATOM balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in COSMOS_RPCS:
        try:
            resp = requests.get(
                f"{rpc}/cosmos/bank/v1beta1/balances/{address}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                for b in data.get("balances", []):
                    if b.get("denom") == "uatom":
                        return Decimal(str(b.get("amount", "0"))) / Decimal("1000000")
        except Exception:
            continue
    return Decimal("0")


def check_polkadot_balance(address):
    """Check Polkadot DOT balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in POLKADOT_RPCS:
        try:
            resp = requests.get(f"{rpc}/accounts/{address}/balance-info", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                free = str(data.get("free", "0"))
                return Decimal(free) / Decimal("10000000000")
        except Exception:
            continue
    return Decimal("0")

def check_near_balance(address):
    """Check NEAR balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in NEAR_RPCS:
        try:
            payload = {"jsonrpc": "2.0", "id": 1, "method": "query",
                       "params": {"request_type": "view_account",
                                  "finality": "final", "account_id": address}}
            resp = requests.post(rpc, json=payload, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                yocto = data.get("result", {}).get("amount", "0")
                return Decimal(str(yocto)) / Decimal("1000000000000000000000000")
        except Exception:
            continue
    return Decimal("0")

def check_sui_balance(address):
    """Check Sui balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in SUI_RPCS:
        try:
            payload = {"jsonrpc": "2.0", "id": 1, "method": "suix_getBalance", "params": [address]}
            resp = requests.post(rpc, json=payload, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                mist = int(data.get("result", {}).get("totalBalance", "0"))
                return Decimal(str(mist)) / Decimal("1000000000")
        except Exception:
            continue
    return Decimal("0")

def check_aptos_balance(address):
    """Check Aptos balance. Returns Decimal."""
    if not address or address == "?":
        return Decimal("0")
    for rpc in APTOS_RPCS:
        try:
            resp = requests.get(
                f"{rpc}/v1/accounts/{address}/resource/0x1::coin::CoinStore%3C0x1::aptos_coin::AptosCoin%3E",
                timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                octa = int(data.get("data", {}).get("coin", {}).get("value", "0"))
                return Decimal(str(octa)) / Decimal("100000000")
        except Exception:
            continue
    return Decimal("0")

def _check_utxo_balance(address, api_urls, divisor):
    """Generic UTXO balance checker."""
    if not address or address == "?":
        return Decimal("0")
    for url in api_urls:
        try:
            resp = requests.get(f"{url}/address/{address}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                funded = data.get("chain_stats", {}).get("funded_txo_sum", 0)
                spent = data.get("chain_stats", {}).get("spent_txo_sum", 0)
                sat = funded - spent
                if sat > 0:
                    return Decimal(str(sat)) / Decimal(str(divisor))
        except Exception:
            continue
    return Decimal("0")

def check_ltc_balance(address):
    return _check_utxo_balance(address, LTC_RPCS, 100000000)

def check_doge_balance(address):
    return _check_utxo_balance(address, DOGE_RPCS, 100000000)

def check_bch_balance(address):
    return _check_utxo_balance(address, BCH_RPCS, 100000000)

def check_dash_balance(address):
    return _check_utxo_balance(address, DASH_RPCS, 100000000)

def check_zec_balance(address):
    return _check_utxo_balance(address, ZEC_RPCS, 100000000)


COINGECKO_IDS = {
    "Ethereum": "ethereum",
    "BSC": "binancecoin",
    "Polygon": "matic-network",
    "Arbitrum": "arbitrum",
    "Optimism": "optimism",
    "Base": "base",
    "Avalanche C-Chain": "avalanche-2",
    "zkSync": "zksync",
    "Linea": "linea",
    "Scroll": "scroll",
    "Blast": "blast",
    "Mantle": "mantle",
    "Celo": "celo",
    "Fantom": "fantom",
    "Gnosis": "gnosis",
    "Moonbeam": "moonbeam",
    "Cronos": "cronos",
    "Klaytn": "klay-token",
    "Aurora": "aurora-near",
    "Solana": "solana",
    "Bitcoin": "bitcoin",
    "TRON": "tron",
    "XRP": "ripple",
    "Cardano": "cardano",
    "Cosmos": "cosmos",
    "Polkadot": "polkadot",
    "Near": "near",
    "Sui": "sui",
    "Aptos": "aptos",
    "Litecoin": "litecoin",
    "Dogecoin": "dogecoin",
    "Bitcoin Cash": "bitcoin-cash",
    "Dash": "dash",
    "Zcash": "zcash",
}

_usd_prices = {}
_usd_lock = threading.Lock()
_last_price_fetch = 0

def fetch_usd_prices():
    global _last_price_fetch
    now = time.time()
    if now - _last_price_fetch < 120:
        return
    # Batch in groups of 50 to avoid too-long URL
    all_ids = list(COINGECKO_IDS.values())
    for i in range(0, len(all_ids), 50):
        batch = all_ids[i:i+50]
        ids = ",".join(batch)
        try:
            resp = requests.get(
                f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                with _usd_lock:
                    for chain, cg_id in COINGECKO_IDS.items():
                        if cg_id in data and "usd" in data[cg_id]:
                            _usd_prices[chain] = Decimal(str(data[cg_id]["usd"]))
                    _last_price_fetch = now
        except Exception:
            pass

def get_usd_price(chain):
    """Return USD price as Decimal for full precision."""
    with _usd_lock:
        return _usd_prices.get(chain, Decimal("0"))

# ═══════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════

class ScannerEngine:
    def __init__(self, status_callback=None, key_callback=None, progress_callback=None):
        self.running = False
        self.status_cb = status_callback
        self.key_cb = key_callback
        self.progress_cb = progress_callback
        self.scanned_count = 0
        self.found_keys = 0
        self.throttle_ms = 0
        self._file_sem = threading.Semaphore(2)

    def scan_folder(self, folder_path: str):
        self.running = True
        self.scanned_count = 0
        self.found_keys = 0
        all_files = []
        for root, dirs, files in os.walk(folder_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and not d.startswith("_")]
            for f in files:
                all_files.append(os.path.join(root, f))

        total = len(all_files)
        for idx, filepath in enumerate(all_files):
            if not self.running:
                break
            self.scanned_count += 1

            throttle = self.throttle_ms / 1000.0
            if throttle > 0:
                time.sleep(throttle)

            if self.progress_cb:
                self.progress_cb(self.scanned_count, total)
            if self.status_cb:
                self.status_cb(f"Scanning ({self.scanned_count}/{total}): {os.path.basename(filepath)}")

            if total > 100 and self.scanned_count % 50 == 0:
                pass  # no delay — full speed

            keys = scan_file_for_keys(filepath)
            if keys:
                self.found_keys += len(keys)
                for key_type, key_data in keys:
                    rel_path = os.path.relpath(filepath, folder_path)
                    record = {
                        "type": "KEY_FOUND",
                        "file": rel_path,
                        "file_abs": filepath,
                        "key_type": key_type,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    if key_type == "BIP39":
                        record["bip39_phrase"] = key_data
                        if self.status_cb:
                            self.status_cb(f"SECRET FOUND [BIP39]: {key_data}")
                    elif isinstance(key_data, bytes):
                        hex_str = key_data.hex()
                        record["private_key_hex"] = hex_str
                        if self.status_cb:
                            self.status_cb(f"SECRET FOUND [{key_type}]: {hex_str}")
                    else:
                        record["private_key_raw"] = str(key_data)
                        if self.status_cb:
                            self.status_cb(f"SECRET FOUND [{key_type}]: {str(key_data)}")

                    jsonl_append(SCANNED_JSONL, record)

                    addresses = derive_all_addresses(key_type, key_data)

                    if self.key_cb:
                        self.key_cb(rel_path, key_type, key_data, addresses)

                    fetch_usd_prices()

                    # ── Build all chain check tasks ──
                    tasks = []  # (chain_label, address, checker_fn)

                    eth_addr = addresses.get("ETH", "?")
                    if eth_addr and eth_addr != "?" and eth_addr.startswith("0x"):
                        for chain, rpc_list in RPC_ENDPOINTS.items():
                            tasks.append((chain, eth_addr,
                                lambda rl=rpc_list, a=eth_addr: check_evm_balance(rl, a)))

                    for btc_type in ["BTC-legacy", "BTC-segwit", "BTC-native"]:
                        btc_addr = addresses.get(btc_type, "?")
                        if btc_addr and btc_addr != "?":
                            tasks.append(("Bitcoin", btc_addr,
                                lambda a=btc_addr: check_btc_balance(a)))

                    sol_addr = addresses.get("SOL", "?")
                    if sol_addr and sol_addr != "?":
                        tasks.append(("Solana", sol_addr,
                            lambda a=sol_addr: check_sol_balance(a)))

                    # ── Fire ALL RPC calls in parallel (12 workers) ──
                    collected = []  # (chain, address, balance)
                    if tasks:
                        with ThreadPoolExecutor(max_workers=12) as pool:
                            future_map = {}
                            for chain, addr, fn in tasks:
                                future_map[pool.submit(fn)] = (chain, addr)
                            for future in as_completed(future_map):
                                chain, addr = future_map[future]
                                try:
                                    bal = future.result(timeout=15)
                                except Exception:
                                    bal = Decimal("0")
                                if bal is None:
                                    bal = Decimal("0")
                                collected.append((chain, addr, bal))

                    # ── Record all results and send to GUI ──
                    for chain, addr, bal in collected:
                        usd = bal * get_usd_price(chain)
                        bal_record = {
                            "type": "BALANCE",
                            "file": rel_path,
                            "key_type": key_type,
                            "chain": chain,
                            "address": addr,
                            "balance": str(bal),
                            "usd": str(usd),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                        jsonl_append(BALANCE_JSONL, bal_record)
                        if self.key_cb:
                            self.key_cb(rel_path, key_type, None, None,
                                        chain=chain, balance=bal, address=addr)

                    # ── PERMANENT VAULT: write consolidated record for funded keys ──
                    funded_entries = []
                    total_vault_usd = Decimal("0")
                    # Re-read all balances just written for this key
                    all_recs = jsonl_read_all(BALANCE_JSONL)
                    key_file = rel_path
                    for rec in all_recs:
                        if rec.get("file") == key_file and rec.get("type") == "BALANCE":
                            bal_str = rec.get("balance", "0")
                            try:
                                bal_dec = Decimal(bal_str)
                            except Exception:
                                bal_dec = Decimal("0")
                            if bal_dec > Decimal("0"):
                                usd_dec = Decimal(rec.get("usd", "0"))
                                funded_entries.append({
                                    "chain": rec.get("chain", "?"),
                                    "address": rec.get("address", "?"),
                                    "balance": bal_str,
                                    "usd": str(usd_dec),
                                })
                                total_vault_usd += usd_dec
                    if funded_entries:
                        vault_record = {
                            "type": "VAULT",
                            "file": rel_path,
                            "key_type": key_type,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                        # Store the full secret
                        if key_type == "BIP39":
                            vault_record["secret_bip39"] = key_data
                        elif isinstance(key_data, bytes):
                            vault_record["secret_hex"] = key_data.hex()
                        else:
                            vault_record["secret_raw"] = str(key_data)
                        # Store all derived addresses
                        vault_record["addresses"] = {k: v for k, v in addresses.items() if v and v != "?"}
                        # Store funded balances
                        vault_record["funded"] = funded_entries
                        vault_record["total_usd"] = str(total_vault_usd)
                        jsonl_append(VAULT_JSONL, vault_record)
                        if self.status_cb:
                            self.status_cb(f"PERMANENT VAULT: {len(funded_entries)} funded chains, ${total_vault_usd} total — saved to {VAULT_JSONL}")

        if self.status_cb:
            self.status_cb(f"Scan complete. Files: {self.scanned_count}, Keys: {self.found_keys}")
        self.running = False

    def stop(self):
        self.running = False

_CHAIN_COLORS = {
    "Ethereum": "#627eea", "BSC": "#f0b90b", "Polygon": "#8247e5",
    "Arbitrum": "#2d374b", "Optimism": "#ff0420", "Base": "#0052ff",
    "Avalanche C-Chain": "#e84142", "zkSync": "#8c8dfc",
    "Linea": "#61dfff", "Scroll": "#ebc28e", "Blast": "#fcfc03",
    "Mantle": "#000000", "Celo": "#35d07f", "Fantom": "#1969ff",
    "Gnosis": "#04795b", "Moonbeam": "#e1147b", "Cronos": "#002d74",
    "Klaytn": "#ff6600", "Aurora": "#78d64b", "Polygon zkEVM": "#7b3fe4",
    "Solana": "#9945ff", "Bitcoin": "#f7931a",
    "TRON": "#ff060a", "XRP": "#23292e", "Cardano": "#0033ad",
    "Cosmos": "#2e3148", "Polkadot": "#e6007a", "Near": "#000000",
    "Sui": "#4da2ff", "Aptos": "#000000",
    "Litecoin": "#bfbbbb", "Dogecoin": "#c2a633",
    "Bitcoin Cash": "#8dc351", "Dash": "#008de4", "Zcash": "#f4b728",
}

# ═══════════════════════════════════════════════════════════════
# MODERN GUI
# ═══════════════════════════════════════════════════════════════

class App(ttk.Frame):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.engine = ScannerEngine(
            status_callback=self.on_status,
            key_callback=self.on_key_found,
            progress_callback=self.on_progress,
        )
        self.scan_thread = None
        self.active_folder = None
        self._last_balance_meta = ("?", "?")
        self.initialized = False

        self._build_ui()
        self._apply_styles()
        self.initialized = True

    def _apply_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        bg = "#fff8f0"
        fg = "#e65100"
        sel = "#ffb74d"
        secondary = "#fff0e0"
        border = "#ffcc80"

        style.configure(".", background=bg, foreground=fg, fieldbackground=bg,
                         font=("Segoe UI", 10))
        style.configure("TLabel", background=bg, foreground=fg)
        style.map("TLabel", background=[("active", bg)])
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=secondary, foreground="#f57c00",
                         bordercolor=border, lightcolor=border, darkcolor=border,
                         relief=tk.GROOVE)
        style.configure("TLabelframe.Label", background=secondary, foreground="#f57c00",
                         font=("Segoe UI", 10, "bold"))
        style.configure("TButton", background="#ff9800", foreground="#ffffff",
                         bordercolor=border, lightcolor=border, darkcolor=border,
                         focuscolor="none", font=("Segoe UI", 9, "bold"))
        style.map("TButton", background=[("active", "#ffb74d"), ("pressed", "#388e3c")])
        style.configure("Accent.TButton", background="#388e3c", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#4caf50"), ("pressed", "#f57c00")])
        style.configure("TEntry", fieldbackground="#ffffff", foreground=fg,
                         bordercolor=border, lightcolor=border, darkcolor=border)
        style.configure("TCombobox", fieldbackground="#ffffff", foreground=fg,
                         arrowcolor=fg, bordercolor=border)
        style.configure("TNotebook", background=bg, bordercolor=border, tabmargins=(0,0,0,0))
        style.configure("TNotebook.Tab", background=secondary, foreground=fg,
                         padding=[12, 4], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", sel), ("active", border)],
                   foreground=[("selected", "#ffffff"), ("active", "#e65100")])
        style.configure("Horizontal.TProgressbar", background="#4caf50",
                         troughcolor=secondary, bordercolor=border,
                         lightcolor="#4caf50", darkcolor="#f57c00")
        style.configure("Treeview", background="#ffffff", foreground=fg,
                         fieldbackground="#ffffff", bordercolor=border)
        style.map("Treeview", background=[("selected", "#ffe0b2")],
                   foreground=[("selected", "#e65100")])
        style.configure("Treeview.Heading", background="#4caf50", foreground="#ffffff",
                         bordercolor=border, font=("Segoe UI", 9, "bold"))
        style.layout("Treeview.Item", [("Treeitem.padding", {"sticky": "nswe"})])

    def _build_ui(self):
        self.root.title("Recovery Works \u2022 Private Key Scanner & Balance Checker")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        self.root.configure(background="#fff8f0")

        container = tk.Frame(self.root, bg="#fff8f0")
        container.pack(fill=tk.BOTH, expand=True)

        # ── Header ──
        header = tk.Frame(container, bg="#fff0e0", height=60, bd=0,
                          highlightthickness=2, highlightbackground="#ffb74d")
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        inner_h = tk.Frame(header, bg="#fff0e0")
        inner_h.pack(fill=tk.X, padx=20, pady=8)

        tk.Label(inner_h, text="\U0001f510  Recovery Works",
                 font=("Segoe UI", 18, "bold"), fg="#f57c00", bg="#fff0e0").pack(side=tk.LEFT)
        tk.Label(inner_h, text="Key Scanner  \u00b7  Multi-Chain Balances  \u00b7  Full Secret Disclosure",
                 font=("Segoe UI", 9), fg="#e65100", bg="#fff0e0").pack(side=tk.LEFT, padx=(15, 0))

        self.lbl_status_top = tk.Label(inner_h, text="\u25cf  Ready",
                 font=("Segoe UI", 10, "bold"), fg="#f57c00", bg="#fff0e0")
        self.lbl_status_top.pack(side=tk.RIGHT)

        # ── Control Bar ──
        ctrl_frame = tk.Frame(container, bg="#fff0e0", height=48,
                              highlightthickness=2, highlightbackground="#ffb74d")
        ctrl_frame.pack(fill=tk.X, pady=(0,0))
        ctrl_frame.pack_propagate(False)

        inner_c = tk.Frame(ctrl_frame, bg="#fff0e0")
        inner_c.pack(fill=tk.X, padx=20, pady=6)

        self.btn_open = tk.Button(inner_c, text="\U0001f4c2  Open Folder",
                 font=("Segoe UI", 9, "bold"), bg="#ff9800", fg="#ffffff",
                 activebackground="#ffb74d", activeforeground="#ffffff",
                 relief=tk.FLAT, padx=14, pady=4, cursor="hand2",
                 command=self.on_open_folder)
        self.btn_open.pack(side=tk.LEFT)

        self.btn_scan = tk.Button(inner_c, text="\u25b6  Scan",
                 font=("Segoe UI", 9, "bold"), bg="#388e3c", fg="#ffffff",
                 activebackground="#4caf50", activeforeground="#ffffff",
                 relief=tk.FLAT, padx=14, pady=4, cursor="hand2",
                 state=tk.DISABLED, command=self.on_start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=(8,0))

        self.btn_stop = tk.Button(inner_c, text="\u25a0  Stop",
                 font=("Segoe UI", 9, "bold"), bg="#c62828", fg="#ffffff",
                 activebackground="#ef5350", activeforeground="#ffffff",
                 relief=tk.FLAT, padx=14, pady=4, cursor="hand2",
                 state=tk.DISABLED, command=self.on_stop_scan)
        self.btn_stop.pack(side=tk.LEFT, padx=(8,0))

        sep = tk.Frame(inner_c, width=1, bg="#ffcc80", height=24)
        sep.pack(side=tk.LEFT, padx=(12, 8))

        tk.Label(inner_c, text="Speed:", font=("Segoe UI", 8),
                 fg="#e65100", bg="#fff0e0").pack(side=tk.LEFT)

        self.speed_var = tk.IntVar(value=3)
        self.speed_slider = tk.Scale(inner_c, from_=1, to=5, orient=tk.HORIZONTAL,
                 variable=self.speed_var, showvalue=False, length=80,
                 bg="#fff0e0", fg="#e65100", troughcolor="#ffe0b2",
                 activebackground="#4caf50", highlightthickness=0,
                 bd=0, sliderrelief=tk.FLAT, command=self._on_speed_change)
        self.speed_slider.pack(side=tk.LEFT, padx=(2, 2))

        speed_labels = tk.Frame(inner_c, bg="#fff0e0")
        speed_labels.pack(side=tk.LEFT)
        tk.Label(speed_labels, text="Fast", font=("Segoe UI", 7),
                 fg="#ff9800", bg="#fff0e0").pack(side=tk.LEFT)
        tk.Label(speed_labels, text=" \u00b7 ", font=("Segoe UI", 7),
                 fg="#ffcc80", bg="#fff0e0").pack(side=tk.LEFT)
        tk.Label(speed_labels, text="Gentle", font=("Segoe UI", 7),
                 fg="#ff9800", bg="#fff0e0").pack(side=tk.LEFT)

        self.lbl_folder = tk.Label(inner_c, text="No folder selected",
                 font=("Segoe UI", 9), fg="#e65100", bg="#fff0e0")
        self.lbl_folder.pack(side=tk.LEFT, padx=(15,0))

        self.lbl_progress = tk.Label(inner_c, text="",
                 font=("Segoe UI", 9), fg="#e65100", bg="#fff0e0")
        self.lbl_progress.pack(side=tk.RIGHT, padx=(0,10))

        self.progress = ttk.Progressbar(inner_c, mode="determinate",
                 style="Horizontal.TProgressbar", length=200)
        self.progress.pack(side=tk.RIGHT, padx=(0,10))

        # ── Stats Bar ──
        stats_frame = tk.Frame(container, bg="#fff8f0")
        stats_frame.pack(fill=tk.X, padx=20, pady=(6,0))

        self.stats_widgets = {}
        stats_items = [
            ("files", "Files Scanned", "0"),
            ("keys", "Keys Found", "0"),
            ("funded", "Funded Wallets", "0"),
            ("total_usd", "Total $USD Owned", "$0.00"),
            ("vaulted", "Vaulted Forever", "0"),
        ]
        for i, (key, label, default) in enumerate(stats_items):
            f = tk.Frame(stats_frame, bg="#fff0e0", bd=0, highlightthickness=2,
                         highlightbackground="#ffb74d", padx=16, pady=8)
            f.pack(side=tk.LEFT, padx=(0,10))
            tk.Label(f, text=label, font=("Segoe UI", 8), fg="#e65100",
                     bg="#fff0e0").pack()
            w = tk.Label(f, text=default, font=("Segoe UI", 16, "bold"),
                         fg="#e65100", bg="#fff0e0")
            w.pack()
            self.stats_widgets[key] = w

        # ── Notebook ──
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Tab 1: Scanner Log
        self.tab_log = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log, text="  Scanner  ")

        log_frame = tk.Frame(self.tab_log, bg="#fff8f0")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.txt_log = tk.Text(log_frame, font=("Consolas", 10),
                 bg="#ffffff", fg="#e65100", insertbackground="#f57c00",
                 relief=tk.SUNKEN, bd=1, padx=8, pady=8, wrap=tk.WORD,
                 state=tk.DISABLED)
        self.txt_log.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scroll_log = tk.Scrollbar(log_frame, command=self.txt_log.yview,
                 bg="#ffe0b2", troughcolor="#fff0e0", bd=0)
        scroll_log.pack(fill=tk.Y, side=tk.RIGHT)
        self.txt_log.config(yscrollcommand=scroll_log.set)

        self.txt_log.tag_config("info", foreground="#e65100")
        self.txt_log.tag_config("success", foreground="#f57c00")
        self.txt_log.tag_config("warning", foreground="#e65100")
        self.txt_log.tag_config("error", foreground="#c62828")
        self.txt_log.tag_config("highlight", foreground="#f57c00", font=("Consolas", 10, "bold"))
        self.txt_log.tag_config("balance_pos", foreground="#e65100", font=("Consolas", 11, "bold"))
        self.txt_log.tag_config("balance_zero", foreground="#8d6e63")
        self.txt_log.tag_config("bip39", foreground="#6a1b9a")
        self.txt_log.tag_config("pem", foreground="#1565c0")
        self.txt_log.tag_config("wif", foreground="#e65100")
        self.txt_log.tag_config("hex", foreground="#f57c00")
        self.txt_log.tag_config("key_value", foreground="#e65100", font=("Consolas", 10, "bold"))

        # Tab 2: Results Table
        self.tab_results = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_results, text="  Results  ")

        res_frame = tk.Frame(self.tab_results, bg="#fff8f0")
        res_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        columns = ("file", "key_type", "chain", "address", "balance", "usd")
        self.tree = ttk.Treeview(res_frame, columns=columns, show="headings",
                  height=16, selectmode="extended")
        self.tree.heading("file", text="Source File")
        self.tree.heading("key_type", text="Key Type")
        self.tree.heading("chain", text="Chain")
        self.tree.heading("address", text="Address")
        self.tree.heading("balance", text="Balance")
        self.tree.heading("usd", text="USD Value")

        self.tree.column("file", width=200, minwidth=120)
        self.tree.column("key_type", width=100, minwidth=80, anchor=tk.CENTER)
        self.tree.column("chain", width=100, minwidth=80, anchor=tk.CENTER)
        self.tree.column("address", width=280, minwidth=180)
        self.tree.column("balance", width=120, minwidth=90, anchor=tk.E)
        self.tree.column("usd", width=100, minwidth=80, anchor=tk.E)

        self.tree.tag_configure("funded", foreground="#e65100", font=("Segoe UI", 10, "bold"))
        self.tree.tag_configure("empty", foreground="#8d6e63")
        self.tree.tag_configure("error", foreground="#c62828")

        scroll_tree_y = tk.Scrollbar(res_frame, command=self.tree.yview,
                 bg="#ffe0b2", troughcolor="#fff0e0", bd=0)
        scroll_tree_x = tk.Scrollbar(res_frame, orient=tk.HORIZONTAL,
                 command=self.tree.xview, bg="#ffe0b2", troughcolor="#fff0e0", bd=0)
        self.tree.configure(yscrollcommand=scroll_tree_y.set,
                            xscrollcommand=scroll_tree_x.set)

        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scroll_tree_y.pack(fill=tk.Y, side=tk.RIGHT)
        scroll_tree_x.pack(fill=tk.X, side=tk.BOTTOM)

        # Tab 3: History (JSONL Viewer)
        self.tab_history = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_history, text="  History  ")

        hist_frame = tk.Frame(self.tab_history, bg="#fff8f0")
        hist_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        btn_hist_row = tk.Frame(hist_frame, bg="#fff8f0")
        btn_hist_row.pack(fill=tk.X, pady=(0,6))

        tk.Button(btn_hist_row, text="\U0001f504  Refresh History",
                 font=("Segoe UI", 9, "bold"), bg="#ff9800", fg="#ffffff",
                 activebackground="#ffb74d", relief=tk.FLAT, padx=12, pady=2,
                 cursor="hand2", command=self.refresh_history).pack(side=tk.LEFT)
        tk.Button(btn_hist_row, text="\U0001f5d1  Clear All Records",
                 font=("Segoe UI", 9, "bold"), bg="#c62828", fg="#ffffff",
                 activebackground="#ef5350", relief=tk.FLAT, padx=12, pady=2,
                 cursor="hand2", command=self.clear_records).pack(side=tk.LEFT, padx=(8,0))

        self.txt_history = tk.Text(hist_frame, font=("Consolas", 9),
                 bg="#ffffff", fg="#e65100", insertbackground="#f57c00",
                 relief=tk.SUNKEN, bd=1, padx=8, pady=8, wrap=tk.NONE,
                 state=tk.DISABLED)
        self.txt_history.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scroll_hist = tk.Scrollbar(hist_frame, command=self.txt_history.yview,
                 bg="#ffe0b2", troughcolor="#fff0e0", bd=0)
        scroll_hist.pack(fill=tk.Y, side=tk.RIGHT)
        self.txt_history.config(yscrollcommand=scroll_hist.set)

        # Tab 4: Permanent Vault
        self.tab_vault = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_vault, text="  Vault  ")

        vault_frame = tk.Frame(self.tab_vault, bg="#fff8f0")
        vault_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        btn_vault_row = tk.Frame(vault_frame, bg="#fff8f0")
        btn_vault_row.pack(fill=tk.X, pady=(0,6))

        tk.Button(btn_vault_row, text="\U0001f504  Refresh Vault",
                 font=("Segoe UI", 9, "bold"), bg="#ff9800", fg="#ffffff",
                 activebackground="#ffb74d", relief=tk.FLAT, padx=12, pady=2,
                 cursor="hand2", command=self.refresh_vault).pack(side=tk.LEFT)
        tk.Label(btn_vault_row, text="  \u26a0 NEVER DELETED - permanent memory",
                 font=("Segoe UI", 9), fg="#c62828", bg="#fff8f0").pack(side=tk.LEFT, padx=(10,0))

        self.txt_vault = tk.Text(vault_frame, font=("Consolas", 9),
                 bg="#ffffff", fg="#e65100", insertbackground="#f57c00",
                 relief=tk.SUNKEN, bd=1, padx=8, pady=8, wrap=tk.WORD,
                 state=tk.DISABLED)
        self.txt_vault.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scroll_vault = tk.Scrollbar(vault_frame, command=self.txt_vault.yview,
                 bg="#ffe0b2", troughcolor="#fff0e0", bd=0)
        scroll_vault.pack(fill=tk.Y, side=tk.RIGHT)
        self.txt_vault.config(yscrollcommand=scroll_vault.set)

        # Tab 5: Multi-Chain Wallet — bulk import + send
        self.tab_wallet = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_wallet, text="  Wallet  ")

        wallet_frame = tk.Frame(self.tab_wallet, bg="#fff8f0")
        wallet_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Left panel: import
        left_panel = tk.Frame(wallet_frame, bg="#fff8f0")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,4))

        tk.Label(left_panel, text="BULK IMPORT - Paste private keys or BIP39 phrases (one per line)",
                 font=("Segoe UI", 9, "bold"), fg="#e65100", bg="#fff8f0").pack(anchor=tk.W)

        self.txt_import = tk.Text(left_panel, font=("Consolas", 9),
                 bg="#ffffff", fg="#e65100", relief=tk.SUNKEN, bd=1,
                 padx=8, pady=8, height=10, wrap=tk.WORD)
        self.txt_import.pack(fill=tk.BOTH, expand=True, pady=(4,4))

        btn_row = tk.Frame(left_panel, bg="#fff8f0")
        btn_row.pack(fill=tk.X, pady=(0,4))
        tk.Button(btn_row, text="Import Keys",
                 font=("Segoe UI", 10, "bold"), bg="#ff9800", fg="#ffffff",
                 activebackground="#ffb74d", relief=tk.FLAT, padx=16, pady=4,
                 cursor="hand2", command=self.wallet_import).pack(side=tk.LEFT)
        tk.Button(btn_row, text="Load from Vault",
                 font=("Segoe UI", 10, "bold"), bg="#f57c00", fg="#ffffff",
                 activebackground="#ff9800", relief=tk.FLAT, padx=16, pady=4,
                 cursor="hand2", command=self.wallet_load_vault).pack(side=tk.LEFT, padx=(8,0))

        # Right panel: wallet list + send
        right_panel = tk.Frame(wallet_frame, bg="#fff8f0")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4,0))

        tk.Label(right_panel, text="IMPORTED WALLETS",
                 font=("Segoe UI", 9, "bold"), fg="#e65100", bg="#fff8f0").pack(anchor=tk.W)

        columns_w = ("addr", "chain", "balance", "usd")
        self.tree_wallets = ttk.Treeview(right_panel, columns=columns_w,
                 show="headings", height=8, selectmode="browse")
        self.tree_wallets.heading("addr", text="Address")
        self.tree_wallets.heading("chain", text="Chain")
        self.tree_wallets.heading("balance", text="Balance")
        self.tree_wallets.heading("usd", text="USD")
        self.tree_wallets.column("addr", width=260, minwidth=140)
        self.tree_wallets.column("chain", width=90, minwidth=60, anchor=tk.CENTER)
        self.tree_wallets.column("balance", width=120, minwidth=80, anchor=tk.E)
        self.tree_wallets.column("usd", width=90, minwidth=60, anchor=tk.E)
        self.tree_wallets.pack(fill=tk.BOTH, expand=True, pady=(4,4))

        # Send section
        send_frame = tk.LabelFrame(right_panel, text=" SEND TRANSACTION ",
                 font=("Segoe UI", 9, "bold"), fg="#e65100", bg="#fff8f0",
                 bd=1, relief=tk.GROOVE)
        send_frame.pack(fill=tk.X, pady=(4,0))

        send_inner = tk.Frame(send_frame, bg="#fff8f0")
        send_inner.pack(fill=tk.X, padx=8, pady=6)

        tk.Label(send_inner, text="Chain:", font=("Segoe UI", 9),
                 fg="#e65100", bg="#fff8f0").grid(row=0, column=0, sticky=tk.W, padx=(0,4))
        self.send_chain_var = tk.StringVar(value="Ethereum")
        chain_options = list(RPC_ENDPOINTS.keys())
        self.send_chain = ttk.Combobox(send_inner, textvariable=self.send_chain_var,
                 values=chain_options, state="readonly", width=18)
        self.send_chain.grid(row=0, column=1, sticky=tk.W, padx=(0,8))

        tk.Label(send_inner, text="To:", font=("Segoe UI", 9),
                 fg="#e65100", bg="#fff8f0").grid(row=0, column=2, sticky=tk.W, padx=(0,4))
        self.send_to = tk.Entry(send_inner, font=("Consolas", 9), width=32,
                 relief=tk.SUNKEN, bd=1)
        self.send_to.grid(row=0, column=3, sticky=tk.EW, padx=(0,8))

        tk.Label(send_inner, text="Amount:", font=("Segoe UI", 9),
                 fg="#e65100", bg="#fff8f0").grid(row=0, column=4, sticky=tk.W, padx=(0,4))
        self.send_amount = tk.Entry(send_inner, font=("Consolas", 9), width=12,
                 relief=tk.SUNKEN, bd=1)
        self.send_amount.grid(row=0, column=5, sticky=tk.W, padx=(0,8))

        tk.Button(send_inner, text="SEND",
                 font=("Segoe UI", 10, "bold"), bg="#e65100", fg="#ffffff",
                 activebackground="#f57c00", relief=tk.FLAT, padx=20, pady=4,
                 cursor="hand2", command=self.wallet_send).grid(row=0, column=6)

        send_inner.columnconfigure(3, weight=1)

        # Stored imported wallets: [(priv_key_hex, address, chain, balance)]
        self._imported_wallets = []

        # ── Footer with resize grip ──
        footer = tk.Frame(container, bg="#fff0e0", height=32,
                          highlightthickness=2, highlightbackground="#ffb74d")
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)

        self.lbl_footer = tk.Label(footer,
                 text="\u2699  Ready to scan  |  0 keys found  |  0 funded",
                 font=("Segoe UI", 9), fg="#e65100", bg="#fff0e0")
        self.lbl_footer.pack(side=tk.LEFT, padx=15)

        self.lbl_jsonl = tk.Label(footer,
                 text=f"\U0001f4be  {SCANNED_JSONL} / {BALANCE_JSONL}",
                 font=("Segoe UI", 8), fg="#ff9800", bg="#fff0e0")
        self.lbl_jsonl.pack(side=tk.RIGHT, padx=15)

        resize_grip = tk.Frame(footer, bg="#ffb74d", width=20, height=20,
                                highlightthickness=0, cursor="bottom_right_corner")
        resize_grip.pack(side=tk.RIGHT, padx=(0, 0), pady=0)
        tk.Label(resize_grip, text="\u2b0a", font=("Segoe UI", 10),
                 fg="#ffffff", bg="#ffb74d").pack()

        # ── Vault tags + initial count ──
        for txt in (self.txt_vault,):
            txt.tag_config("key_value", foreground="#e65100", font=("Consolas", 10, "bold"))
            txt.tag_config("balance_pos", foreground="#f57c00", font=("Consolas", 10, "bold"))
            txt.tag_config("highlight", foreground="#f57c00", font=("Consolas", 9, "bold"))
            txt.tag_config("info", foreground="#e65100")
            txt.tag_config("warning", foreground="#e65100")
        # Set initial vaulted count from permanent file
        vault_recs = jsonl_read_all(VAULT_JSONL)
        self.stats_widgets["vaulted"].config(text=str(len(vault_recs)))

    # ── GUI Actions ──

    def on_open_folder(self):
        folder = filedialog.askdirectory(title="Select folder to scan for private keys")
        if folder:
            self.active_folder = folder
            self.lbl_folder.config(text=f"\U0001f4c2  {folder}")
            self.btn_scan.config(state=tk.NORMAL)
            self.log("info", f"Selected folder: {folder}")
            self.log("info", "Click \u25b6 Scan to begin key extraction and balance checking")

    def _on_speed_change(self, val):
        speed_map = {1: 0.5, 2: 0.2, 3: 0.05, 4: 0.01, 5: 0.0}
        delay = speed_map.get(int(float(val)), 0.05)
        self.engine.throttle_ms = delay
        self.lbl_status_top.config(text=f"\u25cf  {'Gentle' if delay >= 0.2 else 'Balanced' if delay >= 0.05 else 'Fast' if delay > 0 else 'Turbo'}")

    def on_start_scan(self):
        if not self.active_folder:
            return

        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_open.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.lbl_status_top.config(text="\u25cf  Scanning...", fg="#e65100", bg="#fff0e0")
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.config(state=tk.DISABLED)
        for key, w in self.stats_widgets.items():
            if key == "total_usd":
                w.config(text="$0.00")
            elif key == "vaulted":
                # NEVER reset — count from permanent file
                existing = jsonl_read_all(VAULT_JSONL)
                w.config(text=str(len(existing)))
            else:
                w.config(text="0")
        for item in self.tree.get_children():
            self.tree.delete(item)

        # ── Pre-fetch USD prices before scan starts ──
        self.log("info", "\u25cf Fetching live USD prices from CoinGecko...")
        fetch_usd_prices()
        price_count = sum(1 for v in _usd_prices.values() if float(str(v)) > 0)
        if price_count > 0:
            self.log("success", f"\u25cf  Prices loaded for {price_count} chains")
        else:
            self.log("warning", "\u25cf  WARNING: No USD prices loaded - tally will show $0.00")

        self._on_speed_change(self.speed_var.get())

        self.scan_thread = threading.Thread(
            target=self.engine.scan_folder,
            args=(self.active_folder,),
            daemon=True
        )
        self.scan_thread.start()

    def on_stop_scan(self):
        self.engine.stop()
        self.btn_stop.config(state=tk.DISABLED)
        self.log("warning", "Scan stopped by user")

    def on_status(self, message: str):
        self.root.after(0, self._update_status, message)

    def _update_status(self, message: str):
        self.lbl_footer.config(text=f"\u2699  {message}")
        # Detect vault writes: message starts with "PERMANENT VAULT:"
        if message.startswith("PERMANENT VAULT:"):
            try:
                curr = int(self.stats_widgets["vaulted"]["text"])
            except Exception:
                curr = 0
            self.stats_widgets["vaulted"].config(text=str(curr + 1))
        if "complete" in message.lower():
            self.lbl_status_top.config(text="\u25cf  Ready", fg="#f57c00")
            self.btn_scan.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_open.config(state=tk.NORMAL)

    def on_progress(self, current: int, total: int):
        pct = int((current / max(total, 1)) * 100)
        self.root.after(0, self._update_progress, current, total, pct)

    def _update_progress(self, current: int, total: int, pct: int):
        self.progress["value"] = pct
        self.lbl_progress.config(text=f"{current}/{total} files ({pct}%)")
        self.stats_widgets["files"].config(text=str(current))

    def on_key_found(self, file_rel, key_type, key_data, addresses,
                     chain=None, balance=None, address=None):
        self.root.after(0, self._handle_key_found, file_rel, key_type, key_data, addresses, chain, balance, address)

    def _handle_key_found(self, file_rel, key_type, key_data, addresses, chain, balance, address):
        if key_data is not None:
            self.stats_widgets["keys"].config(text=str(int(self.stats_widgets["keys"]["text"]) + 1))

            lbl = {
                "BIP39": "BIP39 Mnemonic", "PEM-EC": "PEM EC Key", "PEM-RSA": "PEM RSA Key",
                "WIF": "WIF Key", "WIF-Compressed": "WIF (Compressed)",
                "RAW-HEX": "Raw Hex Private Key", "SOLANA-JSON": "Solana Keypair",
                "SOLANA-B58": "Solana Base58", "ETH-KEYSTORE": "ETH Keystore",
                "SSH": "SSH Private Key", "PGP": "PGP Private Key",
                "BIP38-Encrypted": "BIP38 Encrypted Key",
                "BASE64-PK": "Base64 Private Key", "BASE64-KEY": "Base64 Key",
                "NAMED-B64": "Named Base64 Key", "NAMED-HEX": "Named Hex Key",
                "NAMED-PHRASE": "Named Phrase", "NAMED-WIF": "Named WIF",
            }.get(key_type, key_type)

            tag_map = {"BIP39": "bip39", "PEM-EC": "pem", "PEM-RSA": "pem",
                       "WIF": "wif", "WIF-Compressed": "wif",
                       "RAW-HEX": "hex", "SOLANA-JSON": "hex", "SOLANA-B58": "hex",
                       "BASE64-PK": "hex", "BASE64-KEY": "hex",
                       "NAMED-B64": "hex", "NAMED-HEX": "hex",
                       "NAMED-WIF": "wif"}

            self.log(tag_map.get(key_type, "highlight"), f"[{lbl}] in {file_rel}")

            key_display = (
                key_data if isinstance(key_data, str) and key_type == "BIP39"
                else key_data.hex() if isinstance(key_data, bytes)
                else str(key_data)
            )
            self.log("key_value", f"   Full Secret: {key_display}")

            if addresses:
                for addr_name, addr in addresses.items():
                    if addr and addr != "?":
                        self.log("info", f"   {addr_name}: {addr}")
            self._last_balance_meta = (file_rel, lbl)

        if chain is not None and balance is not None:
            meta = getattr(self, "_last_balance_meta", (file_rel or "?", key_type or "?"))
            self._record_balance(meta[0], meta[1], chain, balance, address)

    def _record_balance(self, file_rel, key_type, chain, balance, address):
        # NO TRUNCATION - show full precision
        try:
            bal_dec = Decimal(str(balance))
        except Exception:
            bal_dec = Decimal("0")
        funded = bal_dec > Decimal("0")
        bal_label = str(bal_dec) if funded else "0"
        usd_price_dec = get_usd_price(chain) if funded else Decimal("0")
        usd_val = bal_dec * usd_price_dec if funded else Decimal("0")

        log_line = f"   \u2192 {chain} ({address}): {bal_label}"
        if funded:
            usd_str = str(usd_val)
            log_line += f"  \u2192 ${usd_str}"
            try:
                curr = int(self.stats_widgets["funded"]["text"])
            except Exception:
                curr = 0
            self.stats_widgets["funded"].config(text=str(curr + 1))

            # ── Accumulate running USD total (pure Decimal, no truncation) ──
            old_raw = self.stats_widgets["total_usd"]["text"]
            try:
                raw = old_raw.replace("$","").replace(",","")
                running = Decimal(raw) if raw else Decimal("0")
            except Exception:
                running = Decimal("0")
            running += usd_val
            new_text = f"${running:.8f}".rstrip("0").rstrip(".")
            if new_text.endswith("."):
                new_text += "00"
            self.stats_widgets["total_usd"].config(text=new_text)
            # Log tally update
            self.log("balance_pos",
                f"   \u25b3 TALLY: {old_raw} + ${usd_val} = {new_text}  [price: ${usd_price_dec}]")

            self.log("balance_pos", log_line)
        else:
            self.log("balance_zero", log_line)

        src_file = file_rel if file_rel else (getattr(self, "_last_balance_meta", ("?", "?"))[0])
        ktype = key_type if key_type else (getattr(self, "_last_balance_meta", ("?", "?"))[1])

        funded_tag = "funded" if funded else "empty"
        bal_str = str(bal_dec)  # FULL precision
        usd_str = str(usd_val)  # FULL precision
        self.tree.insert("", tk.END,
            values=(src_file, ktype, chain, address or "?", bal_str, f"${usd_str}"),
            tags=(funded_tag,))

        try:
            kc = int(self.stats_widgets["keys"]["text"])
        except Exception:
            kc = 0
        try:
            fc = int(self.stats_widgets["funded"]["text"])
        except Exception:
            fc = 0
        total_usd = self.stats_widgets["total_usd"]["text"]
        self.lbl_footer.config(
            text=f"\u2699  {kc} keys  |  {fc} funded  |  {total_usd} total  |  checking {chain}...")

    def log(self, tag: str, message: str, extra: str = ""):
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.insert(tk.END, message + "\n", tag)
        self.txt_log.see(tk.END)
        self.txt_log.config(state=tk.DISABLED)

    def refresh_history(self):
        self.txt_history.config(state=tk.NORMAL)
        self.txt_history.delete("1.0", tk.END)
        records = []
        records.extend(jsonl_read_all(SCANNED_JSONL))
        records.extend(jsonl_read_all(BALANCE_JSONL))
        records.sort(key=lambda r: r.get("_ts", ""), reverse=True)

        if not records:
            self.txt_history.insert(tk.END, "No records found.\n", "info")
        else:
            for r in records[:2000]:
                self.txt_history.insert(tk.END, json.dumps(r, indent=1) + "\n\n")
        self.txt_history.config(state=tk.DISABLED)
        self.log("info", f"Loaded {len(records)} historical records")

    def refresh_vault(self):
        """Load and display permanent vault records."""
        self.txt_vault.config(state=tk.NORMAL)
        self.txt_vault.delete("1.0", tk.END)
        records = jsonl_read_all(VAULT_JSONL)
        if not records:
            self.txt_vault.insert(tk.END, "Vault is empty. Funded secrets will appear here forever.\n", "info")
        else:
            for r in records:
                # Show complete record - NO TRUNCATION
                secret = r.get("secret_bip39") or r.get("secret_hex") or r.get("secret_raw", "?")
                secret_display = str(secret)  # FULL secret, never truncated
                self.txt_vault.insert(tk.END, f"SECRET: {secret_display}\n", "key_value")
                self.txt_vault.insert(tk.END, f"  Type: {r.get('key_type','?')}  |  File: {r.get('file','?')}\n", "info")
                self.txt_vault.insert(tk.END, f"  Time: {r.get('timestamp','?')}\n", "info")
                addrs = r.get("addresses", {})
                if addrs:
                    self.txt_vault.insert(tk.END, "  Addresses:\n", "highlight")
                    for k, v in addrs.items():
                        self.txt_vault.insert(tk.END, f"    {k}: {v}\n", "info")
                funded = r.get("funded", [])
                total = r.get("total_usd", "0")
                self.txt_vault.insert(tk.END, f"  FUNDED ({len(funded)} chains, ${total} total):\n", "balance_pos")
                for fb in funded:
                    self.txt_vault.insert(tk.END,
                        f"    {fb['chain']}: {fb['balance']} @ {fb['address']} = ${fb['usd']}\n", "balance_pos")
                self.txt_vault.insert(tk.END, f"  FULL SECRET: {secret}\n", "key_value")
                self.txt_vault.insert(tk.END, "\n" + "-"*60 + "\n\n")
        self.txt_vault.config(state=tk.DISABLED)
        # Update vaulted count
        try:
            self.stats_widgets["vaulted"].config(text=str(len(records)))
        except Exception:
            pass
        self.log("info", f"Vault: {len(records)} permanent records loaded")

    # ── Wallet Methods ──

    def wallet_import(self):
        """Bulk import private keys or BIP39 phrases, derive addresses, check balances."""
        raw = self.txt_import.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Import", "Paste private keys or BIP39 phrases first.")
            return

        self._imported_wallets = []
        self.tree_wallets.delete(*self.tree_wallets.get_children())
        lines = [l.strip() for l in raw.splitlines() if l.strip()]

        fetch_usd_prices()
        stored_keys = set()  # track which keys got a funded entry

        for line in lines:
            key_type, key_data = classify_key_line(line)
            if key_type is None:
                continue

            addresses = derive_all_addresses(key_type, key_data)
            eth_addr = addresses.get("ETH", "?")

            has_funded = False
            if eth_addr and eth_addr != "?" and eth_addr.startswith("0x"):
                for chain, rpc_list in RPC_ENDPOINTS.items():
                    bal = check_evm_balance(rpc_list, eth_addr)
                    if bal > Decimal("0"):
                        usd = bal * get_usd_price(chain)
                        key_id = eth_addr + chain
                        self._imported_wallets.append((key_data, eth_addr, chain, bal, usd))
                        self.tree_wallets.insert("", tk.END,
                            values=(eth_addr, chain, str(bal), f"${float(usd):,.8f}".rstrip("0").rstrip(".")))
                        has_funded = True
                        stored_keys.add(key_id)

            # Store key for sending (only if no funded entry was added for this key)
            if not has_funded:
                # Derive private key bytes if BIP39
                if isinstance(key_data, str) and key_type == "BIP39":
                    seed = Bip39SeedGenerator(key_data).Generate()
                    bip44 = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
                    pk = bip44.Purpose().Coin().Account(0).Change(0).AddressIndex(0).PrivateKey().Raw().ToBytes()
                elif isinstance(key_data, bytes):
                    pk = key_data
                else:
                    pk = bytes.fromhex(str(key_data)) if len(str(key_data)) == 64 else None
                if pk and eth_addr != "?":
                    self._imported_wallets.append((pk, eth_addr, "Ethereum", Decimal("0"), Decimal("0")))

        self.log("info", f"Wallet: {len(self._imported_wallets)} wallets ready ({len(stored_keys)} funded)")

    def wallet_load_vault(self):
        """Load keys from permanent vault into wallet."""
        records = jsonl_read_all(VAULT_JSONL)
        if not records:
            messagebox.showinfo("Vault", "Vault is empty. Run a scan first to find funded keys.")
            return

        lines = []
        for r in records:
            secret = r.get("secret_bip39") or r.get("secret_hex") or r.get("secret_raw", "")
            if secret:
                lines.append(str(secret))

        self.txt_import.delete("1.0", tk.END)
        self.txt_import.insert("1.0", "\n".join(lines))
        self.wallet_import()

    def wallet_send(self):
        """Send a transaction from the first imported wallet."""
        if not self._imported_wallets:
            messagebox.showwarning("Send", "Import keys first in the Wallet tab.")
            return

        chain = self.send_chain_var.get()
        to_addr = self.send_to.get().strip()
        amount_str = self.send_amount.get().strip()

        if not to_addr or not amount_str:
            messagebox.showwarning("Send", "Enter destination address and amount.")
            return

        try:
            amount = float(amount_str)
        except ValueError:
            messagebox.showerror("Send", "Invalid amount.")
            return

        # Find a wallet for this chain
        wallet = None
        for w in self._imported_wallets:
            if len(w) >= 3 and w[2] == chain:
                wallet = w
                break
        if wallet is None:
            messagebox.showerror("Send", f"No imported wallet for chain: {chain}")
            return

        priv_key = wallet[0]
        from_addr = wallet[1]

        # Get RPC
        rpc_list = RPC_ENDPOINTS.get(chain, ["https://cloudflare-eth.com"])
        w3 = Web3(Web3.HTTPProvider(rpc_list[0]))

        if not w3.is_connected():
            # Try fallback
            for rpc_url in rpc_list[1:]:
                w3 = Web3(Web3.HTTPProvider(rpc_url))
                if w3.is_connected():
                    break
            else:
                messagebox.showerror("Send", f"Cannot connect to {chain} RPC.")
                return

        try:
            account = w3.eth.account.from_key(priv_key if isinstance(priv_key, bytes) else bytes.fromhex(priv_key))
            nonce = w3.eth.get_transaction_count(from_addr)
            tx = {
                'nonce': nonce,
                'to': w3.to_checksum_address(to_addr),
                'value': w3.to_wei(amount, 'ether'),
                'gas': 21000,
                'gasPrice': w3.eth.gas_price,
                'chainId': w3.eth.chain_id,
            }
            signed = account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            self.log("success", f"TX SENT: {tx_hash.hex()} — {amount} to {to_addr} on {chain}")
            messagebox.showinfo("Sent", f"Transaction sent!\nHash: {tx_hash.hex()}")
        except Exception as e:
            self.log("error", f"Send failed: {e}")
            messagebox.showerror("Send Error", str(e))

    def clear_records(self):
        if messagebox.askyesno("Clear Records",
                "Delete scan/balance records?\n\nVAULT records are PERMANENT and will NOT be deleted.\nThis cannot be undone."):
            for fp in (SCANNED_JSONL, BALANCE_JSONL):
                if os.path.exists(fp):
                    try:
                        os.remove(fp)
                    except Exception:
                        pass
            self.refresh_history()
            self.log("warning", "Scan/balance records cleared (vault preserved)")

    def on_closing(self):
        self.engine.stop()
        self.root.destroy()

# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
