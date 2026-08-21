# AGENTS.md — Recovery Works

## What this repo is

A single-file Python desktop app (`Recovery_Works.py`, ~2130 lines) that scans a
folder of files for private keys / seed phrases, derives cryptocurrency addresses
across 30+ chains, and checks live on-chain balances via real RPC endpoints. It has
a Tkinter GUI with five tabs: **Scanner**, **Results**, **History**, **Vault**, and
**Wallet** (bulk import + broadcast-send). Secrecy is a core design goal: every key,
seed, and full balance is logged/disclosed in full precision (no truncation, no mocks).

There is no package, no `requirements.txt`, no test suite, no CI, and no build step.
`test_me.py` and `Untitled.txt` are scratch files, not part of the app.

## Running it

```bash
python Recovery_Works.py
```

- This is a **GUI app**; the `__main__` block builds a `tk.Tk()` root and starts
  `mainloop()`. It requires a display (X server / Windows desktop). It will not run
  usefully headless.
- There is no CLI mode, no argparse, and no `--help`. All behavior is driven from the GUI.
- Dependencies are NOT pinned anywhere. Install manually (see below). The interpreter
  must be Python 3 with Tk support.

### Dependencies (observed imports; install these before running)

`tkinter` (stdlib), `requests`, `web3`, `bip_utils`, `mnemonic`, `base58`, `solders`,
`cryptography`, `eth_keys`, `bitcoinlib`. `pynacl` is used as a fallback inside
`private_key_to_sol_address`. `web3` is only needed for the Wallet tab's send path.
USD valuation uses the public CoinGecko simple-price API (live network call).

If something fails to import it is usually swallowed and the chain address is reported
as `"?"` rather than raising — see "Gotchas".

## Architecture & data flow

The file is organized top-to-bottom as one module (no subpackages):

1. **Config block** (top): RPC endpoints. EVM chains live in `RPC_ENDPOINTS`
   (`OrderedDict` mapping chain name -> list of `[primary, fallback, ...]` URLs).
   Non-EVM chains have `*_RPCS` lists (`SOLANA_RPCS`, `TRON_RPCS`, `XRP_RPCS`,
   `CARDANO_RPCS`, `COSMOS_RPCS`, `POLKADOT_RPCS`, `NEAR_RPCS`, `SUI_RPCS`,
   `APTOS_RPCS`, `LTC/DOGE/BCH/DASH/ZEC_RPCS`). `BTC_API` is a single URL.
2. **`.env` loader** (`_load_dotenv`): reads `key=value` lines from a `.env` next to
   the script into `os.environ` (falls back to hardcoded defaults if absent). Env vars
   override RPC URLs (e.g. `ETH_RPC_ANKR`, `SOL_RPC_HELIUS`).
3. **JSONL streaming store** (`jsonl_append` / `jsonl_read_all`): line-delimited JSON,
   append-only, guarded by a module-level `_jsonl_lock`. Three files:
   - `scanned_records.jsonl` — every key found
   - `balance_records.jsonl` — every balance check result
   - `permanent_vault.jsonl` — funded secrets only; **intentionally permanent**
4. **Key detection** (`detect_*` + `scan_file_for_keys`): regex/heuristic scanners for
   BIP39, PEM (EC/RSA), WIF, raw hex, Solana JSON/base58, ETH keystore, SSH, PGP,
   BIP38, base64, and "named" keys. `scan_file_for_keys` runs them all and returns a
   list of `(key_type, key_data)`.
5. **Address derivation** (`derive_all_addresses`): given a key type + data, returns a
   dict of `{ETH, BTC-legacy, BTC-segwit, BTC-native, SOL, Litecoin, Dogecoin,
   Bitcoin Cash, Dash, Zcash, TRON, XRP, Cardano, Cosmos, Polkadot, Near, Sui,
   Aptos}` addresses. `derive_all_addresses` calls `_derive_fork_addresses`
   (BTC-family + TRON from the compressed secp256k1 pubkey: p2pkh with per-chain
   version byte / keccak for TRON) and `_derive_extra_addresses` (the remaining
   non-EVM chains; see below).
6. **Balance checkers** (`check_evm_balance`, `check_btc_balance`, `check_sol_balance`,
   `check_tron_balance`, `check_ltc/doge/bch/dash/zec_balance`, `check_xrp/cardano/
   cosmos/polkadot/near/sui/aptos_balance`, and `_check_utxo_balance` helper): each takes
   an address and returns a `Decimal`. They iterate fallback URLs and return
   `Decimal("0")` on any failure. **Wired into the scan loop (all parallel via the 12-worker
   pool):** all 20 EVM chains (via `RPC_ENDPOINTS`), BTC (3 types), SOL, and every
   non-EVM chain — Litecoin, Dogecoin, Bitcoin Cash, Dash, Zcash, TRON, XRP, Cardano,
   Cosmos, Polkadot, Near, Sui, Aptos. Address derivation per chain:
   - XRP/Cosmos/Polkadot/Sui/Aptos: standard schemes from the secp256k1 key
     (XRP = ripemd160+sha256 → XRP base58; Cosmos = ripemd160+sha256 → bech32 `cosmos`;
     Polkadot = SS58 of the compressed secp256k1 pubkey; Sui = `0x`+blake2b(0x01‖pub);
     Aptos = `0x`+sha3(0x01‖pub)).
   - NEAR/Cardano: ed25519-native, NOT derivable from a secp256k1 key in a standard way.
     They use a **best-effort** ed25519 keypair seeded from the same private-key bytes,
     so the address is deterministic but may not match the user's actual NEAR/Cardano
     account. Treat their balances as best-effort, not authoritative.
7. **`ScannerEngine`** (class): the scan loop. `scan_folder(folder)` walks the tree,
   calls detectors + derivation + balance checkers, fires all RPC calls with a
   `ThreadPoolExecutor(max_workers=12)`, writes JSONL + vault, and pushes results to the
   GUI via callbacks. Runs in a daemon thread started by the GUI.
8. **`App`** (class, subclasses `ttk.Frame`): the GUI. Owns the `ScannerEngine` and
   implements `status_callback` / `key_callback` / `progress_callback`. All GUI updates
   from the scan thread go through `root.after(0, ...)` to avoid Tk thread errors.
9. **Wallet tab methods**: `wallet_import`, `wallet_load_vault`, `wallet_send` — import
   keys and (destructively) broadcast EVM transactions via `web3`.

### Control / data flow at scan time

```
App.on_start_scan → new daemon Thread → ScannerEngine.scan_folder(folder)
  for each file: scan_file_for_keys → detect_* (return (type, data))
    derive_all_addresses(type, data) → {chain: address}
    build task list (per EVM chain via RPC_ENDPOINTS, BTC x3, SOL)
    ThreadPoolExecutor(12) → check_*_balance → Decimal
    jsonl_append(SCANNED_JSONL) + jsonl_append(BALANCE_JSONL)
    if any balance > 0: jsonl_append(permanent_vault.jsonl)
    callbacks → App._handle_key_found → GUI log / Results tree / stat counters
```

## Conventions & patterns

- **Full Decimal precision everywhere.** `getcontext().prec = 50` at import. Balances are
  `Decimal`, USD values are `Decimal(balance * price)`, and display deliberately does
  NOT truncate. Do not convert balances to `float` for storage; `float` is only used in
  the Wallet tab's USD display formatting.
- **Failures are silent by design.** Most detection/derivation/check paths use
  `try/except` that returns `Decimal("0")` or `"?"` and logs nothing. This is intentional
  (keep scanning), so an agent adding diagnostics should not assume an exception means a
  bug.
- **RPC fallback ordering matters.** `RPC_ENDPOINTS` is an `OrderedDict`; the first entry
  per chain is primary. Add new RPCs by appending to the list, not by replacing.
- **Threading boundary**: never touch Tk widgets from `ScannerEngine`. All cross-thread
  UI work funnels through `root.after(0, ...)`.
- **BIP39 words set** is built once at import (`BIP39_WORDS_SET`) and reused for fast
  membership checks in detectors.
- **GUI style is centralized** in `App._apply_styles` (ttk "clam" theme, green palette).
  Colors per chain live in `_CHAIN_COLORS`. Log text tags (`bip39`, `pem`, `wif`, `hex`,
  `balance_pos`, `balance_zero`, ...) are defined in `_build_ui`.

## Gotchas (non-obvious, read before changing code)

- **Hardcoded API keys in source.** `_ANKR_KEY` (line ~82) and Solana keys
  (`SOL_RPC_HELIUS`, `SOLANA_RPC_URL` ~line 180-181) are committed inline, not just in
  `.env`. Treat these as live credentials. Don't broaden their exposure, and don't assume
  `.env` is the only place keys come from.
- **Vault is permanent and one-way.** `permanent_vault.jsonl` is NEVER cleared by
  `clear_records` (which only removes `scanned_records.jsonl` and `balance_records.jsonl`).
  There is no delete-the-vault path by design. Don't add one unless intended.
- **`*.jsonl` is gitignored.** The vault/scanned/balance files are not committed (the
  `.gitignore` ignores `*.jsonl` and `recovered_portfolio.csv`). Expect these to be absent
  on a fresh clone; the app creates them at runtime.
- **Scan skips dot/hidden dirs and dirs starting with `_`** (`dirs[:] = [d for d in dirs
  if not d.startswith(".") and not d.startswith("_")]`). Files over `MAX_FILE_SIZE`
  (5 MB) and binary files (by extension or NUL-byte sniff) are skipped.
- **Speed slider sets a throttle, not parallelism.** `App._on_speed_change` maps slider
  1-5 to per-file `time.sleep` delays (0.5s down to 0.0/Turbo). RPC fan-out is always 12
  workers regardless.
- **Wallet tab can move real funds.** `wallet_send` builds and broadcasts a signed EVM
  tx via `web3` using the imported private key. It uses a fixed `gas: 21000` and
  `gasPrice: w3.eth.gas_price`. Changes there are financially destructive — test against
  testnets/fake keys only.
- **`btc` address derivation depends on `bitcoinlib`** (optional import). If missing, BTC
  addresses return `"?"` instead of erroring — so a missing `bitcoinlib` install silently
  disables BTC address display rather than crashing.
- **`eth_keys` is preferred but optional** for ETH derivation; falls back to a manual
  keccak path if not installed.
- **USD prices cached 120s.** `fetch_usd_prices` skips refetching if last fetch < 120s ago;
  guarded by `_usd_lock`. If CoinGecko is unreachable the tally shows `$0.00` (a warning,
  not an error).
- **`detect_named_private_keys` is regex-heavy and intentionally broad** (matches
  `secret`, `private_key`, `wif`, etc. in any JSON/text). It will surface secrets from
  config files — expected behavior, not a false positive.

## Editing guidance

- Keep a single module. There is no import graph to wire up; new checkers/detectors are
  added as standalone functions and registered into the relevant call site (e.g. add a new
  `check_*_balance`, then call it from `ScannerEngine.scan_folder`).
- Match existing style: snake_case functions, ALL_CAPS module constants, boxed ASCII
  section banners (`# ═══ ...`), and broad `try/except` with `Decimal("0")`/`"?"` fallbacks.
- Preserve full-precision `Decimal` handling; do not introduce `float` into balance math.
- After touching the scan loop or balance checkers, the only way to verify end-to-end is
  the GUI (open a folder, Scan, watch the Results/Vault tabs). There are no unit tests to
  run.
