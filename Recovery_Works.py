import re
import csv
import time
import requests
import argparse
from web3 import Web3
import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, simpledialog

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

print(">>> Recovery_Works.py is running under Python <<<")

# -----------------------------
# CONFIG
# -----------------------------
# Folder where Decoder Engine saves plain JSON exports.
# Adjust this path if you use a different folder.
DECODER_EXPORT_DIR = r"C:\Users\Taylor\Decoder_Engine\exports"

# Watcher interval (seconds) for re-checking balances.
BALANCE_WATCH_INTERVAL = 300  # 5 minutes


# -----------------------------
# CHAINS
# -----------------------------
CHAINS = {
    "Ethereum": ("https://eth.llamarpc.com", "ethereum"),
    "Base": ("https://base.llamarpc.com", "ethereum"),
    "BNB": ("https://bsc-dataseed.binance.org", "binancecoin"),
    "Polygon": ("https://polygon-rpc.com", "matic-network"),
    "Arbitrum": ("https://arb1.arbitrum.io/rpc", "ethereum"),
    "Optimism": ("https://mainnet.optimism.io", "ethereum"),
}

SOLANA_RPC = "https://api.mainnet-beta.solana.com"

# -----------------------------
# PATTERNS
# -----------------------------
ETH_RE = re.compile(r"0x[a-fA-F0-9]{40}")
SOL_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

# "secret-ish" patterns to store in encrypted vault:
BIP39_RE = re.compile(r"\b[a-z]{3,8}(?:\s+[a-z]{3,8}){11,23}\b")
PEM_RE = re.compile(
    r"-----BEGIN(?:[ A-Z]*)?PRIVATE KEY-----(?:[\s\S]*?)-----END(?:[ A-Z]*)?PRIVATE KEY-----"
)
HEX64_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


# -----------------------------
# CRYPTO HELPERS (Fernet + PBKDF2)
# -----------------------------
def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_json_to_file(obj, out_path: str, passphrase: str):
    salt = os.urandom(16)
    key = derive_key_from_passphrase(passphrase, salt)
    f = Fernet(key)
    plaintext = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    ciphertext = f.encrypt(plaintext)

    container = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "alg": "fernet-pbkdf2-sha256",
    }
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(container, fp, indent=2)


# -----------------------------
# JSON INGEST HELPERS (Decoder Engine)
# -----------------------------
def extract_wallets_from_decoder_item(item: dict) -> list[str]:
    candidates = []
    for field in ("raw", "decoded"):
        val = item.get(field)
        if not isinstance(val, str):
            continue
        candidates.append(val)
    text = " ".join(candidates)
    eth = ETH_RE.findall(text)
    sol = SOL_RE.findall(text)
    return list(set(eth + sol))


def load_wallets_from_decoder_json(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    if isinstance(data, dict) and "ciphertext" in data and "salt" in data:
        raise ValueError(
            "This looks like an encrypted JSON (.enc.json). "
            "Use a plain JSON export from Decoder Engine for wallet ingestion."
        )

    items = data.get("items", []) if isinstance(data, dict) else []
    all_wallets = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        for w in extract_wallets_from_decoder_item(item):
            all_wallets.add(w)

    return sorted(all_wallets)


# -----------------------------
# CORE LOGIC
# -----------------------------
def load_from_file(path: str) -> str:
    with open(path, "r", errors="ignore") as f:
        return f.read()


def extract(text: str):
    eth = set(ETH_RE.findall(text))
    sol = set(SOL_RE.findall(text))
    return list(eth), list(sol)


def evm_balance(addr: str, rpc: str) -> float:
    try:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
        bal = w3.eth.get_balance(Web3.to_checksum_address(addr))
        return float(w3.from_wei(bal, "ether"))
    except Exception:
        return 0.0


def sol_balance(addr: str) -> float:
    try:
        r = requests.post(
            SOLANA_RPC,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [addr],
            },
            timeout=10,
        )
        lamports = r.json().get("result", {}).get("value", 0)
        return lamports / 1e9
    except Exception:
        return 0.0


def prices() -> dict:
    url = (
        "https://api.coingecko.com/api/v3/simple/price"
        "?ids=ethereum,binancecoin,matic-network,solana"
        "&vs_currencies=usd"
    )
    return requests.get(url, timeout=20).json()


def extract_secret_candidates(text: str):
    secrets = []

    for m in BIP39_RE.findall(text):
        secrets.append({"type": "BIP39", "value": " ".join(m.split())})

    for m in PEM_RE.findall(text):
        secrets.append({"type": "PEM_PRIVATE_KEY", "value": m.strip()})

    for m in HEX64_RE.findall(text):
        secrets.append({"type": "HEX64", "value": m})

    return secrets


def analyze_text(text: str, log_fn=print, label_prefix: str = ""):
    eth, sol = extract(text)
    secret_candidates = extract_secret_candidates(text)

    log_fn(f"\n[+] ETH wallets found in this input: {len(eth)}")
    log_fn(f"[+] SOL wallets found in this input: {len(sol)}")
    log_fn(f"[+] Secret candidates found in this input: {len(secret_candidates)}")

    p = prices()
    total = 0.0
    rows = []

    for w in eth:
        label = label_prefix
        log_fn(f"\nWallet: {w}")
        for chain, (rpc, cg) in CHAINS.items():
            bal = evm_balance(w, rpc)
            usd = bal * p.get(cg, {}).get("usd", 0)
            rows.append([w, label, chain, bal, usd])
            total += usd
            log_fn(f"{chain} {bal} ${usd:,.2f}")
        time.sleep(0.1)

    for w in sol:
        label = label_prefix
        bal = sol_balance(w)
        usd = bal * p.get("solana", {}).get("usd", 0)
        rows.append([w, label, "Solana", bal, usd])
        total += usd
        log_fn(f"Solana {bal} ${usd:,.2f}")

    for sc in secret_candidates:
        sc["label"] = label_prefix

    return rows, total, secret_candidates


def write_csv(rows, total, log_fn=print):
    out_path = "recovered_portfolio.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["wallet", "label", "chain", "balance", "usd"])
        writer.writerows(rows)

    log_fn("\n====================")
    log_fn(f"TOTAL USD (all inputs): ${total:,.2f}")
    log_fn(f"Saved CSV to: {out_path}")
    log_fn("====================")

    try:
        os.startfile(out_path)
        log_fn("[+] Opened recovered_portfolio.csv in the default viewer.")
    except Exception as e:
        log_fn(f"[!] Could not auto-open CSV: {e}")


# -----------------------------
# GUI
# -----------------------------
class RecoveryWorksGUI:
    def __init__(self):
        print(">>> Initializing RecoveryWorksGUI (Tk window should appear) <<<")
        self.root = tk.Tk()
        self.root.title("Recovery Works")
        self.root.geometry("1000x700")

        # state
        self.all_rows = []          # portfolio rows
        self.all_secrets = []       # secret candidates
        self.grand_total = 0.0      # total USD
        self.pause_watcher = False  # pause/resume for periodic balance watcher
        self.last_decoder_sync_count = 0  # number of wallets before last sync

        # derived wallet data {wallet: {"chains": set(), "usd": float}}
        self.wallet_summary = {}

        # top status panel
        status_frame = tk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        # indicator light (canvas)
        self.status_canvas = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
        self.status_canvas.pack(side=tk.LEFT, padx=(0, 5))
        self.status_light = self.status_canvas.create_oval(2, 2, 18, 18, fill="red")

        self.status_label = tk.Label(status_frame, text="Decoder: idle", font=("Segoe UI", 10))
        self.status_label.pack(side=tk.LEFT, padx=(0, 20))

        self.wallets_found_var = tk.StringVar(value="Wallets Found (total): 0")
        self.wallets_with_balance_var = tk.StringVar(value="Wallets With Balance (> $0.01): 0")

        lbl_wallets = tk.Label(status_frame, textvariable=self.wallets_found_var, font=("Segoe UI", 10, "bold"))
        lbl_wallets.pack(side=tk.LEFT, padx=10)

        lbl_wallets_bal = tk.Label(status_frame, textvariable=self.wallets_with_balance_var, font=("Segoe UI", 10, "bold"))
        lbl_wallets_bal.pack(side=tk.LEFT, padx=10)

        # buttons row
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        btn_file = tk.Button(top_frame, text="Open File…", command=self.open_file)
        btn_file.pack(side=tk.LEFT, padx=5)

        btn_folder = tk.Button(top_frame, text="Open Folder (scan all)…", command=self.open_folder)
        btn_folder.pack(side=tk.LEFT, padx=5)

        btn_paste = tk.Button(top_frame, text="Paste Text…", command=self.open_paste_window)
        btn_paste.pack(side=tk.LEFT, padx=5)

        btn_json = tk.Button(top_frame, text="Open JSON (Decoder)…", command=self.open_decoder_json)
        btn_json.pack(side=tk.LEFT, padx=5)

        btn_sync = tk.Button(top_frame, text="Sync from Decoder (latest)", command=self.sync_from_decoder_latest)
        btn_sync.pack(side=tk.LEFT, padx=5)

        btn_show_bal = tk.Button(top_frame, text="Show Wallets With Balance", command=self.show_wallets_with_balance)
        btn_show_bal.pack(side=tk.LEFT, padx=5)

        self.btn_pause = tk.Button(top_frame, text="Pause Watcher", command=self.toggle_pause_watcher)
        self.btn_pause.pack(side=tk.LEFT, padx=5)

        btn_export_vault = tk.Button(top_frame, text="Export Encrypted Keys…", command=self.export_encrypted_keys)
        btn_export_vault.pack(side=tk.LEFT, padx=5)

        btn_export_portfolio = tk.Button(top_frame, text="Export Encrypted Portfolio…", command=self.export_encrypted_portfolio)
        btn_export_portfolio.pack(side=tk.LEFT, padx=5)

        # log
        self.log_box = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Consolas", 10))
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # start periodic watcher
        self.root.after(BALANCE_WATCH_INTERVAL * 1000, self.balance_watcher_tick)

    def log(self, msg: str):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)
        self.root.update_idletasks()

    def update_wallet_summary_and_counters(self):
        summary = {}
        for w, label, chain, bal, usd in self.all_rows:
            if w not in summary:
                summary[w] = {"chains": set(), "usd": 0.0}
            summary[w]["chains"].add(chain)
            summary[w]["usd"] += usd

        self.wallet_summary = summary

        total_wallets = len(self.wallet_summary)
        wallets_with_bal = sum(1 for w, info in self.wallet_summary.items() if info["usd"] > 0.01)

        self.wallets_found_var.set(f"Wallets Found (total): {total_wallets}")
        self.wallets_with_balance_var.set(f"Wallets With Balance (> $0.01): {wallets_with_bal}")

    # ----- Single-file mode -----
    def open_file(self):
        path = filedialog.askopenfilename(
            title="Select recovery dump text file",
            filetypes=[("Text files", "*.txt;*.log;*.csv;*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            text = load_from_file(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")
            return

        self.log(f"\n[+] Loaded file: {path}")
        rows, total, secrets = analyze_text(text, log_fn=self.log, label_prefix=os.path.basename(path))
        self.all_rows.extend(rows)
        self.all_secrets.extend(secrets)
        self.grand_total += total
        self.update_wallet_summary_and_counters()
        write_csv(self.all_rows, self.grand_total, log_fn=self.log)

    # ----- Folder mode -----
    def open_folder(self):
        folder = filedialog.askdirectory(
            title="Select folder to scan (all files)"
        )
        if not folder:
            return

        self.log(f"\n[+] Scanning folder (recursive): {folder}")
        for root_dir, dirs, files in os.walk(folder):
            for name in files:
                file_path = os.path.join(root_dir, name)
                if name.lower().endswith((
                    ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".exe", ".dll", ".zip", ".rar",
                    ".7z", ".pdf"
                )):
                    continue

                self.log(f"\n[+] Checking file: {file_path}")
                try:
                    text = load_from_file(file_path)
                except Exception as e:
                    self.log(f"[!] Could not read {file_path}: {e}")
                    continue

                rel_label = os.path.relpath(file_path, folder)
                rows, total, secrets = analyze_text(text, log_fn=self.log, label_prefix=rel_label)
                self.all_rows.extend(rows)
                self.all_secrets.extend(secrets)
                self.grand_total += total

        if not self.all_rows:
            self.log("\n[!] No wallets found in any file in this folder.")
        else:
            self.update_wallet_summary_and_counters()
            write_csv(self.all_rows, self.grand_total, log_fn=self.log)

    # ----- Paste mode -----
    def open_paste_window(self):
        win = tk.Toplevel(self.root)
        win.title("Paste Recovery Text")
        win.geometry("700x400")

        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def run_paste():
            content = txt.get("1.0", tk.END)
            win.destroy()
            self.log("\n[+] Analyzing pasted text")
            rows, total, secrets = analyze_text(content, log_fn=self.log, label_prefix="pasted_input")
            self.all_rows.extend(rows)
            self.all_secrets.extend(secrets)
            self.grand_total += total
            self.update_wallet_summary_and_counters()
            write_csv(self.all_rows, self.grand_total, log_fn=self.log)

        btn_run = tk.Button(win, text="Analyze", command=run_paste)
        btn_run.pack(pady=5)

    # ----- Open Decoder JSON manually -----
    def open_decoder_json(self):
        path = filedialog.askopenfilename(
            title="Select Decoder Engine JSON file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            wallets = load_wallets_from_decoder_json(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load wallets from JSON:\n{e}")
            return

        if not wallets:
            self.log("\n[!] No ETH/SOL wallets found in this Decoder JSON.")
            return

        blob = " ".join(wallets)
        self.log(f"\n[+] Loaded {len(wallets)} wallets from Decoder JSON: {path}")
        rows, total, secrets = analyze_text(blob, log_fn=self.log, label_prefix=os.path.basename(path))
        self.all_rows.extend(rows)
        self.all_secrets.extend(secrets)
        self.grand_total += total
        self.update_wallet_summary_and_counters()
        write_csv(self.all_rows, self.grand_total, log_fn=self.log)

    # ----- Sync from latest Decoder export -----
    def sync_from_decoder_latest(self):
        if not os.path.isdir(DECODER_EXPORT_DIR):
            messagebox.showerror("Error", f"Decoder export directory does not exist:\n{DECODER_EXPORT_DIR}")
            return

        files = [
            os.path.join(DECODER_EXPORT_DIR, f)
            for f in os.listdir(DECODER_EXPORT_DIR)
            if f.lower().endswith(".json")
        ]
        if not files:
            self.log("\n[!] No plain JSON files found in Decoder export directory.")
            return

        latest = max(files, key=os.path.getmtime)
        self.log(f"\n[+] Syncing from latest Decoder JSON: {latest}")

        try:
            wallets = load_wallets_from_decoder_json(latest)
        except Exception as e:
            messagebox.showerror("Error", f"Could not load wallets from JSON:\n{e}")
            return

        if not wallets:
            self.log("[!] No wallets found in latest Decoder JSON.")
            return

        blob = " ".join(wallets)
        rows_before = len(self.all_rows)
        rows, total, secrets = analyze_text(blob, log_fn=self.log, label_prefix=os.path.basename(latest))
        self.all_rows.extend(rows)
        self.all_secrets.extend(secrets)
        self.grand_total += total
        self.update_wallet_summary_and_counters()
        write_csv(self.all_rows, self.grand_total, log_fn=self.log)

        new_rows = len(self.all_rows) - rows_before
        if new_rows > 0:
            # turn light green and set status text
            self.status_canvas.itemconfig(self.status_light, fill="green")
            self.status_label.config(text=f"Decoder: new data synced ({new_rows} rows)")
        else:
            self.status_canvas.itemconfig(self.status_light, fill="yellow")
            self.status_label.config(text="Decoder: no new wallets")

    # ----- Show wallets with balance > 0.01 -----
    def show_wallets_with_balance(self):
        if not self.wallet_summary:
            messagebox.showinfo("Wallets With Balance", "No wallets tracked yet.")
            return

        win = tk.Toplevel(self.root)
        win.title("Wallets With Balance (> $0.01)")
        win.geometry("900x500")

        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for w, info in self.wallet_summary.items():
            if info["usd"] > 0.01:
                chains = ", ".join(sorted(info["chains"]))
                txt.insert(tk.END, f"{w}\n  Chains: {chains}\n  Total USD: ${info['usd']:.2f}\n\n")

        txt.configure(state="disabled")

    # ----- Pause/resume balance watcher -----
    def toggle_pause_watcher(self):
        self.pause_watcher = not self.pause_watcher
        if self.pause_watcher:
            self.btn_pause.config(text="Resume Watcher")
            self.log("[*] Balance watcher paused.")
        else:
            self.btn_pause.config(text="Pause Watcher")
            self.log("[*] Balance watcher resumed.")

    # ----- Periodic balance watcher -----
    def balance_watcher_tick(self):
        if not self.pause_watcher and self.all_rows:
            self.log("\n[+] Balance watcher tick: re-checking known wallets.")
            # re-run analyze_text on a synthetic text built from wallet list
            # but avoid duplicating rows: just recompute balances fresh
            try:
                all_wallets = list(self.wallet_summary.keys())
                if all_wallets:
                    blob = " ".join(all_wallets)
                    rows, total, _ = analyze_text(blob, log_fn=self.log, label_prefix="watcher_update")
                    # Replace all_rows with the latest watcher rows
                    self.all_rows = rows
                    self.grand_total = total
                    self.update_wallet_summary_and_counters()
                    write_csv(self.all_rows, self.grand_total, log_fn=self.log)
            except Exception as e:
                self.log(f"[!] Balance watcher error: {e}")

        # schedule next tick
        self.root.after(BALANCE_WATCH_INTERVAL * 1000, self.balance_watcher_tick)

    # ----- Encrypted keys vault -----
    def export_encrypted_keys(self):
        if not self.all_secrets:
            messagebox.showinfo("Export Encrypted Keys", "No secret candidates collected yet.")
            return

        passphrase = simpledialog.askstring(
            "Encryption Passphrase",
            "Enter a strong passphrase for the encrypted key vault.\nYou MUST remember this to decrypt later.",
            show="*",
            parent=self.root,
        )
        if not passphrase:
            return

        out_path = filedialog.asksaveasfilename(
            title="Save encrypted key vault",
            defaultextension=".keys.enc.json",
            filetypes=[("Encrypted JSON", "*.enc.json"), ("All files", "*.*")]
        )
        if not out_path:
            return

        try:
            vault_obj = {
                "secrets": self.all_secrets,
                "total_wallet_usd": self.grand_total,
            }
            encrypt_json_to_file(vault_obj, out_path, passphrase)
            self.log(f"[+] Encrypted secret vault saved to: {out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write encrypted vault:\n{e}")

    # ----- Encrypted portfolio -----
    def export_encrypted_portfolio(self):
        if not self.all_rows:
            messagebox.showinfo("Encrypted Portfolio", "No portfolio rows to export yet.")
            return

        passphrase = simpledialog.askstring(
            "Encryption Passphrase",
            "Enter a strong passphrase for encrypted portfolio.\nYou must remember this to decrypt later.",
            show="*",
            parent=self.root,
        )
        if not passphrase:
            return

        out_path = filedialog.asksaveasfilename(
            title="Save encrypted portfolio",
            defaultextension=".portfolio.enc.json",
            filetypes=[("Encrypted JSON", "*.enc.json"), ("All files", "*.*")]
        )
        if not out_path:
            return

        try:
            portfolio_obj = {
                "total_usd": self.grand_total,
                "rows": self.all_rows,
            }
            encrypt_json_to_file(portfolio_obj, out_path, passphrase)
            self.log(f"[+] Encrypted portfolio saved to: {out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save encrypted portfolio:\n{e}")

    def run(self):
        self.root.mainloop()


# -----------------------------
# ENTRY
# -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="load file path")
    parser.add_argument("--folder", help="scan all files in this folder recursively")
    parser.add_argument("--paste", action="store_true")
    args, unknown = parser.parse_known_args()

    if args.file or args.folder or args.paste:
        all_rows = []
        all_secrets = []
        grand_total = 0.0

        if args.paste:
            print("\nPaste your recovery text. Press CTRL+Z then Enter (Windows) when done:\n")
            import sys
            text = sys.stdin.read()
            rows, total, secrets = analyze_text(text)
            all_rows.extend(rows)
            all_secrets.extend(secrets)
            grand_total += total
        elif args.file:
            text = load_from_file(args.file)
            rows, total, secrets = analyze_text(text, label_prefix=os.path.basename(args.file))
            all_rows.extend(rows)
            all_secrets.extend(secrets)
            grand_total += total
        else:
            for root_dir, dirs, files in os.walk(args.folder):
                for name in files:
                    file_path = os.path.join(root_dir, name)
                    if name.lower().endswith((
                        ".png", ".jpg", ".jpeg", ".gif", ".svg",
                        ".ico", ".exe", ".dll", ".zip", ".rar",
                        ".7z", ".pdf"
                    )):
                        continue
                    try:
                        text = load_from_file(file_path)
                    except Exception as e:
                        print(f"[!] Could not read {file_path}: {e}")
                        continue
                    rel_label = os.path.relpath(file_path, args.folder)
                    rows, total, secrets = analyze_text(text, label_prefix=rel_label)
                    all_rows.extend(rows)
                    all_secrets.extend(secrets)
                    grand_total += total

        write_csv(all_rows, grand_total)
    else:
        app = RecoveryWorksGUI()
        app.run()