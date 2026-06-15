import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import threading
import os
import subprocess

class RecoveryWorksGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LeakHound & RecoveryWorks Master Management Dashboard")
        self.root.geometry("1260x880")
        self.root.configure(bg="#f0f0f0")

        # Storage absolute file tracking paths
        self.output_file = "C:\\Users\\Taylor\\Desktop\\infinite_github_scan.json"
        self.balance_file = "C:\\Users\\Taylor\\Desktop\\positive_balances.json"
        self.stats_file = "C:\\Users\\Taylor\\Desktop\\all_time_stats.json"
        self.trufflehog_exe = "C:\\Users\\Taylor\\GIT_repos\\trufflehog\\scripts\\bin\\First_Truffle\\trufflehog.exe"
        self.config_yaml = "C:\\Users\\Taylor\\GIT_repos\\trufflehog\\scripts\\bin\\First_Truffle\\config.yaml"

        # Initialize persistent counters
        self.all_time_funded = 0
        self.all_time_empty = 0
        self.load_persistent_stats()

        # Config Panel Container Layout
        self.top_frame = tk.LabelFrame(root, text="⚙️ Scan Engine Configuration Panel", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
        self.top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # RESTORED INTERACTIVE INTERFACE BUTTONS
        self.btn_load = ttk.Button(self.top_frame, text="📂 Load Scan File", command=self.start_parse_thread)
        self.btn_load.grid(row=0, column=0, padx=4, pady=5)

        self.btn_folder = ttk.Button(self.top_frame, text="📁 Pick & Scan Folder", command=self.pick_and_scan_folder)
        self.btn_folder.grid(row=0, column=1, padx=4, pady=5)

        self.btn_view_bal = ttk.Button(self.top_frame, text="💰 View Funded Wallets", command=self.view_funded_wallets)
        self.btn_view_bal.grid(row=0, column=2, padx=4, pady=5)

        tk.Label(self.top_frame, text="Local Path:", font=("Segoe UI", 9)).grid(row=0, column=3, padx=2)
        self.ent_path = ttk.Entry(self.top_frame, width=12)
        self.ent_path.insert(0, "C:\\")
        self.ent_path.grid(row=0, column=4, padx=4)

        # DROP-DOWN CONFIGURATION FILTERS
        tk.Label(self.top_frame, text="Filter:", font=("Segoe UI", 9)).grid(row=0, column=5, padx=2)
        self.filter_var = tk.StringVar(value="All Data")
        self.filter_combo = ttk.Combobox(self.top_frame, textvariable=self.filter_var, values=["All Data", "Verified Keys Only", "BIP39 Mnemonic Only"], state="readonly", width=14)
        self.filter_combo.grid(row=0, column=6, padx=4)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self.trigger_reparse())

        self.balance_filter_var = tk.BooleanVar(value=False)
        self.chk_balance = tk.Checkbutton(self.top_frame, text="💰 Bal > $0.01", variable=self.balance_filter_var, font=("Segoe UI", 9, "bold"), fg="#0055ff", command=self.trigger_reparse)
        self.chk_balance.grid(row=0, column=7, padx=6)
        
        # ALL-TIME METRICS DISPLAY BANNER
        self.lbl_all_time = tk.Label(root, text=f"♾️ All-Time Funded Wallets: {self.all_time_funded}   |   ♾️ All-Time Empty Found: {self.all_time_empty}", font=("Segoe UI", 10, "bold"), fg="#0055ff", bg="#e6f2ff", bd=1, relief=tk.SOLID, pady=4)
        self.lbl_all_time.pack(fill=tk.X, padx=10, pady=2)

        # Active Live Session Metrics Counter Status Strip
        self.lbl_stats = tk.Label(root, text="🔢 Scans Checked: 0   |   🟢 Verified Secret Leaks: 0   |   🚨 Total Dashboard Alerts: 0", font=("Segoe UI", 11, "bold"), fg="#006400", bg="#e6f2e6", bd=1, relief=tk.SOLID, pady=4)
        self.lbl_stats.pack(fill=tk.X, padx=10, pady=2)

        # Split Bounding Window Frames
        self.main_split = tk.PanedWindow(root, orient=tk.VERTICAL, sashwidth=6, bg="#dcdcdc")
        self.main_split.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Notification Alerts view display pane (Newest stays on top)
        self.alert_panel = tk.LabelFrame(self.main_split, text="🚨 Real-Time Matches & Verification Flags (Newest Entries Remain on Top)", font=("Segoe UI", 10, "bold"), fg="#cc0000")
        self.txt_alerts = tk.Text(self.alert_panel, font=("Consolas", 10), wrap=tk.WORD, height=8, bg="#fafafa")
        self.txt_alerts.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.main_split.add(self.alert_panel)

        # Master JSON Trace log file window pane
        self.payload_panel = tk.LabelFrame(self.main_split, text="📋 Full Raw Decoded JSON Payload & Stored Configuration Data Logs (Newest on Top)", font=("Segoe UI", 10, "bold"), fg="#0055ff")
        self.txt_master = tk.Text(self.payload_panel, font=("Consolas", 10), wrap=tk.WORD, bg="#ffffff")
        self.txt_master.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.main_split.add(self.payload_panel)

        self.active_file = None

    def load_persistent_stats(self):
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, "r") as f:
                    stats = json.load(f)
                    self.all_time_funded = stats.get("all_time_funded", 0)
                    self.all_time_empty = stats.get("all_time_empty", 0)
            except Exception:
                pass

    def save_persistent_stats(self):
        try:
            with open(self.stats_file, "w") as f:
                json.dump({"all_time_funded": self.all_time_funded, "all_time_empty": self.all_time_empty}, f)
            self.lbl_all_time.config(text=f"♾️ All-Time Funded Wallets: {self.all_time_funded}   |   ♾️ All-Time Empty Found: {self.all_time_empty}")
        except Exception:
            pass
    def pick_and_scan_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            target_path = os.path.normpath(folder_selected)
            self.ent_path.delete(0, tk.END)
            self.ent_path.insert(0, target_path)
            threading.Thread(target=self.execute_filesystem_scan, args=(target_path,), daemon=True).start()

    def execute_filesystem_scan(self, target_path):
        self.txt_alerts.insert("1.0", f"[INFO] Starting Filesystem Scan on target path: {target_path}\n")
        try:
            cmd = [self.trufflehog_exe, "filesystem", target_path, "--json"]
            if os.path.exists(self.config_yaml):
                cmd.append(f"--config={self.config_yaml}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            stdout, stderr = process.communicate()

            found_count = 0
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                with open(self.output_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                found_count += 1
            
            messagebox.showinfo("Scan Complete", f"Completed scanning {target_path}.\nAdded {found_count} secret lines to master log file.")
            if os.path.exists(self.output_file):
                self.active_file = self.output_file
                self.trigger_reparse()
        except Exception as e:
            print(f"Error executing scan: {e}")

    def view_funded_wallets(self):
        if not os.path.exists(self.balance_file) or os.path.getsize(self.balance_file) == 0:
            messagebox.showinfo("Fund Viewer", "No funded balance records matched yet. Keep crawling!")
            return
        
        view_win = tk.Toplevel(self.root)
        view_win.title("💰 Permanent Funded Wallet Ledger ($>0.01)")
        view_win.geometry("800x500")
        
        txt_area = tk.Text(view_win, font=("Consolas", 10), wrap=tk.WORD)
        txt_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        lines = []
        with open(self.balance_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    lines.append(line.strip())
        lines.reverse()
        txt_area.insert(tk.END, "\n\n".join(lines))

    def start_parse_thread(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON Logs", "*.json")])
        if file_path:
            self.active_file = file_path
            self.trigger_reparse()

    def trigger_reparse(self):
        if not self.active_file:
            return
        self.txt_alerts.delete("1.0", tk.END)
        self.txt_master.delete("1.0", tk.END)
        threading.Thread(target=self.stream_json_file, args=(self.active_file,), daemon=True).start()

    def stream_json_file(self, file_path):
        repos = 0
        verified_count = 0
        total_alerts = 0
        filter_mode = self.filter_var.get()
        filter_balance = self.balance_filter_var.get()
        
        temporary_master_buffer = []
        temporary_alert_buffer = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                cleaned_line = line.strip()
                if not cleaned_line:
                    continue
                try:
                    data = json.loads(cleaned_line)
                    if data.get("Type") == "CRAWL_HEARTBEAT":
                        repos += 1
                        continue
                    
                    is_verified = data.get("Verified", False) == True or str(data.get("Verified")).lower() == "true"
                    detector_name = data.get("DetectorName", "Custom Rule Check")
                    raw_key = data.get('Raw', data.get('Redacted', 'No Raw Decoded Content Blocks Available'))
                    balance_val = float(data.get("Balance", data.get("ExtraData", {}).get("balance", 0.0)))
                    
                    if balance_val > 0.01:
                        self.all_time_funded += 1
                        with open(self.balance_file, "a", encoding="utf-8") as bf:
                            bf.write(f"[FUNDED MATCH] Detector: {detector_name} | Key/Address: {raw_key} | Balance: ${balance_val}\n")
                    else:
                        self.all_time_empty += 1

                    if filter_balance and balance_val <= 0.01:
                        continue
                    if filter_mode == "Verified Keys Only" and not is_verified:
                        continue
                    if filter_mode == "BIP39 Mnemonic Only" and "BIP39" not in detector_name:
                        continue

                    total_alerts += 1
                    if is_verified:
                        verified_count += 1

                    source_metadata = data.get('SourceMetadata', {})
                    metadata_data = source_metadata.get('Data', {})
                    git_meta = metadata_data.get('Git', {})
                    github_meta = metadata_data.get('Github', {})

                    repo_url = git_meta.get('Url') or github_meta.get('repository') or github_meta.get('link') or 'Missing File Path Target'
                    filename = git_meta.get('File') or github_meta.get('file') or 'Unknown Code Block File'
                    line_num = git_meta.get('Line') or github_meta.get('line') or '?'

                    print(f"[{data.get('Time', 'Active')}] MATCH: {detector_name} | Key/Address: {raw_key} | Source: {repo_url}", flush=True)

                    alert_entry = f"[{data.get('Time', 'Active')}] 🎯 MATCH: {detector_name} | Verified: {is_verified} | Source Target: {repo_url}\n"
                    temporary_alert_buffer.append(alert_entry)

                    master_entry = f"=== CONSOLE INTERFACE ALERT LOG ENTRY #{total_alerts} ===\n"
                    master_entry += f"📄 Path Location: {filename} (Line Reference: {line_num})\n"
                    master_entry += f"🔑 Raw Decoded Content Extraction: {raw_key}\n"
                    master_entry += f"⚙️ Complete Meta String Object Structure:\n{json.dumps(data, indent=2)}\n"
                    master_entry += "-"*100 + "\n"
                    temporary_master_buffer.append(master_entry)

                    if len(temporary_alert_buffer) >= 500:
                        alert_chunk = "".join(temporary_alert_buffer)
                        self.root.after(0, self.flush_alert_chunk, alert_chunk)
                        temporary_alert_buffer = []

                except Exception:
                    pass

        if temporary_alert_buffer:
            alert_chunk = "".join(temporary_alert_buffer)
            self.root.after(0, self.flush_alert_chunk, alert_chunk)

        temporary_master_buffer.reverse()
        final_payload_block_string = "".join(temporary_master_buffer)
        
        self.root.after(0, self.set_master_pane_text, final_payload_block_string)
        self.root.after(0, self.update_counters, repos, verified_count, total_alerts)
        self.root.after(0, self.save_persistent_stats)

    def flush_alert_chunk(self, text_chunk):
        self.txt_alerts.insert("1.0", text_chunk)

    def set_master_pane_text(self, text):
        self.txt_master.delete("1.0", tk.END)
        self.txt_master.insert(tk.END, text)

    def update_counters(self, repos, verified, alerts):
        self.lbl_stats.config(text=f"🔢 Scans Checked: {repos}   |   🟢 Verified Secret Leaks: {verified}   |   🚨 Total Dashboard Alerts: {alerts}")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("winnative")
    app = RecoveryWorksGUI(root)
    root.mainloop()
