#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   NJÓSNARI GUI — Cyber Viking Tactical Recon Dashboard                       ║
║   Version : 1.0.0 (Ultimate Deep Integration Edition)                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
import tkinter as tk
import threading, queue, subprocess
from scanners import ALL_SCANNERS

class NjOsnariApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NJÓSNARI v1.0.0 — Tactical Cyber Suite")
        self.q = queue.Queue()
        
        # UI Components
        self.btn = tk.Button(root, text="⚡ EXECUTE SECURITY MATRIX", command=self.start)
        self.btn.pack(pady=10)
        self.log = tk.Text(root, bg="#080B0F", fg="#00E5FF", font=("Courier", 10))
        self.log.pack(fill="both", expand=True)
        
        self.root.after(100, self.process_q)

    def start(self):
        self.btn.config(state="disabled")
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        state = {"findings": []}
        for scanner in ALL_SCANNERS:
            try:
                res = scanner(state)
                self.q.put(f"[+] {res}\n")
            except Exception as e:
                self.q.put(f"[!] Error: {e}\n")
        self.q.put("[***] SECURITY MATRIX EXECUTION COMPLETE\n")
        self.root.after(0, lambda: self.btn.config(state="normal"))

    def process_q(self):
        while not self.q.empty(): self.log.insert(tk.END, self.q.get())
        self.root.after(100, self.process_q)

if __name__ == "__main__":
    # Start Metasploit RPC daemon background process
    subprocess.Popen(["msfrpcd", "-U", "msf", "-P", "msfpassword", "-S", "-a", "127.0.0.1", "-p", "55553"], 
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    root = tk.Tk()
    NjOsnariApp(root)
    root.mainloop()
