import io
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox

import numpy as np
import pandas as pd
import zstandard as zstd
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from core.classifier import IPIDSequence

STATE_FILE = "results/experimental/intersections/seq_vs_b2b/state.json"
GT_CSV = "results/experimental/intersections/seq_vs_b2b/gt.csv.zst"
GT_BASE = "results/experimental/intersections/seq_vs_b2b/gt_base.csv.zst"

REAL_PATTERNS = [
    "Reflection", "Constant", "Local (=1)", "Global",
    "Local (≥1)", "Multi Global", "Random", "Fallback", "None"
]


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"currentLine": 0}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def append_zst(path, df):
    cctx = zstd.ZstdCompressor(level=3)

    file_exists = os.path.exists(path)
    csv_bytes = df.to_csv(index=False, header=not file_exists).encode()

    mode = "ab" if file_exists else "wb"
    with open(path, mode) as f:
        f.write(cctx.compress(csv_bytes))


def count_existing_gt():
    if not os.path.exists(GT_CSV):
        return pd.DataFrame(columns=[
            "IP", "IP_ID_SEQUENCE", "IP_ID_PATTERN",
            "REAL_IP_ID_PATTERN", "REAL_CLUSTER_COUNT"
        ])

    dctx = zstd.ZstdDecompressor(max_window_size=2 ** 31)

    rows = []
    with open(GT_CSV, "rb") as f:
        with dctx.stream_reader(f) as reader:
            text = reader.read().decode()

    return pd.read_csv(io.StringIO(text))


class GTGui:
    def __init__(self):
        self.state = load_state()
        self.df = pd.read_csv(GT_BASE, compression="zstd")

        self.saved_df = count_existing_gt()

        self.root = tk.Tk()
        self.root.title("Ground Truth Builder")

        self.ip_label = ttk.Label(self.root, font=("Arial", 12))
        self.ip_label.pack(pady=3)

        # Plot Frame
        self.plot_frame = ttk.Frame(self.root)
        self.plot_frame.pack(pady=6)

        self.s_label = ttk.Label(self.root, font=("Arial", 10))
        self.s_label.pack(pady=3)
        self.a_label = ttk.Label(self.root, font=("Arial", 10))
        self.a_label.pack(pady=3)
        self.b_label = ttk.Label(self.root, font=("Arial", 10))
        self.b_label.pack(pady=3)
        self.si_label = ttk.Label(self.root, font=("Arial", 10))
        self.si_label.pack(pady=3)
        self.ai_label = ttk.Label(self.root, font=("Arial", 10))
        self.ai_label.pack(pady=3)
        self.bi_label = ttk.Label(self.root, font=("Arial", 10))
        self.bi_label.pack(pady=3)

        ttk.Label(self.root, text="REAL_IP_ID_PATTERN:").pack()
        self.pattern_var = tk.StringVar()

        frame = ttk.Frame(self.root)
        frame.pack(pady=3)

        # 8 Toggles (Radio Buttons)
        for p in REAL_PATTERNS:
            rb = ttk.Radiobutton(frame, text=p, value=p, variable=self.pattern_var)
            rb.pack(anchor="w")

        ttk.Label(self.root, text="REAL_CLUSTER_COUNT:").pack()
        self.cluster_entry = ttk.Entry(self.root)
        self.cluster_entry.insert(0, "0")
        self.cluster_entry.pack(pady=3)

        self.save_btn = ttk.Button(self.root, text="Save", command=self.save_entry)
        self.save_btn.pack(pady=5)

        self.stats_label = ttk.Label(self.root, font=("Arial", 9))
        self.stats_label.pack(pady=4)

        self.load_current()

        self.root.protocol("WM_DELETE_WINDOW", self.exit_clean)
        self.root.mainloop()

    def draw_plot(self, sequence: np.ndarray):
        # Plot Frame leeren
        for child in self.plot_frame.winfo_children():
            child.destroy()

        # Sequenz konvertieren
        try:
            y_values = sequence.tolist()
        except:
            return

        x_values = list(range(1, len(y_values) + 1))

        fig = Figure(figsize=(4, 2.4), dpi=100)
        ax = fig.add_subplot(111)

        ax.plot(x_values, y_values, marker='o')
        ax.set_xlabel("Index")
        ax.set_ylabel("Value")
        ax.grid(True)

        canvas = FigureCanvasTkAgg(fig, master=self.plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    def load_current(self):
        if self.state["currentLine"] >= len(self.df):
            messagebox.showinfo("Fertig", "Alle Zeilen annotiert")
            self.exit_clean()
            return

        row = self.df.iloc[self.state["currentLine"]]
        self.current_row = row

        # --- AUTO-SKIP ----------------------------------------------------
        auto_patterns = ["Reflection", "Constant", "Local (=1)"]
        if row["IP_ID_PATTERN"] in auto_patterns:
            out_row = pd.DataFrame([[
                row["IP"],
                row["IP_ID_SEQUENCE"],
                row["IP_ID_PATTERN"],
                row["IP_ID_PATTERN"],  # REAL_IP_ID_PATTERN
                0  # REAL_CLUSTER_COUNT
            ]], columns=[
                "IP", "IP_ID_SEQUENCE", "IP_ID_PATTERN",
                "REAL_IP_ID_PATTERN", "REAL_CLUSTER_COUNT"
            ])

            append_zst(GT_CSV, out_row)
            self.saved_df = pd.concat([self.saved_df, out_row], ignore_index=True)

            self.state["currentLine"] += 1
            save_state(self.state)

            # direkt nächste Zeile laden
            self.load_current()
            return
        # ------------------------------------------------------------------

        # GUI laden (nur wenn kein Autoskip)
        self.ip_label.config(text=f"IP: {row['IP']}")

        ip_ids = np.fromstring(row.IP_ID_SEQUENCE, sep=",", dtype=np.int32)
        s = IPIDSequence(ip_ids)
        self.draw_plot(s.full.sequence)

        n = 10
        suffix = ""
        if len(s.full.sequence) > n:
            suffix = ", ..."

        self.s_label.config(text=f"s = [{', '.join(map(str, s.full.sequence[:n]))}{suffix}]")
        self.a_label.config(text=f"a = [{', '.join(map(str, s.even.sequence[:n]))}{suffix}]")
        self.b_label.config(text=f"b = [{', '.join(map(str, s.odd.sequence[:n]))}{suffix}]")
        self.si_label.config(text=f"s' = [{', '.join(map(str, s.full.increments[:n]))}{suffix}]")
        self.ai_label.config(text=f"a' = [{', '.join(map(str, s.even.increments[:n]))}{suffix}]")
        self.bi_label.config(text=f"b' = [{', '.join(map(str, s.odd.increments[:n]))}{suffix}]")

        self.pattern_var.set(row["IP_ID_PATTERN"])
        self.cluster_entry.delete(0, tk.END)
        self.cluster_entry.insert(0, "0")

        self.update_stats()

    def update_stats(self):
        counts = self.saved_df["REAL_IP_ID_PATTERN"].value_counts().to_dict()
        lines_saved = len(self.saved_df)
        text = f"currentLine: {self.state['currentLine']} / {len(self.df)}\n"
        text += f"saved: {lines_saved}\n"
        for p in REAL_PATTERNS:
            text += f"{p}: {counts.get(p, 0)}  "
        self.stats_label.config(text=text)

    def save_entry(self):
        real_p = self.pattern_var.get()
        try:
            real_c = int(self.cluster_entry.get())
        except:
            messagebox.showerror("Fehler", "Cluster Count muss eine Zahl sein")
            return

        if real_p == "Multi Global" and real_c <= 0:
            messagebox.showerror("Fehler", "Cluster Count muss >0 sein für Multi Global")
            return

        real_c = 0

        out_row = pd.DataFrame([[
            self.current_row["IP"],
            self.current_row["IP_ID_SEQUENCE"],
            self.current_row["IP_ID_PATTERN"],
            real_p,
            real_c
        ]], columns=[
            "IP", "IP_ID_SEQUENCE", "IP_ID_PATTERN",
            "REAL_IP_ID_PATTERN", "REAL_CLUSTER_COUNT"
        ])

        append_zst(GT_CSV, out_row)
        self.saved_df = pd.concat([self.saved_df, out_row], ignore_index=True)

        self.state["currentLine"] += 1
        save_state(self.state)

        self.load_current()

    def exit_clean(self):
        save_state(self.state)
        self.root.destroy()


GTGui()
