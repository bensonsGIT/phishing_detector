import tkinter as tk
from email import message_from_string, policy
from tkinter import filedialog, messagebox, scrolledtext

from phish_detector import analyze, extract_parts, parse_eml, parse_pasted

COLORS = {
    "LIKELY PHISHING": "#c0392b",
    "SUSPICIOUS": "#e67e22",
    "LIKELY LEGITIMATE": "#27ae60",
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Email Detector")
        self.geometry("700x600")

        tk.Label(self, text="Paste an email (raw source or just the body), or open an .eml file:").pack(
            anchor="w", padx=10, pady=(10, 0)
        )
        self.input_box = scrolledtext.ScrolledText(self, height=15, wrap="word")
        self.input_box.pack(fill="both", expand=True, padx=10, pady=5)

        buttons = tk.Frame(self)
        buttons.pack(pady=5)
        tk.Button(buttons, text="Open .eml...", command=self.open_file).pack(side="left", padx=5)
        tk.Button(buttons, text="Analyze", command=self.run_analysis).pack(side="left", padx=5)
        tk.Button(buttons, text="Clear", command=self.clear).pack(side="left", padx=5)

        self.verdict_label = tk.Label(self, text="", font=("Helvetica", 18, "bold"))
        self.verdict_label.pack(pady=(10, 0))

        self.reasons_box = scrolledtext.ScrolledText(self, height=8, wrap="word", state="disabled")
        self.reasons_box.pack(fill="both", expand=True, padx=10, pady=10)

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.show_result(analyze(parse_eml(path)))
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")

    def run_analysis(self):
        raw = self.input_box.get("1.0", "end").strip()
        if not raw:
            messagebox.showinfo("Nothing to analyze", "Paste an email first.")
            return
        # If it looks like raw email source (has headers), parse it; otherwise treat as body text.
        if raw.lower().startswith(("from:", "received:", "return-path:", "subject:", "mime-version:")):
            data = extract_parts(message_from_string(raw, policy=policy.default))
        else:
            data = parse_pasted(raw)
        self.show_result(analyze(data))

    def show_result(self, result):
        verdict, score, reasons = result
        self.verdict_label.config(text=f"{verdict} (score {score:.1f})", fg=COLORS[verdict])
        self.reasons_box.config(state="normal")
        self.reasons_box.delete("1.0", "end")
        self.reasons_box.insert("end", "\n".join(f"• {r}" for r in reasons) or "No red flags found.")
        self.reasons_box.config(state="disabled")

    def clear(self):
        self.input_box.delete("1.0", "end")
        self.verdict_label.config(text="")
        self.reasons_box.config(state="normal")
        self.reasons_box.delete("1.0", "end")
        self.reasons_box.config(state="disabled")


if __name__ == "__main__":
    App().mainloop()