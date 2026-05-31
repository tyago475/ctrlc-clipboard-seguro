"""
gui — interface grafica Tkinter para o gestor CTRL+C (tema escuro).

Mostra as entradas do historico; DUPLO-CLIQUE numa entrada decifra-a
seletivamente e copia-a de volta para o clipboard. Botoes para verificar
assinatura, gravar agora e procurar por hash. A logica e a mesma do nucleo
ja validado — apenas a apresentacao foi redesenhada.

Uso:
    python3 gui.py --user alice               # versao simples
    python3 gui.py --user alice --master       # versao elaborada (PBKDF2)
"""
import argparse, os, getpass, time
import tkinter as tk
from tkinter import messagebox, simpledialog, font as tkfont
from tkinter import scrolledtext  # Suporte para caixa de texto com scroll
from app import ClipManager, clip_set, CLIP_REAL, HELP
from clipsec import random_key, derive_key

# --- paleta (estetica de ferramenta de seguranca) ---
BG      = "#0d1117"
PANEL   = "#161b22"
BORDER  = "#30363d"
FG      = "#c9d1d9"
MUTED   = "#8b949e"
ACCENT  = "#39d353"
ACCENT2 = "#58a6ff"
AMBER   = "#e3b341"
RED     = "#f85149"
SELBG   = "#1f6feb"


class ClipGUI:
    def __init__(self, mgr: ClipManager):
        self.mgr = mgr
        self.root = tk.Tk()
        self.root.title(f"CTRL+C — Gestor de Clipboard Seguro · {mgr.user}")
        self.root.geometry("680x520")
        self.root.configure(bg=BG)
        self.root.minsize(560, 420)

        self.mono = tkfont.Font(family="DejaVu Sans Mono", size=10)
        self.mono_b = tkfont.Font(family="DejaVu Sans Mono", size=10, weight="bold")
        self.title_f = tkfont.Font(family="DejaVu Sans Mono", size=15, weight="bold")
        self.small = tkfont.Font(family="DejaVu Sans Mono", size=8)

        self._build_header()
        self._build_list()
        self._build_detail()
        self._build_bar()
        self._build_status()

        self.refresh()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_header(self):
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(head, text="\u258c CTRL+C", font=self.title_f, bg=BG, fg=ACCENT).pack(side="left")
        mode = "PBKDF2 \u00b7 persistente" if self.mgr.persist else "chave em memoria"
        tag = "\u25cf REAL" if CLIP_REAL else "\u25cf MOCK"
        tk.Label(head, text=f"{tag}   {mode}", font=self.small, bg=BG,
                 fg=(ACCENT if CLIP_REAL else AMBER)).pack(side="right", pady=6)
        tk.Label(self.root,
                 text="AES-256-GCM \u00b7 SHA-256 \u00b7 RSA-PSS \u00b7 X.509   \u2014   duplo-clique repoe a entrada no clipboard",
                 font=self.small, bg=BG, fg=MUTED).pack(fill="x", padx=16, anchor="w")

    def _build_list(self):
        wrap = tk.Frame(self.root, bg=BORDER, bd=0)
        wrap.pack(fill="both", expand=True, padx=16, pady=(10, 8))
        inner = tk.Frame(wrap, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Label(inner, text="HISTORICO DO CLIPBOARD (cifrado)", font=self.small,
                 bg=PANEL, fg=MUTED, anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        row = tk.Frame(inner, bg=PANEL); row.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.listbox = tk.Listbox(
            row, font=self.mono, bg=PANEL, fg=FG, bd=0, highlightthickness=0,
            selectbackground=SELBG, selectforeground="#ffffff", activestyle="none")
        sb = tk.Scrollbar(row, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<Double-Button-1>", self.on_double_click)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

    def _build_detail(self):
        self.detail = tk.Label(
            self.root, text="Seleciona uma entrada para ver o hash; duplo-clique decifra.",
            font=self.small, bg=PANEL, fg=MUTED, anchor="w", justify="left", padx=10, pady=6)
        self.detail.pack(fill="x", padx=16)

    def _btn(self, parent, text, cmd, color):
        b = tk.Label(parent, text=text, font=self.mono_b, bg=PANEL, fg=color,
                     padx=14, pady=8, cursor="hand2")
        b.pack(side="left", padx=(0, 8))
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.config(bg=BORDER))
        b.bind("<Leave>", lambda e: b.config(bg=PANEL))
        return b

    def _build_bar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=16, pady=10)
        self._btn(bar, "\u2713 Verificar assinatura", self.verify, ACCENT)
        self._btn(bar, "\u2913 Gravar agora", self.flush, ACCENT2)
        self._btn(bar, "\u2315 Procurar (hash)", self.search, AMBER)
        self._btn(bar, "\u2139 Ajuda", self.show_help, MUTED)

    def _build_status(self):
        self.status = tk.Label(self.root, text="pronto.", font=self.small, bg=BG,
                                fg=MUTED, anchor="w", padx=16)
        self.status.pack(fill="x", pady=(0, 10))

    def set_status(self, msg, color=MUTED):
        self.status.config(text=msg, fg=color)

    def refresh(self):
        sel = self.listbox.curselection()
        self.listbox.delete(0, tk.END)
        for i, e in enumerate(self.mgr.hist.entries):
            t = time.strftime("%H:%M:%S", time.localtime(e.ts))
            self.listbox.insert(tk.END, f"  {i:>3}   {t}   {e.sha256[:24]}\u2026")
        if sel:
            try: self.listbox.selection_set(sel[0])
            except Exception: pass
        n = len(self.mgr.hist.entries)
        self.detail.config(
            text=f"{n} entrada(s) capturada(s) \u00b7 max={self.mgr.cfg.get('max_entries')} \u00b7 "
                 f"poll={self.mgr.cfg.get('poll_interval')}s \u00b7 save={self.mgr.cfg.get('save_interval')}s")
        self.root.after(2000, self.refresh)

    def on_select(self, _):
        sel = self.listbox.curselection()
        if not sel: return
        e = self.mgr.hist.entries[sel[0]]
        self.detail.config(text=f"entrada {sel[0]} \u00b7 sha256={e.sha256}", fg=FG)

    def on_double_click(self, _):
        sel = self.listbox.curselection()
        if not sel: return
        i = sel[0]
        try:
            txt = self.mgr.hist.decrypt_one(i, self.mgr.key)
            clip_set(txt)
            self.set_status(f"entrada {i} decifrada e copiada para o clipboard.", ACCENT)
        except Exception as e:
            self.set_status(f"erro ao decifrar: {e}", RED)

    def verify(self):
        ok = self.mgr.verify()
        if ok:
            self.set_status("assinatura VALIDA (cadeia X.509 ok).", ACCENT)
        else:
            self.set_status("assinatura INVALIDA ou ausente (faz 'Gravar agora' primeiro).", AMBER)

    def flush(self):
        self.mgr.flush()
        self.set_status("historico gravado (cifrado + assinado).", ACCENT2)

    def search(self):
        q = simpledialog.askstring("Procurar", "Texto a procurar (via hash):", parent=self.root)
        if q is None: return
        found = self.mgr.hist.contains(q)
        if found: self.set_status(f"'{q}' EXISTE no historico (confirmado via hash).", ACCENT)
        else:     self.set_status(f"'{q}' nao encontrado.", MUTED)

    def show_help(self):
        """Abre uma janela secundaria dedicada com o texto de ajuda sem cortar."""
        help_win = tk.Toplevel(self.root)
        help_win.title("Ajuda — CTRL+C")
        help_win.geometry("640x460")
        help_win.configure(bg=BG)
        help_win.transient(self.root)  # Garante foco sobre a janela principal
        help_win.minsize(520, 360)

        # Titulo interno
        tk.Label(help_win, text="\u2139 INSTRUÇÕES E SEGURANÇA", font=self.mono_b, 
                 bg=BG, fg=ACCENT, anchor="w").pack(fill="x", padx=16, pady=(16, 8))

        # Contentor de texto com quebra automatica e scrollbar
        txt_area = scrolledtext.ScrolledText(
            help_win, font=self.mono, bg=PANEL, fg=FG, bd=0, 
            highlightthickness=1, highlightbackground=BORDER,
            wrap=tk.WORD, padx=12, pady=12
        )
        txt_area.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        # Insercao estatica do HELP do app.py
        txt_area.insert(tk.END, HELP)
        txt_area.config(state=tk.DISABLED)

        # Botao estilizado para fechar
        btn_close = tk.Label(help_win, text="Fechar", font=self.mono_b, bg=PANEL, fg=RED,
                             padx=22, pady=7, cursor="hand2")
        btn_close.pack(pady=(0, 16))
        btn_close.bind("<Button-1>", lambda e: help_win.destroy())
        btn_close.bind("<Enter>", lambda e: btn_close.config(bg=BORDER))
        btn_close.bind("<Leave>", lambda e: btn_close.config(bg=PANEL))

    def on_close(self):
        self.mgr.stop(); self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--user", default="default")
    p.add_argument("--master", action="store_true")
    a = p.parse_args()
    if a.master:
        sp = f"hist_{a.user}/master.salt"; os.makedirs(f"hist_{a.user}", exist_ok=True)
        salt = open(sp, "rb").read() if os.path.exists(sp) else os.urandom(16)
        if not os.path.exists(sp): open(sp, "wb").write(salt)
        try:
            mgr = ClipManager(a.user, derive_key(getpass.getpass("password mestra: "), salt), persist=True)
        except ValueError:
            print("password incorreta — nao foi possivel decifrar a chave."); return
    else:
        mgr = ClipManager(a.user, random_key(), persist=False)
    mgr.start()
    ClipGUI(mgr).run()


if __name__ == "__main__":
    main()
