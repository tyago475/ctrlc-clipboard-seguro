"""
gui — interface grafica Tkinter para o gestor CTRL+C.

Mostra as entradas do historico; DUPLO-CLIQUE numa entrada decifra-a
seletivamente e copia-a de volta para o clipboard. Botoes para verificar
assinatura, gravar agora e procurar por hash.

Uso:
    python3 gui.py --user alice               # versao simples
    python3 gui.py --user alice --master       # versao elaborada (PBKDF2)
"""
import argparse, os, getpass, time
import tkinter as tk
from tkinter import messagebox, simpledialog
from app import ClipManager, clip_set, CLIP_REAL
from clipsec import random_key, derive_key


class ClipGUI:
    def __init__(self, mgr: ClipManager):
        self.mgr = mgr
        self.root = tk.Tk()
        self.root.title(f"CTRL+C — {mgr.user}")
        self.root.geometry("520x420")

        tk.Label(self.root, text="Historico do Clipboard (duplo-clique para repor)",
                 font=("", 11, "bold")).pack(pady=6)

        frame = tk.Frame(self.root); frame.pack(fill="both", expand=True, padx=8)
        self.listbox = tk.Listbox(frame, font=("Courier", 10))
        sb = tk.Scrollbar(frame, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<Double-Button-1>", self.on_double_click)

        bar = tk.Frame(self.root); bar.pack(fill="x", pady=6)
        tk.Button(bar, text="Verificar assinatura", command=self.verify).pack(side="left", padx=4)
        tk.Button(bar, text="Gravar agora", command=self.flush).pack(side="left", padx=4)
        tk.Button(bar, text="Procurar (hash)", command=self.search).pack(side="left", padx=4)

        self.status = tk.Label(self.root, text="", anchor="w", fg="gray")
        self.status.pack(fill="x", padx=8, pady=2)

        self.refresh()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def refresh(self):
        self.listbox.delete(0, tk.END)
        for i, e in enumerate(self.mgr.hist.entries):
            t = time.strftime("%H:%M:%S", time.localtime(e.ts))
            self.listbox.insert(tk.END, f"[{i:3}] {t}  {e.sha256[:16]}…")
        self.root.after(2000, self.refresh)  # actualiza c/ as capturas da thread

    def on_double_click(self, _):
        sel = self.listbox.curselection()
        if not sel: return
        i = sel[0]
        try:
            txt = self.mgr.hist.decrypt_one(i, self.mgr.key)  # decifracao seletiva
            clip_set(txt)
            self.status.config(text=f"Entrada {i} decifrada e copiada para o clipboard.")
        except Exception as e:
            messagebox.showerror("Erro", f"Nao foi possivel decifrar: {e}")

    def verify(self):
        ok = self.mgr.verify()
        messagebox.showinfo("Assinatura",
                            "Assinatura VALIDA (cadeia X.509 ok)." if ok
                            else "Assinatura INVALIDA ou ausente.")

    def flush(self):
        self.mgr.flush(); self.status.config(text="Historico gravado (cifrado + assinado).")

    def search(self):
        q = simpledialog.askstring("Procurar", "Texto a procurar (via hash):")
        if q is None: return
        found = self.mgr.hist.contains(q)
        messagebox.showinfo("Resultado",
                            "EXISTE no historico." if found else "Nao encontrado.")

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
        key = derive_key(getpass.getpass("password mestra: "), salt)
        mgr = ClipManager(a.user, key, persist=True)
    else:
        mgr = ClipManager(a.user, random_key(), persist=False)
    mgr.start()
    ClipGUI(mgr).run()


if __name__ == "__main__":
    main()
