"""
CTRL+C — aplicação CLI + daemon de captura do clipboard.
A thread de fundo "simula CTRL+V" a cada poll_interval s; autosave cifrado a
cada save_interval s. Integra configuração, certificados X.509 e proteção da
chave privada em disco.

Uso:
    python3 app.py --user alice                 # versao simples (chave em memoria)
    python3 app.py --user alice --master         # versao elaborada (PBKDF2 + persistencia)

Comandos: list | get <i> | check <txt> | verify | flush | config | help | quit
"""
import argparse, threading, time, os, getpass
from clipsec import (History, random_key, derive_key, SAVE_INTERVAL, POLL_INTERVAL)
from config import Config
import pki

# --- abstracao de clipboard (pyperclip se existir; senao mock para testes) ---
try:
    import pyperclip
    def clip_get(): return pyperclip.paste()
    def clip_set(v): pyperclip.copy(v)
    CLIP_REAL = True
except ImportError:
    _mock = {"v": ""}
    def clip_get(): return _mock["v"]
    def clip_set(v): _mock["v"] = v
    CLIP_REAL = False


class ClipManager:
    """Reutilizavel pela CLI e pela GUI."""
    def __init__(self, user, key, persist=False):
        self.user = user
        self.key = key
        self.persist = persist
        self.cfg = Config(user)
        self.hist = History(user)
        if persist:
            self.hist.load()
        self.last = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._setup_pki()
        clip_set("") # limpa o clipboard no arranque (opcional)

    def _setup_pki(self):
        """Carrega/gera CA, certificado de assinatura e chave privada protegida."""
        d = self.hist.dir
        ca_key_p  = os.path.join(d, "ca_key.pem")
        ca_crt_p  = os.path.join(d, "ca_cert.pem")
        usr_key_p = os.path.join(d, "sign_key.pem")
        usr_crt_p = os.path.join(d, "sign_cert.pem")
        if self.persist and all(os.path.exists(p) for p in (ca_crt_p, usr_key_p, usr_crt_p)):
            self.ca_cert   = pki.load_cert(ca_crt_p)
            self.user_cert = pki.load_cert(usr_crt_p)
            self.priv      = pki.load_private_key(usr_key_p, self.key)
        else:
            ca_key, self.ca_cert = pki.build_ca()
            self.priv, self.user_cert = pki.issue_signing_cert(ca_key, self.ca_cert, self.user)
            if self.persist:
                pki.save_private_key(ca_key, ca_key_p, self.key)
                pki.save_cert(self.ca_cert, ca_crt_p)
                pki.save_private_key(self.priv, usr_key_p, self.key)  # cifrada!
                pki.save_cert(self.user_cert, usr_crt_p)

    def _poll_loop(self):
        last_save = time.time()
        interval = self.cfg.get("save_interval")
        poll = self.cfg.get("poll_interval")
        while not self._stop.is_set():
            cur = clip_get()
            if cur and cur != self.last:
                with self._lock:
                    self.hist.add(cur, self.key)
                    # respeita max_entries (descarta as mais antigas)
                    mx = self.cfg.get("max_entries")
                    if len(self.hist.entries) > mx:
                        self.hist.entries = self.hist.entries[-mx:]
                self.last = cur
            if time.time() - last_save >= interval:
                self.flush(); last_save = time.time()
            self._stop.wait(poll)

    def flush(self):
        with self._lock:
            self.hist.save(self.key, self.priv)

    def start(self):
        self.t = threading.Thread(target=self._poll_loop, daemon=True); self.t.start()

    def stop(self):
        self._stop.set()
        if self.persist:
            self.flush()

    # verificacao de assinatura via certificado (cadeia de confianca)
    def verify(self) -> bool:
        if not os.path.exists(self.hist.sig_file):
            return False
        blob = open(self.hist.enc_file, "rb").read()
        sig  = open(self.hist.sig_file, "rb").read()
        if self.cfg.get("use_certificates"):
            return pki.verify_with_cert(blob, sig, self.user_cert, self.ca_cert)
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            self.priv.public_key().verify(
                sig, blob,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return True
        except Exception:
            return False


HELP = """CTRL+C — Gestor de Clipboard seguro. Comandos disponiveis:

  list             Lista as entradas do historico (indice, hora, prefixo do hash).
                   NAO decifra o conteudo — apenas metadados.
  get <i>          Decifra SELETIVAMENTE a entrada de indice <i> (so essa) e
                   copia-a de volta para o clipboard.
  check <texto>    Verifica se <texto> ja esteve no historico usando APENAS os
                   valores de hash em texto-limpo, SEM decifrar nada.
  verify           Verifica a assinatura digital do ficheiro cifrado, validando
                   a cadeia de confianca ate ao certificado da CA (X.509).
  flush            Forca a gravacao cifrada+assinada do historico imediatamente.
  config           Mostra a configuracao atual (max_entries, intervalos, etc.).
  help             Mostra esta ajuda.
  quit             Termina. Na versao simples (sem --master) o historico perde-se
                   porque a chave de cifra so existe em memoria.

Notas de seguranca:
  - Cada entrada e cifrada com AES-256-GCM e um nonce proprio.
  - Os hashes (SHA-256) ficam num ficheiro a parte, em texto limpo.
  - A chave privada RSA e guardada em disco cifrada (PKCS#8) com a chave derivada.
  - Com --master, a chave de cifra deriva da password mestra via PBKDF2 (600k iter)."""


def repl(mgr: ClipManager):
    print(HELP)
    while True:
        try: cmd = input("ctrl+c> ").strip()
        except EOFError: break
        if not cmd: continue
        op, *rest = cmd.split(maxsplit=1)
        if op == "quit": break
        elif op == "help": print(HELP)
        elif op == "config":
            for k, v in mgr.cfg.data.items(): print(f"  {k:16} = {v}")
        elif op == "list":
            for i, e in enumerate(mgr.hist.entries):
                print(f"  [{i}] {time.strftime('%H:%M:%S', time.localtime(e.ts))}  sha={e.sha256[:12]}…")
        elif op == "get" and rest:
            try:
                i = int(rest[0]); txt = mgr.hist.decrypt_one(i, mgr.key)
                clip_set(txt); print(f"  decifrado e copiado: {txt!r}")
            except (IndexError, ValueError): print("  indice invalido")
        elif op == "check" and rest:
            print("  EXISTE no historico" if mgr.hist.contains(rest[0]) else "  nao encontrado")
        elif op == "verify":
            print("  assinatura VALIDA (cadeia ok)" if mgr.verify() else "  assinatura INVALIDA")
        elif op == "flush":
            mgr.flush(); print("  gravado (cifrado + assinado).")
        else: print("  comando invalido — escreve 'help'")
    mgr.stop()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--user", default="default")
    p.add_argument("--master", action="store_true", help="password mestra (PBKDF2) + persistencia")
    a = p.parse_args()
    if not CLIP_REAL:
        print("[aviso] pyperclip indisponivel — modo mock (sem clipboard real)")
    if a.master:
        sp = f"hist_{a.user}/master.salt"; os.makedirs(f"hist_{a.user}", exist_ok=True)
        salt = open(sp,"rb").read() if os.path.exists(sp) else os.urandom(16)
        if not os.path.exists(sp): open(sp,"wb").write(salt)
        try:
            key = derive_key(getpass.getpass("password mestra: "), salt)
            mgr = ClipManager(a.user, key, persist=True)
        except ValueError:
            print("password incorreta — nao foi possivel decifrar a chave."); exit(1)
    else:
        mgr = ClipManager(a.user, random_key(), persist=False)
    mgr.start(); repl(mgr)