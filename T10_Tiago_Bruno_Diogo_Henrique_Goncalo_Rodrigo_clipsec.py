"""
CTRL+C — Gestor de Clipboard com segurança embutida
Segurança Informática & Cibersegurança 2025/26

Núcleo criptográfico + gestão de histórico.
Cifra : AES-256-GCM por-entrada (permite decifração seletiva)
Hash  : SHA-256 por entrada (ficheiro à parte, texto limpo)
Assin.: RSA-2048 PSS / SHA-256 sobre o ficheiro cifrado
KDF   : PBKDF2-HMAC-SHA256 (versão elaborada, password mestra + sal)
"""
from __future__ import annotations
import os, json, time, base64, hashlib, threading, hmac
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PBKDF2_ITERS = 600_000
KEY_LEN = 32          # AES-256
SAVE_INTERVAL = 300   # 5 minutos (requisito)
POLL_INTERVAL = 2     # simula CTRL+V a cada 2s


def b64(d: bytes) -> str:  return base64.b64encode(d).decode()
def ub64(s: str) -> bytes: return base64.b64decode(s)


# ----------------------------- KEY MANAGEMENT --------------------------------
# --- Gera uma chave aleatória (versão simples) ---
def random_key() -> bytes:
    """Versão simples: chave aleatória só em memória."""
    return os.urandom(KEY_LEN)

# --- Gera uma chave aleatória com uma password mestra e um sal para mais segurança (versão elaborada) ---
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Versão elaborada: PBKDF2 a partir de password mestra + pitada de sal."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(master_password.encode())


# ----------------------------- PER-ENTRY CRYPTO ------------------------------
@dataclass
class Entry:
    """Uma entrada do clipboard, cifrada individualmente."""
    nonce: str            # b64
    ciphertext: str       # b64 (inclui tag GCM)
    sha256: str           # hex — hash do texto-limpo (vai para ficheiro à parte)
    ts: float

    @staticmethod
# --- Cria uma nova entrada a partir do texto-limpo, cifrando-a e calculando o hash ---
    def create(plaintext: str, key: bytes) -> "Entry":
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        digest = hashlib.sha256(plaintext.encode()).hexdigest()
        return Entry(b64(nonce), b64(ct), digest, time.time())
# --- Decifra a entrada usando a chave fornecida, retornando o texto-limpo ---
    def decrypt(self, key: bytes) -> str:
        pt = AESGCM(key).decrypt(ub64(self.nonce), ub64(self.ciphertext), None)
        return pt.decode()


# ----------------------------- HISTORY MANAGER -------------------------------
class History:
    def __init__(self, user: str, base_dir: str = "."):
        self.user = user
        self.dir = os.path.join(base_dir, f"hist_{user}")
        os.makedirs(self.dir, exist_ok=True)
        self.enc_file   = os.path.join(self.dir, "history.enc")
        self.hash_file  = os.path.join(self.dir, "history.hashes")  # texto limpo
        self.sig_file   = os.path.join(self.dir, "history.sig")
        self.entries: list[Entry] = []

# --- Salva o histórico ---
    def save(self, key: bytes, priv_key: rsa.RSAPrivateKey):
# --- apaga o anterior reescrevendo o ficheiro ---
        blob = json.dumps([asdict(e) for e in self.entries]).encode()
        with open(self.enc_file, "wb") as f:
            f.write(blob)
# --- Hashes em texto limpo, ficheiro à parte ---
        with open(self.hash_file, "w") as f:
            f.write("\n".join(e.sha256 for e in self.entries))
# --- Assinatura digital RSA-PSS do ficheiro cifrado ---
        sig = priv_key.sign(
            blob,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        with open(self.sig_file, "wb") as f:
            f.write(sig)

    def load(self):
# --- carrega o histórico, reconstruindo as entradas em memória (sem decifrar) ---
        if not os.path.exists(self.enc_file):
            return
        with open(self.enc_file, "rb") as f:
            data = json.loads(f.read().decode())
        self.entries = [Entry(**d) for d in data]

# --- Verifica se o histórico contém uma entrada com o hash especificado ---
    def contains(self, plaintext: str) -> bool:
        target = hashlib.sha256(plaintext.encode()).hexdigest()
# --- entradas atuais em memória (não exige gravação prévia)
        if any(e.sha256 == target for e in self.entries):
            return True
# --- fallback: ficheiro de hashes em disco (históricos já gravados)
        if not os.path.exists(self.hash_file):
            return False
        with open(self.hash_file) as f:
            return target in {l.strip() for l in f if l.strip()}

# --- decifra uma entrada específica ---
    def decrypt_one(self, idx: int, key: bytes) -> str:
        return self.entries[idx].decrypt(key)

    def add(self, plaintext: str, key: bytes):
        self.entries.append(Entry.create(plaintext, key))


# ----------------------------- SIGNATURE VERIFY ------------------------------
def verify_signature(enc_file: str, sig_file: str, pub_key: rsa.RSAPublicKey) -> bool:
# --- Verifica assinatura RSA-PSS do ficheiro cifrado usando a chave pública fornecida ---
    with open(enc_file, "rb") as f: blob = f.read()
    with open(sig_file, "rb") as f: sig  = f.read()
    try:
        pub_key.verify(sig, blob,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                   salt_length=padding.PSS.MAX_LENGTH),
                       hashes.SHA256())
        return True
    except Exception:
        return False


def gen_rsa_keypair():
# --- Gera um par de chaves RSA 2048 bits e devolve um par de chaves(privada, pública) ---
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

