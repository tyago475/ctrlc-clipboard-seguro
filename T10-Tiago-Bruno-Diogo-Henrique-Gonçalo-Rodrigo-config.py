"""
config — gestão de parâmetros do gestor (app de configuração).

Guarda preferências por utilizador num JSON simples. Pode correr-se como
ferramenta autónoma:  python3 config.py --user alice --set max_entries 200
"""
from __future__ import annotations
import os, json, argparse

DEFAULTS = {
    "max_entries": 100,      # quantas entradas o historico suporta
    "save_interval": 300,    # segundos entre gravacoes cifradas
    "poll_interval": 2,      # segundos entre "CTRL+V"
    "use_certificates": True # validar assinaturas via X.509
}


class Config:
# --- Inicializa a configuração de um utilizador específico ---
    def __init__(self, user: str, base_dir: str = "."):
        self.path = os.path.join(base_dir, f"config_{user}.json")
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
# --- Carrega a configuração do ficheiro JSON, se existir, sobrescrevendo os defaults ---
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.data.update(json.load(f))

    def save(self):
# --- Salva a configuração atual num ficheiro JSON, criando ou sobrescrevendo o anterior ---
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)
            
# --- getters e setters com validação e coerção de tipos ---
    def get(self, k): return self.data.get(k, DEFAULTS.get(k))

    def set(self, k, v):
        if k not in DEFAULTS:
            raise KeyError(f"parametro desconhecido: {k}")
        # coage ao tipo do default
        t = type(DEFAULTS[k])
        self.data[k] = t(v) if t is not bool else str(v).lower() in ("1","true","sim","yes")
        self.save()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Configuracao do gestor CTRL+C")
    p.add_argument("--user", default="default")
    p.add_argument("--set", nargs=2, metavar=("CHAVE", "VALOR"))
    p.add_argument("--list", action="store_true")
    a = p.parse_args()
    cfg = Config(a.user)
    if a.set:
        cfg.set(a.set[0], a.set[1]); print(f"definido {a.set[0]} = {cfg.get(a.set[0])}")
    if a.list or not a.set:
        print(f"configuracao de '{a.user}':")
        for k, v in cfg.data.items():
            print(f"  {k:16} = {v}")
