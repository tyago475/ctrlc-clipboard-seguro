"""
attack — demonstracao de uma FALHA da nossa propria implementacao.

Vulnerabilidade: o ficheiro de hashes (history.hashes) guarda SHA-256 SEM SAL
do texto-limpo de cada entrada. Como o clipboard copia frequentemente segredos
de baixa entropia (passwords, PINs, cartoes), um atacante com acesso de leitura
a esse ficheiro consegue CONFIRMAR a presenca de um segredo conhecido, fazendo
um ataque de dicionario / confirmacao — sem nunca decifrar o historico.

Isto anula parcialmente a confidencialidade que a cifra AES pretendia garantir.

Mitigacao demonstrada no fim: substituir SHA-256(texto) por HMAC-SHA256(texto)
com uma chave secreta mantida so em memoria. Mantem a funcionalidade "check"
para o proprio utilizador, mas torna o ficheiro inutil para um atacante externo.
"""
import hashlib, hmac, os, time
from clipsec import History, random_key


def run_demo():
    print("=" * 64)
    print("DEMONSTRACAO DE ATAQUE — confirmacao via ficheiro de hashes")
    print("=" * 64)

# --- vítima usa o gestor normalmente ---
    key = random_key()
    h = History("vitima", "/tmp/attack_demo")
    from clipsec import gen_rsa_keypair
    priv, _ = gen_rsa_keypair()
    for s in ["bom dia", "Banco#2024!senha", "lista de compras"]:
        h.add(s, key)
    h.save(key, priv)
    print(f"\n[vitima] historico cifrado guardado em {h.enc_file}")
    print(f"[vitima] hashes (texto limpo) em        {h.hash_file}")

# --- atacante só tem acesso de leitura ao ficheiro de hashes ---
    stolen_hashes = set(open(h.hash_file).read().split())
    print(f"\n[atacante] roubou {len(stolen_hashes)} hashes (NAO tem a chave AES)")

# --- ataque de dicionario: testa palavras-passe comuns ---
    dicionario = ["123456", "password", "Banco#2024!senha", "admin", "qwerty"]
    print("[atacante] a testar dicionario de passwords comuns...")
    for cand in dicionario:
        if hashlib.sha256(cand.encode()).hexdigest() in stolen_hashes:
            print(f"   >>> ACERTOU! A vitima copiou: {cand!r}")
    print("[atacante] confidencialidade comprometida SEM decifrar o historico.\n")

# --- MITIGACAO: HMAC com chave secreta em memória ---
    print("-" * 64)
    print("MITIGACAO: usar HMAC-SHA256 com chave secreta (so em memoria)")
    print("-" * 64)
    secret = os.urandom(32)  # nunca tocada no disco
    secure_hashes = {hmac.new(secret, s.encode(), hashlib.sha256).hexdigest()
                     for s in ["bom dia", "Banco#2024!senha", "lista de compras"]}
    print(f"[atacante] rouba os hashes HMAC, mas NAO tem a chave secreta")
    hits = 0
    for cand in dicionario:
# --- O atacante so consegue testar com SHA-256 simples (nao tem a chave) ---
        if hashlib.sha256(cand.encode()).hexdigest() in secure_hashes:
            hits += 1
    print(f"[atacante] acertos com HMAC: {hits}  -> ataque de dicionario falha")
# --- O utilizador legitimo (que tem a chave) continua a poder verificar ---
    legit = hmac.new(secret, b"Banco#2024!senha", hashlib.sha256).hexdigest() in secure_hashes
    print(f"[utilizador legitimo] check continua a funcionar: {legit}")


if __name__ == "__main__":
    run_demo()
