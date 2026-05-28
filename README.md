# CTRL+C — Gestor de Clipboard Seguro

Projeto 2.10 — Segurança Informática & Cibersegurança 2025/26.
Gestor de clipboard que guarda o histórico cifrado, com hashes, assinaturas
digitais e suporte a certificados X.509.

## Ficheiros

| Ficheiro     | Papel |
|--------------|-------|
| `clipsec.py` | Núcleo cripto: AES-256-GCM por entrada, SHA-256, assinatura RSA-PSS, PBKDF2. |
| `pki.py`     | Certificados X.509 (CA + cert de assinatura) e proteção da chave privada em disco. |
| `config.py`  | Gestão e ferramenta de configuração (max_entries, intervalos, etc.). |
| `app.py`     | Daemon de captura (thread, "CTRL+V" a cada 2 s; autosave 5 min) + CLI. |
| `gui.py`     | Interface Tkinter; **duplo-clique** repõe a entrada no clipboard. |
| `attack.py`  | Demonstração de uma falha da implementação + mitigação (para a apresentação). |

## Instalação

```bash
pip install cryptography pyperclip   # pyperclip só é preciso para clipboard real
```

Sem `pyperclip` a app corre em modo *mock* (útil para testes).

## Uso

```bash
# Versão simples — chave de cifra só em memória (histórico perde-se ao sair)
python3 app.py --user alice
python3 gui.py --user alice

# Versão elaborada — chave derivada de password mestra (PBKDF2) + persistência
python3 app.py --user alice --master
python3 gui.py --user alice --master

# Configuração
python3 config.py --user alice --set max_entries 200
python3 config.py --user alice --list

# Demonstração do ataque
python3 attack.py
```

Comandos da CLI: `list`, `get <i>`, `check <txt>`, `verify`, `flush`, `config`, `help`, `quit`.

## Requisitos cobertos

Base: histórico cifrado (AES-256-GCM), chave gerada de forma segura e mantida em
memória, gravação cifrada a cada 5 min (apaga anterior), hashes SHA-256 em
ficheiro separado em texto limpo, verificação de existência sem decifrar,
assinatura RSA do ficheiro cifrado a cada gravação.

Elaborada: PBKDF2 (password mestra + sal), decifração de históricos anteriores,
decifração seletiva por entrada, multi-utilizador, verificação a pedido,
certificados X.509 para validar assinaturas, chave privada cifrada em disco,
help completo.

## A falha demonstrada

Os hashes são SHA-256 **sem sal** do texto-limpo. Como o clipboard copia
segredos de baixa entropia, um atacante com acesso ao ficheiro de hashes pode
confirmar a presença de um segredo conhecido via ataque de dicionário, sem
decifrar nada. Mitigação: HMAC-SHA256 com chave secreta mantida em memória
(ver `attack.py`).

## Por fazer

Apresentação (~10 slides) e artefactos de autoria (histórico Git com commits
dos vários membros do grupo).
