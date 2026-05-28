"""
PKI — certificados digitais X.509 + proteção da chave privada RSA.

- Gera um certificado auto-assinado (CA) e um certificado de assinatura emitido
  por essa CA, para que os programas cliente validem assinaturas via cadeia de
  confiança (e não com a chave pública crua).
- A chave privada é guardada em disco CIFRADA com a chave derivada (PBKDF2),
  usando o formato PKCS#8 com BestAvailableEncryption.
"""
from __future__ import annotations
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SegInf CTRL+C"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def build_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """CA auto-assinada que servirá de raiz de confiança."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(_name("CTRL+C Root CA"))
            .issuer_name(_name("CTRL+C Root CA"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue_signing_cert(ca_key, ca_cert, user: str):
    """Certificado de assinatura do utilizador, emitido pela CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(f"ctrlc-user-{user}"))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


# --------------------- persistência protegida -------------------------------
def save_private_key(key: rsa.RSAPrivateKey, path: str, enc_key: bytes):
    """Guarda a chave privada CIFRADA com a chave derivada (PBKDF2)."""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(enc_key))
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str, enc_key: bytes) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=enc_key)


def save_cert(cert: x509.Certificate, path: str):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


# --------------------- verificação via cadeia -------------------------------
def verify_cert_chain(leaf: x509.Certificate, ca: x509.Certificate) -> bool:
    """Valida que o certificado-folha foi emitido pela CA e está dentro da validade."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
        return False
    try:
        ca.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes,
            padding.PKCS1v15(), leaf.signature_hash_algorithm)
        return True
    except Exception:
        return False


def verify_with_cert(blob: bytes, sig: bytes, leaf: x509.Certificate,
                     ca: x509.Certificate) -> bool:
    """Verifica assinatura E cadeia de confiança até à CA."""
    if not verify_cert_chain(leaf, ca):
        return False
    try:
        leaf.public_key().verify(
            sig, blob,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except Exception:
        return False
