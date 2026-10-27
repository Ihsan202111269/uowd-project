from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _serial_number() -> int:
    return secrets.randbits(159) + 1


def _subject_from_name(name: str | x509.Name) -> x509.Name:
    if isinstance(name, x509.Name):
        return name
    clean_name = name.strip()
    if clean_name.startswith("CN="):
        clean_name = clean_name[3:]
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, clean_name)])


def create_root_ca(subject: str = "CN=Project Root CA") -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_name = _subject_from_name(subject)
    now = _utc_now()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def create_issuing_ca(
    root_key: rsa.RSAPrivateKey,
    root_cert: x509.Certificate,
    subject: str = "CN=Project Issuing CA",
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_name = _subject_from_name(subject)
    now = _utc_now()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return key, cert


def issue_user_certificate(
    issuing_key: rsa.RSAPrivateKey,
    issuing_cert: x509.Certificate,
    subject: str,
    validity_days: int = 365,
    public_key=None,
):
    user_key = None
    if public_key is None:
        user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = user_key.public_key()
    subject_name = _subject_from_name(subject)
    now = _utc_now()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuing_cert.subject)
        .public_key(public_key)
        .serial_number(_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuing_key.public_key()), critical=False)
        .sign(issuing_key, hashes.SHA256())
    )
    return user_key, cert


def apply_certificate_chain_validation(cert: x509.Certificate, root_cert: x509.Certificate, intermediate_cert: Optional[x509.Certificate] = None, crl: Optional[x509.CertificateRevocationList] = None) -> bool:
    if cert is None or root_cert is None:
        return False

    if crl is not None and crl.get_revoked_certificate_by_serial_number(cert.serial_number):
        return False

    now = _utc_now()
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        return False

    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if basic_constraints.ca:
            return False
    except x509.ExtensionNotFound:
        return False

    if intermediate_cert is None:
        if cert.issuer != root_cert.subject:
            return False
        return _verify_certificate_signature(cert, root_cert.public_key())

    if cert.issuer != intermediate_cert.subject:
        return False
    if intermediate_cert.issuer != root_cert.subject:
        return False

    if now < intermediate_cert.not_valid_before_utc or now > intermediate_cert.not_valid_after_utc:
        return False

    if not _verify_certificate_signature(cert, intermediate_cert.public_key()):
        return False

    return _verify_certificate_signature(intermediate_cert, root_cert.public_key())


def validate_certificate_chain(
    cert: x509.Certificate,
    root_cert: x509.Certificate,
    intermediate_cert: Optional[x509.Certificate] = None,
    crl: Optional[x509.CertificateRevocationList] = None,
) -> bool:
    return apply_certificate_chain_validation(cert, root_cert, intermediate_cert, crl)


def _verify_certificate_signature(cert: x509.Certificate, issuer_public_key) -> bool:
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False


def create_crl(
    issuing_key: rsa.RSAPrivateKey,
    issuing_cert: x509.Certificate,
    revoked_serials: Optional[Iterable[int]] = None,
) -> x509.CertificateRevocationList:
    now = _utc_now()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuing_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
    )

    for serial_number in revoked_serials or []:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial_number)
            .revocation_date(now)
            .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
            .build()
        )

    return builder.sign(issuing_key, hashes.SHA256())


def revoke_certificate(
    issuing_key: rsa.RSAPrivateKey,
    issuing_cert: x509.Certificate,
    serial_number: int,
    current_crl: Optional[x509.CertificateRevocationList] = None,
) -> x509.CertificateRevocationList:
    revoked = []
    if current_crl is not None:
        revoked = [item.serial_number for item in current_crl]
    if serial_number not in revoked:
        revoked.append(serial_number)
    return create_crl(issuing_key, issuing_cert, revoked)


def sign_document_bytes(private_key, document_bytes: bytes) -> bytes:
    return private_key.sign(
        document_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_document_bytes(document_bytes: bytes, signature: bytes, public_key) -> bool:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                document_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if len(signature) == 64:
                signature = encode_dss_signature(
                    int.from_bytes(signature[:32], "big"),
                    int.from_bytes(signature[32:], "big"),
                )
            public_key.verify(signature, document_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False


def generate_x25519_key_pair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_x25519_private(private_key: x25519.X25519PrivateKey) -> str:
    return base64.b64encode(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )).decode("ascii")


def serialize_x25519_public(public_key: x25519.X25519PublicKey) -> str:
    return base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")


def deserialize_x25519_private(raw: str) -> x25519.X25519PrivateKey:
    key_bytes = base64.b64decode(raw)
    return x25519.X25519PrivateKey.from_private_bytes(key_bytes)


def deserialize_x25519_public(raw: str) -> x25519.X25519PublicKey:
    key_bytes = base64.b64decode(raw)
    return x25519.X25519PublicKey.from_public_bytes(key_bytes)


def derive_shared_key(private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey) -> bytes:
    shared_secret = private_key.exchange(public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"macs902-secure-document-encryption",
    ).derive(shared_secret)


def encrypt_document_for_recipient(plaintext: str, recipient_public_key) -> dict:
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    shared_key = derive_shared_key(ephemeral_private, recipient_public_key)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(shared_key).encrypt(nonce, plaintext.encode("utf-8"), None)

    return {
        "ephemeral_public": serialize_x25519_public(ephemeral_public),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "metadata": json.dumps({"algorithm": "X25519/HKDF-SHA256/AES-256-GCM", "version": 1})
    }


def decrypt_document_for_recipient(payload: dict, private_key: x25519.X25519PrivateKey) -> str:
    recipient_public = private_key.public_key()
    ephemeral_public = deserialize_x25519_public(payload["ephemeral_public"])
    shared_key = derive_shared_key(private_key, ephemeral_public)
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    plaintext = AESGCM(shared_key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
