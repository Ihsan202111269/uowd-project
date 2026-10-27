from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import pytest

from app.pki import (
    create_root_ca,
    create_issuing_ca,
    issue_user_certificate,
    validate_certificate_chain,
    create_crl,
    revoke_certificate,
)

TEST_ENCRYPTION_KEY = Fernet.generate_key()


class TestConfig:
    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-only-secret-for-unit-tests-secret"
    PRIVATE_KEY_ENCRYPTION_KEY = TEST_ENCRYPTION_KEY
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PKI_STATE_PATH = None
    BOOTSTRAP_ADMIN_USERNAME = "admin"
    BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
    BOOTSTRAP_ADMIN_PASSWORD = "test-admin-password"


def test_app_home_page():
    from app import create_app

    app = create_app(TestConfig)
    client = app.test_client()
    response = client.get("/")

    assert response.status_code == 200
    assert b"Secure documents." in response.data
    assert b"Trusted signatures." in response.data
    assert b'href="/login"' in response.data
    assert b'href="/register"' in response.data
    assert b'document.addEventListener("submit"' in response.data
    assert b'form.dataset.submitting = "true"' in response.data
    background = client.get("/static/images/security-background.png")
    assert background.status_code == 200
    assert background.mimetype == "image/png"

    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    dashboard = client.get("/dashboard")
    assert b'class="app-sidebar"' in dashboard.data
    assert b"Verify signature" in dashboard.data
    assert b"Sign &amp; Encrypt" in dashboard.data


def test_server_restart_requires_login_again_and_home_stays_at_auth_choice(tmp_path):
    from app import create_app

    database_uri = f"sqlite:///{tmp_path / 'session-restart.db'}"

    class PersistentSessionConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = database_uri

    first_app = create_app(PersistentSessionConfig)
    first_client = first_app.test_client()
    first_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    assert first_client.get("/dashboard").status_code == 200
    cookie = first_client.get_cookie(first_app.config["SESSION_COOKIE_NAME"])
    assert cookie is not None

    restarted_app = create_app(PersistentSessionConfig)
    restarted_client = restarted_app.test_client()
    restarted_client.set_cookie(
        restarted_app.config["SESSION_COOKIE_NAME"],
        cookie.value,
    )

    dashboard = restarted_client.get("/dashboard")
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].startswith("/login")

    home = restarted_client.get("/")
    assert home.status_code == 200
    assert b"Secure documents." in home.data
    assert b'href="/login"' in home.data
    assert b'href="/register"' in home.data


def test_multiple_users_can_use_separate_sessions_at_the_same_time():
    from app import create_app

    app = create_app(TestConfig)
    admin_client = app.test_client()
    recipient_client = app.test_client()

    admin_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    recipient_client.post(
        "/register",
        data={
            "username": "recipient",
            "email": "recipient@example.com",
            "password": "recipient-password-123",
        },
    )
    recipient_client.post(
        "/login",
        data={"username": "recipient", "password": "recipient-password-123"},
    )

    admin_dashboard = admin_client.get("/dashboard")
    recipient_dashboard = recipient_client.get("/dashboard")

    assert admin_dashboard.status_code == 200
    assert b"admin</strong> \xc2\xb7 Admin" in admin_dashboard.data
    assert b"class=\"button button-compact account-password-button\"" in admin_dashboard.data
    assert recipient_dashboard.status_code == 200
    assert b"recipient</strong> \xc2\xb7 User" in recipient_dashboard.data
    assert b"recipient</strong> \xc2\xb7 User" not in admin_dashboard.data
    assert b"admin</strong> \xc2\xb7 Admin" not in recipient_dashboard.data


def test_admin_can_change_password_and_bootstrap_does_not_reset_it(tmp_path):
    from app import create_app

    database_uri = f"sqlite:///{tmp_path / 'password-change.db'}"

    class PersistentConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = database_uri

    app = create_app(PersistentConfig)
    admin_client = app.test_client()
    second_session = app.test_client()
    for client in (admin_client, second_session):
        client.post(
            "/login",
            data={"username": "admin", "password": "test-admin-password"},
        )

    changed_password = "test-only-new-password-456"
    response = admin_client.post(
        "/account/password",
        data={
            "current_password": "test-admin-password",
            "new_password": changed_password,
            "confirm_password": changed_password,
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert second_session.get("/dashboard").status_code == 302

    restarted_app = create_app(PersistentConfig)
    old_password_client = restarted_app.test_client()
    old_login = old_password_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    assert old_login.status_code == 302
    assert old_login.headers["Location"].endswith("/login")

    new_password_client = restarted_app.test_client()
    new_password_login = new_password_client.post(
        "/login",
        data={"username": "admin", "password": changed_password},
    )
    assert new_password_login.status_code == 302
    assert new_password_login.headers["Location"].endswith("/dashboard")
    assert new_password_client.get("/dashboard").status_code == 200


def test_e2ee_reset_and_browser_encrypted_message_round_trip():
    import base64
    import hashlib
    import json
    import os
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from app import create_app
    from app.models import (
        CertificateRecord,
        EncryptedDocument,
        EncryptionSystemState,
        User,
        db,
    )

    app = create_app(TestConfig)
    admin = app.test_client()
    recipient = app.test_client()
    admin.post("/login", data={"username": "admin", "password": "test-admin-password"})
    admin.post("/request-certificate", data={"subject": "admin"})
    recipient.post(
        "/register",
        data={
            "username": "recipient",
            "email": "recipient@example.com",
            "password": "recipient-password-123",
        },
    )
    with app.app_context():
        old_certificate = CertificateRecord.query.one()
        old_certificate_id = old_certificate.id
        old_private_key = old_certificate.private_key_pem
        admin_user = User.query.filter_by(username="admin").one()
        recipient_user = User.query.filter_by(username="recipient").one()
        old_message = EncryptedDocument(
            title="Legacy message",
            sender_id=admin_user.id,
            recipient_id=recipient_user.id,
            payload="{}",
            payload_metadata=json.dumps({"status": "signed_and_encrypted"}),
        )
        db.session.add(old_message)
        db.session.commit()
        old_message_id = old_message.id

    reset = admin.post(
        "/admin/e2ee-reset",
        data={"confirmation": "RESET"},
    )
    assert reset.status_code == 302
    assert reset.headers["Location"].endswith("/login")
    with app.app_context():
        state = db.session.get(EncryptionSystemState, 1)
        legacy_certificate = db.session.get(CertificateRecord, old_certificate_id)
        legacy_message = db.session.get(EncryptedDocument, old_message_id)
        assert state.clean_reset_completed
        assert legacy_certificate.status == "revoked"
        assert legacy_certificate.private_key_pem == ""
        assert json.loads(legacy_message.payload_metadata)["status"] == "e2ee_reset"
        assert old_private_key != legacy_certificate.private_key_pem
        assert all(
            user.key_agreement_private is None
            and user.key_agreement_public is None
            and user.encrypted_client_key_bundle is None
            for user in User.query.all()
        )

    recipient.post(
        "/login",
        data={"username": "recipient", "password": "recipient-password-123"},
    )
    locked_legacy_message = recipient.get(f"/decrypt-document/{old_message_id}")
    assert locked_legacy_message.status_code == 302
    assert locked_legacy_message.headers["Location"].endswith("/dashboard")
    assert recipient.post(
        "/admin/e2ee-reset",
        data={"confirmation": "RESET"},
    ).status_code == 403

    admin.post("/login", data={"username": "admin", "password": "test-admin-password"})
    repeated_reset = admin.post(
        "/admin/e2ee-reset",
        data={"confirmation": "RESET"},
    )
    assert repeated_reset.status_code == 302
    assert repeated_reset.headers["Location"].endswith("/admin")
    legacy_submission = admin.post(
        "/encrypt-document",
        data={
            "recipient_id": "2",
            "certificate_id": "1",
            "title": "Legacy form",
            "document_text": "Must not be accepted after reset",
        },
    )
    assert legacy_submission.status_code == 302

    def enroll(client, username):
        signing_private = ec.generate_private_key(ec.SECP256R1())
        encryption_private = ec.generate_private_key(ec.SECP256R1())
        signing_public_der = signing_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        encryption_public_der = encryption_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        response = client.post(
            "/request-certificate",
            json={
                "signing_public_key": base64.b64encode(signing_public_der).decode(),
                "encryption_public_key": base64.b64encode(encryption_public_der).decode(),
                "encrypted_key_bundle": {
                    "version": 1,
                    "kdf": "PBKDF2-SHA256",
                    "iterations": 310000,
                    "salt": base64.b64encode(os.urandom(16)).decode(),
                    "iv": base64.b64encode(os.urandom(12)).decode(),
                    "ciphertext": base64.b64encode(os.urandom(32)).decode(),
                },
            },
        )
        assert response.status_code == 200, response.json
        with app.app_context():
            user = User.query.filter_by(username=username).one()
            certificate = CertificateRecord.query.filter_by(
                user_id=user.id,
                status="active",
            ).one()
            assert certificate.private_key_pem == ""
            assert user.key_agreement_private is None
            assert user.encrypted_client_key_bundle is not None
        return signing_private, encryption_private, response.json

    admin.post("/login", data={"username": "admin", "password": "test-admin-password"})
    admin_signing_key, _, admin_enrollment = enroll(admin, "admin")
    encrypted_bundle_response = admin.get("/api/client-key-bundle")
    assert encrypted_bundle_response.status_code == 200
    assert "signing_private_key" not in encrypted_bundle_response.json["bundle"]
    with app.app_context():
        admin_user = User.query.filter_by(username="admin").one()
        encryption_public_key = admin_user.key_agreement_public
    signing_public_key = admin_signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    restored = admin.post(
        "/account/keys/restore",
        json={
            "signing_public_key": base64.b64encode(signing_public_key).decode(),
            "encryption_public_key": encryption_public_key,
            "encrypted_key_bundle": encrypted_bundle_response.json["bundle"],
        },
    )
    assert restored.status_code == 200
    recipient.post(
        "/login",
        data={"username": "recipient", "password": "recipient-password-123"},
    )
    _, recipient_encryption_key, _ = enroll(recipient, "recipient")

    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
    title = "E2EE message"
    message_bytes = pdf_content
    content_hash = base64.b64encode(hashlib.sha256(message_bytes).digest()).decode()
    signature_payload = json.dumps(
        {
            "version": 2,
            "title": title,
            "sender_id": 1,
            "recipient_id": 2,
            "content_type": "application/pdf",
            "filename": "report.pdf",
            "content_hash": content_hash,
        },
        separators=(",", ":"),
    )
    signature_der = admin_signing_key.sign(
        signature_payload.encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    envelope = {
        "version": 2,
        "title": title,
        "sender_id": 1,
        "recipient_id": 2,
        "content_type": "application/pdf",
        "filename": "report.pdf",
        "content_hash": content_hash,
        "content_base64": base64.b64encode(message_bytes).decode(),
        "signature": base64.b64encode(signature_raw).decode(),
        "signer_certificate_serial": admin_enrollment["serial_number"],
        "signer_certificate_pem": admin_enrollment["certificate_pem"],
    }
    salt = os.urandom(16)
    iv = os.urandom(12)
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_private.exchange(
        ec.ECDH(),
        recipient_encryption_key.public_key(),
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secure-exchange-e2ee-message-v2",
    ).derive(shared_secret)
    ciphertext = AESGCM(key).encrypt(iv, json.dumps(envelope).encode(), None)
    ephemeral_public_der = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sent = admin.post(
        "/encrypt-document/legacy",
        json={
            "title": title,
            "recipient_id": "2",
            "certificate_id": "2",
            "payload": {
                "version": 2,
                "ephemeral_public_key": base64.b64encode(ephemeral_public_der).decode(),
                "salt": base64.b64encode(salt).decode(),
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            },
        },
    )
    assert sent.status_code == 200, sent.json
    message_id = sent.json["document_id"]
    with app.app_context():
        stored = db.session.get(EncryptedDocument, message_id)
        assert base64.b64encode(pdf_content).decode() not in stored.payload
        assert json.loads(stored.payload_metadata)["format_version"] == 2

    recipient_page = recipient.get(f"/decrypt-document/{message_id}")
    assert recipient_page.status_code == 200
    assert b"Key-unlock passphrase" in recipient_page.data
    assert pdf_content not in recipient_page.data
    assert b"encrypted_key_bundle" not in recipient_page.data
    assert recipient.post(f"/decrypt-document/{message_id}").status_code == 200
    assert recipient.get(f"/decrypt-document/{message_id}/download").status_code == 400
    stored_payload = json.loads(stored.payload)
    ephemeral_public = serialization.load_der_public_key(
        base64.b64decode(stored_payload["ephemeral_public_key"])
    )
    recipient_shared_secret = recipient_encryption_key.exchange(
        ec.ECDH(),
        ephemeral_public,
    )
    recipient_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(stored_payload["salt"]),
        info=b"secure-exchange-e2ee-message-v2",
    ).derive(recipient_shared_secret)
    opened_envelope = json.loads(
        AESGCM(recipient_key).decrypt(
            base64.b64decode(stored_payload["iv"]),
            base64.b64decode(stored_payload["ciphertext"]),
            None,
        )
    )
    assert base64.b64decode(opened_envelope["content_base64"]) == pdf_content
    opened_signature = base64.b64decode(opened_envelope["signature"])
    opened_signature_der = encode_dss_signature(
        int.from_bytes(opened_signature[:32], "big"),
        int.from_bytes(opened_signature[32:], "big"),
    )
    admin_signing_key.public_key().verify(
        opened_signature_der,
        signature_payload.encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    trust_before_revocation = recipient.get(
        f"/api/certificates/{admin_enrollment['serial_number']}/trust"
    )
    assert trust_before_revocation.status_code == 200
    assert trust_before_revocation.json["trusted"] is True
    report = recipient.post(
        f"/api/documents/{message_id}/decryption-result",
        json={"verified": True},
    )
    assert report.status_code == 200
    with app.app_context():
        new_admin_certificate_id = CertificateRecord.query.filter_by(
            serial_number=admin_enrollment["serial_number"]
        ).one().id
    assert admin.post(f"/admin/revoke/{new_admin_certificate_id}").status_code == 302
    trust_after_revocation = recipient.get(
        f"/api/certificates/{admin_enrollment['serial_number']}/trust"
    )
    assert trust_after_revocation.status_code == 200
    assert trust_after_revocation.json["trusted"] is False
    assert recipient.get(f"/decrypt-document/{message_id}").status_code == 302
    assert recipient.get(f"/decrypt-document/{message_id}/download").status_code == 410
    with app.app_context():
        from app.models import AuditEvent

        assert AuditEvent.query.filter_by(
            action="client_decrypt_and_verify",
            outcome="client_reported_success",
        ).count() == 1
        stored = db.session.get(EncryptedDocument, message_id)
        assert json.loads(stored.payload_metadata)["status"] == "access_revoked"


def test_browser_held_document_signature_is_saved_and_verified():
    import base64
    import os
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from app import create_app
    from app.models import CertificateRecord, DocumentRecord, db

    app = create_app(TestConfig)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    client.post("/admin/e2ee-reset", data={"confirmation": "RESET"})
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})

    signing_key = ec.generate_private_key(ec.SECP256R1())
    public_key_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    enrollment = client.post(
        "/request-certificate",
        json={
            "signing_public_key": base64.b64encode(public_key_der).decode(),
            "encryption_public_key": base64.b64encode(public_key_der).decode(),
            "encrypted_key_bundle": {
                "version": 1,
                "kdf": "PBKDF2-SHA256",
                "iterations": 310000,
                "salt": base64.b64encode(os.urandom(16)).decode(),
                "iv": base64.b64encode(os.urandom(12)).decode(),
                "ciphertext": base64.b64encode(os.urandom(32)).decode(),
            },
        },
    )
    assert enrollment.status_code == 200
    content = "Signed in the browser".encode()
    signature = signing_key.sign(content, ec.ECDSA(hashes.SHA256()))
    with app.app_context():
        certificate_id = CertificateRecord.query.one().id

    signed = client.post(
        "/sign-document",
        data={
            "title": "Browser signed",
            "certificate_id": str(certificate_id),
            "document_text": content.decode(),
            "signature_hex": signature.hex(),
        },
    )
    assert signed.status_code == 200
    assert b"Signature created in your browser and saved successfully." in signed.data
    with app.app_context():
        document = DocumentRecord.query.one()
        assert document.document_text == content.decode()
        assert document.signature_hex == signature.hex()


def test_e2ee_message_uses_sender_shared_one_time_key_without_recipient_key_enrollment():
    import base64
    import hashlib
    import json
    import os
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app import create_app
    from app.models import CertificateRecord, EncryptedDocument, User, db

    app = create_app(TestConfig)
    admin = app.test_client()
    recipient = app.test_client()
    admin.post("/login", data={"username": "admin", "password": "test-admin-password"})
    recipient.post(
        "/register",
        data={
            "username": "recipient",
            "email": "recipient@example.com",
            "password": "recipient-password-123",
        },
    )
    admin.post("/admin/e2ee-reset", data={"confirmation": "RESET"})
    admin.post("/login", data={"username": "admin", "password": "test-admin-password"})
    recipient.post(
        "/login",
        data={"username": "recipient", "password": "recipient-password-123"},
    )

    signing_key = ec.generate_private_key(ec.SECP256R1())
    signing_public_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    enrollment = admin.post(
        "/request-certificate",
        json={
            "signing_public_key": base64.b64encode(signing_public_der).decode(),
            "encryption_public_key": base64.b64encode(signing_public_der).decode(),
            "encrypted_key_bundle": {
                "version": 1,
                "kdf": "PBKDF2-SHA256",
                "iterations": 310000,
                "salt": base64.b64encode(os.urandom(16)).decode(),
                "iv": base64.b64encode(os.urandom(12)).decode(),
                "ciphertext": base64.b64encode(os.urandom(32)).decode(),
            },
        },
    )
    assert enrollment.status_code == 200
    with app.app_context():
        sender = User.query.filter_by(username="admin").one()
        recipient_user = User.query.filter_by(username="recipient").one()
        certificate = CertificateRecord.query.filter_by(
            user_id=sender.id,
            status="active",
        ).one()
        sender_id, recipient_id, certificate_id = sender.id, recipient_user.id, certificate.id
        assert recipient_user.key_agreement_public is None
    send_page = admin.get("/encrypt-document")
    assert send_page.status_code == 200
    assert b"Request a signing certificate before sending an encrypted message." in send_page.data

    title = "One-time key test"
    content = b"Only the sender and recipient know the key."
    content_hash = base64.b64encode(hashlib.sha256(content).digest()).decode()
    signature_payload = json.dumps(
        {
            "version": 2,
            "title": title,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "content_type": "text/plain",
            "filename": "",
            "content_hash": content_hash,
        },
        separators=(",", ":"),
    ).encode()
    signature_der = signing_key.sign(signature_payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    envelope = {
        "version": 2,
        "title": title,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "content_type": "text/plain",
        "filename": "",
        "content_hash": content_hash,
        "content_base64": base64.b64encode(content).decode(),
        "signature": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        "signer_certificate_serial": enrollment.json["serial_number"],
        "signer_certificate_pem": enrollment.json["certificate_pem"],
    }
    one_time_key = os.urandom(32)
    iv = os.urandom(12)
    ciphertext = AESGCM(one_time_key).encrypt(iv, json.dumps(envelope).encode(), None)
    sent = admin.post(
        "/encrypt-document/legacy",
        json={
            "title": title,
            "recipient_id": str(recipient_id),
            "certificate_id": str(certificate_id),
            "payload": {
                "version": 3,
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            },
        },
    )
    assert sent.status_code == 200
    message_id = sent.json["document_id"]

    with app.app_context():
        stored = db.session.get(EncryptedDocument, message_id)
        assert content.decode() not in stored.payload
        assert json.loads(stored.payload_metadata)["format_version"] == 3
        assert base64.urlsafe_b64encode(one_time_key).decode().rstrip("=") not in stored.payload

    decrypt_page = recipient.get(f"/decrypt-document/{message_id}")
    assert decrypt_page.status_code == 200
    assert b"One-time decryption key" in decrypt_page.data
    assert b"Key-unlock passphrase" not in decrypt_page.data
    assert content not in decrypt_page.data
    assert recipient.post(f"/decrypt-document/{message_id}").status_code == 200
    assert recipient.get(f"/decrypt-document/{message_id}/download").status_code == 405
    assert recipient.post(f"/decrypt-document/{message_id}/download").status_code == 403


def test_simple_one_time_key_flow_issues_certificate_and_decrypts_without_reset():
    import re
    from io import BytesIO
    from app import create_app
    from app.models import CertificateRecord, EncryptedDocument, User, db

    app = create_app(TestConfig)
    sender = app.test_client()
    recipient = app.test_client()
    sender.post("/login", data={"username": "admin", "password": "test-admin-password"})
    recipient.post(
        "/register",
        data={
            "username": "recipient",
            "email": "recipient@example.com",
            "password": "recipient-password-123",
        },
    )
    recipient.post(
        "/login",
        data={"username": "recipient", "password": "recipient-password-123"},
    )

    certificate_page = sender.get("/request-certificate")
    assert b"Subject name" in certificate_page.data
    issued = sender.post("/request-certificate", data={"subject": "admin"})
    assert issued.status_code == 302
    with app.app_context():
        sender_user = User.query.filter_by(username="admin").one()
        recipient_user = User.query.filter_by(username="recipient").one()
        certificate = CertificateRecord.query.filter_by(
            user_id=sender_user.id,
            status="active",
        ).one()
        sender_id, recipient_id, certificate_id = (
            sender_user.id,
            recipient_user.id,
            certificate.id,
        )
        assert certificate.private_key_pem
        assert recipient_user.encrypted_client_key_bundle is None

    pdf_bytes = b"%PDF-1.4\none-time protected document\n%%EOF\n"
    sent = sender.post(
        "/encrypt-document",
        data={
            "title": "Protected PDF",
            "recipient_id": str(recipient_id),
            "certificate_id": str(certificate_id),
            "document_file": (BytesIO(pdf_bytes), "protected.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert sent.status_code == 200
    assert b"Message sent" in sent.data
    key_match = re.search(
        rb"One-time decryption key:</strong>\s*<code>([A-Za-z0-9_-]{43})</code>",
        sent.data,
    )
    assert key_match is not None
    message_key = key_match.group(1).decode()
    with app.app_context():
        message = EncryptedDocument.query.one()
        message_id = message.id
        assert pdf_bytes not in message.payload.encode()
        assert message_key not in message.payload
        assert message.sender_id == sender_id

    decrypt_page = recipient.get(f"/decrypt-document/{message_id}")
    assert b"One-time decryption key" in decrypt_page.data
    assert b"Key-unlock passphrase" not in decrypt_page.data
    bad_key_page = recipient.post(
        f"/decrypt-document/{message_id}",
        data={"message_key": "A" * 43},
    )
    assert b"incorrect or the message is damaged" in bad_key_page.data
    verified = recipient.post(
        f"/decrypt-document/{message_id}",
        data={"message_key": message_key},
    )
    assert b"Overall status: VERIFIED" in verified.data
    assert b"The PDF was decrypted and its signature verified." in verified.data
    download = recipient.post(
        f"/decrypt-document/{message_id}/download",
        data={"message_key": message_key},
    )
    assert download.status_code == 200
    assert download.mimetype == "application/pdf"
    assert download.data == pdf_bytes


def test_app_requires_private_key_encryption_secret():
    from app import create_app

    class MissingEncryptionKeyConfig(TestConfig):
        PRIVATE_KEY_ENCRYPTION_KEY = None

    with pytest.raises(RuntimeError, match="PRIVATE_KEY_ENCRYPTION_KEY"):
        create_app(MissingEncryptionKeyConfig)


def test_disabled_pki_persistence_does_not_write_instance_state(tmp_path):
    from app import create_app, save_pki_state

    app = create_app(TestConfig)
    app.instance_path = str(tmp_path)
    with app.app_context():
        save_pki_state(app)

    assert not (tmp_path / "pki-state.enc").exists()


def test_csrf_protects_post_requests():
    from app import create_app

    class CsrfConfig(TestConfig):
        WTF_CSRF_ENABLED = True

    response = create_app(CsrfConfig).test_client().post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    assert response.status_code == 400


def test_private_keys_are_encrypted_at_rest():
    from app import create_app, decrypt_private_key
    from app.models import CertificateRecord, User

    app = create_app(TestConfig)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    sign_page = client.get("/sign-document")
    assert sign_page.status_code == 200
    assert b"Signature result" not in sign_page.data

    client.post("/request-certificate", data={"subject": "admin"})

    with app.app_context():
        user = User.query.filter_by(username="admin").one()
        certificate = CertificateRecord.query.one()
        assert user.key_agreement_private.startswith("fernet:v1:")
        assert certificate.private_key_pem.startswith("fernet:v1:")
        assert user.key_agreement_private != decrypt_private_key(
            app, user.key_agreement_private
        )
        assert "PRIVATE KEY" in decrypt_private_key(app, certificate.private_key_pem)


def test_database_and_existing_plaintext_keys_survive_restart_and_are_migrated(tmp_path):
    from app import create_app
    from app.models import User, db

    database_uri = f"sqlite:///{tmp_path / 'persistent.db'}"

    class PersistentConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = database_uri

    first_app = create_app(PersistentConfig)
    first_client = first_app.test_client()
    first_client.post(
        "/register",
        data={
            "username": "alice",
            "email": "alice@example.com",
            "password": "alice-password-123",
        },
    )
    with first_app.app_context():
        alice = User.query.filter_by(username="alice").one()
        alice.key_agreement_private = "legacy-plaintext-key"
        db.session.commit()

    second_app = create_app(PersistentConfig)
    with second_app.app_context():
        alice = User.query.filter_by(username="alice").one()
        from app import decrypt_private_key

        assert alice.key_agreement_private.startswith("fernet:v1:")
        assert decrypt_private_key(second_app, alice.key_agreement_private) == "legacy-plaintext-key"


def test_ca_and_signature_trust_survive_application_restart(tmp_path):
    from app import create_app
    from app.models import CertificateRecord, DocumentRecord

    database_uri = f"sqlite:///{tmp_path / 'persistent-pki.db'}"

    class PersistentPKIConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = database_uri
        PKI_STATE_PATH = tmp_path / "pki-state.enc"

    first_app = create_app(PersistentPKIConfig)
    first_client = first_app.test_client()
    first_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    first_client.post("/request-certificate", data={"subject": "admin"})
    first_client.post(
        "/sign-document",
        data={
            "title": "Persistence check",
            "certificate_id": "1",
            "document_text": "Verify after restarting",
        },
    )
    with first_app.app_context():
        root_certificate = first_app.config["PKI_STATE"]["root_cert"].public_bytes(
            serialization.Encoding.DER
        )
        document = DocumentRecord.query.one()
        signature_data = {
            "document_id": str(document.id),
            "signature_hex": document.signature_hex,
        }
        assert CertificateRecord.query.count() == 1

    second_app = create_app(PersistentPKIConfig)
    second_client = second_app.test_client()
    second_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    response = second_client.post("/verify-document", data=signature_data)

    assert response.status_code == 200
    assert b"Overall status: VERIFIED" in response.data
    assert b"Signature matches the exact document content: Yes" in response.data
    assert b'name="document_text"' not in response.data
    assert (
        second_app.config["PKI_STATE"]["root_cert"].public_bytes(
            serialization.Encoding.DER
        )
        == root_certificate
    )
    assert PersistentPKIConfig.PKI_STATE_PATH.exists()


def test_root_issuing_user_chain_and_revocation():
    root_key, root_cert = create_root_ca()
    issuing_key, issuing_cert = create_issuing_ca(root_key, root_cert)
    user_key, user_cert = issue_user_certificate(issuing_key, issuing_cert, "CN=Alice Example")

    assert validate_certificate_chain(user_cert, root_cert, issuing_cert)

    crl = create_crl(issuing_key, issuing_cert, [])
    assert crl is not None

    revoked_crl = revoke_certificate(issuing_key, issuing_cert, user_cert.serial_number, crl)
    assert revoked_crl is not None
    assert not validate_certificate_chain(user_cert, root_cert, issuing_cert, revoked_crl)
    assert user_key is not None


def test_saved_signature_verifies_and_revocation_invalidates_trust():
    from app import create_app
    from app.models import CertificateRecord, DocumentRecord, db

    app = create_app(TestConfig)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    client.post("/request-certificate", data={"subject": "admin"})

    with app.app_context():
        certificate = CertificateRecord.query.one()
        certificate_id = certificate.id

    client.post(
        "/sign-document",
        data={
            "title": "Verification test",
            "certificate_id": str(certificate_id),
            "document_text": "Exact signed content",
        },
    )
    with app.app_context():
        document = DocumentRecord.query.one()
        document_id = document.id
        signature_hex = document.signature_hex

    verification_form = client.get(f"/verify-document?document_id={document_id}")
    assert verification_form.status_code == 200
    assert b"Verification test" in verification_form.data
    assert b'name="signature_hex"' in verification_form.data
    assert b'name="document_text"' not in verification_form.data
    assert b'name="certificate_id"' not in verification_form.data

    saved_verification = client.post(
        "/verify-document",
        data={"document_id": str(document_id), "signature_hex": signature_hex},
    )
    assert b"Overall status: VERIFIED" in saved_verification.data
    assert b"Signature matches the exact document content: Yes" in saved_verification.data

    pdf = client.get(f"/documents/{document_id}/download")
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.data.startswith(b"%PDF-")
    assert "filename=Verification_test.pdf" in pdf.headers["Content-Disposition"]

    signature = bytes.fromhex(signature_hex)
    incorrect_signature = (bytes([signature[0] ^ 1]) + signature[1:]).hex()
    invalid_saved_verification = client.post(
        "/verify-document",
        data={
            "document_id": str(document_id),
            "signature_hex": incorrect_signature,
        },
    )
    assert b"Overall status: UNVERIFIED" in invalid_saved_verification.data
    assert b"Signature matches the exact document content: No" in invalid_saved_verification.data

    with app.app_context():
        certificate_id = DocumentRecord.query.one().certificate_id
    client.post(f"/admin/revoke/{certificate_id}")
    assert client.get(f"/documents/{document_id}/download").status_code == 403
    assert client.get(f"/verify-document?document_id={document_id}").status_code == 403
    assert client.post(
        "/verify-document",
        data={"document_id": str(document_id), "signature_hex": signature_hex},
    ).status_code == 403
    revoked_dashboard = client.get("/dashboard")
    assert f'href="/verify-document?document_id={document_id}"'.encode() not in revoked_dashboard.data
    assert f'href="/documents/{document_id}/download"'.encode() not in revoked_dashboard.data
    assert b"Unavailable" not in revoked_dashboard.data
    assert f'action="/documents/{document_id}/delete"'.encode() in revoked_dashboard.data
    assert b">Delete</button>" in revoked_dashboard.data

    rejected_signing = client.post(
        "/sign-document",
        data={
            "title": "Should not sign",
            "certificate_id": str(certificate_id),
            "document_text": "More content",
        },
    )
    assert rejected_signing.status_code == 302
    with app.app_context():
        assert DocumentRecord.query.count() == 1


def test_certificates_receive_sequential_display_codes():
    from app import create_app
    from app.models import CertificateRecord, db

    app = create_app(TestConfig)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})

    client.post("/request-certificate", data={"subject": "first"})
    with app.app_context():
        first = CertificateRecord.query.one()
        first.status = "revoked"
        db.session.commit()
    client.post("/request-certificate", data={"subject": "second"})

    with app.app_context():
        certificates = CertificateRecord.query.order_by(CertificateRecord.id).all()
        assert [certificate.certificate_code for certificate in certificates] == [
            "CER-0001",
            "CER-0002",
        ]
        assert all(certificate.serial_number != certificate.certificate_code for certificate in certificates)

        first_id = certificates[0].id
        db.session.delete(certificates[0])
        certificates[1].status = "revoked"
        db.session.commit()

    client.post("/request-certificate", data={"subject": "third"})
    with app.app_context():
        third = CertificateRecord.query.filter_by(subject="third").one()
        assert third.certificate_code == "CER-0003"
        assert CertificateRecord.query.filter_by(id=first_id).count() == 0


def test_uploaded_txt_and_pdf_are_signed_and_verified_as_exact_bytes():
    from io import BytesIO
    from app import create_app
    from app.models import CertificateRecord, DocumentRecord

    app = create_app(TestConfig)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    client.post("/request-certificate", data={"subject": "admin"})
    with app.app_context():
        certificate = CertificateRecord.query.one()
        certificate_id = certificate.id
        certificate_code = certificate.certificate_code

    pdf_bytes = b"%PDF-1.4\nsample exact pdf bytes\n%%EOF\n"
    signed_pdf_response = client.post(
        "/sign-document",
        data={
            "title": "",
            "certificate_id": str(certificate_id),
            "document_file": (BytesIO(pdf_bytes), "agreement.pdf"),
        },
        content_type="multipart/form-data",
    )
    assert signed_pdf_response.status_code == 200
    assert certificate_code.encode() in signed_pdf_response.data

    with app.app_context():
        pdf_document = DocumentRecord.query.one()
        pdf_document_id = pdf_document.id
        pdf_signature = pdf_document.signature_hex
        assert pdf_document.title == "agreement"
        assert pdf_document.content_bytes == pdf_bytes
        assert pdf_document.content_type == "application/pdf"

    saved_pdf_verification = client.post(
        "/verify-document",
        data={"document_id": str(pdf_document_id), "signature_hex": pdf_signature},
    )
    assert b"Overall status: VERIFIED" in saved_pdf_verification.data

    downloaded_pdf = client.get(f"/documents/{pdf_document_id}/download")
    assert downloaded_pdf.status_code == 200
    assert downloaded_pdf.mimetype == "application/pdf"
    assert downloaded_pdf.data == pdf_bytes

    txt_bytes = "Exact UTF-8 text\n".encode("utf-8")
    client.post(
        "/sign-document",
        data={
            "certificate_id": str(certificate_id),
            "document_file": (BytesIO(txt_bytes), "notes.txt"),
        },
        content_type="multipart/form-data",
    )
    with app.app_context():
        txt_document = DocumentRecord.query.filter_by(title="notes").one()
        txt_document_id = txt_document.id
        txt_signature = txt_document.signature_hex

    verified_txt = client.post(
        "/verify-document",
        data={"document_id": str(txt_document_id), "signature_hex": txt_signature},
    )
    assert b"Overall status: VERIFIED" in verified_txt.data


def test_signature_verification_navigation_and_signature_only_form():
    from app import create_app
    from app.models import CertificateRecord, DocumentRecord

    client = create_app(TestConfig).test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    client.post("/request-certificate", data={"subject": "admin"})
    with client.application.app_context():
        certificate_id = CertificateRecord.query.one().id

    client.post(
        "/sign-document",
        data={
            "certificate_id": str(certificate_id),
            "document_text": "Navigation target",
        },
    )
    with client.application.app_context():
        document_id = DocumentRecord.query.one().id

    response = client.get("/verify-document")
    assert response.status_code == 200
    assert b'href="/verify-document"' in response.data
    assert b'aria-current="page"' in response.data
    assert f'href="/verify-document?document_id={document_id}"'.encode() in response.data
    assert b'name="signature_hex"' not in response.data

    selected_document = client.get(f"/verify-document?document_id={document_id}")
    assert selected_document.status_code == 200
    assert b'name="signature_hex"' in selected_document.data
    assert b'name="document_text"' not in selected_document.data
    assert b'name="document_file"' not in selected_document.data
    assert b'name="certificate_id"' not in selected_document.data

    dashboard = client.get("/dashboard")
    assert b'class="document-actions"' in dashboard.data
    assert b"Verify signature</a>" in dashboard.data
    assert b"Download PDF</a>" in dashboard.data


def test_signed_documents_can_be_deleted_only_by_owner_and_dashboard_limits_recent_items():
    from app import create_app
    from app.models import AuditEvent, CertificateRecord, DocumentRecord, db

    app = create_app(TestConfig)
    owner = app.test_client()
    other_user = app.test_client()
    owner.post("/login", data={"username": "admin", "password": "test-admin-password"})
    owner.post("/request-certificate", data={"subject": "admin"})
    with app.app_context():
        certificate_id = CertificateRecord.query.one().id

    for number in range(6):
        owner.post(
            "/sign-document",
            data={
                "title": f"Document {number}",
                "certificate_id": str(certificate_id),
                "document_text": f"Text {number}",
            },
        )
    with app.app_context():
        documents = DocumentRecord.query.order_by(DocumentRecord.id.asc()).all()
        first_document_id = documents[0].id
        latest_document_id = documents[-1].id

    other_user.post(
        "/register",
        data={
            "username": "reader",
            "email": "reader@example.com",
            "password": "reader-password-123",
        },
    )
    other_user.post(
        "/login",
        data={"username": "reader", "password": "reader-password-123"},
    )
    assert other_user.post(
        f"/documents/{first_document_id}/delete",
        follow_redirects=False,
    ).status_code == 404

    dashboard = owner.get("/dashboard")
    assert b"Show 1 older signed documents" in dashboard.data
    assert b"Document 5" in dashboard.data
    assert b'name="csrf_token"' in dashboard.data
    assert b"Permanently delete this signed document?" in dashboard.data

    deleted = owner.post(f"/documents/{first_document_id}/delete")
    assert deleted.status_code == 302
    assert owner.get(f"/verify-document?document_id={first_document_id}").status_code == 404
    assert owner.get(f"/documents/{first_document_id}/download").status_code == 404
    with app.app_context():
        assert db.session.get(DocumentRecord, first_document_id) is None
        assert db.session.get(DocumentRecord, latest_document_id) is not None
        assert AuditEvent.query.filter_by(
            action="delete_document",
            object_name="Document 0",
            outcome="success",
        ).count() == 1


def test_audit_trail_is_admin_only():
    from app import create_app

    app = create_app(TestConfig)
    client = app.test_client()

    client.post(
        "/register",
        data={"username": "alice", "email": "alice@example.com", "password": "alice-password-123"},
    )
    client.post("/login", data={"username": "alice", "password": "alice-password-123"})

    response = client.get("/audit")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")

    dashboard = client.get("/dashboard")
    assert b'href="/audit"' not in dashboard.data

    client.post("/logout")
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    admin_panel = client.get("/admin")
    assert admin_panel.status_code == 200
    assert b"locks existing encrypted messages signed with it" in admin_panel.data
    assert b"administrator's access is unaffected" in admin_panel.data
    admin_audit = client.get("/audit")
    assert admin_audit.status_code == 200
    assert b"Audit trail" in admin_audit.data


def test_admin_can_suspend_restore_and_delete_user_account_data():
    from app import create_app
    from app.models import (
        AuditEvent,
        CertificateRecord,
        DocumentRecord,
        EncryptedDocument,
        User,
        db,
    )

    app = create_app(TestConfig)
    alice_client = app.test_client()
    registration = alice_client.post(
        "/register",
        data={
            "username": "alice",
            "email": "alice@example.com",
            "password": "alice-password-123",
        },
    )
    assert registration.status_code == 302
    assert registration.headers["Location"].endswith("/login")
    assert alice_client.get("/dashboard").headers["Location"].startswith("/login")

    login_response = alice_client.post(
        "/login",
        data={"username": "alice", "password": "alice-password-123"},
    )
    assert login_response.status_code == 302
    with alice_client.session_transaction() as session:
        assert session.permanent is False

    alice_client.post("/request-certificate", data={"subject": "alice"})
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        admin = User.query.filter_by(username="admin").one()
        certificate = CertificateRecord.query.filter_by(user_id=alice.id).one()
        alice_id = alice.id
        admin_id = admin.id
        certificate_id = certificate.id
        serial_number = int(certificate.serial_number)
        db.session.add(
            DocumentRecord(
                title="Alice document",
                document_text="content",
                signature_hex="00",
                hash_hex="00",
                user_id=alice.id,
                certificate_id=certificate.id,
            )
        )
        db.session.add(
            EncryptedDocument(
                title="Alice message",
                sender_id=admin.id,
                recipient_id=alice.id,
                payload="{}",
                payload_metadata="{}",
            )
        )
        db.session.commit()

    admin_client = app.test_client()
    admin_client.post(
        "/login",
        data={"username": "admin", "password": "test-admin-password"},
    )
    admin_panel = admin_client.get("/admin")
    assert b"alice@example.com" in admin_panel.data
    suspended = admin_client.post(f"/admin/users/{alice_id}/suspend")
    assert suspended.status_code == 302
    assert alice_client.get("/dashboard").headers["Location"].startswith("/login")

    admin_client.post(f"/admin/users/{alice_id}/activate")
    assert alice_client.get("/dashboard").headers["Location"].startswith("/login")
    alice_client.post(
        "/login",
        data={"username": "alice", "password": "alice-password-123"},
    )
    assert alice_client.get("/dashboard").status_code == 200

    deleted = admin_client.post(f"/admin/users/{alice_id}/delete")
    assert deleted.status_code == 302
    assert alice_client.get("/dashboard").headers["Location"].startswith("/login")
    deleted_login = alice_client.post(
        "/login",
        data={"username": "alice", "password": "alice-password-123"},
    )
    assert deleted_login.status_code == 302
    login_page = alice_client.get("/login")
    assert b"No account was found. Please register to create a new account." in login_page.data
    assert b"Register here" in login_page.data

    with app.app_context():
        assert db.session.get(User, alice_id) is None
        assert CertificateRecord.query.filter_by(id=certificate_id).count() == 0
        assert DocumentRecord.query.filter_by(user_id=alice_id).count() == 0
        assert EncryptedDocument.query.filter(
            (EncryptedDocument.sender_id == alice_id)
            | (EncryptedDocument.recipient_id == alice_id)
        ).count() == 0
        assert serial_number in app.config["PKI_STATE"]["revoked_serials"]
        assert AuditEvent.query.filter_by(action="delete_user", object_name="alice").count() == 1
        assert db.session.get(User, admin_id) is not None


def test_signed_encrypted_exchange_round_trips_both_ways_and_gates_pdf_download():
    from app import create_app
    from app.models import CertificateRecord, EncryptedDocument, User, db
    from app.pki import (
        decrypt_document_for_recipient,
        deserialize_x25519_private,
        encrypt_document_for_recipient,
    )
    import json

    app = create_app(TestConfig)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    client.post("/request-certificate", data={"subject": "admin"})
    client.post(
        "/register",
        data={
            "username": "alice",
            "email": "alice@example.com",
            "password": "alice-password-123",
        },
    )

    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        alice = User.query.filter_by(username="alice").one()
        admin_id = admin.id
        alice_id = alice.id
        admin_certificate_id = CertificateRecord.query.filter_by(
            user_id=admin_id
        ).one().id

    client.post("/logout")
    client.post("/login", data={"username": "alice", "password": "alice-password-123"})
    client.post("/request-certificate", data={"subject": "alice"})
    with app.app_context():
        alice_certificate_id = CertificateRecord.query.filter_by(
            user_id=alice_id
        ).one().id

    client.post("/logout")
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    client.post(
        "/encrypt-document/legacy",
        data={
            "recipient_id": str(alice_id),
            "certificate_id": str(admin_certificate_id),
            "title": "Private note",
            "document_text": "Confidential message",
        },
    )
    with app.app_context():
        encrypted = EncryptedDocument.query.filter_by(sender_id=admin_id).one()
        encrypted_id = encrypted.id

    sent_dashboard = client.get("/dashboard")
    assert b"Sent Secure Documents" in sent_dashboard.data
    assert b"Private note" in sent_dashboard.data

    client.post("/logout")
    client.post("/login", data={"username": "alice", "password": "alice-password-123"})
    decrypted_page = client.post(f"/decrypt-document/{encrypted_id}")
    assert b"Confidential message" in decrypted_page.data
    assert b"Overall status: VERIFIED" in decrypted_page.data
    assert b"Signature verified and the signer certificate is trusted." in decrypted_page.data
    assert b"Signature matches content: Yes" in decrypted_page.data
    assert b"Certificate trusted and active: Yes" in decrypted_page.data

    pdf = client.get(f"/decrypt-document/{encrypted_id}/download")
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.data.startswith(b"%PDF-")
    assert "filename=Private_note.pdf" in pdf.headers["Content-Disposition"]

    with app.app_context():
        encrypted = db.session.get(EncryptedDocument, encrypted_id)
        alice = db.session.get(User, alice_id)
        from app import decrypt_private_key

        recipient_private_key = deserialize_x25519_private(
            decrypt_private_key(app, alice.key_agreement_private)
        )
        envelope = json.loads(
            decrypt_document_for_recipient(
                json.loads(encrypted.payload),
                recipient_private_key,
            )
        )
        bad_signature = bytes.fromhex(envelope["signature_hex"])
        envelope["signature_hex"] = (bytes([bad_signature[0] ^ 1]) + bad_signature[1:]).hex()
        tampered_payload = encrypt_document_for_recipient(
            json.dumps(envelope),
            recipient_private_key.public_key(),
        )
        encrypted.payload = json.dumps(tampered_payload)
        db.session.commit()

    tampered_page = client.post(f"/decrypt-document/{encrypted_id}")
    assert b"REJECTED \xe2\x80\x94 CONTENT WITHHELD" in tampered_page.data
    assert b"Signature verification failed" in tampered_page.data
    assert b"Signature matches content: No" in tampered_page.data
    assert b"Confidential message" not in tampered_page.data
    assert b"plaintext is withheld" in tampered_page.data
    assert b"Download verified PDF" not in tampered_page.data
    assert client.get(f"/decrypt-document/{encrypted_id}/download").status_code == 403

    client.post(
        "/encrypt-document/legacy",
        data={
            "recipient_id": str(admin_id),
            "certificate_id": str(alice_certificate_id),
            "title": "Reply",
            "document_text": "Reply from Alice",
        },
    )
    with app.app_context():
        reply_id = EncryptedDocument.query.filter_by(sender_id=alice_id).one().id

    client.post("/logout")
    client.post("/login", data={"username": "admin", "password": "test-admin-password"})
    reply_page = client.post(f"/decrypt-document/{reply_id}")
    assert b"Reply from Alice" in reply_page.data
    assert b"Signature verified and the signer certificate is trusted." in reply_page.data

    unauthorized_download = client.get(
        f"/decrypt-document/{encrypted_id}/download"
    )
    assert unauthorized_download.status_code == 404

    client.post(f"/admin/revoke/{admin_certificate_id}")
    with app.app_context():
        locked_message = db.session.get(EncryptedDocument, encrypted_id)
        assert json.loads(locked_message.payload_metadata)["status"] == "access_revoked"

    client.post("/logout")
    client.post("/login", data={"username": "alice", "password": "alice-password-123"})
    locked_dashboard = client.get("/dashboard")
    assert b"Locked" in locked_dashboard.data
    locked_page = client.get(f"/decrypt-document/{encrypted_id}")
    assert locked_page.status_code == 302
    assert client.get(f"/decrypt-document/{encrypted_id}/download").status_code == 410
