from __future__ import annotations

import json
import base64
import secrets
import os
from datetime import datetime
from html import escape
from io import BytesIO
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, abort, current_app, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import Index, inspect, select, text
from werkzeug.utils import secure_filename

from app.config import Config
from app.models import (
    AuditEvent,
    CertificateCodeSequence,
    CertificateRecord,
    DocumentRecord,
    EncryptionSystemState,
    EncryptedDocument,
    User,
    db,
)
from app.pki import (
    create_crl,
    create_issuing_ca,
    create_root_ca,
    decrypt_document_for_recipient,
    deserialize_x25519_private,
    deserialize_x25519_public,
    encrypt_document_for_recipient,
    generate_x25519_key_pair,
    issue_user_certificate,
    serialize_x25519_private,
    serialize_x25519_public,
    sha256_hex,
    sign_document_bytes,
    validate_certificate_chain,
    verify_document_bytes,
)

ph = PasswordHasher()
login_manager = LoginManager()
csrf = CSRFProtect()
ENCRYPTED_KEY_PREFIX = "fernet:v1:"
MAX_DOCUMENT_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_E2EE_MESSAGE_BYTES = 6 * 1024 * 1024


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if user is None or not user.active:
        return None
    if session.get("app_session_id") != current_app.config["APP_SESSION_ID"]:
        return None
    if session.get("auth_version") != user.session_version:
        return None
    return user


def ensure_demo_pki(app):
    if app.config.get("PKI_STATE") is not None:
        return

    state_path = app.config.get(
        "PKI_STATE_PATH",
        Path(app.instance_path) / "pki-state.enc",
    )
    if state_path is not None:
        state_path = Path(state_path)
        if state_path.exists():
            try:
                encrypted_state = state_path.read_bytes()
                state_data = json.loads(
                    Fernet(app.config["PRIVATE_KEY_ENCRYPTION_KEY"])
                    .decrypt(encrypted_state)
                    .decode("utf-8")
                )
                root_key = serialization.load_pem_private_key(
                    state_data["root_key"].encode("utf-8"),
                    password=None,
                )
                root_cert = x509.load_pem_x509_certificate(
                    state_data["root_cert"].encode("utf-8")
                )
                issuing_key = serialization.load_pem_private_key(
                    state_data["issuing_key"].encode("utf-8"),
                    password=None,
                )
                issuing_cert = x509.load_pem_x509_certificate(
                    state_data["issuing_cert"].encode("utf-8")
                )
                revoked_serials = state_data["revoked_serials"]
            except (InvalidToken, KeyError, TypeError, ValueError) as error:
                raise RuntimeError(
                    "Saved CA state could not be decrypted. Check the private-key encryption key."
                ) from error
            app.config["PKI_STATE"] = {
                "root_key": root_key,
                "root_cert": root_cert,
                "issuing_key": issuing_key,
                "issuing_cert": issuing_cert,
                "revoked_serials": revoked_serials,
                "crl": create_crl(issuing_key, issuing_cert, revoked_serials)
                if revoked_serials
                else None,
            }
            return

    root_key, root_cert = create_root_ca()
    issuing_key, issuing_cert = create_issuing_ca(root_key, root_cert)
    app.config["PKI_STATE"] = {
        "root_key": root_key,
        "root_cert": root_cert,
        "issuing_key": issuing_key,
        "issuing_cert": issuing_cert,
        "revoked_serials": [],
        "crl": None,
    }
    if state_path is not None:
        save_pki_state(app, state_path)


def save_pki_state(app, state_path=None):
    if state_path is None:
        if "PKI_STATE_PATH" in app.config:
            state_path = app.config["PKI_STATE_PATH"]
        else:
            state_path = Path(app.instance_path) / "pki-state.enc"
    if state_path is None:
        return
    state_path = Path(state_path)
    state = app.config["PKI_STATE"]
    state_data = {
        "root_key": state["root_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        "root_cert": state["root_cert"].public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8"),
        "issuing_key": state["issuing_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        "issuing_cert": state["issuing_cert"].public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8"),
        "revoked_serials": state["revoked_serials"],
    }
    encrypted_state = Fernet(app.config["PRIVATE_KEY_ENCRYPTION_KEY"]).encrypt(
        json.dumps(state_data).encode("utf-8")
    )
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = state_path.with_suffix(f"{state_path.suffix}.tmp")
    temporary_path.write_bytes(encrypted_state)
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, state_path)


def record_audit(actor: str, action: str, object_name: str, outcome: str = "success"):
    event = AuditEvent(actor=actor, action=action, object_name=object_name, outcome=outcome)
    db.session.add(event)
    db.session.commit()


def encrypt_private_key(app, private_key: str) -> str:
    cipher = Fernet(app.config["PRIVATE_KEY_ENCRYPTION_KEY"])
    encrypted = cipher.encrypt(private_key.encode("utf-8")).decode("ascii")
    return f"{ENCRYPTED_KEY_PREFIX}{encrypted}"


def decrypt_private_key(app, stored_key: str) -> str:
    if not stored_key.startswith(ENCRYPTED_KEY_PREFIX):
        raise ValueError("Private key is not encrypted; restart the app to migrate stored keys.")
    cipher = Fernet(app.config["PRIVATE_KEY_ENCRYPTION_KEY"])
    token = stored_key[len(ENCRYPTED_KEY_PREFIX):].encode("ascii")
    return cipher.decrypt(token).decode("utf-8")


def protect_existing_private_keys(app):
    for user in User.query.filter(User.key_agreement_private.is_not(None)).all():
        if not user.key_agreement_private.startswith(ENCRYPTED_KEY_PREFIX):
            user.key_agreement_private = encrypt_private_key(app, user.key_agreement_private)

    for certificate in CertificateRecord.query.all():
        if (
            certificate.private_key_pem
            and not certificate.private_key_pem.startswith(ENCRYPTED_KEY_PREFIX)
        ):
            certificate.private_key_pem = encrypt_private_key(app, certificate.private_key_pem)

    db.session.commit()


def document_pdf_response(title: str, content: str):
    pdf = BytesIO()
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(pdf, pagesize=letter, title=title)
    content_html = escape(content).replace("\n", "<br/>")
    document.build(
        [
            Paragraph(escape(title), styles["Title"]),
            Spacer(1, 12),
            Paragraph(content_html, styles["BodyText"]),
        ]
    )
    pdf.seek(0)
    filename = secure_filename(title) or "document"
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{filename}.pdf",
    )


def verify_signed_envelope(envelope: dict, sender_id: int, pki_state: dict) -> dict:
    if not isinstance(envelope, dict) or envelope.get("version") != 1:
        return {
            "valid": False,
            "signature_valid": False,
            "certificate_trusted": False,
            "signer": "Unknown signer",
            "message": "The decrypted message is not a supported signed document.",
            "content": "",
        }

    content = envelope.get("content", "")
    if not isinstance(content, str):
        content = ""

    result = {
        "valid": False,
        "signature_valid": False,
        "certificate_trusted": False,
        "signer": "Unknown signer",
        "message": "The decrypted message is not a valid signed document.",
    }

    try:
        certificate_pem = envelope["signer_certificate_pem"].encode("utf-8")
        certificate_serial = str(envelope["signer_certificate_serial"])
        signature = bytes.fromhex(envelope["signature_hex"])
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except (KeyError, TypeError, ValueError):
        return {**result, "content": content}

    result["signer"] = certificate.subject.rfc4514_string()
    result["signature_valid"] = verify_document_bytes(
        content.encode("utf-8"),
        signature,
        certificate.public_key(),
    )

    certificate_record = CertificateRecord.query.filter_by(
        user_id=sender_id,
        serial_number=certificate_serial,
    ).first()
    if certificate_record is not None:
        try:
            stored_certificate = x509.load_pem_x509_certificate(
                certificate_record.cert_pem.encode("utf-8")
            )
            certificate_matches_record = (
                stored_certificate.public_bytes(serialization.Encoding.DER)
                == certificate.public_bytes(serialization.Encoding.DER)
            )
        except ValueError:
            certificate_matches_record = False
        result["certificate_trusted"] = (
            certificate_matches_record
            and certificate_record.status == "active"
            and validate_certificate_chain(
                certificate,
                pki_state["root_cert"],
                pki_state["issuing_cert"],
                pki_state["crl"],
            )
        )

    result["valid"] = result["signature_valid"] and result["certificate_trusted"]
    if not result["signature_valid"]:
        result["message"] = "Signature verification failed: the signature does not match the content."
    elif not result["certificate_trusted"]:
        result["message"] = "Signature matches, but the signer certificate is untrusted or revoked."
    else:
        result["message"] = "Signature verified and the signer certificate is trusted."
    result["content"] = content
    return result


def one_time_message_signature_payload(envelope: dict) -> bytes:
    fields = (
        "version",
        "title",
        "sender_id",
        "recipient_id",
        "content_type",
        "filename",
        "content_hash",
        "signer_certificate_serial",
    )
    return json.dumps(
        {field: envelope[field] for field in fields},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_one_time_message(envelope: dict, encrypted: EncryptedDocument, pki_state: dict):
    failed = {
        "valid": False,
        "signature_valid": False,
        "certificate_trusted": False,
        "signer": "Unknown signer",
        "message": "The encrypted message could not be verified.",
        "content": "",
        "content_type": "text/plain",
    }
    try:
        if (
            not isinstance(envelope, dict)
            or envelope.get("version") != 3
            or envelope.get("sender_id") != encrypted.sender_id
            or envelope.get("recipient_id") != encrypted.recipient_id
            or envelope.get("title") != encrypted.title
            or envelope.get("content_type") not in {"text/plain", "application/pdf"}
        ):
            return failed
        content_bytes = base64.b64decode(envelope["content_base64"], validate=True)
        content_hash = sha256_hex(content_bytes)
        if content_hash != envelope.get("content_hash"):
            return {**failed, "message": "The document content hash does not match."}
        if envelope["content_type"] == "application/pdf" and not content_bytes.startswith(b"%PDF-"):
            return {**failed, "message": "The decrypted document is not a valid PDF."}
        signature = bytes.fromhex(envelope["signature_hex"])
        certificate_serial = str(envelope["signer_certificate_serial"])
        certificate = x509.load_pem_x509_certificate(
            envelope["signer_certificate_pem"].encode("utf-8")
        )
    except (KeyError, TypeError, ValueError):
        return failed

    record = CertificateRecord.query.filter_by(
        user_id=encrypted.sender_id,
        serial_number=certificate_serial,
    ).first()
    signature_valid = verify_document_bytes(
        one_time_message_signature_payload(envelope),
        signature,
        certificate.public_key(),
    )
    certificate_matches = False
    if record is not None:
        try:
            stored_certificate = x509.load_pem_x509_certificate(
                record.cert_pem.encode("utf-8")
            )
            certificate_matches = (
                stored_certificate.public_bytes(serialization.Encoding.DER)
                == certificate.public_bytes(serialization.Encoding.DER)
            )
        except ValueError:
            certificate_matches = False
    certificate_trusted = bool(
        certificate_matches
        and record is not None
        and record.status == "active"
        and validate_certificate_chain(
            certificate,
            pki_state["root_cert"],
            pki_state["issuing_cert"],
            pki_state["crl"],
        )
    )
    valid = signature_valid and certificate_trusted
    if not signature_valid:
        message = "Signature verification failed: the signature does not match."
    elif not certificate_trusted:
        message = "Signature matches, but the sender certificate is untrusted or revoked."
    else:
        message = "Signature verified and the sender certificate is trusted."
    try:
        content = (
            content_bytes.decode("utf-8")
            if valid and envelope["content_type"] == "text/plain"
            else ""
        )
    except UnicodeDecodeError:
        return {**failed, "message": "The decrypted text is not valid UTF-8."}
    return {
        "valid": valid,
        "signature_valid": signature_valid,
        "certificate_trusted": certificate_trusted,
        "signer": certificate.subject.rfc4514_string(),
        "message": message,
        "content": content,
        "content_type": envelope["content_type"],
    }


def decrypt_one_time_message(encrypted: EncryptedDocument, key_text: str, pki_state: dict):
    try:
        if len(key_text) != 43 or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
            for character in key_text
        ):
            raise ValueError("The one-time decryption key is invalid.")
        key = base64.b64decode(
            key_text + "=",
            altchars=b"-_",
            validate=True,
        )
        if len(key) != 32:
            raise ValueError("The one-time decryption key must be 32 bytes.")
        payload = json.loads(encrypted.payload)
        if payload.get("version") != 3:
            raise ValueError("This message does not use a one-time decryption key.")
        iv = base64.b64decode(payload["iv"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
        if len(iv) != 12:
            raise ValueError("The encrypted message is invalid.")
        plaintext = AESGCM(key).decrypt(iv, ciphertext, None)
        envelope = json.loads(plaintext)
    except (InvalidTag, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("The decryption key is incorrect or the message is damaged.") from error
    verification = verify_one_time_message(envelope, encrypted, pki_state)
    return envelope, verification


def get_signed_input():
    uploaded_file = request.files.get("document_file")
    has_upload = uploaded_file is not None and bool(uploaded_file.filename)
    text_content = request.form.get("document_text", "")
    has_text = bool(text_content)

    if has_upload == has_text:
        raise ValueError("Provide either pasted text or one file, not both.")

    if has_text:
        content_bytes = text_content.encode("utf-8")
        return content_bytes, text_content, None, "text/plain"

    filename = secure_filename(uploaded_file.filename)
    suffix = Path(filename).suffix.lower()
    if suffix not in {".txt", ".pdf"}:
        raise ValueError("Upload a .txt or .pdf file.")

    content_bytes = uploaded_file.read(MAX_DOCUMENT_UPLOAD_BYTES + 1)
    if not content_bytes:
        raise ValueError("The uploaded file is empty.")
    if len(content_bytes) > MAX_DOCUMENT_UPLOAD_BYTES:
        raise ValueError("The uploaded file exceeds the 10 MB limit.")

    if suffix == ".txt":
        try:
            text_content = content_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Text files must use UTF-8 encoding.") from error
        content_type = "text/plain"
    else:
        if not content_bytes.startswith(b"%PDF-"):
            raise ValueError("The uploaded file is not a valid PDF.")
        text_content = ""
        content_type = "application/pdf"

    return content_bytes, text_content, filename, content_type


def allocate_certificate_code():
    sequence = db.session.execute(
        select(CertificateCodeSequence)
        .where(CertificateCodeSequence.id == 1)
        .with_for_update()
    ).scalar_one()
    certificate_code = f"CER-{sequence.next_value:04d}"
    sequence.next_value += 1
    return certificate_code


def verify_content_signature(content_bytes, signature_hex, certificate_record, pki_state):
    certificate = x509.load_pem_x509_certificate(
        certificate_record.cert_pem.strip().encode("utf-8")
    )
    signature = bytes.fromhex(signature_hex)
    signature_valid = bool(signature) and verify_document_bytes(
        content_bytes,
        signature,
        certificate.public_key(),
    )
    certificate_trusted = (
        certificate_record.status == "active"
        and validate_certificate_chain(
            certificate,
            pki_state["root_cert"],
            pki_state["issuing_cert"],
            pki_state["crl"],
        )
    )

    if not signature_valid:
        message = "Rejected: The signature does not match the exact content or file bytes."
    elif not certificate_trusted and certificate_record.status == "revoked":
        message = "Signature matches, but its certificate has been revoked."
    elif not certificate_trusted:
        message = "Signature matches, but its certificate trust chain is invalid."
    else:
        message = "Verified successfully: signature matches and the signer certificate is trusted."

    return {
        "valid": signature_valid and certificate_trusted,
        "signature_valid": signature_valid,
        "chain_valid": certificate_trusted,
        "message": message,
    }


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="templates")
    app.config.from_object(config_class)
    app.config.setdefault("MAX_CONTENT_LENGTH", MAX_DOCUMENT_UPLOAD_BYTES + 1024 * 1024)
    app.config["APP_SESSION_ID"] = secrets.token_urlsafe(32)
    secret_key = app.config.get("SECRET_KEY")
    if (
        not secret_key
        or len(secret_key) < 32
        or secret_key == "generate-a-random-secret-before-running"
    ):
        raise RuntimeError("Set a random SECRET_KEY of at least 32 characters before starting.")
    encryption_key = app.config.get("PRIVATE_KEY_ENCRYPTION_KEY")
    if not encryption_key:
        raise RuntimeError(
            "Set PRIVATE_KEY_ENCRYPTION_KEY before starting; generate one with Fernet.generate_key()."
        )
    try:
        Fernet(encryption_key)
        encryption_key_bytes = (
            encryption_key.encode("ascii")
            if isinstance(encryption_key, str)
            else encryption_key
        )
    except (TypeError, ValueError) as error:
        raise RuntimeError("PRIVATE_KEY_ENCRYPTION_KEY must be a valid Fernet key.") from error
    app.config["PRIVATE_KEY_ENCRYPTION_KEY"] = encryption_key_bytes
    if encryption_key_bytes.decode("ascii") == secret_key:
        raise RuntimeError("Use a separate key for PRIVATE_KEY_ENCRYPTION_KEY and SECRET_KEY.")

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    csrf.init_app(app)
    login_manager.login_view = "login"

    with app.app_context():
        db.create_all()
        user_columns = {
            column["name"] for column in inspect(db.engine).get_columns(User.__tablename__)
        }
        if "session_version" not in user_columns:
            db.session.execute(
                text("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
            )
            db.session.commit()
        if "encrypted_client_key_bundle" not in user_columns:
            db.session.execute(
                text("ALTER TABLE users ADD COLUMN encrypted_client_key_bundle TEXT")
            )
            db.session.commit()
        certificate_columns = {
            column["name"]
            for column in inspect(db.engine).get_columns(CertificateRecord.__tablename__)
        }
        certificate_code_migrated = "certificate_code" not in certificate_columns
        if certificate_code_migrated:
            db.session.execute(
                text("ALTER TABLE certificate_records ADD COLUMN certificate_code VARCHAR(20)")
            )
            db.session.commit()
        document_columns = {
            column["name"]
            for column in inspect(db.engine).get_columns(DocumentRecord.__tablename__)
        }
        document_additions = {
            "content_bytes": "BLOB",
            "original_filename": "VARCHAR(255)",
            "content_type": "VARCHAR(100)",
        }
        for column_name, column_type in document_additions.items():
            if column_name not in document_columns:
                db.session.execute(
                    text(
                        f"ALTER TABLE document_records ADD COLUMN {column_name} {column_type}"
                    )
                )
        db.session.commit()

        next_code = 1
        existing_certificates = CertificateRecord.query.order_by(CertificateRecord.id).all()
        for certificate in existing_certificates:
            if certificate.certificate_code is None:
                certificate.certificate_code = f"CER-{next_code:04d}"
            try:
                code_value = int(certificate.certificate_code.removeprefix("CER-"))
            except ValueError:
                code_value = 0
            next_code = max(next_code, code_value + 1)

        sequence = db.session.get(CertificateCodeSequence, 1)
        if sequence is None:
            db.session.add(CertificateCodeSequence(id=1, next_value=next_code))
        else:
            sequence.next_value = max(sequence.next_value, next_code)
        db.session.commit()
        if certificate_code_migrated:
            Index(
                "uq_certificate_records_certificate_code",
                CertificateRecord.certificate_code,
                unique=True,
            ).create(bind=db.engine)
        ensure_demo_pki(app)
        protect_existing_private_keys(app)

        admin_username = app.config.get("BOOTSTRAP_ADMIN_USERNAME")
        admin_email = app.config.get("BOOTSTRAP_ADMIN_EMAIL")
        admin_password = app.config.get("BOOTSTRAP_ADMIN_PASSWORD")
        if any((admin_username, admin_email, admin_password)):
            if not all((admin_username, admin_email, admin_password)):
                raise RuntimeError(
                    "Set BOOTSTRAP_ADMIN_USERNAME, BOOTSTRAP_ADMIN_EMAIL, and "
                    "BOOTSTRAP_ADMIN_PASSWORD together."
                )
            if len(admin_password) < 12:
                raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters.")
            if admin_password.startswith("replace-with-"):
                raise RuntimeError("Replace the example BOOTSTRAP_ADMIN_PASSWORD before starting.")

            admin = User.query.filter_by(username=admin_username).first()
            if admin is not None and admin.role != "admin":
                raise RuntimeError("The bootstrap admin username is already used by a non-admin.")
            if admin is not None and User.query.filter(
                User.email == admin_email,
                User.id != admin.id,
            ).first():
                raise RuntimeError("The bootstrap admin email is already in use.")
            if admin is None:
                if User.query.filter_by(email=admin_email).first():
                    raise RuntimeError("The bootstrap admin email is already in use.")
                encryption_state = db.session.get(EncryptionSystemState, 1)
                if not (encryption_state and encryption_state.clean_reset_completed):
                    private_key, public_key = generate_x25519_key_pair()
                    encrypted_private_key = encrypt_private_key(
                        app, serialize_x25519_private(private_key)
                    )
                    public_key_value = serialize_x25519_public(public_key)
                else:
                    encrypted_private_key = None
                    public_key_value = None
                admin = User(
                    username=admin_username,
                    email=admin_email,
                    password_hash=ph.hash(admin_password),
                    role="admin",
                    active=True,
                    key_agreement_private=encrypted_private_key,
                    key_agreement_public=public_key_value,
                )
                db.session.add(admin)
                db.session.commit()
                record_audit("system", "bootstrap", "admin-account", "success")

        legacy_admin = User.query.filter_by(username="admin", role="admin").first()
        if legacy_admin is not None:
            try:
                has_default_password = ph.verify(legacy_admin.password_hash, "admin123")
            except VerificationError:
                has_default_password = False
            if has_default_password:
                if admin_username == "admin" and admin_password:
                    legacy_admin.password_hash = ph.hash(admin_password)
                    legacy_admin.active = True
                else:
                    legacy_admin.password_hash = ph.hash(secrets.token_urlsafe(32))
                    legacy_admin.active = False
                db.session.commit()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            if not username or not email or not password:
                flash("Please complete all fields.")
                return redirect(url_for("register"))
            if len(password) < 12:
                flash("Use a password with at least 12 characters.")
                return redirect(url_for("register"))

            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("That username or email is already in use.")
                return redirect(url_for("register"))

            encryption_state = db.session.get(EncryptionSystemState, 1)
            if not (encryption_state and encryption_state.clean_reset_completed):
                private_key, public_key = generate_x25519_key_pair()
                encrypted_private_key = encrypt_private_key(
                    app, serialize_x25519_private(private_key)
                )
                public_key_value = serialize_x25519_public(public_key)
            else:
                encrypted_private_key = None
                public_key_value = None
            user = User(
                username=username,
                email=email,
                password_hash=ph.hash(password),
                role="user",
                active=True,
                key_agreement_private=encrypted_private_key,
                key_agreement_public=public_key_value,
            )
            db.session.add(user)
            db.session.commit()
            record_audit(username, "register", "account", "success")
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()
            if user is None:
                flash("No account was found. Please register to create a new account.")
                return redirect(url_for("login"))
            if not user.active:
                flash("Invalid username or password.")
                return redirect(url_for("login"))
            try:
                if not ph.verify(user.password_hash, password):
                    flash("Invalid username or password.")
                    return redirect(url_for("login"))
            except Exception:
                flash("Invalid username or password.")
                return redirect(url_for("login"))

            login_user(user)
            session.permanent = False
            session["app_session_id"] = app.config["APP_SESSION_ID"]
            session["auth_version"] = user.session_version
            record_audit(user.username, "login", "session", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        record_audit(current_user.username, "logout", "session", "success")
        logout_user()
        session.pop("auth_version", None)
        return redirect(url_for("index"))

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            try:
                current_password_valid = ph.verify(
                    current_user.password_hash,
                    current_password,
                )
            except VerificationError:
                current_password_valid = False

            if not current_password_valid:
                flash("The current password is incorrect.", "danger")
            elif len(new_password) < 12:
                flash("The new password must be at least 12 characters.", "danger")
            elif new_password != confirm_password:
                flash("The new passwords do not match.", "danger")
            elif new_password == current_password:
                flash("Choose a new password different from your current password.", "danger")
            else:
                username = current_user.username
                current_user.password_hash = ph.hash(new_password)
                current_user.session_version += 1
                db.session.commit()
                record_audit(username, "change_password", "account", "success")
                logout_user()
                session.clear()
                flash("Password updated. Please log in with your new password.")
                return redirect(url_for("login"))

        return render_template("change_password.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        certs = CertificateRecord.query.filter_by(user_id=current_user.id).order_by(
            CertificateRecord.created_at.desc()
        ).all()
        docs = DocumentRecord.query.filter_by(user_id=current_user.id).order_by(
            DocumentRecord.created_at.desc()
        ).all()
        enc_docs = EncryptedDocument.query.filter_by(
            recipient_id=current_user.id
        ).order_by(EncryptedDocument.created_at.desc()).all()
        sent_documents = EncryptedDocument.query.filter_by(
            sender_id=current_user.id
        ).order_by(EncryptedDocument.created_at.desc()).all()
        unavailable_message_statuses = {}
        for message in enc_docs:
            message_status = json.loads(message.payload_metadata).get("status")
            if message_status in {
                "unreadable_after_key_rotation",
                "access_revoked",
                "e2ee_reset",
            }:
                unavailable_message_statuses[message.id] = message_status
        return render_template(
            "dashboard.html",
            certificates=certs,
            documents=docs,
            encrypted_documents=enc_docs,
            sent_documents=sent_documents,
            unavailable_message_ids=set(unavailable_message_statuses),
            unavailable_message_statuses=unavailable_message_statuses,
            recent_limit=5,
        )

    @app.route("/request-certificate", methods=["GET", "POST"])
    @login_required
    def request_certificate():
        if request.method == "POST":
            if not request.is_json:
                subject = request.form.get("subject", current_user.username).strip()
                if not subject:
                    flash("Enter a subject name.", "danger")
                    return redirect(url_for("request_certificate"))
                existing_certificate = CertificateRecord.query.filter(
                    CertificateRecord.user_id == current_user.id,
                    CertificateRecord.status == "active",
                    CertificateRecord.private_key_pem != "",
                ).first()
                if existing_certificate is not None:
                    flash(f"Active certificate {existing_certificate.certificate_code} is already available.")
                    return redirect(url_for("dashboard"))
                state = app.config["PKI_STATE"]
                user_key, cert = issue_user_certificate(
                    state["issuing_key"],
                    state["issuing_cert"],
                    f"CN={subject}",
                )
                private_key_pem = user_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8")
                record = CertificateRecord(
                    certificate_code=allocate_certificate_code(),
                    subject=subject,
                    email=current_user.email,
                    serial_number=str(cert.serial_number),
                    issuer=state["issuing_cert"].subject.rfc4514_string(),
                    cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                    private_key_pem=encrypt_private_key(app, private_key_pem),
                    status="active",
                    user_id=current_user.id,
                )
                db.session.add(record)
                db.session.commit()
                record_audit(current_user.username, "issue_certificate", subject, "success")
                flash(f"Certificate {record.certificate_code} issued successfully.")
                return redirect(url_for("dashboard"))

            if CertificateRecord.query.filter_by(
                user_id=current_user.id,
                status="active",
            ).first() is not None:
                return jsonify(error="This account already has an active signing certificate."), 409

            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                return jsonify(error="Browser-generated key enrollment is required."), 400
            try:
                signing_public_der = base64.b64decode(
                    body.get("signing_public_key", ""), validate=True
                )
                encryption_public_der = base64.b64decode(
                    body.get("encryption_public_key", ""), validate=True
                )
                signing_public_key = serialization.load_der_public_key(signing_public_der)
                encryption_public_key = serialization.load_der_public_key(encryption_public_der)
            except (TypeError, ValueError) as error:
                return jsonify(error="The browser public keys are invalid."), 400
            if (
                not isinstance(signing_public_key, ec.EllipticCurvePublicKey)
                or not isinstance(encryption_public_key, ec.EllipticCurvePublicKey)
                or not isinstance(signing_public_key.curve, ec.SECP256R1)
                or not isinstance(encryption_public_key.curve, ec.SECP256R1)
            ):
                return jsonify(error="Use P-256 keys supported by browser cryptography."), 400
            key_bundle = body.get("encrypted_key_bundle")
            if not isinstance(key_bundle, dict) or set(key_bundle) != {
                "version",
                "kdf",
                "iterations",
                "salt",
                "iv",
                "ciphertext",
            } or key_bundle.get("version") != 1 or key_bundle.get(
                "kdf"
            ) != "PBKDF2-SHA256" or key_bundle.get("iterations") != 310000:
                return jsonify(error="The encrypted private-key bundle is invalid."), 400
            try:
                salt = base64.b64decode(key_bundle["salt"], validate=True)
                iv = base64.b64decode(key_bundle["iv"], validate=True)
                ciphertext = base64.b64decode(key_bundle["ciphertext"], validate=True)
            except (TypeError, ValueError):
                return jsonify(error="The encrypted private-key bundle is invalid."), 400
            if len(salt) != 16 or len(iv) != 12 or len(ciphertext) < 16:
                return jsonify(error="The encrypted private-key bundle is invalid."), 400
            subject = current_user.username
            state = app.config["PKI_STATE"]
            _, cert = issue_user_certificate(
                state["issuing_key"],
                state["issuing_cert"],
                f"CN={subject}",
                public_key=signing_public_key,
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

            record = CertificateRecord(
                certificate_code=allocate_certificate_code(),
                subject=subject,
                email=current_user.email,
                serial_number=str(cert.serial_number),
                issuer=state["issuing_cert"].subject.rfc4514_string(),
                cert_pem=cert_pem,
                private_key_pem="",
                status="active",
                user_id=current_user.id,
            )
            current_user.key_agreement_private = None
            current_user.key_agreement_public = base64.b64encode(
                encryption_public_der
            ).decode("ascii")
            current_user.encrypted_client_key_bundle = json.dumps(key_bundle)
            db.session.add(record)
            db.session.commit()
            record_audit(current_user.username, "issue_certificate", subject, "success")
            return jsonify(
                certificate_code=record.certificate_code,
                certificate_pem=cert_pem,
                serial_number=record.serial_number,
            )

        has_active_certificate = CertificateRecord.query.filter_by(
            user_id=current_user.id,
            status="active",
        ).filter(CertificateRecord.private_key_pem != "").first() is not None
        return render_template(
            "request_certificate.html",
            has_active_certificate=has_active_certificate,
        )

    @app.route("/account/keys/restore", methods=["POST"])
    @login_required
    def restore_client_keys():
        encryption_state = db.session.get(EncryptionSystemState, 1)
        if encryption_state is None or not encryption_state.clean_reset_completed:
            return jsonify(error="The E2EE clean reset has not been completed."), 409
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="A valid recovery bundle is required."), 400
        try:
            signing_public_der = base64.b64decode(
                body.get("signing_public_key", ""), validate=True
            )
            encryption_public_der = base64.b64decode(
                body.get("encryption_public_key", ""), validate=True
            )
            signing_public = serialization.load_der_public_key(signing_public_der)
            encryption_public = serialization.load_der_public_key(encryption_public_der)
        except (TypeError, ValueError):
            return jsonify(error="The recovery public keys are invalid."), 400
        if (
            not isinstance(signing_public, ec.EllipticCurvePublicKey)
            or not isinstance(encryption_public, ec.EllipticCurvePublicKey)
            or not isinstance(signing_public.curve, ec.SECP256R1)
            or not isinstance(encryption_public.curve, ec.SECP256R1)
        ):
            return jsonify(error="The recovery file contains unsupported public keys."), 400
        key_bundle = body.get("encrypted_key_bundle")
        if (
            not isinstance(key_bundle, dict)
            or key_bundle.get("version") != 1
            or key_bundle.get("kdf") != "PBKDF2-SHA256"
            or key_bundle.get("iterations") != 310000
        ):
            return jsonify(error="The encrypted key bundle is invalid."), 400
        try:
            salt = base64.b64decode(key_bundle["salt"], validate=True)
            iv = base64.b64decode(key_bundle["iv"], validate=True)
            ciphertext = base64.b64decode(key_bundle["ciphertext"], validate=True)
        except (KeyError, TypeError, ValueError):
            return jsonify(error="The encrypted key bundle is invalid."), 400
        if len(salt) != 16 or len(iv) != 12 or len(ciphertext) < 16:
            return jsonify(error="The encrypted key bundle is invalid."), 400

        certificate = CertificateRecord.query.filter_by(
            user_id=current_user.id,
            status="active",
        ).first()
        if certificate is None:
            return jsonify(error="Enroll an active signing certificate first."), 409
        certificate_public_der = x509.load_pem_x509_certificate(
            certificate.cert_pem.encode("utf-8")
        ).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public_der != signing_public_der:
            return jsonify(error="The recovery signing key does not match your active certificate."), 400

        current_user.key_agreement_public = base64.b64encode(
            encryption_public_der
        ).decode("ascii")
        current_user.key_agreement_private = None
        current_user.encrypted_client_key_bundle = json.dumps(key_bundle)
        db.session.commit()
        record_audit(current_user.username, "restore_client_keys", "account", "success")
        return jsonify(restored=True)

    @app.route("/api/client-key-bundle")
    @login_required
    def client_key_bundle():
        if not current_user.encrypted_client_key_bundle:
            return jsonify(error="Enroll or restore your browser-held keys first."), 404
        return jsonify(bundle=json.loads(current_user.encrypted_client_key_bundle))

    @app.route("/api/users/<int:user_id>/encryption-public-key")
    @login_required
    def recipient_encryption_public_key(user_id):
        recipient = db.session.get(User, user_id)
        if (
            recipient is None
            or not recipient.active
            or not recipient.key_agreement_public
        ):
            return jsonify(error="The recipient has not enrolled E2EE keys."), 409
        return jsonify(public_key=recipient.key_agreement_public)

    @app.route("/api/certificates/<serial_number>/trust")
    @login_required
    def certificate_trust_status(serial_number):
        certificate_record = CertificateRecord.query.filter_by(
            serial_number=serial_number,
        ).first()
        if certificate_record is None:
            return jsonify(error="The sender certificate was not found."), 404
        try:
            certificate = x509.load_pem_x509_certificate(
                certificate_record.cert_pem.encode("utf-8")
            )
            trusted = (
                certificate_record.status == "active"
                and validate_certificate_chain(
                    certificate,
                    app.config["PKI_STATE"]["root_cert"],
                    app.config["PKI_STATE"]["issuing_cert"],
                    app.config["PKI_STATE"]["crl"],
                )
            )
            public_key_der = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (ValueError, TypeError):
            abort(500, description="The signing certificate could not be loaded.")
        return jsonify(
            trusted=trusted,
            certificate_pem=certificate_record.cert_pem,
            signing_public_key=base64.b64encode(public_key_der).decode("ascii"),
            certificate_code=certificate_record.certificate_code,
        )

    @app.route(
        "/api/documents/<int:document_id>/decryption-result",
        methods=["POST"],
    )
    @login_required
    def record_client_decryption_result(document_id):
        encrypted = EncryptedDocument.query.filter_by(
            id=document_id,
            recipient_id=current_user.id,
        ).first_or_404()
        metadata = json.loads(encrypted.payload_metadata)
        if (
            metadata.get("format_version") not in {2, 3}
            or metadata.get("status") != "signed_and_encrypted_e2ee"
        ):
            abort(409)
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("verified"), bool):
            return jsonify(error="A verification result is required."), 400
        record_audit(
            current_user.username,
            "client_decrypt_and_verify",
            encrypted.title,
            "client_reported_success" if body["verified"] else "client_reported_failure",
        )
        return jsonify(recorded=True)

    @app.route("/admin")
    @login_required
    def admin_panel():
        if current_user.role != "admin":
            flash("Access denied.")
            return redirect(url_for("dashboard"))
        certificates = CertificateRecord.query.order_by(CertificateRecord.created_at.desc()).all()
        users = User.query.filter_by(role="user").order_by(User.username.asc()).all()
        events = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(20).all()
        encryption_state = db.session.get(EncryptionSystemState, 1)
        return render_template(
            "admin.html",
            certificates=certificates,
            users=users,
            events=events,
            encryption_state=encryption_state,
        )

    @app.route("/admin/e2ee-reset", methods=["POST"])
    @login_required
    def reset_for_e2ee():
        if current_user.role != "admin":
            abort(403)
        if request.form.get("confirmation", "").strip() != "RESET":
            flash("Type RESET to confirm the E2EE key reset.", "danger")
            return redirect(url_for("admin_panel"))

        encryption_state = db.session.get(EncryptionSystemState, 1)
        if encryption_state is not None and encryption_state.clean_reset_completed:
            flash("The E2EE clean reset has already been completed.", "warning")
            return redirect(url_for("admin_panel"))

        state = app.config["PKI_STATE"]
        certificates = CertificateRecord.query.all()
        for certificate in certificates:
            revoked_serial = int(certificate.serial_number)
            if revoked_serial not in state["revoked_serials"]:
                state["revoked_serials"].append(revoked_serial)
            certificate.status = "revoked"
            certificate.private_key_pem = ""

        state["crl"] = create_crl(
            state["issuing_key"],
            state["issuing_cert"],
            state["revoked_serials"],
        )
        for user in User.query.all():
            user.key_agreement_private = None
            user.key_agreement_public = None
            user.encrypted_client_key_bundle = None
            user.session_version += 1

        for encrypted in EncryptedDocument.query.all():
            metadata = json.loads(encrypted.payload_metadata)
            metadata["status"] = "e2ee_reset"
            metadata["access_revoked_reason"] = "legacy_keys_destroyed"
            encrypted.payload_metadata = json.dumps(metadata)

        if encryption_state is None:
            encryption_state = EncryptionSystemState(
                id=1,
                clean_reset_completed=True,
                reset_at=datetime.utcnow(),
            )
            db.session.add(encryption_state)
        else:
            encryption_state.clean_reset_completed = True
            encryption_state.reset_at = datetime.utcnow()
        db.session.commit()
        save_pki_state(app)
        record_audit(current_user.username, "e2ee_clean_reset", "all-user-keys", "success")
        logout_user()
        session.clear()
        flash("Legacy keys were revoked. Log in again and request a new signing certificate.", "warning")
        return redirect(url_for("login"))

    @app.route("/admin/users/<int:user_id>/suspend", methods=["POST"])
    @login_required
    def suspend_user(user_id):
        if current_user.role != "admin":
            flash("Access denied.")
            return redirect(url_for("dashboard"))

        user = db.session.get(User, user_id)
        if user is None or user.role != "user":
            flash("User not found.")
            return redirect(url_for("admin_panel"))

        user.active = False
        user.session_version += 1
        db.session.commit()
        record_audit(current_user.username, "suspend_user", user.username, "success")
        flash(f"Access for {user.username} has been suspended.")
        return redirect(url_for("admin_panel"))

    @app.route("/admin/users/<int:user_id>/activate", methods=["POST"])
    @login_required
    def activate_user(user_id):
        if current_user.role != "admin":
            flash("Access denied.")
            return redirect(url_for("dashboard"))

        user = db.session.get(User, user_id)
        if user is None or user.role != "user":
            flash("User not found.")
            return redirect(url_for("admin_panel"))

        user.active = True
        db.session.commit()
        record_audit(current_user.username, "activate_user", user.username, "success")
        flash(f"Access for {user.username} has been restored.")
        return redirect(url_for("admin_panel"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    def delete_user(user_id):
        if current_user.role != "admin":
            flash("Access denied.")
            return redirect(url_for("dashboard"))

        user = db.session.get(User, user_id)
        if user is None or user.role != "user":
            flash("User not found.")
            return redirect(url_for("admin_panel"))

        username = user.username
        user_certificates = CertificateRecord.query.filter_by(user_id=user.id).all()
        state = app.config["PKI_STATE"]
        for certificate in user_certificates:
            serial_number = int(certificate.serial_number)
            if serial_number not in state["revoked_serials"]:
                state["revoked_serials"].append(serial_number)
            certificate.status = "revoked"
        if user_certificates:
            state["crl"] = create_crl(
                state["issuing_key"],
                state["issuing_cert"],
                state["revoked_serials"],
            )
            save_pki_state(app)

        DocumentRecord.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        EncryptedDocument.query.filter(
            (EncryptedDocument.sender_id == user.id)
            | (EncryptedDocument.recipient_id == user.id)
        ).delete(synchronize_session=False)
        CertificateRecord.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        db.session.delete(user)
        db.session.commit()
        record_audit(current_user.username, "delete_user", username, "success")
        flash(f"User {username} and their linked records were deleted. They must register again to use the app.")
        return redirect(url_for("admin_panel"))

    @app.route("/admin/revoke/<int:certificate_id>", methods=["POST"])
    @login_required
    def revoke_certificate_route(certificate_id):
        if current_user.role != "admin":
            flash("Access denied.")
            return redirect(url_for("dashboard"))

        certificate = db.session.get(CertificateRecord, certificate_id)
        if certificate is None:
            flash("Certificate not found.")
            return redirect(url_for("admin_panel"))

        state = app.config["PKI_STATE"]
        revoked_serial = int(certificate.serial_number)
        if revoked_serial not in state["revoked_serials"]:
            state["revoked_serials"].append(revoked_serial)
        state["crl"] = create_crl(state["issuing_key"], state["issuing_cert"], state["revoked_serials"])

        certificate.status = "revoked"
        for encrypted in EncryptedDocument.query.all():
            metadata = json.loads(encrypted.payload_metadata)
            if str(metadata.get("signer_certificate_serial")) == certificate.serial_number:
                metadata["status"] = "access_revoked"
                metadata["access_revoked_reason"] = "signer_certificate_revoked"
                encrypted.payload_metadata = json.dumps(metadata)
        db.session.commit()
        save_pki_state(app)
        record_audit(current_user.username, "revoke_certificate", certificate.subject, "success")
        flash("Certificate revoked and CRL updated.")
        return redirect(url_for("admin_panel"))

    @app.route("/sign-document", methods=["GET", "POST"])
    @login_required
    def sign_document():
        certificates = CertificateRecord.query.filter_by(
            user_id=current_user.id,
            status="active",
        ).filter(CertificateRecord.private_key_pem != "").all()
        result = None
        if request.method == "POST":
            cert_id = request.form.get("certificate_id")
            try:
                cert = db.session.get(CertificateRecord, int(cert_id))
            except (TypeError, ValueError):
                cert = None
            if cert is None or cert.user_id != current_user.id or cert.status != "active":
                flash("Invalid certificate selection.")
                return redirect(url_for("sign_document"))

            try:
                content_bytes, content, original_filename, content_type = get_signed_input()
            except ValueError as error:
                flash(str(error), "danger")
                return redirect(url_for("sign_document"))

            if not cert.private_key_pem:
                try:
                    signature = bytes.fromhex(request.form.get("signature_hex", ""))
                    certificate_public_key = x509.load_pem_x509_certificate(
                        cert.cert_pem.encode("utf-8")
                    ).public_key()
                except ValueError:
                    flash("The browser signature is invalid.", "danger")
                    return redirect(url_for("sign_document"))
                if not signature or not verify_document_bytes(
                    content_bytes,
                    signature,
                    certificate_public_key,
                ):
                    flash("The browser signature does not match the exact document bytes.", "danger")
                    return redirect(url_for("sign_document"))
                title = request.form.get("title", "").strip()
                if not title:
                    title = Path(original_filename).stem if original_filename else "Signed Document"
                document = DocumentRecord(
                    title=title,
                    document_text=content,
                    content_bytes=content_bytes,
                    original_filename=original_filename,
                    content_type=content_type,
                    signature_hex=signature.hex(),
                    hash_hex=sha256_hex(content_bytes),
                    status="verified",
                    user_id=current_user.id,
                    certificate_id=cert.id,
                )
                db.session.add(document)
                db.session.commit()
                record_audit(current_user.username, "sign_document", title, "success")
                result = {
                    "signature_hex": signature.hex(),
                    "hash_hex": sha256_hex(content_bytes),
                    "certificate_code": cert.certificate_code,
                }
                flash("Signature created in your browser and saved successfully.")
                return render_template(
                    "sign_document.html",
                    certificates=certificates,
                    result=result,
                    e2ee_mode=False,
                )

            private_key = serialization.load_pem_private_key(decrypt_private_key(app, cert.private_key_pem).encode("utf-8"), password=None)
            signature = sign_document_bytes(private_key, content_bytes)
            title = request.form.get("title", "").strip()
            if not title:
                title = Path(original_filename).stem if original_filename else "Signed Document"
            document = DocumentRecord(
                title=title,
                document_text=content,
                content_bytes=content_bytes,
                original_filename=original_filename,
                content_type=content_type,
                signature_hex=signature.hex(),
                hash_hex=sha256_hex(content_bytes),
                status="verified",
                user_id=current_user.id,
                certificate_id=cert.id,
            )
            db.session.add(document)
            db.session.commit()
            record_audit(current_user.username, "sign_document", title, "success")
            result = {
                "signature_hex": signature.hex(),
                "hash_hex": sha256_hex(content_bytes),
                "certificate_code": cert.certificate_code,
            }
            flash("Signature created successfully.")

        return render_template(
            "sign_document.html",
            certificates=certificates,
            result=result,
            e2ee_mode=False,
        )

    @app.route("/documents/<int:document_id>/download")
    @login_required
    def download_document(document_id):
        document = DocumentRecord.query.filter_by(
            id=document_id, user_id=current_user.id
        ).first()
        if document is None:
            abort(404)
        certificate_record = document.certificate
        if certificate_record is None or certificate_record.status != "active":
            abort(403, description="The document's signing certificate is not active.")
        try:
            certificate = x509.load_pem_x509_certificate(
                certificate_record.cert_pem.encode("utf-8")
            )
            signature = bytes.fromhex(document.signature_hex)
        except ValueError:
            abort(403, description="The document signature could not be verified.")
        content_bytes = (
            document.content_bytes
            if document.content_bytes is not None
            else document.document_text.encode("utf-8")
        )
        if not verify_document_bytes(
            content_bytes,
            signature,
            certificate.public_key(),
        ) or not validate_certificate_chain(
            certificate,
            app.config["PKI_STATE"]["root_cert"],
            app.config["PKI_STATE"]["issuing_cert"],
            app.config["PKI_STATE"]["crl"],
        ):
            record_audit(current_user.username, "download_document", document.title, "failed")
            abort(403, description="The document signature or certificate could not be verified.")
        record_audit(current_user.username, "download_document", document.title, "success")
        if document.content_type == "application/pdf" and document.content_bytes is not None:
            return send_file(
                BytesIO(document.content_bytes),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=secure_filename(document.original_filename or document.title)
                or "signed-document.pdf",
            )
        return document_pdf_response(document.title, document.document_text)

    @app.route("/documents/<int:document_id>/delete", methods=["POST"])
    @login_required
    def delete_document(document_id):
        document = DocumentRecord.query.filter_by(
            id=document_id,
            user_id=current_user.id,
        ).first()
        if document is None:
            abort(404)
        title = document.title
        db.session.delete(document)
        db.session.commit()
        record_audit(current_user.username, "delete_document", title, "success")
        flash(f"Signed document “{title}” was permanently deleted.")
        return redirect(url_for("dashboard"))

    @app.route("/verify-document", methods=["GET", "POST"])
    @login_required
    def verify_document():
        result = None
        saved_document_id = (
            request.form.get("document_id", "")
            if request.method == "POST"
            else request.args.get("document_id", "")
        ).strip()
        document = None

        if saved_document_id:
            try:
                document_id = int(saved_document_id)
            except ValueError:
                abort(404)
            document = DocumentRecord.query.filter_by(
                id=document_id,
                user_id=current_user.id,
            ).first_or_404()
            if document.certificate is None or document.certificate.status != "active":
                record_audit(
                    current_user.username,
                    "verify_document",
                    document.title,
                    "failed",
                )
                abort(403, description="The document's signing certificate is not active.")
            if request.method == "POST":
                certificate = document.certificate
                content_bytes = (
                    document.content_bytes
                    if document.content_bytes is not None
                    else document.document_text.encode("utf-8")
                )
                if certificate is None:
                    result = {
                        "valid": False,
                        "signature_valid": False,
                        "chain_valid": False,
                        "message": "The document's signing certificate is unavailable.",
                    }
                else:
                    try:
                        result = verify_content_signature(
                            content_bytes,
                            request.form.get("signature_hex", "").strip(),
                            certificate,
                            app.config["PKI_STATE"],
                        )
                        entered_signature = bytes.fromhex(
                            request.form.get("signature_hex", "").strip()
                        )
                        saved_signature = bytes.fromhex(document.signature_hex)
                        if entered_signature != saved_signature:
                            result.update(
                                {
                                    "valid": False,
                                    "signature_valid": False,
                                    "message": "Rejected: The entered signature does not match the signature saved for this document.",
                                }
                            )
                    except ValueError as error:
                        result = {
                            "valid": False,
                            "signature_valid": False,
                            "chain_valid": False,
                            "message": f"The entered signature could not be verified: {error}",
                        }
                record_audit(
                    current_user.username,
                    "verify_document",
                    document.title,
                    "success" if result["valid"] else "failed",
                )
                result["document_title"] = document.title
                result["certificate_code"] = (
                    certificate.certificate_code if certificate else None
                )
                result["source"] = "saved"

        documents = DocumentRecord.query.filter_by(
            user_id=current_user.id
        ).order_by(DocumentRecord.created_at.desc()).all()

        return render_template(
            "verify_document.html",
            result=result,
            document=document,
            documents=documents,
            entered_signature=request.form.get("signature_hex", "") if request.method == "POST" else "",
        )

    @app.route("/encrypt-document/legacy", methods=["GET", "POST"])
    @login_required
    def encrypt_document_legacy(simple_key_mode=False):
        encryption_state = db.session.get(EncryptionSystemState, 1)
        e2ee_mode = simple_key_mode or bool(
            encryption_state and encryption_state.clean_reset_completed
        )
        recipients = User.query.filter(User.id != current_user.id).all()
        if e2ee_mode:
            certificates = CertificateRecord.query.filter_by(
                user_id=current_user.id,
                status="active",
            ).filter(CertificateRecord.private_key_pem != "").all()
            sent_message_key = None
            sent_message_id = None
            if request.is_json:
                body = request.get_json(silent=True)
                try:
                    recipient_id = int(body.get("recipient_id", ""))
                    certificate_id = int(body.get("certificate_id", ""))
                except (AttributeError, TypeError, ValueError):
                    return jsonify(error="Choose a recipient and an active certificate."), 400
                recipient = db.session.get(User, recipient_id)
                certificate = CertificateRecord.query.filter_by(
                    id=certificate_id,
                    user_id=current_user.id,
                    status="active",
                ).first()
                payload = body.get("payload") if isinstance(body, dict) else None
                title = body.get("title", "") if isinstance(body, dict) else ""
                if recipient is None or not recipient.active:
                    return jsonify(error="Choose an active recipient."), 409
                if certificate is None or not isinstance(payload, dict):
                    return jsonify(error="The encrypted message is invalid."), 400
                version = payload.get("version")
                required_fields = (
                    ("ephemeral_public_key", "salt", "iv", "ciphertext")
                    if version == 2
                    else ("iv", "ciphertext")
                    if version == 3
                    else ()
                )
                if (
                    not required_fields
                    or not isinstance(title, str)
                    or not title.strip()
                    or not all(isinstance(payload.get(field), str) for field in required_fields)
                ):
                    return jsonify(error="The encrypted message is invalid."), 400
                try:
                    decoded_payload = {
                        field: base64.b64decode(payload[field], validate=True)
                        for field in required_fields
                    }
                except (TypeError, ValueError):
                    return jsonify(error="The encrypted message is invalid."), 400
                ciphertext = decoded_payload["ciphertext"]
                valid_ciphertext = 16 <= len(ciphertext) <= MAX_E2EE_MESSAGE_BYTES + 64 * 1024
                valid_iv = len(decoded_payload["iv"]) == 12
                if version == 2:
                    valid_iv = (
                        bool(decoded_payload["ephemeral_public_key"])
                        and len(decoded_payload["salt"]) == 16
                        and valid_iv
                        and bool(recipient.key_agreement_public)
                    )
                if not valid_ciphertext or not valid_iv:
                    return jsonify(error="The encrypted message is invalid."), 400
                encrypted = EncryptedDocument(
                    title=title.strip(),
                    sender_id=current_user.id,
                    recipient_id=recipient.id,
                    payload=json.dumps(payload),
                    payload_metadata=json.dumps({
                        "provider": (
                            "ECDH-P256/HKDF-SHA256/AES-256-GCM"
                            if version == 2
                            else "AES-256-GCM-one-time-key"
                        ),
                        "status": "signed_and_encrypted_e2ee",
                        "signer_certificate_serial": certificate.serial_number,
                        "format_version": version,
                    }),
                )
                db.session.add(encrypted)
                db.session.commit()
                record_audit(current_user.username, "encrypt_document", title, "success")
                return jsonify(sent=True, document_id=encrypted.id)

            if request.method == "POST":
                try:
                    recipient_id = int(request.form.get("recipient_id", ""))
                    certificate_id = int(request.form.get("certificate_id", ""))
                except (TypeError, ValueError):
                    flash("Choose a recipient and an active certificate.", "danger")
                    return redirect(url_for("encrypt_document"))
                recipient = db.session.get(User, recipient_id)
                certificate = CertificateRecord.query.filter_by(
                    id=certificate_id,
                    user_id=current_user.id,
                    status="active",
                ).first()
                if recipient is None or not recipient.active:
                    flash("Choose an active recipient.", "danger")
                    return redirect(url_for("encrypt_document"))
                if certificate is None or not certificate.private_key_pem:
                    flash("Request a signing certificate before sending a message.", "danger")
                    return redirect(url_for("request_certificate"))
                try:
                    content_bytes, _, original_filename, content_type = get_signed_input()
                except ValueError as error:
                    flash(str(error), "danger")
                    return redirect(url_for("encrypt_document"))
                if len(content_bytes) > MAX_E2EE_MESSAGE_BYTES:
                    flash("Messages and files must be no larger than 6 MB.", "danger")
                    return redirect(url_for("encrypt_document"))
                title = request.form.get("title", "").strip()
                if not title:
                    title = Path(original_filename).stem if original_filename else "Encrypted Message"
                signing_key = serialization.load_pem_private_key(
                    decrypt_private_key(app, certificate.private_key_pem).encode("utf-8"),
                    password=None,
                )
                envelope = {
                    "version": 3,
                    "title": title,
                    "sender_id": current_user.id,
                    "recipient_id": recipient.id,
                    "content_type": content_type,
                    "filename": original_filename or "",
                    "content_hash": sha256_hex(content_bytes),
                    "content_base64": base64.b64encode(content_bytes).decode("ascii"),
                    "signer_certificate_serial": certificate.serial_number,
                    "signer_certificate_pem": certificate.cert_pem,
                }
                envelope["signature_hex"] = sign_document_bytes(
                    signing_key,
                    one_time_message_signature_payload(envelope),
                ).hex()
                one_time_key = secrets.token_bytes(32)
                iv = secrets.token_bytes(12)
                ciphertext = AESGCM(one_time_key).encrypt(
                    iv,
                    json.dumps(envelope).encode("utf-8"),
                    None,
                )
                encrypted = EncryptedDocument(
                    title=title,
                    sender_id=current_user.id,
                    recipient_id=recipient.id,
                    payload=json.dumps({
                        "version": 3,
                        "iv": base64.b64encode(iv).decode("ascii"),
                        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                    }),
                    payload_metadata=json.dumps({
                        "provider": "AES-256-GCM-one-time-key",
                        "status": "signed_and_encrypted_one_time_key",
                        "signer_certificate_serial": certificate.serial_number,
                        "format_version": 3,
                    }),
                )
                db.session.add(encrypted)
                db.session.commit()
                record_audit(current_user.username, "encrypt_document", title, "success")
                sent_message_key = base64.urlsafe_b64encode(one_time_key).decode("ascii").rstrip("=")
                sent_message_id = encrypted.id
                flash("Document signed and encrypted. Share the one-time key separately.", "success")

            return render_template(
                "encrypt_document.html",
                recipients=recipients,
                certificates=certificates,
                e2ee_mode=False,
                simple_key_mode=True,
                sent_message_key=sent_message_key,
                sent_message_id=sent_message_id,
            )

        certificates = CertificateRecord.query.filter_by(
            user_id=current_user.id,
            status="active",
        ).all()
        if request.method == "POST":
            if e2ee_mode:
                body = request.get_json(silent=True)
                if not isinstance(body, dict):
                    return jsonify(error="Browser-side encryption is required."), 400
                try:
                    recipient_id = int(body.get("recipient_id", ""))
                    certificate_id = int(body.get("certificate_id", ""))
                except (TypeError, ValueError):
                    return jsonify(error="Choose a recipient and an active certificate."), 400
                recipient = db.session.get(User, recipient_id)
                certificate = CertificateRecord.query.filter_by(
                    id=certificate_id,
                    user_id=current_user.id,
                    status="active",
                ).first()
                if recipient is None or not recipient.active:
                    return jsonify(error="Choose an active recipient."), 409
                if certificate is None or not current_user.encrypted_client_key_bundle:
                    return jsonify(error="Enroll browser-held signing keys first."), 409
                payload = body.get("payload")
                title = body.get("title", "")
                if (
                    not isinstance(title, str)
                    or not title.strip()
                    or not isinstance(payload, dict)
                ):
                    return jsonify(error="The encrypted payload is invalid."), 400
                payload_version = payload.get("version")
                if payload_version == 3:
                    payload_fields = ("iv", "ciphertext")
                elif payload_version == 2 and recipient.key_agreement_public:
                    payload_fields = ("ephemeral_public_key", "salt", "iv", "ciphertext")
                else:
                    return jsonify(error="The encrypted payload is invalid."), 400
                if not all(isinstance(payload.get(field), str) for field in payload_fields):
                    return jsonify(error="The encrypted payload is invalid."), 400
                try:
                    payload_bytes = [
                        base64.b64decode(payload[field], validate=True)
                        for field in payload_fields
                    ]
                except (TypeError, ValueError):
                    return jsonify(error="The encrypted payload is invalid."), 400
                ciphertext = payload_bytes[-1]
                if payload_version == 2:
                    valid_payload = (
                        bool(payload_bytes[0])
                        and len(payload_bytes[1]) == 16
                        and len(payload_bytes[2]) == 12
                        and len(ciphertext) >= 16
                        and len(ciphertext) <= MAX_E2EE_MESSAGE_BYTES + 64 * 1024
                    )
                else:
                    valid_payload = (
                        len(payload_bytes[0]) == 12
                        and len(ciphertext) >= 16
                        and len(ciphertext) <= MAX_E2EE_MESSAGE_BYTES + 64 * 1024
                    )
                if not valid_payload:
                    return jsonify(error="The encrypted payload is invalid."), 400
                encrypted = EncryptedDocument(
                    title=title.strip(),
                    sender_id=current_user.id,
                    recipient_id=recipient.id,
                    payload=json.dumps(payload),
                    payload_metadata=json.dumps(
                        {
                            "provider": (
                                "AES-256-GCM-one-time-key"
                                if payload_version == 3
                                else "ECDH-P256/HKDF-SHA256/AES-256-GCM"
                            ),
                            "status": "signed_and_encrypted_e2ee",
                            "signer_certificate_serial": certificate.serial_number,
                            "format_version": payload_version,
                        }
                    ),
                )
                db.session.add(encrypted)
                db.session.commit()
                record_audit(current_user.username, "encrypt_document", encrypted.title, "success")
                return jsonify(sent=True, document_id=encrypted.id)

            try:
                recipient_id = int(request.form.get("recipient_id", ""))
                certificate_id = int(request.form.get("certificate_id", ""))
            except ValueError:
                flash("Select a recipient and an active signing certificate.", "danger")
                return redirect(url_for("encrypt_document"))
            message = request.form.get("document_text", "")
            recipient = db.session.get(User, recipient_id)
            if recipient is None or not recipient.key_agreement_public:
                flash("Recipient has no valid key-agreement key.")
                return redirect(url_for("encrypt_document"))
            certificate = CertificateRecord.query.filter_by(
                id=certificate_id,
                user_id=current_user.id,
                status="active",
            ).first()
            if certificate is None:
                flash("Choose one of your active signing certificates.", "danger")
                return redirect(url_for("encrypt_document"))

            signing_key = serialization.load_pem_private_key(
                decrypt_private_key(app, certificate.private_key_pem).encode("utf-8"),
                password=None,
            )
            envelope = {
                "version": 1,
                "content": message,
                "signature_hex": sign_document_bytes(
                    signing_key,
                    message.encode("utf-8"),
                ).hex(),
                "signer_certificate_serial": certificate.serial_number,
                "signer_certificate_pem": certificate.cert_pem,
            }
            recipient_public_key = deserialize_x25519_public(recipient.key_agreement_public)
            payload = encrypt_document_for_recipient(
                json.dumps(envelope),
                recipient_public_key,
            )
            encrypted = EncryptedDocument(
                title=request.form.get("title", "Encrypted Message"),
                sender_id=current_user.id,
                recipient_id=recipient.id,
                payload=json.dumps(payload),
                payload_metadata=json.dumps(
                    {
                        "provider": "X25519/HKDF-SHA256/AESGCM",
                        "status": "signed_and_encrypted",
                        "signer_certificate_serial": certificate.serial_number,
                        "format_version": 1,
                    }
                ),
            )
            db.session.add(encrypted)
            db.session.commit()
            record_audit(current_user.username, "encrypt_document", encrypted.title, "success")
            flash("Document signed and encrypted for the recipient.", "success")

        return render_template(
            "encrypt_document.html",
            recipients=recipients,
            certificates=certificates,
            e2ee_mode=e2ee_mode,
        )

    @app.route("/encrypt-document", methods=["GET", "POST"])
    @login_required
    def encrypt_document():
        return encrypt_document_legacy(simple_key_mode=True)

    @app.route("/decrypt-document/<int:document_id>", methods=["GET", "POST"])
    @login_required
    def decrypt_document(document_id):
        encrypted = db.session.get(EncryptedDocument, document_id)
        if encrypted is None or encrypted.recipient_id != current_user.id:
            flash("Document not available or unauthorized access.", "danger")
            return redirect(url_for("dashboard"))
        message_status = json.loads(encrypted.payload_metadata).get("status")
        if message_status == "unreadable_after_key_rotation":
            flash(
                "This message was encrypted with a previous key and cannot be decrypted after key rotation.",
                "danger",
            )
            return redirect(url_for("dashboard"))
        if message_status == "e2ee_reset":
            flash(
                "This legacy message cannot be decrypted after the E2EE key reset.",
                "danger",
            )
            return redirect(url_for("dashboard"))
        if message_status == "access_revoked":
            flash(
                "Access to this message is locked because the signer's certificate was revoked.",
                "danger",
            )
            return redirect(url_for("dashboard"))

        message_metadata = json.loads(encrypted.payload_metadata)
        if message_metadata.get("format_version") == 3:
            verification = None
            submitted_key = ""
            if request.method == "POST":
                submitted_key = request.form.get("message_key", "").strip()
                try:
                    _, verification = decrypt_one_time_message(
                        encrypted,
                        submitted_key,
                        app.config["PKI_STATE"],
                    )
                except ValueError as error:
                    flash(str(error), "danger")
                    record_audit(
                        current_user.username,
                        "decrypt_document",
                        encrypted.title,
                        "failed",
                    )
                else:
                    record_audit(
                        current_user.username,
                        "decrypt_document",
                        encrypted.title,
                        "success" if verification["valid"] else "failed",
                    )
                    if not verification["valid"]:
                        verification["content"] = ""
                        submitted_key = ""
            return render_template(
                "decrypt_document.html",
                encrypted=encrypted,
                verification=verification,
                e2ee_mode=False,
                one_time_message=True,
                submitted_key=submitted_key,
                payload=json.loads(encrypted.payload),
            )

        if message_metadata.get("format_version") == 2:
            return render_template(
                "decrypt_document.html",
                encrypted=encrypted,
                verification=None,
                e2ee_mode=True,
                payload=json.loads(encrypted.payload),
                message_metadata=json.loads(encrypted.payload_metadata),
            )

        verification = None
        if request.method == "POST":
            try:
                payload = json.loads(encrypted.payload)
                private_key = deserialize_x25519_private(decrypt_private_key(app, current_user.key_agreement_private))
                plaintext = decrypt_document_for_recipient(payload, private_key)
                envelope = json.loads(plaintext)
                verification = verify_signed_envelope(
                    envelope,
                    encrypted.sender_id,
                    app.config["PKI_STATE"],
                )
                if not verification["valid"]:
                    verification["content"] = ""
                outcome = "success" if verification["valid"] else "failed"
                record_audit(current_user.username, "decrypt_document", encrypted.title, outcome)
                flash(
                    "Document decrypted and signature verified."
                    if verification["valid"]
                    else "Document decrypted, but its signature or certificate could not be verified.",
                    "success" if verification["valid"] else "danger",
                )
            except Exception as e:
                flash(f"Decryption failed: {str(e)}", "danger")
                record_audit(current_user.username, "decrypt_document", encrypted.title, "failed")

        return render_template(
            "decrypt_document.html",
            encrypted=encrypted,
            verification=verification,
        )

    @app.route("/decrypt-document/<int:document_id>/download", methods=["GET", "POST"])
    @login_required
    def download_decrypted_document(document_id):
        encrypted = EncryptedDocument.query.filter_by(
            id=document_id, recipient_id=current_user.id
        ).first()
        if encrypted is None:
            abort(404)
        message_status = json.loads(encrypted.payload_metadata).get("status")
        format_version = json.loads(encrypted.payload_metadata).get("format_version")
        if message_status in {"unreadable_after_key_rotation", "e2ee_reset", "access_revoked"}:
            abort(410, description="Access to this encrypted message is no longer available.")
        if format_version == 3:
            if request.method != "POST":
                abort(405)
            try:
                envelope, verification = decrypt_one_time_message(
                    encrypted,
                    request.form.get("message_key", "").strip(),
                    app.config["PKI_STATE"],
                )
            except ValueError:
                record_audit(
                    current_user.username,
                    "download_decrypted_document",
                    encrypted.title,
                    "failed",
                )
                abort(403, description="The one-time key is incorrect or the message is damaged.")
            if not verification["valid"]:
                record_audit(
                    current_user.username,
                    "download_decrypted_document",
                    encrypted.title,
                    "failed",
                )
                abort(403, description="The signature or signer certificate could not be verified.")
            content_bytes = base64.b64decode(envelope["content_base64"], validate=True)
            record_audit(
                current_user.username,
                "download_decrypted_document",
                encrypted.title,
                "success",
            )
            if envelope["content_type"] == "application/pdf":
                return send_file(
                    BytesIO(content_bytes),
                    mimetype="application/pdf",
                    as_attachment=True,
                    download_name=secure_filename(envelope.get("filename") or encrypted.title)
                    or "verified-document.pdf",
                )
            return document_pdf_response(encrypted.title, verification["content"])
        if format_version == 2:
            abort(400, description="End-to-end encrypted messages can only be decrypted and downloaded in the recipient's browser.")
        try:
            payload = json.loads(encrypted.payload)
            private_key = deserialize_x25519_private(decrypt_private_key(app, current_user.key_agreement_private))
            plaintext = decrypt_document_for_recipient(payload, private_key)
            envelope = json.loads(plaintext)
            verification = verify_signed_envelope(
                envelope,
                encrypted.sender_id,
                app.config["PKI_STATE"],
            )
        except Exception:
            record_audit(
                current_user.username,
                "download_decrypted_document",
                encrypted.title,
                "failed",
            )
            raise
        if not verification["valid"]:
            record_audit(
                current_user.username,
                "download_decrypted_document",
                encrypted.title,
                "failed",
            )
            abort(403, description="The signature or signer certificate could not be verified.")
        record_audit(
            current_user.username,
            "download_decrypted_document",
            encrypted.title,
            "success",
        )
        return document_pdf_response(encrypted.title, verification["content"])

    @app.route("/audit")
    @login_required
    def audit():
        if current_user.role != "admin":
            flash("Access denied.")
            return redirect(url_for("dashboard"))
        events = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(25).all()
        return render_template("audit.html", events=events)

    return app