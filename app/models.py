from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="user")
    active = db.Column(db.Boolean, nullable=False, default=True)
    session_version = db.Column(db.Integer, nullable=False, default=0)
    key_agreement_public = db.Column(db.Text, nullable=True)
    key_agreement_private = db.Column(db.Text, nullable=True)
    encrypted_client_key_bundle = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"


class CertificateRecord(db.Model):
    __tablename__ = "certificate_records"

    id = db.Column(db.Integer, primary_key=True)
    certificate_code = db.Column(db.String(20), unique=True, nullable=True)
    subject = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    serial_number = db.Column(db.String(80), nullable=False)
    issuer = db.Column(db.String(200), nullable=False)
    cert_pem = db.Column(db.Text, nullable=False)
    private_key_pem = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="active")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("certificates", lazy=True))


class DocumentRecord(db.Model):
    __tablename__ = "document_records"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    document_text = db.Column(db.Text, nullable=False)
    content_bytes = db.Column(db.LargeBinary, nullable=True)
    original_filename = db.Column(db.String(255), nullable=True)
    content_type = db.Column(db.String(100), nullable=True)
    signature_hex = db.Column(db.Text, nullable=False)
    hash_hex = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(20), default="verified")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificate_records.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("documents", lazy=True))
    certificate = db.relationship("CertificateRecord")


class CertificateCodeSequence(db.Model):
    __tablename__ = "certificate_code_sequences"

    id = db.Column(db.Integer, primary_key=True)
    next_value = db.Column(db.Integer, nullable=False)


class EncryptedDocument(db.Model):
    __tablename__ = "encrypted_documents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    payload_metadata = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id], backref=db.backref("sent_documents", lazy=True))
    recipient = db.relationship("User", foreign_keys=[recipient_id], backref=db.backref("received_documents", lazy=True))


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    object_name = db.Column(db.String(200), nullable=True)
    outcome = db.Column(db.String(50), nullable=False, default="success")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class EncryptionSystemState(db.Model):
    __tablename__ = "encryption_system_state"

    id = db.Column(db.Integer, primary_key=True)
    clean_reset_completed = db.Column(db.Boolean, nullable=False, default=False)
    reset_at = db.Column(db.DateTime, nullable=True)
