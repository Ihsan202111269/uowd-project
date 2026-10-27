# PKI-Based Secure Digital Document Signing and Verification System

This repository contains the foundation for the MACS902 project prototype: a local Flask application with a PKI service layer, SQLite-ready models, and automated tests covering the trust chain and certificate revocation flow.

## Project status

- The Flask application supports user registration, login and a local PKI certificate enrollment flow.
- Registration does not automatically sign users in; users log in after registering. Login sessions are non-permanent, are invalidated whenever the app server starts, and the database stores password hashes rather than plaintext passwords. The home page always offers login or registration instead of redirecting authenticated browsers to the dashboard.
- The main index page is the public entry point, with direct login and registration actions. The supplied security illustration is used as a local, darkened background; signed-in users get a responsive side navigation on desktop and a compact navigation bar on mobile.
- Administrators can suspend or restore a user's access, or permanently delete a user and their linked certificates, signed documents, and encrypted messages. A deleted username must register again before it can log in.
- Any signed-in user, including the administrator, can change their password from the account link in the sidebar. The current password is required; a successful change signs out all sessions for that account. Bootstrap credentials are used to create the initial administrator and do not overwrite a password changed in the app.
- The dashboard shows the five newest signed documents and messages in each section; older items stay available in expandable history. Users can permanently delete their own saved signed documents. When a document's signing certificate is revoked, verification and download are blocked and only the delete action remains. Encrypted messages are shared between sender and recipient, so they are not removed by the signed-document delete action.
- Users can issue a certificate, sign a document, and verify signatures and certificate trust/revocation.
- Certificates receive a sequential display code such as `CER-0001`; the underlying X.509 serial number remains unchanged and is used for PKI validation and revocation.
- After enrollment, users can sign pasted plaintext or upload a UTF-8 `.txt` or PDF file (up to 10 MB). PDF signatures cover the exact original bytes, which are retained for in-app verification.
- The administrator can perform an optional one-time reset that revokes existing certificates and permanently locks existing encrypted messages. New one-time-key messages work without this reset.
- Certificate requests and new messages use regular Flask forms; no browser key enrollment or recovery download is needed for recipients.
- Each new message gets a fresh random 256-bit AES-GCM key. The sender sees the key once after sending and shares it with the recipient through a separate trusted channel. The key is not saved with the message.
- The recipient enters that one-time key on the decrypt page. The server decrypts the message, checks its signature and certificate trust, and releases the content only when both checks pass. The recipient does not need a certificate to receive a message.
- New encrypted messages accept pasted text or an uploaded UTF-8 `.txt` or PDF file (up to 6 MB). Signatures bind the document hash and message context; verified PDF files can be downloaded unchanged.
- Earlier browser-encrypted messages continue to use their existing browser-held key/passphrase flow. Earlier server-managed messages continue to use the existing server-held recipient-key flow.
- This simplified one-time-key workflow is **not end-to-end encryption against the app server**: the server processes message content while signing and decrypts it when the recipient submits the key. It avoids storing the one-time key alongside the ciphertext, but does not hide plaintext from the server.
- Overall verification is successful only when both the signature matches the exact content and the signer certificate is trusted and not revoked.
- Admin certificate revocation affects signature trust, prevents further signing with that certificate, and locks existing encrypted messages signed with it. It does not affect the admin's access.

## Quick start

```bash
cd /workspaces/uowd-project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create the local secrets and admin account with one command:

```bash
python - <<'PY'
from pathlib import Path
import secrets
from cryptography.fernet import Fernet

env_file = Path(".env")
if env_file.exists():
    raise SystemExit(".env already exists; leaving it unchanged.")

admin_password = secrets.token_urlsafe(24)
env_file.write_text(
    "\n".join([
        f"SECRET_KEY={secrets.token_urlsafe(48)}",
        f"PRIVATE_KEY_ENCRYPTION_KEY={Fernet.generate_key().decode()}",
        "DATABASE_URL=sqlite:///project.db",
        "BOOTSTRAP_ADMIN_USERNAME=admin",
        "BOOTSTRAP_ADMIN_EMAIL=admin@example.com",
        f"BOOTSTRAP_ADMIN_PASSWORD={admin_password}",
        "SESSION_COOKIE_SECURE=false",
        "",
    ]),
    encoding="utf-8",
)
env_file.chmod(0o600)
print("Created .env. Save this admin login somewhere safe:")
print("Username: admin")
print(f"Password: {admin_password}")
PY
```

Save the generated password; it is only shown once. Keep `.env` private and do not commit it. Then start the app:

```bash
flask --app app run --debug
```

Then open the app at http://127.0.0.1:5000/.

The app does not create an administrator with a public default password. It creates the administrator specified by the three `BOOTSTRAP_ADMIN_*` settings. Use a unique, long password. For HTTPS deployments, set `SESSION_COOKIE_SECURE=true`.

After logging in, use **Change password** in the sidebar to set a new admin password. The app stores only an Argon2 password hash; successful changes invalidate all sessions for that account. The bootstrap password is only used when the admin account is first created.

## Demonstrating two users at once

Run one app server and use two separate browser profiles (for example, a regular window and a private/incognito window). Each profile has its own login cookie, while both use the same application database. The sidebar identifies the currently signed-in username and role.

1. Log in as the configured admin and register/log in as the recipient in the second profile.
2. The admin requests a signing certificate from **Certificates**; the recipient does not need one to receive messages.
3. In the admin profile, open **Sign & Encrypt**, select the recipient, and send. Copy the one-time decryption key shown after sending and share it separately with the recipient.
4. In the recipient profile, open the dashboard, select **Decrypt**, and enter the one-time decryption key. The app verifies the signature and certificate before displaying content.
5. To demonstrate access control, revoke the sender's certificate from **Admin**. Existing messages signed with it are locked for the recipient.

Logging out in one browser profile does not log out the other. The app currently uses browser-cookie sessions rather than a server-side active-session registry, so there is no admin screen listing individual browser sessions. Suspending a user invalidates that user's sessions, and restarting the app server invalidates all login sessions.

## Repository structure

- app/__init__.py — Flask application factory
- app/config.py — environment and database configuration
- app/models.py — database models for the initial user model
- app/pki.py — PKI functions for root, issuing CA, user certs and CRL checks
- tests/test_pki.py — proof-of-concept tests for CA chain and revocation
- pytest.ini — ensures the project root is on the Python path for pytest

## Security focus

The prototype uses the recommended baseline approach:

- Flask with SQLAlchemy and a SQLite-ready data model
- X.509 certificate issuance and validation with cryptography
- CRL generation and revocation checks
- User certificate flow with non-CA key usage restrictions

## Secure exchange workflow

1. Both users register. The sender requests a signing certificate; the recipient does not need one.
2. To sign a standalone file or text, the user chooses an active signing certificate and either pastes plaintext or uploads a UTF-8 `.txt`/PDF file. This signing step follows certificate enrollment; a certificate identifies the signer and does not certify a particular document.
3. To exchange a text message, the sender chooses a recipient and an active signing certificate.
4. The application signs the message, includes the signer certificate, and encrypts the envelope for the recipient.
5. The recipient selects **Decrypt** in the inbox and enters the one-time key shared by the sender. The app checks the signature and certificate before showing the content.
6. The recipient can download a PDF only after both checks pass. To reply, the recipient starts a new exchange and selects the original sender.

To verify a saved document, choose **Verify signature** beside it on the dashboard, or open **Verify signature** in the sidebar and select a saved document. Enter only the signature in hexadecimal; the app uses the saved document and its signing certificate to verify it without asking for another upload or document paste. The entered signature must match the document's saved signature and verify cryptographically. This workflow only exposes documents owned by the signed-in user; manual verification of external signatures is not supported. Verification reports **VERIFIED** only when the signature matches and the certificate is trusted and not revoked. Otherwise, it reports **UNVERIFIED**, with each check shown separately.

The Admin page's **Revoke** action revokes the selected signing certificate. The owner's signatures from that certificate will no longer have trusted status, and it cannot be used for new signatures. Existing signed document PDFs and encrypted messages signed with that certificate are locked in the app; recipients cannot decrypt or download those encrypted messages. The signature remains in the data, but the message is unavailable through the app. Revocation is permanent; issuing a replacement certificate does not unlock old messages. Revocation cannot remove plaintext or files already downloaded, and it does not change the administrator's own access.

The Admin page's **Suspend access** action blocks the user from logging in and invalidates their existing app session on the next request, while retaining their data. **Restore access** permits login again. **Delete user and data** permanently removes the account and linked certificates, signed documents, and encrypted messages; audit events are retained for accountability. A deleted user must register again. A browser-session cookie is not a guarantee that every browser will discard session cookies on close; users should explicitly log out on shared devices.

Signing and decryption happen on the Flask server, so the server can access document plaintext while processing it. The one-time decryption key is not stored with the message, but is sent to the server when the recipient decrypts. This is not E2EE against a malicious or compromised server. Use this as a learning prototype, not for real confidential documents.

## Simple security safeguards

- Database tables are kept when the app starts; startup no longer erases user data.
- The server refuses to start without a session secret and a separate key-encryption secret.
- Server-managed user private keys are encrypted at rest with the server key-encryption secret. The server processes plaintext when signing and decrypting the simplified one-time-key messages.
- The key-encryption secret also protects CA state and legacy keys. Losing it can make those values unusable. The app does not perform an automatic database backup. Back up the database, CA-state file, and encryption secret together using a protected process before changing keys.
- Passwords must be at least 12 characters. Web forms that change data require a CSRF token, and session cookies use HttpOnly and SameSite protections.
- These safeguards protect stored data and browser sessions, but do not hide plaintext from the server. They do not protect against a compromised server, and this prototype should not be used for real confidential documents.

## Testing

```bash
cd /workspaces/uowd-project
source .venv/bin/activate
pytest -q
```

## Notes

This is a learning prototype, not a production secure-document service. Its certificate authority keys and revocation list are stored in an encrypted file under the app's instance folder so certificate trust survives restarts. Keep the private-key encryption key backed up; without it, stored user and CA keys cannot be recovered. For a real deployment, use managed key storage, protected backups, and client-held keys if the server must not be able to read documents.
