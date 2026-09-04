# VaultDiary

A private, tamper-evident diary web application built for **CSE447: Cryptography and Cryptanalysis**. VaultDiary lets users write and store personal diary entries that are encrypted end-to-end — even a compromised database or a curious administrator cannot read entry content.

Built by forking [Simple-Blog-w-Flask](https://github.com/harshit-saraswat/Simple-Blog-w-Flask) and replacing every piece of authentication, storage, and session logic with custom, from-scratch cryptographic implementations.

## Features

- **Login & Registration** with encrypted account data
- **RSA encryption** (implemented from scratch) protects user PII — username, email, contact info
- **ECC / EC-ElGamal encryption** (implemented from scratch) protects diary entry content
- **Custom salted password hashing** — no bcrypt or other built-in hashing library
- **HMAC-based Two-Factor Authentication** via email/SMS OTP
- **Key Management Module** — key generation, encrypted storage, and rotation, with a master keypair protecting all user private keys at rest
- **HMAC data integrity tags** on all critical records, with an admin-facing tamper-detection scanner
- **Role-Based Access Control** — separate Admin and User privileges
- **Fully self-issued session tokens** (HMAC-signed, DB-backed) — not Flask's default signed cookies

No symmetric encryption (AES/DES) is used anywhere in the system. All cryptographic primitives — RSA, ECC, HMAC, and password hashing — are implemented from scratch without relying on built-in framework encryption functions.

## Tech Stack

- **Backend:** Python 3, Flask
- **Database:** SQLite via Flask-SQLAlchemy
- **Frontend:** HTML, Jinja2, Bootstrap
- **Email:** Flask-Mail (SMTP)
- **Custom crypto modules:** `rsa_custom.py`, `ecc_custom.py`, `hmac_custom.py`, `password_hash.py`, `key_management.py`, `session_manager.py`, `rbac.py`

## Setup Instructions

### 1. Clone the repository
```
git clone https://github.com/yourusername/VaultDiary.git
cd VaultDiary
```

### 2. Create and activate a virtual environment
```
python -m venv venv
```
Windows (cmd):
```
venv\Scripts\activate
```
Windows (PowerShell):
```
venv\Scripts\Activate.ps1
```

### 3. Install dependencies
```
pip install -r requirements.txt
```

### 4. Configure local secrets
Before running the app, a local configuration file needs to be created with your own credentials — including an application secret key, database location, and an email account (with an app-specific password, not your regular login password) used to send 2FA and password-reset codes. SMS-based 2FA can optionally be configured with a Twilio account; if left unconfigured, the app falls back to displaying the verification code directly for local testing purposes.

### 5. Initialize the database
Once configured, the application's database tables are created through a short one-time setup step before the first run. This also generates the root key used to protect all users' private keys at rest, and sets up an initial administrator account.

### 6. Run the app
```
python app.py
```

## Security Design Notes

- Private RSA/ECC keys are never stored in plaintext — they are encrypted under a separate master RSA keypair before being saved to the database.
- Password hashes use a random 16-byte salt per user with 100,000 rounds of SHA-256 stretching.
- HMAC-SHA256 (implemented from scratch, validated against RFC 4231 test vectors) is used both for data integrity tags and for signing session tokens and password-reset tokens.
- ECC uses **EC-ElGamal** rather than standard ECIES, since ECIES relies on a symmetric cipher (AES) under the hood — prohibited by the project's asymmetric-only requirement.
- Session tokens are self-issued and DB-backed, with client fingerprinting (IP + User-Agent) to detect and immediately revoke hijacked sessions.

## Course

CSE447: Cryptography and Cryptanalysis — Summer 2026, BRAC University
