# -*- coding: utf-8 -*-
"""
models.py
Database models with integrated Dual Asymmetric Encryption (RSA & ECC),
HMAC Data Integrity MAC tags, and Key Management.
"""

import json
import hashlib
import time
from datetime import datetime
from flask import current_app
from flaskblog import db, loginManager
from flaskblog import rsa_custom, ecc_custom, hmac_custom
from flask_login import UserMixin


@loginManager.user_loader
def load_user(userID):
    return User.query.get(int(userID))


class KeyVault(db.Model):
    """Stores versioned RSA and ECC asymmetric key pairs."""
    id = db.Column(db.Integer, primary_key=True)
    key_type = db.Column(db.String(10), nullable=False)  # 'RSA' or 'ECC'
    version = db.Column(db.Integer, nullable=False)
    public_key_json = db.Column(db.Text, nullable=False)
    private_key_json = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"KeyVault('{self.key_type}', v{self.version}, active={self.is_active})"


class UserSession(db.Model):
    """
    Server-side record of an active login session (requirement #11).
    Replaces Flask's default itsdangerous-signed session cookie as the
    source of truth for 'who is logged in' — the cookie only carries an
    opaque, HMAC-signed session_id; everything that matters (which user,
    when it expires, whether it's been revoked, what client fingerprint
    it was issued to) lives here server-side, so a session can be killed
    instantly (logout, hijack detection) without waiting for a cookie to
    expire client-side.
    """
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)  # HMAC(secret, user_id|ip|user-agent)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)

    def is_valid(self) -> bool:
        return (not self.revoked) and (datetime.utcnow() < self.expires_at)

    def __repr__(self):
        return f"UserSession(user={self.user_id}, expires={self.expires_at}, revoked={self.revoked})"


class User(db.Model, UserMixin):
    """
    User model storing encrypted PII using RSA Asymmetric Encryption
    and HMAC-SHA256 integrity tags for tamper detection.
    """
    id = db.Column(db.Integer, primary_key=True)
    
    # Asymmetrically encrypted PII (RSA)
    username_encrypted = db.Column(db.Text, nullable=False)
    email_encrypted = db.Column(db.Text, nullable=False)
    contact_info_encrypted = db.Column(db.Text, nullable=True)
    
    # Blind search hashes (HMAC/SHA256) for lookups and uniqueness checks without decrypting all rows
    username_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    
    image_file = db.Column(db.String(50), nullable=False, default="default.jpg")
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'user' or 'admin'
    
    # 2FA Secret (RSA Encrypted) & status
    two_factor_secret = db.Column(db.Text, nullable=True)
    two_factor_enabled = db.Column(db.Boolean, nullable=False, default=True)
    
    # Cryptographic Integrity MAC tag (HMAC-SHA256)
    mac_tag = db.Column(db.String(64), nullable=False)
    key_version = db.Column(db.Integer, nullable=False, default=1)
    
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")

    @staticmethod
    def hash_search_field(value: str) -> str:
        """Compute deterministic blind hash for lookups."""
        return hashlib.sha256(value.strip().lower().encode('utf-8')).hexdigest()

    def _get_hmac_secret(self) -> bytes:
        return current_app.config.get('SECRET_KEY', 'default-hmac-secret').encode('utf-8')

    def calculate_mac(self) -> str:
        """Compute HMAC-SHA256 over all encrypted user attributes."""
        payload = f"{self.username_encrypted}|{self.email_encrypted}|{self.contact_info_encrypted or ''}|{self.role}|{self.key_version}".encode('utf-8')
        return hmac_custom.hmac_sha256_hex(self._get_hmac_secret(), payload)

    def verify_integrity(self) -> bool:
        """Verify that user data has not been altered or tampered with."""
        expected = self.calculate_mac()
        return hmac_custom.verify_hmac(self._get_hmac_secret(), 
                                      f"{self.username_encrypted}|{self.email_encrypted}|{self.contact_info_encrypted or ''}|{self.role}|{self.key_version}".encode('utf-8'),
                                      bytes.fromhex(self.mac_tag))

    def set_user_info(self, username: str, email: str, contact_info: str = "", two_factor_secret: str = None, rsa_pub=None, version: int = None):
        """Encrypt user attributes with RSA and calculate HMAC MAC tag."""
        from flaskblog import key_management
        if rsa_pub is None or version is None:
            rsa_pub, version = key_management.get_active_rsa_public_key()

        self.username_hash = self.hash_search_field(username)
        self.email_hash = self.hash_search_field(email)

        # Encrypt with RSA public key
        ct_username = rsa_custom.encrypt_text(username, rsa_pub)
        self.username_encrypted = json.dumps(ct_username)

        ct_email = rsa_custom.encrypt_text(email, rsa_pub)
        self.email_encrypted = json.dumps(ct_email)

        ct_contact = rsa_custom.encrypt_text(contact_info or "", rsa_pub)
        self.contact_info_encrypted = json.dumps(ct_contact)

        if two_factor_secret:
            ct_2fa = rsa_custom.encrypt_text(two_factor_secret, rsa_pub)
            self.two_factor_secret = json.dumps(ct_2fa)

        self.key_version = version
        self.mac_tag = self.calculate_mac()

    def get_decrypted_username(self, priv_key=None) -> str:
        from flaskblog import key_management
        if not self.username_encrypted:
            return ""
        if priv_key is None:
            priv_key = key_management.get_rsa_private_key_by_version(self.key_version)
        try:
            chunks = json.loads(self.username_encrypted)
            return rsa_custom.decrypt_text([int(c) for c in chunks], priv_key)
        except Exception:
            return "[Decryption Error]"

    def get_decrypted_email(self, priv_key=None) -> str:
        from flaskblog import key_management
        if not self.email_encrypted:
            return ""
        if priv_key is None:
            priv_key = key_management.get_rsa_private_key_by_version(self.key_version)
        try:
            chunks = json.loads(self.email_encrypted)
            return rsa_custom.decrypt_text([int(c) for c in chunks], priv_key)
        except Exception:
            return "[Decryption Error]"

    def get_decrypted_contact_info(self, priv_key=None) -> str:
        from flaskblog import key_management
        if not self.contact_info_encrypted:
            return ""
        if priv_key is None:
            priv_key = key_management.get_rsa_private_key_by_version(self.key_version)
        try:
            chunks = json.loads(self.contact_info_encrypted)
            return rsa_custom.decrypt_text([int(c) for c in chunks], priv_key)
        except Exception:
            return ""

    def get_decrypted_2fa_secret(self, priv_key=None) -> str:
        from flaskblog import key_management
        if not self.two_factor_secret:
            return ""
        if priv_key is None:
            priv_key = key_management.get_rsa_private_key_by_version(self.key_version)
        try:
            chunks = json.loads(self.two_factor_secret)
            return rsa_custom.decrypt_text([int(c) for c in chunks], priv_key)
        except Exception:
            return ""

    @property
    def username(self) -> str:
        return self.get_decrypted_username()

    @property
    def email(self) -> str:
        return self.get_decrypted_email()

    @property
    def contact_info(self) -> str:
        return self.get_decrypted_contact_info()

    def get_reset_token(self, expires_sec=1800):
        """
        Custom HMAC-signed, time-limited password-reset token — replaces
        itsdangerous's TimedJSONWebSignatureSerializer. Format:
        "<user_id>.<expiry_unix_ts>.<hmac_signature>"
        The signature covers user_id+expiry, so neither can be tampered
        with without invalidating the token (requirement #7's MAC idea,
        applied to tokens instead of stored data).
        """
        secret = current_app.config['SECRET_KEY'].encode('utf-8')
        expiry = int(time.time()) + expires_sec
        payload = f"{self.id}.{expiry}".encode('utf-8')
        signature = hmac_custom.hmac_sha256_hex(secret, payload)
        return f"{self.id}.{expiry}.{signature}"

    @staticmethod
    def verify_reset_token(token):
        secret = current_app.config['SECRET_KEY'].encode('utf-8')
        try:
            user_id_str, expiry_str, signature = token.split('.')
            payload = f"{user_id_str}.{expiry_str}".encode('utf-8')

            if not hmac_custom.verify_hmac(secret, payload, bytes.fromhex(signature)):
                return None  # tampered or forged token

            if int(time.time()) > int(expiry_str):
                return None  # expired

            return User.query.get(int(user_id_str))
        except (ValueError, AttributeError):
            return None  # malformed token

    def __repr__(self):
        return f"User(id={self.id}, role='{self.role}', version={self.key_version})"


class Post(db.Model):
    """
    Post model storing diary entries asymmetrically encrypted using ECC ElGamal
    on curve secp256k1 with HMAC-SHA256 integrity verification.
    """
    id = db.Column(db.Integer, primary_key=True)
    
    # Asymmetrically encrypted content (ECC-ElGamal)
    title_encrypted = db.Column(db.Text, nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)
    
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Cryptographic Integrity MAC tag (HMAC-SHA256)
    mac_tag = db.Column(db.String(64), nullable=False)
    key_version = db.Column(db.Integer, nullable=False, default=1)

    def _get_hmac_secret(self) -> bytes:
        return current_app.config.get('SECRET_KEY', 'default-hmac-secret').encode('utf-8')

    def calculate_mac(self) -> str:
        """Compute HMAC-SHA256 over post's encrypted content."""
        payload = f"{self.title_encrypted}|{self.content_encrypted}|{self.user_id}|{self.key_version}".encode('utf-8')
        return hmac_custom.hmac_sha256_hex(self._get_hmac_secret(), payload)

    def verify_integrity(self) -> bool:
        """Verify that post content has not been tampered with or modified."""
        payload = f"{self.title_encrypted}|{self.content_encrypted}|{self.user_id}|{self.key_version}".encode('utf-8')
        return hmac_custom.verify_hmac(self._get_hmac_secret(), payload, bytes.fromhex(self.mac_tag))

    def set_post_data(self, title: str, content: str, ecc_pub=None, version: int = None):
        """Encrypt title and content using ECC ElGamal and compute HMAC MAC tag."""
        from flaskblog import key_management
        if ecc_pub is None or version is None:
            ecc_pub, version = key_management.get_active_ecc_public_key()

        # Encrypt with ECC ElGamal
        ct_title = ecc_custom.encrypt_text(title, ecc_pub)
        # Serialize list of point-pairs: [((C1x, C1y), (C2x, C2y)), ...]
        serialized_title = [
            [[str(pair[0][0]), str(pair[0][1])], [str(pair[1][0]), str(pair[1][1])]]
            for pair in ct_title
        ]
        self.title_encrypted = json.dumps(serialized_title)

        ct_content = ecc_custom.encrypt_text(content, ecc_pub)
        serialized_content = [
            [[str(pair[0][0]), str(pair[0][1])], [str(pair[1][0]), str(pair[1][1])]]
            for pair in ct_content
        ]
        self.content_encrypted = json.dumps(serialized_content)

        self.key_version = version
        self.mac_tag = self.calculate_mac()

    def get_decrypted_title(self, priv_key=None) -> str:
        from flaskblog import key_management
        if not self.title_encrypted:
            return ""
        if priv_key is None:
            priv_key = key_management.get_ecc_private_key_by_version(self.key_version)
        try:
            raw = json.loads(self.title_encrypted)
            ciphertext = [
                ((int(pair[0][0]), int(pair[0][1])), (int(pair[1][0]), int(pair[1][1])))
                for pair in raw
            ]
            return ecc_custom.decrypt_text(ciphertext, priv_key)
        except Exception:
            return "[Decryption Error]"

    def get_decrypted_content(self, priv_key=None) -> str:
        from flaskblog import key_management
        if not self.content_encrypted:
            return ""
        if priv_key is None:
            priv_key = key_management.get_ecc_private_key_by_version(self.key_version)
        try:
            raw = json.loads(self.content_encrypted)
            ciphertext = [
                ((int(pair[0][0]), int(pair[0][1])), (int(pair[1][0]), int(pair[1][1])))
                for pair in raw
            ]
            return ecc_custom.decrypt_text(ciphertext, priv_key)
        except Exception:
            return "[Decryption Error]"

    @property
    def title(self) -> str:
        return self.get_decrypted_title()

    @property
    def content(self) -> str:
        return self.get_decrypted_content()

    def __repr__(self):
        return f"Post(id={self.id}, user_id={self.user_id}, v{self.key_version})"
