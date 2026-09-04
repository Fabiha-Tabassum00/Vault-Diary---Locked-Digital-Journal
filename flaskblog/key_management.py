# -*- coding: utf-8 -*-
"""
key_management.py
Key Management Module for Vault Diary.

Handles:
  1. Key Generation: Generates asymmetric RSA and ECC keypairs from scratch.
  2. Key Storage: Persists active and historical keys in the database KeyVault
     table. Private key material is ENCRYPTED before storage under a
     separate app-level master RSA keypair, so a leaked database does not
     expose usable private keys (requirement #6).
  3. Key Distribution: Provides active public keys for encryption and
     versioned private keys (decrypted on demand) for decryption.
  4. Key Rotation: Atomically generates new keys, re-encrypts all database
     records (User PII with RSA, Posts with ECC), recomputes HMAC integrity
     tags, updates key versions, and marks new keys as active.

Master keypair:
  A one-time, app-level RSA keypair kept in flaskblog/master_key.json
  (NOT committed to git — see .gitignore). This is the "root of trust":
  every user/post private key stored in KeyVault is encrypted under the
  master PUBLIC key, and only decrypted (in memory, on demand) using the
  master PRIVATE key. This mirrors how real key-management systems (AWS
  KMS, HashiCorp Vault) protect stored key material.
"""

import json
import os
from datetime import datetime
from flaskblog import db
from flaskblog import rsa_custom, ecc_custom, hmac_custom

MASTER_KEY_FILE = os.path.join(os.path.dirname(__file__), "master_key.json")
MASTER_KEY_BITS = 1024  # sized up since this key protects everything else


# ---------- master keypair (root of trust) ----------

def get_or_create_master_keypair():
    """Load the master RSA keypair from disk, or generate + save it if missing."""
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "r") as f:
            data = json.load(f)
        public_key = (int(data["e"]), int(data["n"]))
        private_key = (int(data["d"]), int(data["n"]))
        return public_key, private_key

    public_key, private_key = rsa_custom.generate_keys(bits=MASTER_KEY_BITS)
    e, n = public_key
    d, _ = private_key
    with open(MASTER_KEY_FILE, "w") as f:
        json.dump({"e": str(e), "d": str(d), "n": str(n)}, f)
    return public_key, private_key


# ---------- serialization (public keys: plain / private keys: master-encrypted) ----------

def serialize_rsa_public(pub_key) -> str:
    """Serialize (e, n) tuple to JSON string. Public keys don't need protecting."""
    return json.dumps([str(pub_key[0]), str(pub_key[1])])


def deserialize_rsa_public(data_str: str):
    """Deserialize JSON string to (e, n) int tuple."""
    raw = json.loads(data_str)
    return (int(raw[0]), int(raw[1]))


def serialize_rsa_private(priv_key) -> str:
    """
    Encrypt the RSA private exponent d under the master public key before
    storing. n is not secret (it's already public in the public key row),
    so only d needs protecting.
    """
    master_pub, _ = get_or_create_master_keypair()
    d, _n = priv_key
    encrypted_chunks = rsa_custom.encrypt_text(str(d), master_pub)
    return json.dumps(encrypted_chunks)


def deserialize_rsa_private(data_str: str, n: int):
    """Decrypt the stored RSA private exponent using the master private key."""
    _, master_priv = get_or_create_master_keypair()
    encrypted_chunks = json.loads(data_str)
    d = int(rsa_custom.decrypt_text(encrypted_chunks, master_priv))
    return (d, n)


def serialize_ecc_public(pub_point) -> str:
    """Serialize (Qx, Qy) tuple to JSON string. Public keys don't need protecting."""
    return json.dumps([str(pub_point[0]), str(pub_point[1])])


def deserialize_ecc_public(data_str: str):
    """Deserialize JSON string to (Qx, Qy) int tuple."""
    raw = json.loads(data_str)
    return (int(raw[0]), int(raw[1]))


def serialize_ecc_private(priv_scalar: int) -> str:
    """Encrypt the ECC private scalar under the master RSA public key before storing."""
    master_pub, _ = get_or_create_master_keypair()
    encrypted_chunks = rsa_custom.encrypt_text(str(priv_scalar), master_pub)
    return json.dumps(encrypted_chunks)


def deserialize_ecc_private(data_str: str) -> int:
    """Decrypt the stored ECC private scalar using the master private key."""
    _, master_priv = get_or_create_master_keypair()
    encrypted_chunks = json.loads(data_str)
    return int(rsa_custom.decrypt_text(encrypted_chunks, master_priv))


# ---------- ensure active keys exist ----------

def ensure_keys_initialized():
    """Ensure active RSA and ECC keys exist in the KeyVault table."""
    from flaskblog.models import KeyVault

    active_rsa = KeyVault.query.filter_by(key_type='RSA', is_active=True).first()
    if not active_rsa:
        rsa_pub, rsa_priv = rsa_custom.generate_keys(bits=512)
        rsa_entry = KeyVault(
            key_type='RSA',
            version=1,
            public_key_json=serialize_rsa_public(rsa_pub),
            private_key_json=serialize_rsa_private(rsa_priv),
            is_active=True,
            created_at=datetime.utcnow()
        )
        db.session.add(rsa_entry)

    active_ecc = KeyVault.query.filter_by(key_type='ECC', is_active=True).first()
    if not active_ecc:
        ecc_pub, ecc_priv = ecc_custom.generate_keys()
        ecc_entry = KeyVault(
            key_type='ECC',
            version=1,
            public_key_json=serialize_ecc_public(ecc_pub),
            private_key_json=serialize_ecc_private(ecc_priv),
            is_active=True,
            created_at=datetime.utcnow()
        )
        db.session.add(ecc_entry)

    db.session.commit()


# ---------- RSA key access ----------

def get_active_rsa_key_entry():
    from flaskblog.models import KeyVault
    entry = KeyVault.query.filter_by(key_type='RSA', is_active=True).order_by(KeyVault.version.desc()).first()
    if not entry:
        ensure_keys_initialized()
        entry = KeyVault.query.filter_by(key_type='RSA', is_active=True).order_by(KeyVault.version.desc()).first()
    return entry


def get_active_rsa_public_key():
    entry = get_active_rsa_key_entry()
    return deserialize_rsa_public(entry.public_key_json), entry.version


def get_active_rsa_private_key():
    entry = get_active_rsa_key_entry()
    _, n = deserialize_rsa_public(entry.public_key_json)
    return deserialize_rsa_private(entry.private_key_json, n), entry.version


def get_rsa_private_key_by_version(version: int):
    from flaskblog.models import KeyVault
    entry = KeyVault.query.filter_by(key_type='RSA', version=version).first()
    if not entry:
        return get_active_rsa_private_key()[0]
    _, n = deserialize_rsa_public(entry.public_key_json)
    return deserialize_rsa_private(entry.private_key_json, n)


def get_rsa_public_key_by_version(version: int):
    from flaskblog.models import KeyVault
    entry = KeyVault.query.filter_by(key_type='RSA', version=version).first()
    if not entry:
        return get_active_rsa_public_key()[0]
    return deserialize_rsa_public(entry.public_key_json)


# ---------- ECC key access ----------

def get_active_ecc_key_entry():
    from flaskblog.models import KeyVault
    entry = KeyVault.query.filter_by(key_type='ECC', is_active=True).order_by(KeyVault.version.desc()).first()
    if not entry:
        ensure_keys_initialized()
        entry = KeyVault.query.filter_by(key_type='ECC', is_active=True).order_by(KeyVault.version.desc()).first()
    return entry


def get_active_ecc_public_key():
    entry = get_active_ecc_key_entry()
    return deserialize_ecc_public(entry.public_key_json), entry.version


def get_active_ecc_private_key():
    entry = get_active_ecc_key_entry()
    return deserialize_ecc_private(entry.private_key_json), entry.version


def get_ecc_private_key_by_version(version: int) -> int:
    from flaskblog.models import KeyVault
    entry = KeyVault.query.filter_by(key_type='ECC', version=version).first()
    if not entry:
        return get_active_ecc_private_key()[0]
    return deserialize_ecc_private(entry.private_key_json)


def get_ecc_public_key_by_version(version: int):
    from flaskblog.models import KeyVault
    entry = KeyVault.query.filter_by(key_type='ECC', version=version).first()
    if not entry:
        return get_active_ecc_public_key()[0]
    return deserialize_ecc_public(entry.public_key_json)


# ---------- key rotation ----------

def rotate_rsa_keys():
    """
    Generate new active RSA keypair, re-encrypt all User PII with new key,
    recalculate HMAC MAC tags, and update versions atomically.
    """
    from flaskblog.models import KeyVault, User

    current_entry = get_active_rsa_key_entry()
    old_version = current_entry.version
    new_version = old_version + 1

    new_pub, new_priv = rsa_custom.generate_keys(bits=512)

    current_entry.is_active = False

    new_entry = KeyVault(
        key_type='RSA',
        version=new_version,
        public_key_json=serialize_rsa_public(new_pub),
        private_key_json=serialize_rsa_private(new_priv),
        is_active=True,
        created_at=datetime.utcnow()
    )
    db.session.add(new_entry)

    users = User.query.all()
    count = 0
    for u in users:
        old_priv = get_rsa_private_key_by_version(u.key_version)
        username = u.get_decrypted_username(old_priv)
        email = u.get_decrypted_email(old_priv)
        contact_info = u.get_decrypted_contact_info(old_priv)
        two_factor_secret = u.get_decrypted_2fa_secret(old_priv)

        u.set_user_info(
            username=username,
            email=email,
            contact_info=contact_info,
            two_factor_secret=two_factor_secret,
            rsa_pub=new_pub,
            version=new_version
        )
        count += 1

    db.session.commit()
    return {
        'key_type': 'RSA',
        'old_version': old_version,
        'new_version': new_version,
        'records_reencrypted': count
    }


def rotate_ecc_keys():
    """
    Generate new active ECC keypair, re-encrypt all Post data with new key,
    recalculate HMAC MAC tags, and update versions atomically.
    """
    from flaskblog.models import KeyVault, Post

    current_entry = get_active_ecc_key_entry()
    old_version = current_entry.version
    new_version = old_version + 1

    new_pub, new_priv = ecc_custom.generate_keys()

    current_entry.is_active = False

    new_entry = KeyVault(
        key_type='ECC',
        version=new_version,
        public_key_json=serialize_ecc_public(new_pub),
        private_key_json=serialize_ecc_private(new_priv),
        is_active=True,
        created_at=datetime.utcnow()
    )
    db.session.add(new_entry)

    posts = Post.query.all()
    count = 0
    for p in posts:
        old_priv = get_ecc_private_key_by_version(p.key_version)
        title = p.get_decrypted_title(old_priv)
        content = p.get_decrypted_content(old_priv)

        p.set_post_data(
            title=title,
            content=content,
            ecc_pub=new_pub,
            version=new_version
        )
        count += 1

    db.session.commit()
    return {
        'key_type': 'ECC',
        'old_version': old_version,
        'new_version': new_version,
        'records_reencrypted': count
    }


def rotate_all_keys():
    """Rotate both RSA and ECC keys."""
    rsa_res = rotate_rsa_keys()
    ecc_res = rotate_ecc_keys()
    return {'rsa': rsa_res, 'ecc': ecc_res}
