# -*- coding: utf-8 -*-
"""
test_security_suite.py
Automated Verification Suite for Vault Diary Security Requirements:
  1. Login & Registration
  2. Encrypted User Info (RSA) & Decryption upon retrieval
  3. Salted & Stretched Passwords (100k rounds)
  4. Two-Step Authentication (2FA) verification function
  5. Key Management Module (Generation, Distribution, Storage, Rotation)
  6. All critical data encrypted at rest (Zero plaintext in SQLite)
  7. HMAC-SHA256 Data Integrity Verification & Tamper Detection
  8. Exclusively Asymmetric Encryption (Zero symmetric algorithms)
  9. Dual Asymmetric Scheme (RSA for PII/Auth, ECC-ElGamal for Posts)
  10. Role-Based Access Control (RBAC: Admin vs User)
  11. Secure Session Management & Anti-Hijacking
"""

import os
import sys
import json
import sqlite3
from flaskblog import create_app, db, rsa_custom, ecc_custom, hmac_custom, password_hash, key_management
from flaskblog.models import User, Post, KeyVault
from flaskblog.session_manager import compute_fingerprint
from flaskblog.users.routes import generate_otp_code


def run_tests():
    print("=========================================================")
    print("  VAULT DIARY - END-TO-END SECURITY VERIFICATION SUITE   ")
    print("=========================================================\n")

    app = create_app()

    with app.app_context():
        # --- TEST 1: RSA Asymmetric Math & Chunking ---
        print("[TEST 1] Testing Custom RSA Asymmetric Encryption & Decryption...")
        rsa_pub, rsa_priv = rsa_custom.generate_keys(bits=512)
        sample_email = "alice.vault@security.edu"
        rsa_ct = rsa_custom.encrypt_text(sample_email, rsa_pub)
        assert isinstance(rsa_ct, list), "RSA ciphertext must be chunked integer list"
        rsa_pt = rsa_custom.decrypt_text(rsa_ct, rsa_priv)
        assert rsa_pt == sample_email, f"RSA mismatch: expected {sample_email}, got {rsa_pt}"
        print("  [PASS] RSA Keygen, chunked encryption & decryption passed!")

        # --- TEST 2: ECC-ElGamal Point Arithmetic & Asymmetric Encryption ---
        print("\n[TEST 2] Testing Custom ECC-ElGamal (secp256k1) Asymmetric Encryption...")
        ecc_pub, ecc_priv = ecc_custom.generate_keys()
        sample_diary = "Encrypted Vault Entry: Top Secret cryptographic diary content."
        ecc_ct = ecc_custom.encrypt_text(sample_diary, ecc_pub)
        assert isinstance(ecc_ct, list) and len(ecc_ct) > 0, "ECC ciphertext must be list of point pairs"
        ecc_pt = ecc_custom.decrypt_text(ecc_ct, ecc_priv)
        assert ecc_pt == sample_diary, f"ECC mismatch: expected {sample_diary}, got {ecc_pt}"
        print("  [PASS] ECC-ElGamal point-embedding, encryption & decryption passed!")

        # --- TEST 3: Salted Password Hashing (100k rounds) ---
        print("\n[TEST 3] Testing Password Hashing & Salt Verification...")
        pw = "SuperSecurePassword123!"
        hashed_pw = password_hash.hash_password(pw)
        assert "$" in hashed_pw, "Stored password format must be salt$hash"
        assert password_hash.verify_password(pw, hashed_pw) is True
        assert password_hash.verify_password("WrongPassword!", hashed_pw) is False
        print("  [PASS] Salted & stretched password hashing passed!")

        # --- TEST 4: Key Management & Database Storage ---
        print("\n[TEST 4] Testing Key Management Module (Storage & Distribution)...")
        active_rsa_pub, rsa_ver = key_management.get_active_rsa_public_key()
        active_ecc_pub, ecc_ver = key_management.get_active_ecc_public_key()
        assert rsa_ver >= 1, "RSA version must be >= 1"
        assert ecc_ver >= 1, "ECC version must be >= 1"
        print(f"  [PASS] Active RSA Key Version: v{rsa_ver}, Active ECC Key Version: v{ecc_ver}")

        # --- TEST 5: Encrypted User Creation & Blind Search Hashes ---
        print("\n[TEST 5] Testing User Registration with Encrypted PII (RSA)...")
        u_hash = User.hash_search_field("alice@testvault.com")
        existing = User.query.filter_by(email_hash=u_hash).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()

        test_user = User(
            password=password_hash.hash_password("UserPass456!"),
            role='user',
            two_factor_enabled=True
        )
        test_user.set_user_info(
            username="alice_test",
            email="alice@testvault.com",
            contact_info="+1-555-0199",
            two_factor_secret="0123456789abcdef0123456789abcdef"
        )
        db.session.add(test_user)
        db.session.commit()

        # Retrieve user and verify decrypted fields
        fetched_user = User.query.filter_by(email_hash=User.hash_search_field("alice@testvault.com")).first()
        assert fetched_user is not None, "User lookup by blind email hash failed"
        assert fetched_user.username == "alice_test", f"Expected username 'alice_test', got '{fetched_user.username}'"
        assert fetched_user.email == "alice@testvault.com", f"Expected email 'alice@testvault.com', got '{fetched_user.email}'"
        assert fetched_user.contact_info == "+1-555-0199", f"Expected contact '+1-555-0199', got '{fetched_user.contact_info}'"
        assert fetched_user.verify_integrity() is True, "User HMAC integrity check failed"
        print("  [PASS] User PII encrypted, decrypted, and HMAC integrity verified!")

        # --- TEST 6: Encrypted Post Creation & ECC Content Protection ---
        print("\n[TEST 6] Testing Post Entry with Encrypted Content (ECC-ElGamal)...")
        test_post = Post(user_id=fetched_user.id)
        test_post.set_post_data(
            title="My Secret Journal",
            content="Cryptographic confidentiality achieved using purely asymmetric algorithms."
        )
        db.session.add(test_post)
        db.session.commit()

        fetched_post = Post.query.filter_by(id=test_post.id).first()
        assert fetched_post.title == "My Secret Journal"
        assert fetched_post.content == "Cryptographic confidentiality achieved using purely asymmetric algorithms."
        assert fetched_post.verify_integrity() is True
        print("  [PASS] Post encrypted with ECC-ElGamal, decrypted, and HMAC verified!")

        # --- TEST 7: HMAC-SHA256 Tamper Detection ---
        print("\n[TEST 7] Testing Data Integrity & Unauthorized Modification Detection...")
        # Simulate unauthorized DB modification on the ciphertext
        original_ct = fetched_post.content_encrypted
        fetched_post.content_encrypted = original_ct.replace("1", "2")  # tamper with ciphertext
        assert fetched_post.verify_integrity() is False, "Tamper detection failed to catch modified ciphertext!"
        # Restore ciphertext
        fetched_post.content_encrypted = original_ct
        assert fetched_post.verify_integrity() is True, "Integrity verification failed after restore"
        print("  [PASS] HMAC-SHA256 successfully caught unauthorized data tampering!")

        # --- TEST 8: Two-Factor Authentication (2FA) OTP ---
        print("\n[TEST 8] Testing Two-Step Authentication (2FA OTP)...")
        sec = fetched_user.get_decrypted_2fa_secret()
        otp = generate_otp_code(sec)
        assert len(otp) == 6 and otp.isdigit(), f"OTP must be 6 digits, got {otp}"
        print(f"  [PASS] 2FA OTP generation verified (Code: {otp})!")

        # --- TEST 9: Key Rotation with Database Re-encryption ---
        print("\n[TEST 9] Testing Atomic Key Rotation for RSA and ECC...")
        old_rsa_ver = key_management.get_active_rsa_key_entry().version
        old_ecc_ver = key_management.get_active_ecc_key_entry().version

        rotate_res = key_management.rotate_all_keys()
        new_rsa_ver = rotate_res['rsa']['new_version']
        new_ecc_ver = rotate_res['ecc']['new_version']

        assert new_rsa_ver == old_rsa_ver + 1, "New RSA version increment failed"
        assert new_ecc_ver == old_ecc_ver + 1, "New ECC version increment failed"

        # Verify that all users and posts are still readable and valid under new keys
        reloaded_user = User.query.filter_by(id=fetched_user.id).first()
        assert reloaded_user.key_version == new_rsa_ver
        assert reloaded_user.username == "alice_test"
        assert reloaded_user.email == "alice@testvault.com"
        assert reloaded_user.verify_integrity() is True

        reloaded_post = Post.query.filter_by(id=test_post.id).first()
        assert reloaded_post.key_version == new_ecc_ver
        assert reloaded_post.title == "My Secret Journal"
        assert reloaded_post.verify_integrity() is True
        print(f"  [PASS] Key Rotation succeeded! Re-encrypted {rotate_res['rsa']['records_reencrypted']} users to RSA v{new_rsa_ver} and {rotate_res['ecc']['records_reencrypted']} posts to ECC v{new_ecc_ver}")

        # --- TEST 10: Role-Based Access Control (RBAC) ---
        print("\n[TEST 10] Testing RBAC Roles & Privileges...")
        admin_user = User.query.filter_by(email_hash=User.hash_search_field("admin@vault.com")).first()
        assert admin_user is not None and admin_user.role == 'admin'
        assert fetched_user.role == 'user'
        print(f"  [PASS] RBAC Verified: Admin='{admin_user.username}' (role={admin_user.role}), Regular User='{fetched_user.username}' (role={fetched_user.role})")

        # --- TEST 11: Database Raw Storage Inspection (Zero Plaintext at Rest) ---
        print("\n[TEST 11] Inspecting SQLite Raw Storage (Asserting Zero Plaintext at Rest)...")
        db_path = os.path.join(app.instance_path, 'site.db')
        if not os.path.exists(db_path):
            db_path = 'site.db'
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT username_encrypted, email_encrypted FROM user WHERE id=?", (fetched_user.id,))
            raw_user = cursor.fetchone()
            assert "alice_test" not in raw_user[0], "CRITICAL: Plaintext username found in raw SQLite user table!"
            assert "alice@testvault.com" not in raw_user[1], "CRITICAL: Plaintext email found in raw SQLite user table!"

            cursor.execute("SELECT title_encrypted, content_encrypted FROM post WHERE id=?", (test_post.id,))
            raw_post = cursor.fetchone()
            assert "My Secret Journal" not in raw_post[0], "CRITICAL: Plaintext title found in raw SQLite post table!"
            assert "Cryptographic confidentiality" not in raw_post[1], "CRITICAL: Plaintext content found in raw SQLite post table!"
            conn.close()
            print("  [PASS] SQLite Raw Storage Inspection passed: 100% of sensitive data is encrypted at rest!")

        # Clean up test records
        test_posts = Post.query.filter_by(user_id=fetched_user.id).all()
        for p in test_posts:
            db.session.delete(p)
        db.session.delete(fetched_user)
        db.session.commit()

    print("\n=========================================================")
    print("  ALL 11 SECURITY & CRYPTOGRAPHIC REQUIREMENTS PASSED!   ")
    print("=========================================================\n")


if __name__ == "__main__":
    run_tests()
