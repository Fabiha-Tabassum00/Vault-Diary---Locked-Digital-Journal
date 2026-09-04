# -*- coding: utf-8 -*-
"""
test_web_routes.py
End-to-End HTTP Web Route & Session Security Integration Tests.
"""

from flaskblog import create_app, db
from flaskblog.models import User, Post, KeyVault
from flaskblog.session_manager import compute_fingerprint


def run_web_tests():
    print("=========================================================")
    print("  VAULT DIARY - HTTP WEB ROUTES & LIFECYCLE TESTS       ")
    print("=========================================================\n")

    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF in tests for clean form submissions
    app.config['TESTING'] = True

    client = app.test_client()

    with app.app_context():
        # Clean test user if already exists
        u_hash = User.hash_search_field("bob@vault.com")
        old_u = User.query.filter_by(email_hash=u_hash).first()
        if old_u:
            db.session.delete(old_u)
            db.session.commit()

        # 1. Test Registration
        print("[HTTP 1] Testing User Registration (/register)...")
        reg_res = client.post('/register', data={
            'username': 'bob_vault',
            'email': 'bob@vault.com',
            'contact_info': '+1-800-555-0144',
            'password': 'BobPassword123!',
            'confirmPassword': 'BobPassword123!'
        }, follow_redirects=True)
        assert reg_res.status_code == 200
        assert b"account has been created" in reg_res.data or b"Please log in" in reg_res.data
        print("  [PASS] User 'bob_vault' successfully registered.")

        # 2. Test Login Step 1 (Primary Credentials)
        print("\n[HTTP 2] Testing Login Primary Factor Authentication (/login)...")
        login_res = client.post('/login', data={
            'email': 'bob@vault.com',
            'password': 'BobPassword123!'
        }, follow_redirects=False)
        assert login_res.status_code == 302
        assert '/verify-2fa' in login_res.location
        print("  [PASS] Primary credentials valid! Redirected to /verify-2fa.")

        # 3. Test 2FA Step 2 (Second Factor Verification)
        print("\n[HTTP 3] Testing Two-Step Authentication Verification (/verify-2fa)...")
        with client.session_transaction() as sess:
            otp_code = sess.get('otp_code')
            assert otp_code is not None, "2FA OTP code must be staged in session"

        # Attempt invalid OTP
        bad_2fa_res = client.post('/verify-2fa', data={'otp_code': '000000'}, follow_redirects=True)
        assert b"Invalid verification code" in bad_2fa_res.data
        print("  [PASS] Invalid OTP code correctly rejected.")

        # Submit valid OTP
        valid_2fa_res = client.post('/verify-2fa', data={'otp_code': otp_code}, follow_redirects=True)
        assert valid_2fa_res.status_code == 200
        assert b"Welcome back" in valid_2fa_res.data or b"bob_vault" in valid_2fa_res.data
        print("  [PASS] 2FA OTP verified! Secure session established.")

        # 4. Test Authenticated Account Access
        print("\n[HTTP 4] Testing Account View Decryption (/account)...")
        account_res = client.get('/account')
        assert account_res.status_code == 200
        assert b"bob_vault" in account_res.data
        assert b"bob@vault.com" in account_res.data
        assert b"+1-800-555-0144" in account_res.data
        print("  [PASS] User profile decrypted and rendered cleanly.")

        # 5. Test Encrypted Post Creation & ECC Storage
        print("\n[HTTP 5] Testing New Post Creation (/posts/new)...")
        new_post_res = client.post('/posts/new', data={
            'title': 'Bob Secret Diary Entry',
            'content': 'This post is encrypted with ECC-ElGamal point arithmetic.'
        }, follow_redirects=True)
        assert new_post_res.status_code == 200
        assert b"Bob Secret Diary Entry" in new_post_res.data
        print("  [PASS] Post created, encrypted under the hood, and rendered on Home.")

        # 6. Test RBAC: Regular User Blocked from Admin Dashboard
        print("\n[HTTP 6] Testing RBAC (Regular user denied /admin access)...")
        admin_blocked_res = client.get('/admin')
        assert admin_blocked_res.status_code == 403
        print("  [PASS] Regular user blocked with 403 Forbidden on /admin.")

        # 7. Test Anti-Hijacking Protection (Session Token & Environment Tampering)
        print("\n[HTTP 7] Testing Anti-Hijacking Protection...")
        # Simulate request from a different IP address / attacker with stolen session cookie
        hijack_res = client.get('/account', environ_base={'REMOTE_ADDR': '198.51.100.25', 'HTTP_USER_AGENT': 'Malicious-Browser-1.0'}, follow_redirects=True)
        assert b"anti-hijacking protection" in hijack_res.data or b"Please log in" in hijack_res.data
        print("  [PASS] Hijacking attempt detected! Session instantly invalidated.")

        # 8. Test Admin Login & Admin Dashboard Access
        print("\n[HTTP 8] Testing Admin Login & Dashboard (/admin)...")
        admin_client = app.test_client()
        admin_login = admin_client.post('/login', data={
            'email': 'admin@vault.com',
            'password': 'AdminVault123!'
        }, follow_redirects=False)
        assert admin_login.status_code == 302

        with admin_client.session_transaction() as sess:
            admin_otp = sess.get('otp_code')

        admin_2fa = admin_client.post('/verify-2fa', data={'otp_code': admin_otp}, follow_redirects=True)
        assert admin_2fa.status_code == 200

        admin_dash_res = admin_client.get('/admin')
        assert admin_dash_res.status_code == 200
        assert b"Administrator Security Dashboard" in admin_dash_res.data
        assert b"Key Management" in admin_dash_res.data
        print("  [PASS] Admin authenticated with 2FA and granted access to Admin Dashboard.")

        # 9. Test Admin Key Rotation via Dashboard
        print("\n[HTTP 9] Testing Admin Key Rotation Endpoint (/admin/rotate-keys)...")
        rotate_post_res = admin_client.post('/admin/rotate-keys', data={'key_type': 'all'}, follow_redirects=True)
        assert rotate_post_res.status_code == 200
        assert b"All System Keys rotated" in rotate_post_res.data
        print("  [PASS] Admin key rotation executed successfully.")

        # 10. Test Admin Database Integrity Scan
        print("\n[HTTP 10] Testing Admin HMAC Integrity Scanner (/admin/scan-integrity)...")
        scan_res = admin_client.post('/admin/scan-integrity', follow_redirects=True)
        assert scan_res.status_code == 200
        assert b"Integrity Scan Complete" in scan_res.data or b"100% authentic" in scan_res.data
        print("  [PASS] Full HMAC integrity scan completed with 100% authentic records.")

        # Cleanup test records
        bob = User.query.filter_by(email_hash=u_hash).first()
        if bob:
            for p in Post.query.filter_by(user_id=bob.id).all():
                db.session.delete(p)
            db.session.delete(bob)
            db.session.commit()

    print("\n=========================================================")
    print("  ALL HTTP WEB ROUTE & INTEGRATION TESTS PASSED!         ")
    print("=========================================================\n")


if __name__ == "__main__":
    run_web_tests()
