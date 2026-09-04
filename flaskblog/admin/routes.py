# -*-coding:utf-8 -*-
"""
admin/routes.py
Admin Dashboard, RBAC Management, Key Rotation, and System Integrity Scanner.
"""

from flask import render_template, url_for, flash, redirect, request
from flask_login import current_user
from flaskblog import db
from flaskblog.admin import admin
from flaskblog.rbac import admin_required
from flaskblog.models import User, Post, KeyVault
from flaskblog import key_management


@admin.route("/admin")
@admin_required
def dashboard():
    users = User.query.all()
    posts = Post.query.all()
    
    rsa_entry = key_management.get_active_rsa_key_entry()
    ecc_entry = key_management.get_active_ecc_key_entry()
    
    #Running integrity scan
    tampered_users = [u for u in users if not u.verify_integrity()]
    tampered_posts = [p for p in posts if not p.verify_integrity()]
    
    all_keys = KeyVault.query.order_by(KeyVault.key_type, KeyVault.version.desc()).all()
    
    return render_template(
        "admin_dashboard.html",
        title="Admin Security Dashboard",
        users=users,
        posts=posts,
        rsa_version=rsa_entry.version if rsa_entry else 1,
        ecc_version=ecc_entry.version if ecc_entry else 1,
        tampered_users_count=len(tampered_users),
        tampered_posts_count=len(tampered_posts),
        all_keys=all_keys
    )


@admin.route("/admin/rotate-keys", methods=['POST'])
@admin_required
def rotate_keys():
    target = request.form.get('key_type', 'all')
    
    try:
        if target == 'rsa':
            res = key_management.rotate_rsa_keys()
            flash(f"RSA Asymmetric Keys rotated successfully! New active version: v{res['new_version']} ({res['records_reencrypted']} user records re-encrypted).", "success")
        elif target == 'ecc':
            res = key_management.rotate_ecc_keys()
            flash(f"ECC Asymmetric Keys rotated successfully! New active version: v{res['new_version']} ({res['records_reencrypted']} post records re-encrypted).", "success")
        else:
            res = key_management.rotate_all_keys()
            flash(f"All System Keys rotated! RSA: v{res['rsa']['new_version']} ({res['rsa']['records_reencrypted']} users re-encrypted), ECC: v{res['ecc']['new_version']} ({res['ecc']['records_reencrypted']} posts re-encrypted).", "success")
    except Exception as e:
        flash(f"Key Rotation Error: {str(e)}", "danger")
        
    return redirect(url_for('admin.dashboard'))


@admin.route("/admin/scan-integrity", methods=['POST'])
@admin_required
def scan_integrity():
    users = User.query.all()
    posts = Post.query.all()
    
    corrupted_users = [u.id for u in users if not u.verify_integrity()]
    corrupted_posts = [p.id for p in posts if not p.verify_integrity()]
    
    if corrupted_users or corrupted_posts:
        flash(f"Integrity Alert! Tampered records detected. User IDs: {corrupted_users}, Post IDs: {corrupted_posts}", "danger")
    else:
        flash(f"Integrity Scan Complete: All {len(users)} user records and {len(posts)} post records passed HMAC-SHA256 MAC verification (100% authentic).", "success")
        
    return redirect(url_for('admin.dashboard'))


@admin.route("/admin/users/<int:user_id>/toggle-role", methods=['POST'])
@admin_required
def toggle_user_role(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot modify your own administrator role.", "warning")
        return redirect(url_for('admin.dashboard'))
        
    user.role = 'user' if user.role == 'admin' else 'admin'
    user.mac_tag = user.calculate_mac()
    db.session.commit()
    flash(f"User role for ID #{user.id} updated to '{user.role}'.", "success")
    return redirect(url_for('admin.dashboard'))


@admin.route("/admin/users/<int:user_id>/delete", methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own administrator account.", "warning")
        return redirect(url_for('admin.dashboard'))
    uname = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"Account for '{uname}' (ID #{user_id}) has been permanently deleted.", "success")
    return redirect(url_for('admin.dashboard'))
