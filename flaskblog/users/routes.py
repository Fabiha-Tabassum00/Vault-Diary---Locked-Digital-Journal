# -*- coding:utf-8 -*-
"""
users/routes.py
User authentication, verification, and account management.
"""

import time
import secrets
from flask import render_template, url_for, flash, redirect, request, Blueprint, session
from flask_login import current_user, login_required
from flaskblog import db
from flaskblog.password_hash import hash_password, verify_password
from flaskblog.models import User, Post
from flaskblog.users.forms import (RegistrationForm, LoginForm, TwoFactorForm,
                                   UpdateAccountForm, RequestResetForm, ResetPasswordForm)
from flaskblog.users.utils import (save_picture, send_reset_email, mask_email,
                                   mask_phone, dispatch_2fa_code)
from flaskblog.session_manager import create_session, destroy_session_from_request, COOKIE_NAME
from flaskblog import hmac_custom

users = Blueprint('users', __name__)


def generate_otp_code(secret_hex: str) -> str:
    """Generate a 6-digit one-time verification password."""
    secret = secret_hex.encode('utf-8')
    timestamp = str(int(time.time() // 300)).encode('utf-8')
    digest = hmac_custom.hmac_sha256(secret, timestamp)
    num = int.from_bytes(digest[:4], 'big') % 1000000
    return f"{num:06d}"


@users.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = hash_password(form.password.data)
        two_fa_secret = secrets.token_hex(16)
        
        user = User(
            password=hashed_password,
            role='user',
            two_factor_enabled=True
        )
        user.set_user_info(
            username=form.username.data,
            email=form.email.data,
            contact_info=form.contact_info.data or "",
            two_factor_secret=two_fa_secret
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created successfully! Please log in.', 'success')
        return redirect(url_for('users.login'))
        
    return render_template("register.html", title="Register", form=form)


@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    form = LoginForm()
    if form.validate_on_submit():
        e_hash = User.hash_search_field(form.email.data)
        user = User.query.filter_by(email_hash=e_hash).first()
        
        if user and verify_password(form.password.data, user.password):
            if user.two_factor_enabled:
                sec = user.get_decrypted_2fa_secret() or secrets.token_hex(16)
                otp = generate_otp_code(sec)
                
                channel = 'email'
                session['pending_user_id'] = user.id
                session['pending_remember'] = form.remember.data
                session['otp_code'] = otp
                session['otp_expiry'] = time.time() + 300  # 5 minutes
                session['otp_channel'] = channel
                session['next_page'] = request.args.get('next')
                
                # Secure Out-Of-Band Dispatch (Zero plaintext code in flash)
                _, masked_target, msg = dispatch_2fa_code(user, otp, channel=channel)
                session['otp_masked_target'] = masked_target
                
                flash(msg, "info")
                return redirect(url_for('users.verify_2fa'))
            else:
                cookie_value, max_age = create_session(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Logged in successfully!', 'success')
                resp = redirect(url_for(next_page)) if next_page else redirect(url_for('main.home'))
                resp.set_cookie(COOKIE_NAME, cookie_value, max_age=max_age, httponly=True, samesite='Lax')
                return resp
        else:
            flash('Login Unsuccessful. Please check email and password!', 'danger')
            
    return render_template("login.html", title="Login", form=form)


@users.route("/verify-2fa", methods=['GET', 'POST'])
def verify_2fa():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    pending_id = session.get('pending_user_id')
    if not pending_id:
        flash('No verification pending. Please log in.', 'warning')
        return redirect(url_for('users.login'))
        
    user = User.query.get_or_404(pending_id)
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        stored_otp = session.get('otp_code')
        expiry = session.get('otp_expiry', 0)
        
        if time.time() > expiry:
            session.pop('pending_user_id', None)
            session.pop('otp_code', None)
            session.pop('otp_expiry', None)
            session.pop('otp_channel', None)
            session.pop('otp_masked_target', None)
            flash('Verification code has expired. Please log in again.', 'warning')
            return redirect(url_for('users.login'))
            
        if form.otp_code.data.strip() == stored_otp:
            remember = session.pop('pending_remember', False)
            next_page = session.pop('next_page', None)
            session.pop('pending_user_id', None)
            session.pop('otp_code', None)
            session.pop('otp_expiry', None)
            session.pop('otp_channel', None)
            session.pop('otp_masked_target', None)
            
            cookie_value, max_age = create_session(user, remember=remember)

            flash(f'Welcome back, {user.username}!', 'success')
            resp = redirect(next_page) if next_page else redirect(url_for('main.home'))
            resp.set_cookie(COOKIE_NAME, cookie_value, max_age=max_age, httponly=True, samesite='Lax')
            return resp
        else:
            flash('Invalid verification code. Please check and try again.', 'danger')
            
    current_channel = session.get('otp_channel', 'email')
    masked_target = session.get('otp_masked_target') or (mask_email(user.email) if current_channel == 'email' else mask_phone(user.contact_info))
    has_phone = bool(user.contact_info and user.contact_info.strip())
    masked_phone = mask_phone(user.contact_info) if has_phone else ""
    masked_email = mask_email(user.email)
    
    return render_template(
        "verify_2fa.html",
        title="Verification",
        form=form,
        user=user,
        current_channel=current_channel,
        masked_target=masked_target,
        has_phone=has_phone,
        masked_phone=masked_phone,
        masked_email=masked_email
    )


@users.route("/verify-2fa/resend/<string:channel>", methods=['GET', 'POST'])
def resend_2fa(channel):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    pending_id = session.get('pending_user_id')
    if not pending_id:
        flash('No verification pending. Please log in.', 'warning')
        return redirect(url_for('users.login'))
        
    user = User.query.get_or_404(pending_id)
    
    if channel not in ['email', 'sms']:
        flash('Invalid delivery method selected.', 'warning')
        return redirect(url_for('users.verify_2fa'))
        
    if channel == 'sms' and not (user.contact_info and user.contact_info.strip()):
        flash('No phone number is linked to your account. Code sent to email instead.', 'warning')
        channel = 'email'
        
    sec = user.get_decrypted_2fa_secret() or secrets.token_hex(16)
    otp = generate_otp_code(sec)
    session['otp_code'] = otp
    session['otp_expiry'] = time.time() + 300
    session['otp_channel'] = channel
    
    _, masked_target, msg = dispatch_2fa_code(user, otp, channel=channel)
    session['otp_masked_target'] = masked_target
    flash(msg, "info")
    return redirect(url_for('users.verify_2fa'))


@users.route("/logout")
def logout():
    destroy_session_from_request()
    resp = redirect(url_for('main.home'))
    resp.delete_cookie(COOKIE_NAME)
    flash('Logged out successfully!', 'info')
    return resp


@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
            
        current_user.set_user_info(
            username=form.username.data,
            email=form.email.data,
            contact_info=form.contact_info.data or "",
            two_factor_secret=current_user.get_decrypted_2fa_secret()
        )
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.contact_info.data = current_user.contact_info
        
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    integrity_ok = current_user.verify_integrity()
    
    return render_template(
        "account.html",
        title="Account",
        image_file=image_file,
        form=form,
        integrity_ok=integrity_ok
    )


@users.route("/account/delete", methods=['POST'])
@login_required
def delete_account():
    if current_user.role == 'admin':
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash("Cannot delete the only administrator account.", "warning")
            return redirect(url_for('users.account'))
    user = current_user
    destroy_session_from_request()
    db.session.delete(user)
    db.session.commit()
    flash("Your account and all associated entries have been permanently deleted.", "info")
    resp = redirect(url_for('main.home'))
    resp.delete_cookie(COOKIE_NAME)
    return resp


@users.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    u_hash = User.hash_search_field(username)
    user = User.query.filter_by(username_hash=u_hash).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template("user_post.html", posts=posts, user=user)


@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        e_hash = User.hash_search_field(form.email.data)
        user = User.query.filter_by(email_hash=e_hash).first()
        if user:
            send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('Token is invalid or expired.', 'warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = hash_password(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! Please log in.', 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html', title='Reset Password', form=form)
