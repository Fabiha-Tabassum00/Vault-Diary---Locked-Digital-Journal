# -*- coding: utf-8 -*-
"""
flaskblog/__init__.py
Application factory with blueprint registrations, session security hooks,
and cryptographic key initialization.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flaskblog.config import Config

db = SQLAlchemy()
loginManager = LoginManager()
loginManager.login_view = 'users.login'
loginManager.login_message_category = 'info'
mail = Mail()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    loginManager.init_app(app)
    mail.init_app(app)

    # Register blueprints
    from flaskblog.users.routes import users
    from flaskblog.posts.routes import posts
    from flaskblog.main.routes import main
    from flaskblog.errors.handlers import errors
    from flaskblog.admin.routes import admin

    app.register_blueprint(users)
    app.register_blueprint(posts)
    app.register_blueprint(main)
    app.register_blueprint(errors)
    app.register_blueprint(admin)

    # Register secure session verification (Req #11) — fully self-issued,
    # HMAC-signed, DB-backed sessions instead of Flask-Login's default
    # itsdangerous-signed session cookie.
    loginManager.session_protection = None  # we do our own hijack detection via fingerprinting
    from flaskblog.session_manager import load_user_from_request
    loginManager.request_loader(load_user_from_request)

    with app.app_context():
        db.create_all()
        _init_system_security()

    return app


def _init_system_security():
    """Ensure RSA/ECC keys in KeyVault and default admin account exist."""
    from flaskblog import key_management
    from flaskblog.models import User
    from flaskblog.password_hash import hash_password
    import secrets

    # Ensure RSA & ECC keys are generated
    key_management.ensure_keys_initialized()

    # Check if admin user exists
    admin_email_hash = User.hash_search_field("admin@vault.com")
    admin_uname_hash = User.hash_search_field("admin")
    admin_user = User.query.filter((User.email_hash == admin_email_hash) | (User.username_hash == admin_uname_hash)).first()
    if not admin_user:
        admin_user = User(
            password=hash_password("AdminVault123!"),
            role='admin',
            two_factor_enabled=True
        )
        admin_user.set_user_info(
            username="admin",
            email="admin@vault.com",
            contact_info="Security Administrator",
            two_factor_secret=secrets.token_hex(16)
        )
        db.session.add(admin_user)
        db.session.commit()
    else:
        # Ensure admin email is updated if needed
        if admin_user.email != "admin@vault.com" or admin_user.role != 'admin':
            admin_user.role = 'admin'
            admin_user.set_user_info(
                username="admin",
                email="admin@vault.com",
                contact_info="Security Administrator",
                two_factor_secret=admin_user.get_decrypted_2fa_secret() or secrets.token_hex(16)
            )
            db.session.commit()