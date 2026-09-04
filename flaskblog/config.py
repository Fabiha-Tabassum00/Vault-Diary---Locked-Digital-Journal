# -*- coding: utf-8 -*-
from datetime import timedelta
from flaskblog.secrets import Secrets

class Config:
    secretsObj = Secrets()
    SECRET_KEY = secretsObj.SECRET_KEY
    SQLALCHEMY_DATABASE_URI = secretsObj.DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Secure Session Configuration (Req #11)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    
    # Mail Config
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = getattr(secretsObj, 'EMAIL_ADDRESS', 'youremail@gmail.com')
    MAIL_PASSWORD = getattr(secretsObj, 'PASSWORD', 'placeholder')
    MAIL_DEFAULT_SENDER = getattr(secretsObj, 'EMAIL_ADDRESS', 'noreply@vaultdiary.com')
    
    # SMS / Twilio Config (Optional)
    TWILIO_ACCOUNT_SID = getattr(secretsObj, 'TWILIO_ACCOUNT_SID', None)
    TWILIO_AUTH_TOKEN = getattr(secretsObj, 'TWILIO_AUTH_TOKEN', None)
    TWILIO_PHONE_NUMBER = getattr(secretsObj, 'TWILIO_PHONE_NUMBER', None)
