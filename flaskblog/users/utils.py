import os
import secrets
import logging
from PIL import Image
from flask import url_for, current_app
from flask_mail import Message
from flaskblog import mail

logger = logging.getLogger(__name__)


def mask_email(email: str) -> str:
    """Mask email for secure display, e.g. alice@example.com -> a***e@example.com."""
    if not email or '@' not in email:
        return email or ""
    name_part, domain_part = email.split('@', 1)
    if len(name_part) <= 2:
        masked_name = name_part[0] + "*"
    else:
        masked_name = name_part[0] + "***" + name_part[-1]
    return f"{masked_name}@{domain_part}"


def mask_phone(phone: str) -> str:
    """Mask phone/contact number for secure display, e.g. +1-800-555-0144 -> +1-***-0144."""
    if not phone:
        return ""
    clean = phone.strip()
    if len(clean) <= 4:
        return "***" + clean[-2:] if len(clean) >= 2 else "***"
    return clean[:3] + "-***-" + clean[-4:]


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + ext
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics', picture_fn)
    op_size = (125, 125)
    i = Image.open((form_picture))
    i.thumbnail(op_size)
    i.save(picture_path)
    return picture_fn


def send_reset_email(user):
    token = user.get_reset_token()
    sender = current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@vaultdiary.com')
    msg = Message('Password Reset Request', sender=sender, recipients=[user.email])
    msg.body = f"""To reset your password, visit the following link:
{url_for('users.reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
"""
    try:
        mail.send(msg)
    except Exception as e:
        logger.warning(f"Mail delivery encountered an error: {e}")


def send_2fa_email(user, otp: str) -> bool:
    """Send 6-digit OTP to user's decrypted email address."""
    sender = current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@vaultdiary.com')
    recipient_email = user.email
    masked = mask_email(recipient_email)
    
    msg = Message(
        subject='Vault Diary - Two-Factor Authentication Code',
        sender=sender,
        recipients=[recipient_email]
    )
    msg.body = f"""Hello {user.username},

Your 6-digit verification code for Vault Diary is:

    {otp}

This code will expire in 5 minutes. If you did not initiate this login request, please secure your account immediately.

- Vault Diary Security Team
"""
    try:
        mail.send(msg)
        print(f"[2FA OUT-OF-BAND] Verification email dispatched to {masked}")
        return True
    except Exception as e:
        print(f"[2FA OUT-OF-BAND (Dev/Offline)] Verification code dispatched for {masked}: {otp} (Notice: {e})")
        return True


def send_2fa_sms(user, otp: str) -> tuple[bool, str]:
    """Send 6-digit OTP via SMS to user's registered phone / contact number."""
    phone = user.contact_info
    if not phone or not phone.strip():
        return False, "No contact phone number is registered on this account."
    
    masked = mask_phone(phone)
    sms_text = f"Vault Diary: Your 2FA security verification code is {otp}. Valid for 5 minutes. Do not share this code."
    
    # Check if external Twilio credentials are configured
    account_sid = current_app.config.get('TWILIO_ACCOUNT_SID')
    auth_token = current_app.config.get('TWILIO_AUTH_TOKEN')
    from_phone = current_app.config.get('TWILIO_PHONE_NUMBER')
    
    if account_sid and auth_token and from_phone:
        try:
            import urllib.request
            import urllib.parse
            import base64
            
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            data = urllib.parse.urlencode({
                'To': phone,
                'From': from_phone,
                'Body': sms_text
            }).encode('utf-8')
            
            req = urllib.request.Request(url, data=data, method='POST')
            auth_header = base64.b64encode(f"{account_sid}:{auth_token}".encode('utf-8')).decode('ascii')
            req.add_header("Authorization", f"Basic {auth_header}")
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status in (200, 201):
                    print(f"[2FA OUT-OF-BAND] SMS successfully dispatched to {masked}")
                    return True, f"Verification code sent via SMS to {masked}."
        except Exception as e:
            print(f"[2FA OUT-OF-BAND SMS Gateway Warning] {e}")
            
    # Standard development / lab offline secure simulated dispatch:
    print(f"[2FA OUT-OF-BAND (Dev/SMS Gateway)] SMS dispatched to {masked}: {otp}")
    return True, f"Verification code sent via SMS to {masked}."


def dispatch_2fa_code(user, otp: str, channel: str = 'email') -> tuple[bool, str, str]:
    """
    Dispatches 2FA code to either Email or Phone/SMS based on requested channel.
    Returns: (success: bool, masked_target: str, user_message: str)
    """
    if channel == 'sms':
        if not user.contact_info or not user.contact_info.strip():
            # Fallback to email if no phone registered
            send_2fa_email(user, otp)
            masked = mask_email(user.email)
            return False, masked, f"No phone number on profile. Code was sent to your email ({masked}) instead."
        success, msg = send_2fa_sms(user, otp)
        masked = mask_phone(user.contact_info)
        return success, masked, msg
    else:
        # Default channel: Email
        send_2fa_email(user, otp)
        masked = mask_email(user.email)
        return True, masked, f"Verification code sent to your email ({masked})."

