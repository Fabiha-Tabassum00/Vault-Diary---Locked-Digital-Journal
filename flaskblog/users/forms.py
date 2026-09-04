# -*- coding: utf-8 -*-
"""
users/forms.py
Authentication and account management forms.
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user
from flaskblog.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    contact_info = StringField('Phone / Contact Number', validators=[Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        u_hash = User.hash_search_field(username.data)
        user = User.query.filter_by(username_hash=u_hash).first()
        if user:
            raise ValidationError('Username is already taken. Please choose a different username.')

    def validate_email(self, email):
        e_hash = User.hash_search_field(email.data)
        user = User.query.filter_by(email_hash=e_hash).first()
        if user:
            raise ValidationError('An account with this email already exists. Please choose a different email or log in.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class TwoFactorForm(FlaskForm):
    otp_code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    contact_info = StringField('Phone / Contact Number', validators=[Length(max=50)])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['png', 'jpg', 'jpeg'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if User.hash_search_field(username.data) != current_user.username_hash:
            u_hash = User.hash_search_field(username.data)
            user = User.query.filter_by(username_hash=u_hash).first()
            if user:
                raise ValidationError('Username taken. Please choose a different username.')

    def validate_email(self, email):
        if User.hash_search_field(email.data) != current_user.email_hash:
            e_hash = User.hash_search_field(email.data)
            user = User.query.filter_by(email_hash=e_hash).first()
            if user:
                raise ValidationError('Email taken. Please choose a different email.')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        e_hash = User.hash_search_field(email.data)
        user = User.query.filter_by(email_hash=e_hash).first()
        if not user:
            raise ValidationError('No account with that email exists. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
