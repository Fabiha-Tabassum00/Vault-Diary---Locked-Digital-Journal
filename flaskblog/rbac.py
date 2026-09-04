"""
rbac.py
Role-Based Access Control (RBAC) decorators and utility functions.
"""

from functools import wraps
from flask import abort, flash, redirect, url_for, request
from flask_login import current_user


def role_required(*allowed_roles):
    """Decorator requiring the current user to possess one of the allowed roles."""
    def decorator(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('users.login', next=request.path))
            if current_user.role not in allowed_roles:
                abort(403)
            return fn(*args, **kwargs)
        return decorated_view
    return decorator


def admin_required(fn):
    """Decorator restricting route access strictly to administrators."""
    return role_required('admin')(fn)
