from functools import wraps
from flask import abort
from flask_login import current_user

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Assuming admin has user ID = 1
        if not current_user.is_authenticated or current_user.id != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
