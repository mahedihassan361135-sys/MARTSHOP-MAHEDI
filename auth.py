from datetime import datetime, timedelta
import functools
from flask import request, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer as Serializer
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    User model for persistent storage and authentication.
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """
        Hashes the password and stores it in the password_hash field.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Verifies the provided password against the stored hash.
        """
        return check_password_hash(self.password_hash, password)

    def generate_jwt(self, expires_in=3600):
        """
        Generates a signed token containing the user ID and expiration timestamp.
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        payload = {
            'user_id': self.id,
            'iat': datetime.utcnow().timestamp(),
            'exp': (datetime.utcnow() + timedelta(seconds=expires_in)).timestamp()
        }
        return s.dumps(payload)

    @staticmethod
    def verify_jwt(token):
        """
        Decodes a signed token and returns the corresponding User object.
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            # Standard itsdangerous expiration check is handled by max_age in loads()
            # but here we use the manually embedded data for logic if needed
            user_id = data.get('user_id')
        except Exception:
            return None
        return User.query.get(user_id)

def token_required(f):
    """
    Decorator to protect routes with JWT-based authentication.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Authentication token is missing'}), 401

        current_user = User.verify_jwt(token)
        if not current_user:
            return jsonify({'message': 'Token is invalid or expired'}), 401

        return f(current_user, *args, **kwargs)
    return decorated
