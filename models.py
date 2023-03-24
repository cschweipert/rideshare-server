from datetime import datetime

import bcrypt

from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token

db = SQLAlchemy()


class User(db.Model):  # pylint: disable=missing-class-docstring
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<User #{self.id}: {self.first_name}, {self.last_name}, {self.email}>"  # noqa: E501

    @classmethod
    def signup(cls, first_name, last_name, email, password):
        """User signup. Hash password and add user to system."""

        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()).decode('utf-8')

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password_hash
        )

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, email, password):
        """Authenticates user if it finds a user with a matching password hash.
        If no user is found it returns false.
        """

        user = cls.query.filter_by(email=email).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):  # noqa: E501
            access_token = create_access_token(identity=user.id)
            return {'user': user, 'access_token': access_token}
        return jsonify({'error': 'Invalid username or password'}), 401


class Ride(db.Model):
    __tablename__ = 'rides'

    id = db.Column(db.Integer, primary_key=True)
    is_ride = db.Column(db.Boolean, default=False)
    pickup = db.Column(db.String(50), nullable=False)
    destination = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    num_passengers = db.Column(db.Integer)
    bike_rack = db.Column(db.Boolean, default=False)
    ski_rack = db.Column(db.Boolean, default=False)
    comment = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))  # noqa: E501


class Message(db.Model):  # pylint: disable=missing-class-docstring
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    recipient = db.Column(db.String(50), nullable=False)
    body = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


def connect_db(app):
    """
    Connect db to Flask app.
    """

    db.app = app
    db.init_app(app)
