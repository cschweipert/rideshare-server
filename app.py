import os
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, request, jsonify, g, abort, session
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError

from helpers import model_to_dict
from models import db, connect_db, User, Ride, Message

CURRENT_USER = "curr_user"

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
jwt = JWTManager(app)

connect_db(app)


@app.before_request
def add_user_to_g():
    """If the user is logged in, add the current user to Flask global."""

    if CURRENT_USER in session:
        g.user = User.query.get(session[CURRENT_USER])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    session[CURRENT_USER] = user.id


def do_logout():
    """Logout user."""

    if CURRENT_USER in session:
        del session[CURRENT_USER]


# Authentication endpoints
@app.route('/signup', methods=['POST'])
def signup():
    """User signup."""
    if CURRENT_USER in session:
        del session[CURRENT_USER]

    data = request.get_json()

    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')

    try:
        user = User.signup(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password
            )
        db.session.commit()

    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username already taken'}), 400

    do_login(user)

    return jsonify({'message': 'User created successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    """User login."""
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = User.authenticate(email, password)

    do_login(user.get('user'))

    return user.get('access_token')


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout."""

    do_logout()

    return jsonify({'message': 'User successfully logged out.'}), 201


# Endpoints to create, modify and delete rides.
@app.route('/rides', methods=['POST'])
@jwt_required()
def create_ride():
    """
    Endpoint to create a new ride or ride request.
    """
    # id of current user
    current_user = get_jwt_identity()

    data = request.get_json()

    ride = Ride(
        user_id=current_user,
        is_ride=data.get('is_ride', False),
        pickup=data.get('pickup'),
        destination=data.get('destination'),
        date=datetime.strptime(request.json.get('date'), '%Y-%m-%d').date(),
        time=datetime.strptime(request.json.get('time'), '%H:%M'),
        num_passengers=data.get('num_passengers', None),
        bike_rack=data.get('bike_rack', False),
        ski_rack=data.get('ski_rack', False),
        comment=data.get('comment'))

    try:
        db.session.add(ride)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username already taken'}), 400
    return jsonify({'message': 'Ride created successfully'}), 201


@app.route('/rides', methods=['GET'])
def get_rides():
    """Endpoint to get all rides and ride requests."""
    user = g.get("user")
    if user is None:
        return abort(401, description='User not authorized.')

    rides = Ride.query.all()

    ride_data = [model_to_dict(ride) for ride in rides]

    return jsonify({'rides': ride_data})


@app.route('/rides/<int:ride_id>', methods=['GET'])
@jwt_required()
def get_ride(ride_id):
    """Endpoint to get a specific ride by ID."""
    user = g.get("user")
    if user is None:
        return abort(401, description='User not authorized.')

    ride = Ride.query.filter_by(id=ride_id).first()

    if ride:
        return jsonify(model_to_dict(ride))
    return jsonify({'error': 'Ride not found'}), 404


@app.route('/rides/<int:ride_id>', methods=['PUT'])
@jwt_required()
def update_ride(ride_id):
    """Endpoint to update a ride or ride request."""
    user = g.get("user")
    if user is None:
        return abort(401, description='User not authorized.')

    ride = Ride.query.filter_by(id=ride_id).first()

    if not ride:
        return jsonify({'error': 'Ride not found'}), 404

    data = request.get_json()

    ride_data = {
        'pickup': data.get('pickup', ride.pickup),
        'destination': data.get('destination', ride.destination),
        'date': data.get('date', ride.date),
        'time': data.get('time', ride.time.strftime('%H:%M:%S')),
        'num_passengers': data.get('num_passengers', ride.num_passengers),
        'bike_rack': data.get('bike_rack', ride.bike_rack),
        'ski_rack': data.get('ski_rack', ride.ski_rack),
        'comment': data.get('comment', ride.comment)
    }

    Ride.query.filter_by(id=ride_id).update(ride_data)

    db.session.commit()

    return jsonify({'message': 'Ride updated successfully'}), 200


@app.route('/rides/<int:ride_id>', methods=['DELETE'])
@jwt_required()
def delete_ride(ride_id):
    """Endpoint to delete a ride."""
    user = g.get("user")
    if user is None:
        return abort(401, description='User not authorized.')

    ride = Ride.query.filter_by(id=ride_id).first()

    if not ride:
        return jsonify({'error': 'Ride not found'}), 404

    db.session.delete(ride)
    db.session.commit()

    return jsonify({'message': 'Ride deleted successfully'}), 200


# Endpoints to send, receive, and delete messages.
@app.route('/messages', methods=['POST'])
@jwt_required()
def send_message():
    """Endpoint for sending a message."""
    user = g.get("user")
    if user is None:
        return abort(401, description='User not authorized.')

    current_user = get_jwt_identity()
    sender = current_user
    recipient = request.json.get('recipient')
    body = request.json.get('body')

    recipient_exists = User.query.filter_by(email=recipient).first()

    if not recipient_exists:
        return jsonify({'error': 'Recipient not found.'}), 404

    message = Message(sender=sender, recipient=recipient, body=body)

    db.session.add(message)
    db.session.commit()

    return jsonify({'message': 'Message sent successfully.'}), 201


@app.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    """Endpoint for retrieving a user's messages."""
    user = g.get("user")
    if user is None:
        return abort(401, description='User not authorized.')

    current_user = get_jwt_identity()

    messages_received = Message.query.filter_by(
        recipient=str(current_user)
        ).order_by(Message.timestamp.desc()).all()

    messages_sent = Message.query.filter_by(
        sender=str(current_user)
        ).order_by(Message.timestamp.desc()).all()

    received_data = [{
        'id': message.id,
        'sender': message.sender,
        'body': message.body,
        'timestamp': message.timestamp
        } for message in messages_received]

    sent_data = [{
        'id': message.id,
        'recipient': message.recipient,
        'body': message.body,
        'timestamp': message.timestamp
        } for message in messages_sent]

    return jsonify({
        'received_messages': received_data,
        'sent_messages': sent_data}), 200
