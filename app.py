import os
import logging
from flask import Flask, request, make_response, jsonify
from dotenv import load_dotenv
from flask_cors import CORS, cross_origin
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import mysql.connector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Load environment variables from .env file
load_dotenv()

# Database connection
db_connection = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME')
)

# User model
class User:
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.json.get('username')
        email = request.json.get('email')
        password = request.json.get('password')

        if not username or not email or not password:
            logger.error('Please provide username, email, and password')
            return make_response(jsonify({"error": "Please provide username, email, and password"}), 400)

        cursor = db_connection.cursor()
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        insert_query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (username, email, hashed_password))
        db_connection.commit()

        logger.info('User registered successfully')
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        logger.exception('An error occurred while registering user')
        return make_response(jsonify({"error": "An error occurred while registering user"}), 500)



@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.json.get('email')
        password = request.json.get('password')

        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            logger.error('Invalid email or password')
            return make_response(jsonify({"error": "Invalid email or password"}), 401)

        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200
    except Exception as e:
        logger.exception('An error occurred while logging in')
        return make_response(jsonify({"error": "An error occurred while logging in"}), 500)

@app.route('/protected', methods=['GET'])
@jwt_required()  # Authentication required
def protected():
    try:
        current_user = get_jwt_identity()
        return jsonify({"user_id": current_user}), 200
    except Exception as e:
        logger.exception('An error occurred while accessing protected route')
        return make_response(jsonify({"error": "An error occurred while accessing protected route"}), 500)

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
        return jsonify(user_list)
    except Exception as e:
        logger.exception('An error occurred while fetching users')
        return make_response(jsonify({"error": "An error occurred while fetching users"}), 500)

@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            logger.error(f'User not found: {user_id}')
            return make_response(jsonify({"error": "User not found"}), 404)

        db.session.delete(user)
        db.session.commit()

        logger.info('User deleted successfully')
        return jsonify({"message": "User deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception('An error occurred while deleting user')
        return make_response(jsonify({"error": "An error occurred while deleting user"}), 500)

# Error handling middleware
@app.errorhandler(400)
def handle_bad_request(e):
    logger.exception('Bad request')
    return make_response(jsonify({"error": "Bad request"}), 400)

@app.errorhandler(401)
def handle_unauthorized(e):
    logger.exception('Unauthorized')
    return make_response(jsonify({"error": "Unauthorized"}), 401)

@app.errorhandler(404)
def handle_not_found(e):
    logger.exception('Not found')
    return make_response(jsonify({"error": "Not found"}), 404)

@app.errorhandler(429)
def handle_too_many_requests(e):
    logger.exception('Too many requests')
    return make_response(jsonify({"error": "Too many requests"}), 429)

@app.errorhandler(500)
def handle_server_error(e):
    logger.exception('Server error')
    return make_response(jsonify({"error": "Server error"}), 500)


if __name__ == '__main__':
    app.run(debug=True, port=os.getenv("PORT", default=5000))