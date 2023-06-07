from flask import request, make_response, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import app, db, bcrypt
from models import User
from errors import *
from langchain.llms import OpenAI
from langchain.document_loaders import DirectoryLoader
from langchain.vectorstores import Chroma
from langchain.agents.agent_toolkits import (
    create_vectorstore_agent,
    VectorStoreToolkit,
    VectorStoreInfo,
)

# Create instance of OpenAI LLM
llm = OpenAI(temperature=0.1, verbose=True)


def process_prompt(prompt):
    # Process the prompt and return a response and search results
    # This is a placeholder implementation
    response = prompt
    search_results = ""
    return response, search_results


def register_routes(app):
    @app.route("/register", methods=["POST"])
    def register():
        try:
            username = request.json.get("username")
            email = request.json.get("email")
            password = request.json.get("password")

            if not username or not email or not password:
                logger.error("Please provide username, email, and password")
                return make_response(
                    jsonify({"error": "Please provide username, email, and password"}),
                    400,
                )

            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            logger.info("User registered successfully")
            return jsonify({"message": "User registered successfully"}), 201

        except Exception as e:
            db.session.rollback()
            logger.exception("An error occurred while registering user")
            return make_response(
                jsonify({"error": "An error occurred while registering user"}), 500
            )

    @app.route("/login", methods=["POST"])
    def login():
        try:
            email = request.json.get("email")
            password = request.json.get("password")

            user = User.query.filter_by(email=email).first()

            if not user or not bcrypt.check_password_hash(user.password, password):
                logger.error("Invalid email or password")
                return make_response(
                    jsonify({"error": "Invalid email or password"}), 401
                )

            access_token = create_access_token(identity=user.id)
            return jsonify({"access_token": access_token}), 200

        except Exception as e:
            logger.exception("An error occurred while logging in")
            return make_response(
                jsonify({"error": "An error occurred while logging in"}), 500
            )

    @app.route("/protected", methods=["GET"])
    @jwt_required()  # Authentication required
    def protected():
        try:
            current_user = get_jwt_identity()
            return jsonify({"user_id": current_user}), 200

        except Exception as e:
            logger.exception("An error occurred while accessing protected route")
            return make_response(
                jsonify({"error": "An error occurred while accessing protected route"}),
                500,
            )

    @app.route("/users", methods=["GET"])
    def get_users():
        try:
            users = User.query.all()
            user_list = [
                {"id": user.id, "username": user.username, "email": user.email}
                for user in users
            ]
            return jsonify(user_list)

        except Exception as e:
            logger.exception("An error occurred while fetching users")
            return make_response(
                jsonify({"error": "An error occurred while fetching users"}), 500
            )

    @app.route("/users/<user_id>", methods=["DELETE"])
    def delete_user(user_id):
        try:
            user = User.query.get(user_id)
            if not user:
                logger.error(f"User not found: {user_id}")
                return make_response(jsonify({"error": "User not found"}), 404)

            db.session.delete(user)
            db.session.commit()

            logger.info("User deleted successfully")
            return jsonify({"message": "User deleted successfully"}), 200

        except Exception as e:
            db.session.rollback()
            logger.exception("An error occurred while deleting user")
            return make_response(
                jsonify({"error": "An error occurred while deleting user"}), 500
            )


@app.route("/process_prompt", methods=["POST"])
def process():
    try:
        prompt = request.json["prompt"]
        response, search_results = process_prompt(prompt)
        return jsonify({"response": response, "search_results": search_results})

    except Exception as e:
        app.logger.exception("An error occurred while processing prompt")
        return make_response(
            jsonify({"error": "An error occurred while processing prompt"}), 500
        )
