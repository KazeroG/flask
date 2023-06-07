from flask import request, make_response, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import app, db, bcrypt, limiter
from models import Users
import os
from langchain.llms import OpenAI
from langchain.document_loaders import PyPDFLoader
from langchain.vectorstores import Chroma
from langchain.agents.agent_toolkits import (
    create_vectorstore_agent,
    VectorStoreToolkit,
    VectorStoreInfo
)
from langchain.document_loaders import DirectoryLoader

# Error handling middleware
@app.errorhandler(400)
def handle_bad_request(e):
    app.logger.exception('Bad request')
    return make_response(jsonify({"error": "Bad request"}), 400)

@app.errorhandler(401)
def handle_unauthorized(e):
    app.logger.exception('Unauthorized')
    return make_response(jsonify({"error": "Unauthorized"}), 401)

@app.errorhandler(404)
def handle_not_found(e):
    app.logger.exception('Not found')
    return make_response(jsonify({"error": "Not found"}), 404)

@app.errorhandler(429)
def handle_too_many_requests(e):
    app.logger.exception('Too many requests')
    return make_response(jsonify({"error": "Too many requests"}), 429)

@app.errorhandler(500)
def handle_server_error(e):
    app.logger.exception('Server error')
    return make_response(jsonify({"error": "Server error"}), 500)

@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.json.get('username')
        email = request.json.get('email')
        password = request.json.get('password')

        if not username or not email or not password:
            app.logger.error('Please provide username, email, and password')
            return make_response(jsonify({"error": "Please provide username, email, and password"}), 400)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = Users(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        app.logger.info('Users registered successfully')
        return jsonify({"message": "Users registered successfully"}), 201

    except Exception as e:
        db.session.rollback()
        app.logger.exception('An error occurred while registering user')
        return make_response(jsonify({"error": "An error occurred while registering user"}), 500)

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.json.get('email')
        password = request.json.get('password')

        user = Users.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            app.logger.error('Invalid email or password')
            return make_response(jsonify({"error": "Invalid email or password"}), 401)

        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200

    except Exception as e:
        app.logger.exception('An error occurred while logging in')
        return make_response(jsonify({"error": "An error occurred while logging in"}), 500)

@app.route('/protected', methods=['GET'])
@jwt_required()  # Authentication required
def protected():
    try:
        current_user = get_jwt_identity()
        return jsonify({"user_id": current_user}), 200

    except Exception as e:
        app.logger.exception('An error occurred while accessing protected route')
        return make_response(jsonify({"error": "An error occurred while accessing protected route"}), 500)

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = Users.query.all()
        user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
        return jsonify(user_list)

    except Exception as e:
        app.logger.exception('An error occurred while fetching users')
        return make_response(jsonify({"error": "An error occurred while fetching users"}), 500)

@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            app.logger.error(f'Users not found: {user_id}')
            return make_response(jsonify({"error": "Users not found"}), 404)

        db.session.delete(user)
        db.session.commit()

        app.logger.info('Users deleted successfully')
        return jsonify({"message": "Users deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.exception('An error occurred while deleting user')
        return make_response(jsonify({"error": "An error occurred while deleting user"}), 500)
    

@app.route('/process_prompt', methods=['POST'])
def process_prompt():
    try:
        prompt = request.json['prompt']
        
        # Create instance of OpenAI LLM
        llm = OpenAI(temperature=0.1, verbose=True)

        # Set the directory path
        directory_path = 'docs'
        
        # Check if the directory path is valid
        if not os.path.isdir(directory_path):
            return make_response(jsonify({"error": "Invalid directory path"}), 400)

        # Create Directory Loader with the directory path
        loader = DirectoryLoader(directory_path)

        # Split pages from PDF files in the directory
        pages = loader.load_and_split()

        # Load documents into vector database aka ChromaDB
        store = Chroma()

        for page in pages:
            store.add_text(page.page_content, metadata={"page_number": page.page_number})

        # Create vectorstore info object
        vectorstore_info = VectorStoreInfo(
            name="docs_directory",
            description="docs directory",
            vectorstore=store
        )

        # Convert the document store into a langchain toolkit
        toolkit = VectorStoreToolkit(vectorstore_info=vectorstore_info)

        # Add the toolkit to an end-to-end LC
        agent_executor = create_vectorstore_agent(
            llm=llm,
            toolkit=toolkit,
            verbose=True
        )
        
        response = agent_executor.run(prompt)
        search = store.similarity_search_with_score(prompt) 

        return jsonify({
            'response': response,
            'search_results': search[0][0].metadata['page_number']
        })

    except Exception as e:
        app.logger.exception('An error occurred while processing prompt')
        return make_response(jsonify({"error": "An error occurred while processing prompt"}), 500)