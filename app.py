# app.py
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from models import app, db, bcrypt
from routes import register_routes
from errors import register_error_handlers

# Load environment variables from .env file
load_dotenv()

CORS(app)

register_routes(app)
register_error_handlers(app)

if __name__ == '__main__':
    app.run(debug=True)
