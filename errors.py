# errors.py
from flask import make_response, jsonify
from logger import logger

def register_error_handlers(app):
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
