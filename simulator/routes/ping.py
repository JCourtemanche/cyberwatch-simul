"""GET /api/v3/ping — used by the integration's test-module."""
from flask import Blueprint, jsonify

from auth import require_basic_auth


ping_bp = Blueprint('ping', __name__, url_prefix='/api/v3')


@ping_bp.route('/ping', methods=['GET'])
@require_basic_auth
def ping():
    return jsonify({'message': 'pong'}), 200
