"""
Declarative Data endpoints (airgap scan upload + read).
  POST /api/v2/cbw_scans/scripts     — upload declarative data
  GET  /api/v3/servers/<id>/info     — read declarative data (plain text)
"""
from flask import Blueprint, jsonify, request, Response

from auth import require_basic_auth
from generators.assets import declarative_data_text
from generators.catalog import ASSETS_BY_ID


declarative_v2_bp = Blueprint('declarative_v2', __name__, url_prefix='/api/v2')
declarative_v3_bp = Blueprint('declarative_v3', __name__, url_prefix='/api/v3')


def _lookup_server_id_from_output(output_text):
    if not output_text:
        return None
    for line in output_text.splitlines():
        if line.startswith('HOSTNAME:'):
            hostname = line.split(':', 1)[1].strip()
            for asset in ASSETS_BY_ID.values():
                if asset['hostname'] == hostname:
                    return asset['id']
    return None


@declarative_v2_bp.route('/cbw_scans/scripts', methods=['POST'])
@require_basic_auth
def upload_declarative_data():
    payload = request.get_json(silent=True) or {}
    output_text = payload.get('output', '')
    server_id = _lookup_server_id_from_output(output_text)
    return jsonify({
        'server_id': server_id,
        'status': 'submitted',
        'message': 'Declarative data received' if server_id else 'Hostname not matched (server may be created asynchronously)',
    }), 202


@declarative_v3_bp.route('/servers/<int:asset_id>/info', methods=['GET'])
@require_basic_auth
def get_declarative_data(asset_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'error': f'Server {asset_id} not found'}), 404
    text = declarative_data_text(asset)
    return Response(text, status=200, mimetype='text/plain')
