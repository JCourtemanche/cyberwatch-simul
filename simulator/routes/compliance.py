"""
Compliance endpoints.
  GET /api/v3/compliance/assets       — list
  GET /api/v3/compliance/servers/<id> — detail
"""
from flask import Blueprint, jsonify

from auth import require_basic_auth
from generators.assets import compliance_asset_detail, compliance_asset_summary
from generators.catalog import ASSETS, ASSETS_BY_ID, apply_pagination

from ._helpers import get_pagination, pagination_headers


compliance_bp = Blueprint('compliance', __name__, url_prefix='/api/v3/compliance')


@compliance_bp.route('/assets', methods=['GET'])
@require_basic_auth
def list_compliance_assets():
    page, per_page = get_pagination()
    items, per_page, total = apply_pagination(ASSETS, page, per_page)
    return jsonify([compliance_asset_summary(a) for a in items]), 200, pagination_headers(page, per_page, total)


@compliance_bp.route('/servers/<int:asset_id>', methods=['GET'])
@require_basic_auth
def fetch_compliance_asset(asset_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'error': f'Compliance asset {asset_id} not found'}), 404
    return jsonify(compliance_asset_detail(asset)), 200
