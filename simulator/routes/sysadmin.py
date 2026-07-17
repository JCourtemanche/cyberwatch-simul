"""
Sysadmin asset endpoints (a.k.a. /assets/servers view).
  GET /api/v3/assets/servers
  GET /api/v3/assets/servers/<id>
"""
from flask import Blueprint, jsonify

from auth import require_basic_auth
from generators.assets import sysadmin_asset_detail, sysadmin_asset_summary
from generators.catalog import ASSETS, ASSETS_BY_ID, apply_pagination

from ._helpers import get_pagination, pagination_headers


sysadmin_bp = Blueprint('sysadmin', __name__, url_prefix='/api/v3/assets')


@sysadmin_bp.route('/servers', methods=['GET'])
@require_basic_auth
def list_sysadmin_assets():
    page, per_page = get_pagination()
    items, per_page, total = apply_pagination(ASSETS, page, per_page)
    return jsonify([sysadmin_asset_summary(a) for a in items]), 200, pagination_headers(page, per_page, total)


@sysadmin_bp.route('/servers/<int:asset_id>', methods=['GET'])
@require_basic_auth
def fetch_sysadmin_asset(asset_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'error': f'Sysadmin asset {asset_id} not found'}), 404
    return jsonify(sysadmin_asset_detail(asset)), 200
