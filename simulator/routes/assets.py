"""
Vulnerability asset endpoints.
  GET /api/v3/vulnerabilities/servers
  GET /api/v3/vulnerabilities/servers/<id>
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.assets import asset_detail, asset_summary
from generators.catalog import ASSETS, ASSETS_BY_ID, apply_pagination

from ._helpers import get_pagination, pagination_headers


assets_bp = Blueprint('assets', __name__, url_prefix='/api/v3/vulnerabilities')


def _matches_filters(asset):
    args = request.args

    if (env := args.get('environment_id')) and str(asset['environment']['id']) != str(env):
        return False

    if (reboot := args.get('reboot_required')) is not None:
        want = str(reboot).lower() == 'true'
        if bool(asset['reboot_required']) != want:
            return False

    if (os_key := args.get('os')) and asset['os']['key'] != os_key:
        return False

    if (group_id := args.get('group_id')) and str(group_id) not in [str(g['id']) for g in asset['groups']]:
        return False

    if (hostname := args.get('hostname')) and hostname.lower() not in asset['hostname'].lower():
        return False

    if (address := args.get('address')) and address not in asset.get('addresses', []):
        return False

    if (category := args.get('category')) and asset['category'] != category:
        return False

    if (comm_failed := args.get('communication_failed')) is not None:
        want = str(comm_failed).lower() == 'true'
        if bool(asset.get('communication_failed', False)) != want:
            return False

    return True


@assets_bp.route('/servers', methods=['GET'])
@require_basic_auth
def list_vulnerability_assets():
    filtered = [a for a in ASSETS if _matches_filters(a)]
    page, per_page = get_pagination()
    items, per_page, total = apply_pagination(filtered, page, per_page)
    return jsonify([asset_summary(a) for a in items]), 200, pagination_headers(page, per_page, total)


@assets_bp.route('/servers/<int:asset_id>', methods=['GET'])
@require_basic_auth
def fetch_vulnerability_asset(asset_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'error': f'Asset {asset_id} not found'}), 404
    return jsonify(asset_detail(asset)), 200
