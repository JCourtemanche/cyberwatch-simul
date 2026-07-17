"""
Security issue endpoints.
  GET /api/v3/security_issues
  GET /api/v3/security_issues/<id>
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.catalog import ASSETS, SECURITY_ISSUES, SECURITY_ISSUES_BY_ID, apply_pagination

from ._helpers import get_pagination, pagination_headers


security_issues_bp = Blueprint('security_issues', __name__, url_prefix='/api/v3')


def _matches(si):
    args = request.args
    if (level := args.get('level')) and si['level'] != level:
        return False
    if (sid := args.get('sid')) and sid not in si['sid']:
        return False
    return True


@security_issues_bp.route('/security_issues', methods=['GET'])
@require_basic_auth
def list_security_issues():
    filtered = [s for s in SECURITY_ISSUES if _matches(s)]
    page, per_page = get_pagination()
    items, per_page, total = apply_pagination(filtered, page, per_page)
    return jsonify(items), 200, pagination_headers(page, per_page, total)


@security_issues_bp.route('/security_issues/<int:si_id>', methods=['GET'])
@require_basic_auth
def fetch_security_issue(si_id):
    si = SECURITY_ISSUES_BY_ID.get(si_id)
    if si is None:
        return jsonify({'error': f'Security issue {si_id} not found'}), 404

    servers = []
    cve_codes = set()
    for asset in ASSETS:
        if any(s['id'] == si_id for s in asset['_security_issues']):
            servers.append({
                'id': asset['id'],
                'hostname': asset['hostname'],
                'os': asset['os'],
                'detected_at': si['detected_at'],
                'status': 'active',
            })
            cve_codes.update(c['cve_code'] for c in asset['_cves'])

    payload = dict(si)
    payload['servers'] = servers
    payload['servers_count'] = len(servers)
    payload['cve_announcements_count'] = len(cve_codes)
    return jsonify(payload), 200
