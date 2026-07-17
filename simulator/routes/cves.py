"""
CVE endpoints.
  GET /api/v3/vulnerabilities/cve_announcements
  GET /api/v3/vulnerabilities/cve_announcements/<cve_code>
"""
from flask import Blueprint, jsonify, request, abort

from auth import require_basic_auth
from generators.catalog import CVES, CVES_BY_CODE, apply_pagination, servers_affected_by
from generators.cves import full_cve_from_catalog

from ._helpers import get_pagination, pagination_headers


cves_bp = Blueprint('cves', __name__, url_prefix='/api/v3/vulnerabilities')


def _matches_filters(cve):
    """Apply the query-string filters supported by cyberwatch-list-cves."""
    args = request.args

    if (level := args.get('level')) and cve['level'] != level:
        return False

    if (active := args.get('active')) is not None:
        want_active = str(active).lower() == 'true'
        # All catalog CVEs are considered active
        if not want_active:
            return False

    if (ignored := args.get('ignored')) is not None:
        want_ignored = str(ignored).lower() == 'true'
        if want_ignored:
            return False  # none of the catalog CVEs is ignored

    if (prio := args.get('prioritized')) is not None:
        want_prio = str(prio).lower() == 'true'
        is_prio = cve['score'] >= 8.0
        if want_prio != is_prio:
            return False

    if maturities := args.getlist('exploit_code_maturity[]'):
        if cve['exploit_code_maturity'] not in maturities:
            return False

    if avs := args.getlist('access_vector[]'):
        if cve['cvss_v3']['access_vector'] not in avs:
            return False

    if vendor := args.get('technology_vendor'):
        if not any(t['vendor'] == vendor for t in cve['technologies']):
            return False

    if product := args.get('technology_product'):
        if not any(t['product'] == product for t in cve['technologies']):
            return False

    return True


@cves_bp.route('/cve_announcements', methods=['GET'])
@require_basic_auth
def list_cves():
    filtered = [c for c in CVES if _matches_filters(c)]
    page, per_page = get_pagination()
    items, per_page, total = apply_pagination(filtered, page, per_page)
    return jsonify(items), 200, pagination_headers(page, per_page, total)


@cves_bp.route('/cve_announcements/<cve_code>', methods=['GET'])
@require_basic_auth
def fetch_cve(cve_code):
    cve = CVES_BY_CODE.get(cve_code)
    if cve is None:
        return jsonify({'error': f'CVE {cve_code} not found'}), 404
    servers = servers_affected_by(cve_code)
    payload = full_cve_from_catalog(cve, servers)
    return jsonify(payload), 200
