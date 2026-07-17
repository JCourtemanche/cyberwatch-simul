"""
Single instantiation of the whole Cyberwatch dataset.

Importing this module builds the CVE catalog, the security issues catalog and
the assets catalog once, then exposes them as module-level singletons that
every route reuses.
"""
from config import Config

from .assets import build_assets_catalog
from .cves import build_cve_catalog
from .security_issues import build_security_issues_catalog


CVES = build_cve_catalog(count=Config.CVE_COUNT)
SECURITY_ISSUES = build_security_issues_catalog(count=Config.SECURITY_ISSUES_COUNT)
ASSETS = build_assets_catalog(CVES, SECURITY_ISSUES, extra_count=Config.EXTRA_SERVERS)

CVES_BY_CODE = {c['cve_code']: c for c in CVES}
SECURITY_ISSUES_BY_ID = {s['id']: s for s in SECURITY_ISSUES}
ASSETS_BY_ID = {a['id']: a for a in ASSETS}


def servers_affected_by(cve_code):
    """Return a light summary of the servers on which the CVE is applied."""
    affected = []
    for asset in ASSETS:
        cve_hit = next((c for c in asset['_cves'] if c['cve_code'] == cve_code), None)
        if cve_hit is None:
            continue
        affected.append({
            'id': asset['id'],
            'hostname': asset['hostname'],
            'os': asset['os'],
            'updates': [],
            'detected_at': asset['analyzed_at'],
            'active': True,
            'ignored': False,
            'fixed_at': 'None',
            'environmental_score': cve_hit['score'],
            'prioritized': cve_hit['score'] >= 8.0,
        })
    return affected


def apply_pagination(items, page, per_page):
    """
    Slice a list according to page/per_page (1-based page).
    Returns (page_items, per_page, total).
    """
    total = len(items)
    per_page = max(1, min(per_page, 1000))
    page = max(1, page)
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], per_page, total
