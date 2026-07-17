"""
Deterministic asset catalog for the Cyberwatch simulator.

Each asset combines a Business Corp persona (from xsiam-shared-personas) or
a generated server with:
  - a Cyberwatch OS descriptor
  - a category / environment / groups
  - a list of applied CVEs (references into the CVE catalog)
  - a list of applied security issues (references into the SI catalog)
  - a list of updates (patches)

The catalog is built once at import time and reused across every route.
"""
import random
from datetime import timedelta

from .base import (
    CATEGORIES,
    COMPLIANCE_REPOSITORIES,
    ENVIRONMENTS,
    GROUPS,
    OS_CATALOG,
    USERS,
    iso_z,
    iso_offset,
    now_utc,
    os_from_persona,
    past_date,
)


UPDATE_PACKAGES = [
    ('Microsoft', 'KB5031441', 'Packages::Kb', '10.0.19041.3570'),
    ('Microsoft', 'KB4041085', 'Packages::Kb', 'dc4eb637-5391-4ca8-8f08-98584d61effa'),
    ('None', 'Microsoft Office 365 ProPlus - en-us', 'Packages::WinApp', '16130.20990'),
    ('canonical', 'openssl', 'Packages::Deb', '3.0.2-0ubuntu1.15'),
    ('canonical', 'libc6', 'Packages::Deb', '2.35-0ubuntu3.4'),
    ('canonical', 'linux-image-generic', 'Packages::Deb', '5.15.0.113.113'),
    ('None', 'Google Chrome', 'Packages::WinApp', '124.0.6367.207'),
    ('mozilla', 'firefox', 'Packages::Deb', '125.0.3+build1-0ubuntu0.22.04.1'),
    ('apple', 'macOS-Ventura', 'Packages::Macos', '13.6.8'),
]


def _updates_for_asset(cve_codes, r):
    """Generate the `updates` sub-list on a full asset."""
    updates = []
    per_update_cves = max(1, len(cve_codes) // 3)
    for i in range(min(6, max(2, len(cve_codes) // per_update_cves))):
        pkg = r.choice(UPDATE_PACKAGES)
        target_version = pkg[3]
        current_version = target_version.replace('0.', '0.0').rstrip('0') + '0'
        block = cve_codes[i * per_update_cves:(i + 1) * per_update_cves]
        updates.append({
            'id': 400000 + r.randint(1, 999999),
            'ignored': False,
            'patchable': r.choice([True, True, False]),
            'target': {
                'vendor': pkg[0],
                'product': pkg[1],
                'type': pkg[2],
                'version': target_version,
            },
            'current': {
                'vendor': pkg[0],
                'product': pkg[1],
                'type': pkg[2],
                'version': current_version,
            },
            'cve_announcements': block,
        })
    return updates


# Extra generated servers to bulk up the fleet
EXTRA_SERVER_SEED = [
    ('srv-web-01.business.org', 'ubuntu_2204_64', 'server', 'Public web frontend',
     [610, 601, 620]),
    ('srv-web-02.business.org', 'ubuntu_2204_64', 'server', 'Public web frontend (redundant)',
     [610, 601, 620]),
    ('srv-db-01.business.org', 'debian_12_64', 'server', 'Primary PostgreSQL database',
     [611, 601, 620]),
    ('srv-db-02.business.org', 'debian_12_64', 'server', 'PostgreSQL replica',
     [611, 602, 620]),
    ('srv-mail.business.org', 'windows_2019', 'server', 'Exchange 2019 mailbox server',
     [601, 620]),
    ('srv-ad-01.business.org', 'windows_2022', 'server', 'Active Directory domain controller',
     [601, 620]),
    ('srv-fs-01.business.org', 'windows_2019', 'server', 'File share',
     [601, 621]),
    ('srv-vpn.business.org', 'ubuntu_2004_64', 'server', 'OpenVPN gateway',
     [601, 620]),
    ('srv-monitoring.business.org', 'debian_12_64', 'server', 'Prometheus + Grafana',
     [602, 620]),
    ('srv-ci.business.org', 'ubuntu_2204_64', 'server', 'GitLab CI runner',
     [603, 621]),
    ('esxi-01.business.org', 'ubuntu_2004_64', 'hypervisor', 'VMware ESXi host',
     [601, 620]),
    ('nas-01.business.org', 'debian_12_64', 'network_device', 'Synology NAS',
     [601, 621]),
]


def _persona_assets(cve_catalog, si_catalog, r):
    """Build one asset per Business Corp persona."""
    assets = []
    for idx, persona in enumerate(USERS):
        os_desc = os_from_persona(persona)
        category = {
            'windows': 'desktop',
            'macos': 'desktop',
            'ios': 'mobile',
        }.get(persona['os_type'], 'server')
        if persona.get('machine_type') == 'laptop':
            category = 'desktop'
        elif persona.get('machine_type') == 'mobile':
            category = 'mobile'

        created = past_date(min_days=200, max_days=800)
        last_comm = past_date(min_days=0, max_days=3)
        analyzed = last_comm - timedelta(minutes=r.randint(10, 300))

        # Pick a stable subset of CVEs and security issues
        cves_for_asset = r.sample(cve_catalog, k=r.randint(6, 14))
        sis_for_asset = r.sample(si_catalog, k=r.randint(1, 4))

        prioritized = [c for c in cves_for_asset if c['score'] >= 8.0]

        assets.append({
            'id': 900 + idx,
            'hostname': persona['hostname'],
            'description': f"Poste de {persona['name']} ({persona['email']})",
            'last_communication': iso_offset(last_comm),
            'reboot_required': r.choice([False, False, True]),
            'boot_at': iso_offset(last_comm - timedelta(days=r.randint(1, 15))),
            'category': category,
            'created_at': iso_offset(created),
            'analyzed_at': iso_z(analyzed),
            'cve_announcements_count': len(cves_for_asset),
            'prioritized_cve_announcements_count': len(prioritized),
            'updates_count': max(1, len(cves_for_asset) // 3),
            'status': 'server_vulnerable' if len(prioritized) > 0 else 'server_uptodate',
            'communication_failed': False,
            'addresses': [persona['hostname'], persona['internal_ip'], '127.0.0.1'],
            'environment': ENVIRONMENTS[2 if category in ('server', 'hypervisor') else 1],
            'os': os_desc,
            'groups': [GROUPS[g] for g in r.sample(range(len(GROUPS)), k=3)],
            'compliance_repositories': [COMPLIANCE_REPOSITORIES[r.randint(0, len(COMPLIANCE_REPOSITORIES) - 1)]],
            # Internal — used to build the "full asset" payload; not returned in list views.
            '_cves': cves_for_asset,
            '_security_issues': sis_for_asset,
        })
    return assets


def _extra_assets(cve_catalog, si_catalog, r, count):
    assets = []
    seed = EXTRA_SERVER_SEED[:count]
    for idx, (hostname, os_key, category, description, group_ids) in enumerate(seed):
        os_desc = OS_CATALOG[os_key]
        created = past_date(min_days=400, max_days=1600)
        last_comm = past_date(min_days=0, max_days=5)
        analyzed = last_comm - timedelta(minutes=r.randint(5, 240))

        cves_for_asset = r.sample(cve_catalog, k=r.randint(10, 22))
        sis_for_asset = r.sample(si_catalog, k=r.randint(2, 5))
        prioritized = [c for c in cves_for_asset if c['score'] >= 8.0]

        ip = f'10.10.{20 + (idx // 10)}.{50 + idx}'

        assets.append({
            'id': 1000 + idx,
            'hostname': hostname,
            'description': description,
            'last_communication': iso_offset(last_comm),
            'reboot_required': r.choice([False, False, True]),
            'boot_at': iso_offset(last_comm - timedelta(days=r.randint(3, 60))),
            'category': category,
            'created_at': iso_offset(created),
            'analyzed_at': iso_z(analyzed),
            'cve_announcements_count': len(cves_for_asset),
            'prioritized_cve_announcements_count': len(prioritized),
            'updates_count': max(2, len(cves_for_asset) // 3),
            'status': 'server_vulnerable' if len(prioritized) > 0 else 'server_uptodate',
            'communication_failed': False,
            'addresses': [hostname, ip, '127.0.0.1'],
            'environment': ENVIRONMENTS[3 if category == 'server' else 2],
            'os': os_desc,
            'groups': [g for g in GROUPS if g['id'] in group_ids],
            'compliance_repositories': [
                COMPLIANCE_REPOSITORIES[r.randint(0, len(COMPLIANCE_REPOSITORIES) - 1)]
            ],
            '_cves': cves_for_asset,
            '_security_issues': sis_for_asset,
        })
    return assets


def build_assets_catalog(cve_catalog, si_catalog, extra_count=12):
    r = random.Random(2718)
    assets = _persona_assets(cve_catalog, si_catalog, r)
    assets.extend(_extra_assets(cve_catalog, si_catalog, r, extra_count))
    return assets


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def asset_summary(asset):
    """Payload for GET /vulnerabilities/servers (list view)."""
    return {
        'id': asset['id'],
        'hostname': asset['hostname'],
        'description': asset['description'],
        'last_communication': asset['last_communication'],
        'reboot_required': asset['reboot_required'],
        'boot_at': asset['boot_at'],
        'category': asset['category'],
        'created_at': asset['created_at'],
        'environment': asset['environment'],
        'os': asset['os'],
        'groups': asset['groups'],
    }


def asset_detail(asset):
    """Payload for GET /vulnerabilities/servers/<id>."""
    r = random.Random(hash(asset['hostname']) & 0xFFFFFFFF)

    cve_announcements = []
    for cve in asset['_cves']:
        detected = past_date(min_days=1, max_days=180)
        cve_announcements.append({
            'cve_code': cve['cve_code'],
            'score': cve['score'],
            'environmental_score': min(10.0, cve['score'] + r.uniform(-0.5, 0.8)),
            'epss': cve['epss'],
            'ignored': False,
            'active': True,
            'detected_at': iso_z(detected),
            'fixed_at': None,
            'published': cve['published'],
            'prioritized': cve['score'] >= 8.0,
        })

    security_issues = []
    for si in asset['_security_issues']:
        security_issues.append({
            'id': si['id'],
            'sid': si['sid'],
            'level': si['level'],
            'title': si['title'],
            'description': si['description'],
            'editable': si['editable'],
            'detected_at': si['detected_at'],
            'status': r.choice(['active', 'active', 'ignored']),
        })

    cve_codes = [c['cve_code'] for c in asset['_cves']]
    updates = _updates_for_asset(cve_codes, r)

    detail = {
        'id': asset['id'],
        'hostname': asset['hostname'],
        'description': asset['description'],
        'last_communication': asset['last_communication'],
        'reboot_required': asset['reboot_required'],
        'addresses': asset['addresses'],
        'updates_count': asset['updates_count'],
        'boot_at': asset['boot_at'],
        'category': asset['category'],
        'created_at': asset['created_at'],
        'cve_announcements_count': asset['cve_announcements_count'],
        'analyzed_at': asset['analyzed_at'],
        'prioritized_cve_announcements_count': asset['prioritized_cve_announcements_count'],
        'status': asset['status'],
        'cve_announcements': cve_announcements,
        'security_issues': security_issues,
        'os': asset['os'],
        'environment': asset['environment'],
        'groups': asset['groups'],
        'compliance_repositories': asset['compliance_repositories'],
        'updates': updates,
    }
    return detail


def sysadmin_asset_summary(asset):
    """Payload for GET /assets/servers (Sysadmin view)."""
    return {
        'id': asset['id'],
        'hostname': asset['hostname'],
        'last_communication': asset['last_communication'],
        'category': asset['category'],
    }


def sysadmin_asset_detail(asset):
    """Payload for GET /assets/servers/<id>."""
    r = random.Random(hash(asset['hostname'] + '-sysadmin') & 0xFFFFFFFF)
    return {
        'id': asset['id'],
        'hostname': asset['hostname'],
        'description': asset['description'],
        'last_communication': asset['last_communication'],
        'category': asset['category'],
        'deploying_period_id': r.choice([None, 501, 502, 503]),
        'rebooting_period_id': r.choice([None, 601, 602]),
        'policy_id': r.choice([None, 701, 702, 703]),
        'ignoring_policy_id': r.choice([None, 801]),
        'os': asset['os'],
        'groups': asset['groups'],
        'environment': asset['environment'],
        'created_at': asset['created_at'],
    }


def compliance_asset_summary(asset):
    """Payload for GET /compliance/assets."""
    r = random.Random(hash(asset['hostname'] + '-comp-sum') & 0xFFFFFFFF)
    failed = r.randint(0, 20)
    succeeded = r.randint(10, 60)
    status = 'compliant' if failed == 0 else ('partial' if failed < 5 else 'non_compliant')
    return {
        'id': asset['id'],
        'hostname': asset['hostname'],
        'status': status,
        'compliance_rules_failed_count': failed,
        'compliance_rules_succeed_count': succeeded,
    }


def compliance_asset_detail(asset):
    """Payload for GET /compliance/servers/<id>."""
    r = random.Random(hash(asset['hostname'] + '-comp-det') & 0xFFFFFFFF)
    failed = r.randint(0, 20)
    succeeded = r.randint(10, 60)
    total = failed + succeeded
    status = 'compliant' if failed == 0 else ('partial' if failed < 5 else 'non_compliant')
    return {
        'id': asset['id'],
        'hostname': asset['hostname'],
        'status': status,
        'compliance_rules_count': total,
        'compliance_rules_failed_count': failed,
        'compliance_rules_succeed_count': succeeded,
        'compliance_repositories': asset['compliance_repositories'],
        'os': asset['os'],
        'groups': asset['groups'],
        'environment': asset['environment'],
        'last_communication': asset['last_communication'],
        'category': asset['category'],
    }


def declarative_data_text(asset):
    """Payload for GET /servers/<id>/info — plain text, key/value pairs."""
    lines = [
        f"HOSTNAME:{asset['hostname']}",
        f"OS:{asset['os']['name']}",
        f"OS_KEY:{asset['os']['key']}",
        f"ARCH:{asset['os'].get('arch', 'x86_64')}",
        f"CATEGORY:{asset['category']}",
        f"DESCRIPTION:{asset['description']}",
        f"ADDRESSES:{','.join(asset['addresses'])}",
        f"GROUPS:{','.join(g['name'] for g in asset['groups'])}",
        f"CVE_ANNOUNCEMENTS_COUNT:{asset['cve_announcements_count']}",
        f"PRIORITIZED_CVE_COUNT:{asset['prioritized_cve_announcements_count']}",
        f"LAST_COMMUNICATION:{asset['last_communication']}",
    ]
    return '\n'.join(lines) + '\n'
