"""
Shared helpers + persona imports for the Cyberwatch simulator.

Persona data (users, hostnames, IPs, malicious indicators) comes from the
xsiam-shared-personas package so the same Business Corp fleet appears
consistently across every XSIAM simulator.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone
from faker import Faker

# -- Shared personas (do not change these imports) ---------------------------
from xsiam_shared import (
    USERS,
    INTERNAL_IPS,
    MALICIOUS_IPS,
    MALICIOUS_DOMAINS,
    MALICIOUS_URLS,
    MALICIOUS_FILES,
    DOMAIN,
    COMPANY_NAME,
)

fake = Faker()
Faker.seed(42)
random.seed(42)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def now_utc():
    return datetime.now(timezone.utc)


def iso_z(dt=None):
    """Cyberwatch date format: 2024-05-14T14:42:47.842Z"""
    if dt is None:
        dt = now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def iso_offset(dt=None):
    """Cyberwatch also emits: 2020-11-10T16:36:29.000+01:00"""
    if dt is None:
        dt = now_utc()
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000+00:00')


def past_date(min_days=1, max_days=365):
    return now_utc() - timedelta(days=random.randint(min_days, max_days))


def generate_guid():
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Cyberwatch-specific enums
# ---------------------------------------------------------------------------

LEVELS = ['level_low', 'level_medium', 'level_high', 'level_critical']
LEVELS_WITH_INFO = ['level_info', 'level_low', 'level_medium', 'level_high', 'level_critical']
ACCESS_VECTORS = [
    'access_vector_physical',
    'access_vector_local',
    'access_vector_adjacent',
    'access_vector_network',
]
EXPLOIT_MATURITY = [
    'undefined',
    'unproven',
    'proof_of_concept',
    'functional',
    'high',
]

OS_CATALOG = {
    'windows_10': {
        'key': 'windows_10',
        'name': 'Windows 10 Pro',
        'arch': 'x86_64',
        'eol': '2025-10-14',
        'short_name': 'Windows 10',
        'type': 'Os::Windows',
    },
    'windows_11': {
        'key': 'windows_11',
        'name': 'Windows 11 Pro',
        'arch': 'x86_64',
        'eol': '2031-10-14',
        'short_name': 'Windows 11',
        'type': 'Os::Windows',
    },
    'windows_2019': {
        'key': 'windows_2019',
        'name': 'Windows Server 2019',
        'arch': 'AMD64',
        'eol': '2029-01-09',
        'short_name': 'Windows 2019',
        'type': 'Os::Windows',
    },
    'windows_2022': {
        'key': 'windows_2022',
        'name': 'Windows Server 2022',
        'arch': 'AMD64',
        'eol': '2031-10-14',
        'short_name': 'Windows 2022',
        'type': 'Os::Windows',
    },
    'ubuntu_2204_64': {
        'key': 'ubuntu_2204_64',
        'name': 'Ubuntu 22.04 LTS',
        'arch': 'x86_64',
        'eol': '2027-04-01',
        'short_name': 'Ubuntu 22.04',
        'type': 'Os::Ubuntu',
    },
    'ubuntu_2004_64': {
        'key': 'ubuntu_2004_64',
        'name': 'Ubuntu 20.04 LTS',
        'arch': 'x86_64',
        'eol': '2025-04-01',
        'short_name': 'Ubuntu 20.04',
        'type': 'Os::Ubuntu',
    },
    'debian_12_64': {
        'key': 'debian_12_64',
        'name': 'Debian 12',
        'arch': 'x86_64',
        'eol': '2028-06-10',
        'short_name': 'Debian 12',
        'type': 'Os::Debian',
    },
    'macos_ventura': {
        'key': 'macos_ventura',
        'name': 'macOS 13 Ventura',
        'arch': 'arm64',
        'eol': '2025-11-01',
        'short_name': 'macOS 13',
        'type': 'Os::Macos',
    },
    'macos_sonoma': {
        'key': 'macos_sonoma',
        'name': 'macOS 14 Sonoma',
        'arch': 'arm64',
        'eol': '2026-11-01',
        'short_name': 'macOS 14',
        'type': 'Os::Macos',
    },
    'ios_17': {
        'key': 'ios_17',
        'name': 'iOS 17',
        'arch': 'arm64',
        'eol': '2025-09-01',
        'short_name': 'iOS 17',
        'type': 'Os::Ios',
    },
}


def os_from_persona(persona):
    """Map a persona os_name to a Cyberwatch OS descriptor."""
    mapping = {
        'Windows 10 Pro': 'windows_10',
        'Windows 11 Pro': 'windows_11',
        'macOS 13 Ventura': 'macos_ventura',
        'macOS 14 Sonoma': 'macos_sonoma',
        'iOS 17': 'ios_17',
    }
    key = mapping.get(persona['os_name'], 'ubuntu_2204_64')
    return OS_CATALOG[key]


CATEGORIES = ['server', 'desktop', 'hypervisor', 'network_device', 'cloud', 'mobile']

GROUPS = [
    {'id': 601, 'name': 'ENV_PRODUCTION', 'description': None, 'color': '#12AFCB'},
    {'id': 602, 'name': 'ENV_STAGING', 'description': None, 'color': '#F0AD4E'},
    {'id': 603, 'name': 'ENV_DEV', 'description': None, 'color': '#5CB85C'},
    {'id': 610, 'name': 'APP_Web', 'description': None, 'color': '#336699'},
    {'id': 611, 'name': 'APP_Database', 'description': None, 'color': '#993366'},
    {'id': 612, 'name': 'APP_Endpoint', 'description': None, 'color': '#33CC66'},
    {'id': 620, 'name': 'SITE_Paris', 'description': None, 'color': '#996699'},
    {'id': 621, 'name': 'SITE_Lyon', 'description': None, 'color': '#669966'},
]

ENVIRONMENTS = [
    {
        'id': 31,
        'name': 'Low',
        'confidentiality_requirement': 'confidentiality_requirement_low',
        'integrity_requirement': 'integrity_requirement_low',
        'availability_requirement': 'availability_requirement_low',
        'ceiling_cvss_v3': None,
    },
    {
        'id': 32,
        'name': 'Medium',
        'confidentiality_requirement': 'confidentiality_requirement_medium',
        'integrity_requirement': 'integrity_requirement_medium',
        'availability_requirement': 'availability_requirement_medium',
        'ceiling_cvss_v3': None,
    },
    {
        'id': 33,
        'name': 'High',
        'confidentiality_requirement': 'confidentiality_requirement_high',
        'integrity_requirement': 'integrity_requirement_high',
        'availability_requirement': 'availability_requirement_high',
        'ceiling_cvss_v3': None,
    },
    {
        'id': 34,
        'name': 'Critical',
        'confidentiality_requirement': 'confidentiality_requirement_high',
        'integrity_requirement': 'integrity_requirement_high',
        'availability_requirement': 'availability_requirement_high',
        'ceiling_cvss_v3': None,
    },
]

COMPLIANCE_REPOSITORIES = [
    {'id': 11, 'name': 'CIS_Benchmark', 'description': None, 'color': '#3399CC'},
    {'id': 12, 'name': 'ANSSI_Best_Practices', 'description': None, 'color': '#CC3399'},
    {'id': 18, 'name': 'Security_Best_Practices', 'description': None, 'color': '#336699'},
]
