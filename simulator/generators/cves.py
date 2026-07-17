"""
Deterministic CVE catalog. Each CVE mirrors the shape returned by
Cyberwatch's `/api/v3/vulnerabilities/cve_announcements` endpoint.
"""
import random
from datetime import timedelta

from .base import (
    EXPLOIT_MATURITY,
    LEVELS,
    iso_z,
    past_date,
)


# Real CVE codes with realistic scores. Order is stable — do not shuffle.
CVE_CATALOG_SEED = [
    ('CVE-2024-21413', 'Microsoft Outlook Remote Code Execution Vulnerability', 'level_critical', 9.8, 0.00586,
     [('microsoft', '365_apps'), ('microsoft', 'outlook')]),
    ('CVE-2024-3400', 'Palo Alto Networks PAN-OS Command Injection Vulnerability', 'level_critical', 10.0, 0.94326,
     [('paloaltonetworks', 'pan-os')]),
    ('CVE-2024-1709', 'ConnectWise ScreenConnect Authentication Bypass', 'level_critical', 10.0, 0.97231,
     [('connectwise', 'screenconnect')]),
    ('CVE-2023-46604', 'Apache ActiveMQ Remote Code Execution', 'level_critical', 10.0, 0.97418,
     [('apache', 'activemq')]),
    ('CVE-2023-4966', 'Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow', 'level_critical', 9.4, 0.96551,
     [('citrix', 'netscaler_adc')]),
    ('CVE-2023-36884', 'Windows Search Remote Code Execution Vulnerability', 'level_high', 8.8, 0.14512,
     [('microsoft', 'windows_10'), ('microsoft', 'office')]),
    ('CVE-2023-23397', 'Microsoft Outlook Elevation of Privilege Vulnerability', 'level_high', 9.8, 0.94317,
     [('microsoft', 'outlook')]),
    ('CVE-2023-38831', 'RARLAB WinRAR Code Execution', 'level_high', 7.8, 0.96428,
     [('rarlab', 'winrar')]),
    ('CVE-2023-20198', 'Cisco IOS XE Web UI Privilege Escalation', 'level_critical', 10.0, 0.96812,
     [('cisco', 'ios_xe')]),
    ('CVE-2023-34362', 'Progress MOVEit Transfer SQL Injection', 'level_critical', 9.8, 0.96551,
     [('progress', 'moveit_transfer')]),
    ('CVE-2022-30190', 'Microsoft Diagnostic Tool (Follina) Remote Code Execution', 'level_high', 7.8, 0.94212,
     [('microsoft', 'windows'), ('microsoft', 'office')]),
    ('CVE-2022-22965', 'Spring Framework Remote Code Execution (Spring4Shell)', 'level_critical', 9.8, 0.97361,
     [('vmware', 'spring_framework')]),
    ('CVE-2022-26134', 'Atlassian Confluence Server OGNL Injection', 'level_critical', 9.8, 0.97441,
     [('atlassian', 'confluence_server')]),
    ('CVE-2021-44228', 'Apache Log4j Remote Code Execution (Log4Shell)', 'level_critical', 10.0, 0.97540,
     [('apache', 'log4j')]),
    ('CVE-2021-34527', 'Windows Print Spooler Remote Code Execution (PrintNightmare)', 'level_critical', 8.8, 0.97102,
     [('microsoft', 'windows')]),
    ('CVE-2021-26855', 'Microsoft Exchange Server Remote Code Execution (ProxyLogon)', 'level_critical', 9.8, 0.97418,
     [('microsoft', 'exchange_server')]),
    ('CVE-2020-1472', 'Netlogon Elevation of Privilege (Zerologon)', 'level_critical', 10.0, 0.97428,
     [('microsoft', 'windows_server')]),
    ('CVE-2019-19781', 'Citrix Application Delivery Controller Directory Traversal', 'level_critical', 9.8, 0.97418,
     [('citrix', 'application_delivery_controller')]),
    ('CVE-2019-0708', 'Remote Desktop Services Remote Code Execution (BlueKeep)', 'level_critical', 9.8, 0.97435,
     [('microsoft', 'windows_7'), ('microsoft', 'windows_server_2008')]),
    ('CVE-2017-0144', 'Windows SMB Remote Code Execution (EternalBlue)', 'level_high', 8.1, 0.97540,
     [('microsoft', 'windows')]),
    ('CVE-2024-6387', 'OpenSSH regreSSHion Signal Handler Race Condition', 'level_high', 8.1, 0.68432,
     [('openbsd', 'openssh')]),
    ('CVE-2024-38063', 'Windows TCP/IP Remote Code Execution', 'level_critical', 9.8, 0.42155,
     [('microsoft', 'windows_10'), ('microsoft', 'windows_11')]),
    ('CVE-2023-50164', 'Apache Struts Path Traversal', 'level_critical', 9.8, 0.87124,
     [('apache', 'struts')]),
    ('CVE-2024-27198', 'JetBrains TeamCity Authentication Bypass', 'level_critical', 9.8, 0.94341,
     [('jetbrains', 'teamcity')]),
    ('CVE-2024-23917', 'JetBrains TeamCity Authentication Bypass', 'level_critical', 9.8, 0.72561,
     [('jetbrains', 'teamcity')]),
    ('CVE-2023-6875', 'POST SMTP Mailer WordPress plugin Authentication Bypass', 'level_critical', 9.8, 0.66412,
     [('wordpress', 'post_smtp_mailer')]),
    ('CVE-2024-21762', 'Fortinet FortiOS Out-of-Bounds Write', 'level_critical', 9.6, 0.94316,
     [('fortinet', 'fortios')]),
    ('CVE-2023-42917', 'Apple WebKit Memory Corruption', 'level_high', 8.8, 0.28315,
     [('apple', 'webkit'), ('apple', 'macos'), ('apple', 'ios')]),
    ('CVE-2016-3189', 'Use-after-free vulnerability in bzip2recover', 'level_medium', 6.5, 0.03568,
     [('bzip', 'bzip2'), ('python', 'python')]),
    ('CVE-2018-11776', 'Apache Struts 2 Remote Code Execution', 'level_high', 8.1, 0.96820,
     [('apache', 'struts')]),
    ('CVE-2022-1388', 'F5 BIG-IP iControl REST Authentication Bypass', 'level_critical', 9.8, 0.97317,
     [('f5', 'big-ip')]),
    ('CVE-2023-46747', 'F5 BIG-IP TMUI Authentication Bypass', 'level_critical', 9.8, 0.95412,
     [('f5', 'big-ip')]),
    ('CVE-2024-4577', 'PHP CGI Argument Injection', 'level_critical', 9.8, 0.94612,
     [('php', 'php')]),
    ('CVE-2024-30078', 'Windows Wi-Fi Driver Remote Code Execution', 'level_high', 8.8, 0.02418,
     [('microsoft', 'windows_10'), ('microsoft', 'windows_11')]),
    ('CVE-2024-26169', 'Windows Error Reporting Service Elevation of Privilege', 'level_high', 7.8, 0.10214,
     [('microsoft', 'windows_10'), ('microsoft', 'windows_11')]),
    ('CVE-2023-24880', 'Windows SmartScreen Security Feature Bypass', 'level_medium', 5.4, 0.94341,
     [('microsoft', 'windows_10')]),
    ('CVE-2022-41040', 'Microsoft Exchange Server SSRF (ProxyNotShell)', 'level_high', 8.8, 0.94531,
     [('microsoft', 'exchange_server')]),
    ('CVE-2022-41082', 'Microsoft Exchange Server RCE (ProxyNotShell)', 'level_high', 8.8, 0.94531,
     [('microsoft', 'exchange_server')]),
    ('CVE-2023-3519', 'Citrix ADC & Gateway Unauthenticated RCE', 'level_critical', 9.8, 0.96631,
     [('citrix', 'application_delivery_controller')]),
    ('CVE-2024-0204', 'Fortra GoAnywhere MFT Authentication Bypass', 'level_critical', 9.8, 0.94517,
     [('fortra', 'goanywhere_mft')]),
]


def _cwe_for(index):
    cwe_ids = ['CWE-79', 'CWE-89', 'CWE-119', 'CWE-20', 'CWE-352', 'CWE-287', 'CWE-434', 'NVD-CWE-noinfo']
    return {
        'cwe_id': cwe_ids[index % len(cwe_ids)],
        'capecs': [],
        'attacks': [],
    }


def _cvss_v3(score, av='access_vector_network'):
    return {
        'access_vector': av,
        'access_complexity': 'access_complexity_low' if score >= 8 else 'access_complexity_medium',
        'privileges_required': 'privileges_required_none' if score >= 9 else 'privileges_required_low',
        'user_interaction': 'user_interaction_none' if score >= 9.5 else 'user_interaction_required',
        'scope': 'scope_unchanged',
        'confidentiality_impact': 'confidentiality_impact_high' if score >= 7 else 'confidentiality_impact_low',
        'integrity_impact': 'integrity_impact_high' if score >= 7 else 'integrity_impact_low',
        'availability_impact': 'availability_impact_high' if score >= 7 else 'availability_impact_low',
    }


def build_cve_catalog(count=40):
    """Build the deterministic CVE catalog (list of full CVE dicts)."""
    catalog = []
    r = random.Random(1337)
    seed = CVE_CATALOG_SEED[:count]

    for idx, (code, content, level, score, epss, techs) in enumerate(seed):
        av = r.choice([
            'access_vector_network',
            'access_vector_network',
            'access_vector_local',
            'access_vector_adjacent',
        ])
        maturity = r.choice(EXPLOIT_MATURITY[2:]) if score >= 8 else r.choice(EXPLOIT_MATURITY[:3])
        exploitable = score >= 7.0 and maturity in ('proof_of_concept', 'functional', 'high')

        published = past_date(min_days=30, max_days=1500)
        last_modified = published + timedelta(days=r.randint(1, 300))

        catalog.append({
            'content': content,
            'cve_code': code,
            'last_modified': iso_z(last_modified),
            'level': level,
            'published': iso_z(published),
            'score': score,
            'score_v2': None,
            'score_v3': score,
            'score_custom': 'None',
            'epss': epss,
            'exploit_code_maturity': maturity,
            'note_custom': 'None',
            'exploitable': exploitable,
            'technologies': [{'vendor': v, 'product': p} for v, p in techs],
            'cvss': _cvss_v3(score, av),
            'cvss_v3': _cvss_v3(score, av),
            'cvss_custom': 'None',
            'cwe': _cwe_for(idx),
        })
    return catalog


def full_cve_from_catalog(cve, servers_summary):
    """
    Build the extended payload for GET /vulnerabilities/cve_announcements/<cve_code>.
    servers_summary is a list of {id, hostname, os, ...} that are affected.
    """
    extended = dict(cve)
    extended['servers'] = servers_summary
    extended['security_announcements'] = [
        {
            'sa_code': cve['cve_code'],
            'type': 'SecurityAnnouncements::MicrosoftCve',
            'link': f'https://msrc.microsoft.com/update-guide/vulnerability/{cve["cve_code"]}',
            'level': 'level_unknown',
        }
    ]
    extended['references'] = [
        {
            'code': f'CERT-EU-{cve["cve_code"].split("-")[1]}-{cve["cve_code"].split("-")[2][-3:]}',
            'source': 'CERT_EU',
            'url': f'https://cert.europa.eu/publications/security-advisories/{cve["cve_code"]}/',
        },
        {
            'code': cve['cve_code'],
            'source': 'NVD',
            'url': f'https://nvd.nist.gov/vuln/detail/{cve["cve_code"]}',
        },
    ]
    return extended
