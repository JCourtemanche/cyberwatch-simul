import os


class Config:
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))

    # Cyberwatch uses HTTP Basic Auth: username = access_key, password = secret_key
    AUTH_ACCESS_KEY = os.environ.get('CYBERWATCH_ACCESS_KEY', 'cyberwatch-access-key')
    AUTH_SECRET_KEY = os.environ.get('CYBERWATCH_SECRET_KEY', 'cyberwatch-secret-key')

    # Default pagination
    DEFAULT_PER_PAGE = int(os.environ.get('DEFAULT_PER_PAGE', 500))

    # Volumes for generated content
    CVE_COUNT = int(os.environ.get('CVE_COUNT', 40))
    EXTRA_SERVERS = int(os.environ.get('EXTRA_SERVERS', 12))
    SECURITY_ISSUES_COUNT = int(os.environ.get('SECURITY_ISSUES_COUNT', 15))
