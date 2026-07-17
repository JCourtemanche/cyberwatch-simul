"""
Cyberwatch authentication.

The Cortex XSIAM Cyberwatch integration authenticates with HTTP Basic Auth
where the username is the API access key and the password is the API secret
key (see integration-Cyberwatch.yml: `auth=(access_key, secret_key)`).
"""
from functools import wraps
from flask import request, jsonify
from config import Config


def require_basic_auth(f):
    """Validate HTTP Basic Auth using access_key / secret_key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != Config.AUTH_ACCESS_KEY
            or auth.password != Config.AUTH_SECRET_KEY
        ):
            return (
                jsonify({'error': 'Authorization Error: please check your API Key and Secret Key'}),
                401,
                {'WWW-Authenticate': 'Basic realm="Cyberwatch"'},
            )
        return f(*args, **kwargs)
    return decorated
