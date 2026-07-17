"""Shared route helpers."""
import math
from flask import request

from config import Config


def get_pagination():
    """
    Read page / per_page from query params.
    Returns (page, per_page).
    """
    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(request.args.get('per_page', Config.DEFAULT_PER_PAGE))
    except (TypeError, ValueError):
        per_page = Config.DEFAULT_PER_PAGE
    return page, per_page


def pagination_headers(page, per_page, total):
    """
    Build the pagination response headers Cyberwatch clients rely on.
    See the integration's `_http_request(..., resp_type="response")` calls.
    """
    total_pages = max(1, math.ceil(total / max(per_page, 1)))
    return {
        'x-page': str(page),
        'x-per-page': str(per_page),
        'x-total': str(total),
        'x-total-pages': str(total_pages),
    }
