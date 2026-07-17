"""
Cyberwatch to Cortex XSIAM Exposure Management (Bring Your Own Scanner)

XSIAM Automation Script.

Flow
----
1. Call the Cyberwatch integration command `cyberwatch-list-cves` with the
   supplied filters (level, prioritized, exploit maturity, per_page, hard_limit).
2. For each returned CVE, call `cyberwatch-fetch-cve` to retrieve the affected
   servers (with hostname / os / updates / detected_at / prioritized).
3. Aggregate by asset (one asset entry -> multiple CVE findings) into the
   BYOS payload shape.
4. POST the payload in batches to
   `POST /public_api/vulnerability-management/v1/external-scans/assets`
   with the Cortex API key headers.

The script returns the job ids emitted by the BYOS API plus the number of
assets and vulnerabilities submitted, so it can be chained inside a playbook.

XSIAM API reference:
  https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Submit-assets-and-vulnerabilities-from-an-external-scanner
  https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Bring-Your-Own-Scanner
"""
import demistomock as demisto  # noqa: F401  # available in the XSIAM runtime
from CommonServerPython import *  # noqa: F401,F403

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any


VENDOR = "Cyberwatch"
PRODUCT = "Vulnerability Manager"
VERSION = "1.0"

BYOS_PATH = "/public_api/vulnerability-management/v1/external-scans/assets"
DEFAULT_BATCH_SIZE = 100
DEFAULT_HARD_LIMIT = 500
DEFAULT_PER_PAGE = 500

# Cyberwatch exploit_code_maturity -> BYOS confidence
CONFIDENCE_MAP = {
    "high": "High",
    "functional": "High",
    "proof_of_concept": "Medium",
    "unproven": "Low",
    "undefined": "Potential",
}


# ---------------------------------------------------------------------------
# Cyberwatch calls
# ---------------------------------------------------------------------------

def _extract_context(results: list[dict], key: str) -> Any:
    """Pull an EntryContext value out of an executeCommand result list."""
    for entry in results:
        ctx = entry.get("EntryContext") or {}
        for k, v in ctx.items():
            # XSOAR keys look like "Cyberwatch.CVE(val.cve_code == obj.cve_code)"
            if k == key or k.startswith(f"{key}("):
                return v
    return None


def _raise_on_error(results: list[dict], command: str) -> None:
    for entry in results:
        if is_error(entry):
            err = get_error(entry)
            raise DemistoException(f"'{command}' failed: {err}")


def list_cyberwatch_cves(instance: str | None, args: dict) -> list[dict]:
    exec_args = dict(args)
    if instance:
        exec_args["using"] = instance

    demisto.debug(f"Calling cyberwatch-list-cves with {exec_args}")
    results = demisto.executeCommand("cyberwatch-list-cves", exec_args)
    _raise_on_error(results, "cyberwatch-list-cves")

    cves = _extract_context(results, "Cyberwatch.CVE")
    if not cves:
        return []
    if isinstance(cves, dict):
        cves = [cves]
    return cves


def fetch_cyberwatch_cve(instance: str | None, cve_code: str) -> dict | None:
    exec_args: dict[str, Any] = {"cve_code": cve_code}
    if instance:
        exec_args["using"] = instance

    demisto.debug(f"Calling cyberwatch-fetch-cve for {cve_code}")
    results = demisto.executeCommand("cyberwatch-fetch-cve", exec_args)
    _raise_on_error(results, "cyberwatch-fetch-cve")

    cve = _extract_context(results, "Cyberwatch.CVE")
    if isinstance(cve, list):
        cve = cve[0] if cve else None
    return cve


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _to_unix_ts(iso_str: str | None) -> int:
    """Cyberwatch dates come as ISO 8601. BYOS wants seconds since epoch."""
    if not iso_str:
        return int(datetime.now(timezone.utc).timestamp())
    txt = str(iso_str).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp())
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _confidence_from_cve(cve: dict) -> str:
    return CONFIDENCE_MAP.get((cve.get("exploit_code_maturity") or "").lower(), "Potential")


def _asset_key(server: dict) -> str:
    """Cyberwatch asset identity: prefer id, fallback to hostname."""
    if server.get("id"):
        return f"cyberwatch-server-{server['id']}"
    return f"cyberwatch-hostname-{server.get('hostname', 'unknown')}"


def _build_asset_shell(server: dict, os_name: str | None) -> dict:
    fqdns: list[str] = []
    if server.get("hostname"):
        fqdns.append(server["hostname"])
    return {
        "origin_asset_id": _asset_key(server),
        "asset_name": server.get("hostname") or _asset_key(server),
        "fqdn": fqdns,
        "os_name": os_name or (server.get("os") or {}).get("name"),
        "vendor": VENDOR,
        "product": (server.get("os") or {}).get("short_name") or PRODUCT,
        "version": (server.get("os") or {}).get("key") or "",
        "last_seen": _to_unix_ts(server.get("detected_at")),
        "origin_tags": [f"cyberwatch:server_id:{server.get('id')}"] if server.get("id") else [],
        "vulnerabilities": [],
    }


def _build_vulnerability(cve: dict, server_entry: dict) -> dict:
    cve_code = cve.get("cve_code")
    description = cve.get("content") or cve.get("description") or cve_code or ""
    return {
        "vulnerability_id": cve_code,
        "cve_id": [cve_code] if cve_code else [],
        "description": description[:1024],
        "confidence": _confidence_from_cve(cve),
        "last_seen": _to_unix_ts(server_entry.get("detected_at") or cve.get("last_modified")),
        "raw_output": json.dumps({
            "score": cve.get("score"),
            "epss": cve.get("epss"),
            "level": cve.get("level"),
            "exploit_code_maturity": cve.get("exploit_code_maturity"),
            "environmental_score": server_entry.get("environmental_score"),
            "prioritized": server_entry.get("prioritized"),
            "ignored": server_entry.get("ignored"),
            "active": server_entry.get("active"),
            "updates": server_entry.get("updates"),
        }, default=str)[:4000],
        "evidence": f"Detected by Cyberwatch on {server_entry.get('hostname') or 'unknown host'}",
        "scan_name": "Cyberwatch vulnerability scan",
    }


def build_assets_from_cves(instance: str | None, list_cves: list[dict],
                           since_ts: int | None) -> tuple[list[dict], int, int]:
    """
    For each CVE returned by list_cves, fetch its `servers[]` via fetch-cve and
    aggregate into a dict of assets. Returns (assets, cve_count, dropped_count).
    """
    assets_by_key: dict[str, dict] = {}
    dropped = 0
    considered = 0

    for cve_summary in list_cves:
        cve_code = cve_summary.get("cve_code")
        if not cve_code:
            continue
        if since_ts is not None:
            modified_ts = _to_unix_ts(cve_summary.get("last_modified"))
            if modified_ts < since_ts:
                dropped += 1
                continue

        considered += 1
        cve_full = fetch_cyberwatch_cve(instance, cve_code) or cve_summary

        servers = cve_full.get("servers") or []
        for server in servers:
            key = _asset_key(server)
            asset = assets_by_key.get(key)
            if asset is None:
                asset = _build_asset_shell(server, (server.get("os") or {}).get("name"))
                assets_by_key[key] = asset
            asset["vulnerabilities"].append(_build_vulnerability(cve_full, server))
            # Roll `last_seen` forward as we see fresher detections
            new_last = _to_unix_ts(server.get("detected_at"))
            if new_last > asset["last_seen"]:
                asset["last_seen"] = new_last

    return list(assets_by_key.values()), considered, dropped


# ---------------------------------------------------------------------------
# BYOS submission
# ---------------------------------------------------------------------------

def _batched(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def submit_batch(base_url: str, api_key: str, api_key_id: str, verify: bool,
                 payload: dict) -> dict:
    """POST one BYOS batch to Cortex XSIAM and return the parsed response."""
    client = BaseClient(
        base_url=base_url.rstrip("/"),
        verify=verify,
        headers={
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    response = client._http_request(
        method="POST",
        url_suffix=BYOS_PATH,
        json_data=payload,
        resp_type="response",
        ok_codes=(200, 201, 202),
        timeout=120,
    )
    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text}
    return body


def _parse_since(since: str | None) -> int | None:
    if not since:
        return None
    try:
        parsed = dateparser.parse(since)
    except Exception:  # pragma: no cover - dateparser is always available in XSOAR
        parsed = None
    if parsed is None:
        raise DemistoException(f"Invalid 'since' value: {since!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _bool_arg(value, default=False) -> bool | None:
    if value is None or value == "":
        return default
    return str(value).lower() in ("true", "yes", "1")


def main():
    args = demisto.args() or {}

    api_url = args.get("api_url")
    api_key = args.get("api_key")
    api_key_id = args.get("api_key_id")

    if not api_url or not api_key or not api_key_id:
        raise DemistoException(
            "'api_url', 'api_key' and 'api_key_id' are required (Cortex XSIAM API key + tenant URL)."
        )

    instance = args.get("cyberwatch_instance")
    verify = _bool_arg(args.get("verify"), default=True)
    batch_size = int(args.get("batch_size") or DEFAULT_BATCH_SIZE)
    dry_run = _bool_arg(args.get("dry_run"), default=False)

    # Build the args passed to cyberwatch-list-cves
    cw_args: dict[str, Any] = {
        "per_page": args.get("per_page") or DEFAULT_PER_PAGE,
        "hard_limit": args.get("hard_limit") or DEFAULT_HARD_LIMIT,
    }
    for key in ("level", "prioritized", "active", "ignored",
                "technology_vendor", "technology_product"):
        if args.get(key) not in (None, ""):
            cw_args[key] = args[key]
    for key in ("exploit_code_maturity", "access_vector", "groups"):
        if args.get(key) not in (None, ""):
            cw_args[f"{key}[]"] = args[key]

    since_ts = _parse_since(args.get("since"))

    demisto.info(f"Fetching CVEs from Cyberwatch with args={cw_args} since={since_ts}")
    list_cves = list_cyberwatch_cves(instance, cw_args)
    demisto.info(f"cyberwatch-list-cves returned {len(list_cves)} CVEs")

    if not list_cves:
        return_results(CommandResults(
            outputs_prefix="Cyberwatch.BYOS",
            outputs={"assets_count": 0, "vulnerabilities_count": 0, "jobs": []},
            readable_output="No CVEs returned by Cyberwatch - nothing to submit.",
        ))
        return

    assets, considered, dropped = build_assets_from_cves(instance, list_cves, since_ts)
    vuln_count = sum(len(a["vulnerabilities"]) for a in assets)

    demisto.info(
        f"Prepared {len(assets)} assets / {vuln_count} vulnerabilities "
        f"({considered} CVEs considered, {dropped} dropped by 'since')"
    )

    if not assets:
        return_results(CommandResults(
            outputs_prefix="Cyberwatch.BYOS",
            outputs={
                "assets_count": 0,
                "vulnerabilities_count": 0,
                "cves_considered": considered,
                "cves_dropped_by_since": dropped,
                "jobs": [],
            },
            readable_output=(
                f"No assets built from {considered} CVEs. "
                "Either no CVE has affected servers, or all were filtered out."
            ),
        ))
        return

    if dry_run:
        return_results(CommandResults(
            outputs_prefix="Cyberwatch.BYOS",
            outputs={
                "assets_count": len(assets),
                "vulnerabilities_count": vuln_count,
                "cves_considered": considered,
                "cves_dropped_by_since": dropped,
                "sample_payload": {
                    "vendor": VENDOR, "product": PRODUCT, "version": VERSION,
                    "assets": assets[:2],
                },
                "jobs": [],
            },
            readable_output=(
                f"[dry_run] Would submit {len(assets)} assets / {vuln_count} "
                f"vulnerabilities to Cortex XSIAM BYOS in batches of {batch_size}."
            ),
        ))
        return

    jobs: list[dict] = []
    for i, batch in enumerate(_batched(assets, batch_size), start=1):
        batch_vulns = sum(len(a["vulnerabilities"]) for a in batch)
        payload = {
            "vendor": VENDOR,
            "product": PRODUCT,
            "version": VERSION,
            "assets": batch,
        }
        demisto.info(f"Submitting batch {i}: {len(batch)} assets / {batch_vulns} vulnerabilities")
        response = submit_batch(api_url, api_key, api_key_id, verify, payload)
        jobs.append({
            "batch": i,
            "assets_in_batch": len(batch),
            "vulnerabilities_in_batch": batch_vulns,
            "response": response,
        })

    return_results(CommandResults(
        outputs_prefix="Cyberwatch.BYOS",
        outputs={
            "assets_count": len(assets),
            "vulnerabilities_count": vuln_count,
            "cves_considered": considered,
            "cves_dropped_by_since": dropped,
            "jobs": jobs,
        },
        readable_output=tableToMarkdown(
            f"Cyberwatch -> Cortex XSIAM BYOS ({len(assets)} assets, {vuln_count} vulnerabilities)",
            [
                {
                    "batch": j["batch"],
                    "assets_in_batch": j["assets_in_batch"],
                    "vulnerabilities_in_batch": j["vulnerabilities_in_batch"],
                    "job_id": (j["response"] or {}).get("job_id") or (j["response"] or {}).get("reply", {}).get("job_id"),
                    "status": (j["response"] or {}).get("status") or "submitted",
                }
                for j in jobs
            ],
            ["batch", "assets_in_batch", "vulnerabilities_in_batch", "job_id", "status"],
        ),
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
