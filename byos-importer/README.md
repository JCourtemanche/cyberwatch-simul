# Cyberwatch → Cortex XSIAM Exposure Management (BYOS)

XSIAM Automation Script that imports Cyberwatch CVEs into **Cortex Exposure Management** through the [Bring Your Own Scanner (BYOS)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Bring-Your-Own-Scanner) API.

## What it does

1. Calls **`cyberwatch-list-cves`** on the Cyberwatch integration with the filters you pass in (`level`, `prioritized`, `exploit_code_maturity`, `access_vector`, `technology_*`, `hard_limit`, `per_page`).
2. For each returned CVE, calls **`cyberwatch-fetch-cve`** to retrieve the affected `servers[]` (hostname, OS, detection date, prioritized flag, updates).
3. Aggregates the results **by asset** — one asset entry, N vulnerabilities — into the shape expected by the BYOS API.
4. `POST`s the payload in batches to `POST /public_api/vulnerability-management/v1/external-scans/assets` using the Cortex API key.
5. **Auto-polls** each returned `job_id` via `GET /public_api/vulnerability-management/v1/external-scans/assets/jobs/<id>` until a terminal status (`COMPLETED`, `COMPLETED_WITH_ERRORS`, `FAILED`) or `poll_timeout`, with exponential backoff. Disable with `poll_after_submit=false`.

**Standalone poll mode:** pass `poll_job_id=<id>` and the script skips the whole Cyberwatch flow and just reports the status of that job. Useful for a follow-up playbook step ("check on this job later").

## Files

| File | Purpose |
|---|---|
| [`cyberwatch_byos_importer.py`](cyberwatch_byos_importer.py) | Source of the automation script — copy/paste this into a new Script in XSIAM if you prefer to author it manually. |
| [`script-CyberwatchBYOSImporter.yml`](script-CyberwatchBYOSImporter.yml) | XSIAM-importable YAML bundle. `Settings → Automations → Scripts → ⋮ → Import Script`. |
| [`examples/payload_example.json`](examples/payload_example.json) | Real example of the BYOS payload this script builds. |

## Install

### Option A — Import the YAML bundle (recommended)

1. Open your XSIAM console.
2. Navigate to **Settings → Configurations → Automations → Scripts**.
3. Click the ⋮ menu → **Import Script**.
4. Select [`script-CyberwatchBYOSImporter.yml`](script-CyberwatchBYOSImporter.yml).
5. The script appears as `CyberwatchBYOSImporter` and is ready to run.

### Option B — Create manually

1. **Settings → Automations → Scripts → + New Script**.
2. Name it `CyberwatchBYOSImporter`, subtype `python3`, image `demisto/python3:3.12.11.4417419` (or the current default).
3. Paste the contents of [`cyberwatch_byos_importer.py`](cyberwatch_byos_importer.py).
4. Add the arguments listed in the [Arguments](#arguments) table below (all optional except the three API ones).

## Arguments

| Name | Required | Default | Description |
|---|---|---|---|
| `api_url` | ✅ | — | Cortex XSIAM tenant API URL, e.g. `https://api-<tenant>.xdr.<region>.paloaltonetworks.com` |
| `api_key` | ✅ | — | The Cortex XSIAM **API key value** (Standard or Advanced) |
| `api_key_id` | ✅ | — | The Cortex XSIAM API key **ID** (integer, sent as `x-xdr-auth-id`) |
| `cyberwatch_instance` | — | first available | Cyberwatch integration instance name (only if you have several) |
| `level` | — | — | `level_low` \| `level_medium` \| `level_high` \| `level_critical` |
| `prioritized` | — | — | `true` / `false` |
| `active` | — | — | `true` / `false` |
| `ignored` | — | — | `true` / `false` |
| `exploit_code_maturity` | — | — | Comma-separated: `undefined,unproven,proof_of_concept,functional,high` |
| `access_vector` | — | — | Comma-separated CVSS access vectors |
| `technology_vendor` | — | — | CPE vendor filter |
| `technology_product` | — | — | CPE product filter |
| `since` | — | — | Only import CVEs whose `last_modified` ≥ this date. Accepts `3 days`, `2025-01-01`, ISO 8601 |
| `hard_limit` | — | `500` | Max CVEs to fetch from Cyberwatch |
| `per_page` | — | `500` | Cyberwatch pagination size |
| `batch_size` | — | `100` | Assets per BYOS `POST` request |
| `dry_run` | — | `false` | Build the payload but do not `POST` |
| `verify` | — | `true` | Verify Cortex API TLS certificate |
| `poll_after_submit` | — | `true` | After submit, poll each `job_id` until terminal status or timeout |
| `poll_timeout` | — | `180` | Max seconds to wait for terminal status (per job) |
| `poll_interval` | — | `5` | Initial seconds between polls, backs off exponentially (cap 30s) |
| `poll_job_id` | — | — | **Standalone mode**: report the status of an existing job and exit. When set, all Cyberwatch/BYOS-submit args are ignored. |

## Getting the API key

1. In XSIAM: **Settings → Configurations → API Keys → + New Key**.
2. Choose role with `manage_vulnerabilities_action` permission (required by BYOS).
3. Copy the **API key value** → `api_key` argument.
4. Copy the **API key ID** (integer under the "ID" column) → `api_key_id` argument.
5. Your tenant API URL is shown in the top-right of the same page (e.g. `https://api-mytenant.xdr.us.paloaltonetworks.com`).

## Run examples

### Manual — from the war room

```
!CyberwatchBYOSImporter api_url="https://api-mytenant.xdr.eu.paloaltonetworks.com" api_key_id=42 api_key="XXXXXXXXX" level=level_critical prioritized=true since="7 days"
```

### Manual — dry-run to inspect the payload without hitting the API

```
!CyberwatchBYOSImporter api_url="https://api-mytenant.xdr.eu.paloaltonetworks.com" api_key_id=42 api_key="XXXXXXXXX" dry_run=true hard_limit=50
```

### Manual — check status of a previously submitted job

```
!CyberwatchBYOSImporter api_url="https://api-mytenant.xdr.eu.paloaltonetworks.com" api_key_id=42 api_key="XXXXXXXXX" poll_job_id="abcd-1234-..."
```

Returns:

| job_id | job_status | created_timestamp | last_updated | poll_attempts | poll_elapsed_seconds | error_log |
|---|---|---|---|---|---|---|
| abcd-1234-... | COMPLETED | 2026-... | 2026-... | 3 | 12 | null |

### Manual — submit without waiting for completion (fire and forget)

```
!CyberwatchBYOSImporter api_url="..." api_key_id=42 api_key="..." poll_after_submit=false
```

The war-room returns as soon as all batches are POSTed. You can then poll each `Cyberwatch.BYOS.jobs.job_id` in a later step with `poll_job_id`.

### Scheduled — as a Job

**Settings → Playbooks → Jobs → + New Job**:
- Name: `Cyberwatch BYOS Sync`
- Type: **Recurring**, e.g. every 4 hours
- Playbook: a one-step playbook that runs the `CyberwatchBYOSImporter` script with your fixed `api_url`, `api_key`, `api_key_id`, and `since=4 hours` (matching the recurrence).

## Outputs

The script writes to context under `Cyberwatch.BYOS`:

| Path | Description |
|---|---|
| `Cyberwatch.BYOS.assets_count` | Total assets submitted |
| `Cyberwatch.BYOS.vulnerabilities_count` | Total vulnerabilities submitted |
| `Cyberwatch.BYOS.cves_considered` | CVEs kept after the `since` filter |
| `Cyberwatch.BYOS.cves_dropped_by_since` | CVEs skipped because `last_modified` predates `since` |
| `Cyberwatch.BYOS.jobs` | List of per-batch responses (each contains `job_id`, `assets_in_batch`, `vulnerabilities_in_batch`, the raw submit `response`, and — when auto-poll ran — a `poll_result` with `job_status`, `poll_attempts`, `poll_elapsed_seconds`, `error_log`) |
| `Cyberwatch.BYOS.poll_summary` | `{polled, total_jobs, completed, completed_with_errors, failed}` — aggregate counts across all polled jobs |
| `Cyberwatch.BYOS.Poll.*` | Standalone poll mode only: `job_id`, `job_status`, `created_timestamp`, `last_updated`, `poll_attempts`, `poll_elapsed_seconds`, `error_log` |

Auto-poll uses `GET /public_api/vulnerability-management/v1/external-scans/assets/jobs/{job_id}`. Terminal statuses are `COMPLETED`, `COMPLETED_WITH_ERRORS`, `FAILED`; on timeout the last non-terminal status is returned with `poll_timeout_hit: true`.

## BYOS payload shape

The BYOS API expects one payload per submission with the scanner header + a list of assets, each carrying its own vulnerabilities. See [examples/payload_example.json](examples/payload_example.json). Excerpt:

```json
{
  "vendor": "Cyberwatch",
  "product": "Vulnerability Manager",
  "version": "1.0",
  "assets": [
    {
      "origin_asset_id": "cyberwatch-server-900",
      "asset_name": "BSNS-WIN-ALICE",
      "fqdn": ["BSNS-WIN-ALICE"],
      "os_name": "Windows 10 Pro",
      "last_seen": 1749931200,
      "origin_tags": ["cyberwatch:server_id:900"],
      "vulnerabilities": [
        {
          "vulnerability_id": "CVE-2021-44228",
          "cve_id": ["CVE-2021-44228"],
          "description": "Apache Log4j Remote Code Execution (Log4Shell)",
          "confidence": "High",
          "last_seen": 1749931200,
          "scan_name": "Cyberwatch vulnerability scan"
        }
      ]
    }
  ]
}
```

## Confidence mapping

The script maps Cyberwatch's `exploit_code_maturity` to the BYOS `confidence` field:

| Cyberwatch value | BYOS confidence |
|---|---|
| `high`, `functional` | `High` |
| `proof_of_concept` | `Medium` |
| `unproven` | `Low` |
| `undefined` (or missing) | `Potential` |

## Prerequisites

- The Cyberwatch integration (`Cyberwatch (Partner Contribution)`) is installed and configured. Point it at the [cyberwatch-simul](../README.md) simulator or at a real Cyberwatch master scanner.
- Your Cortex tenant has the **Exposure Management** license.
- The API key used has the `manage_vulnerabilities_action` RBAC permission.

## References

- BYOS overview — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Bring-Your-Own-Scanner
- Submit endpoint — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Submit-assets-and-vulnerabilities-from-an-external-scanner
- Poll import job — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Poll-the-status-of-a-BYOS-import-job
