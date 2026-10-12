# tailnet-audit

A small Python CLI that audits a [Tailscale](https://tailscale.com) tailnet for device hygiene issues using the Tailscale API.

Admins of growing tailnets tend to accumulate forgotten devices, node keys that quietly expire and knock machines offline, and clients that fall behind on updates. `tailnet-audit` pulls every device from the API and gives you one report, so you can catch those problems before they cause an outage. It exits non-zero on high-severity findings, which makes it easy to run as a scheduled CI job.

## What it checks

| Issue | Severity | Meaning |
|---|---|---|
| `key_expired` | high | Node key has expired; the device can no longer connect |
| `key_expiring` | medium | Node key expires within the warning window (default 14 days) |
| `unauthorized` | medium | Device is waiting for admin approval |
| `stale` | low | Device hasn't been seen in N days (default 30) |
| `update_available` | low | A newer Tailscale client is available |

Devices with key expiry disabled are skipped for expiry checks.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Create an API access token (or OAuth client with `devices:core:read`) in the Tailscale admin console under **Settings → Keys**, then:

```bash
export TAILSCALE_API_KEY=tskey-api-...
```

## Usage

```bash
python tailnet_audit.py                     # table output for your default tailnet
python tailnet_audit.py --stale-days 14     # tighter staleness window
python tailnet_audit.py --json > audit.json # machine-readable output
```

Example output:

```
SEVERITY  DEVICE           ISSUE             DETAIL
HIGH      build-runner-02  key_expired       Node key expired 2026-10-01.
MEDIUM    laptop-musab     key_expiring      Node key expires in 8 days (2026-10-20).
LOW       old-pi           stale             Last seen 72 days ago.

Audited 12 devices: 1 high, 1 medium, 1 low.
```

Exit codes: `0` no high-severity findings, `1` high-severity findings present, `2` configuration or API error.

## Design notes

- **Retries:** the API client retries on `429` and `5xx` responses with exponential backoff, honouring the `Retry-After` header when present. Auth failures (`401`/`403`) fail fast instead of retrying, since retrying won't fix a bad key.
- **Timestamps:** Tailscale uses a zero timestamp (`0001-01-01T00:00:00Z`) for unset values; these are treated as missing rather than as "expired in year 1".
- **Testability:** the HTTP session and sleep function are injectable, so the test suite runs offline with no real API calls and no actual waiting.

## Tests

```bash
pip install pytest
pytest -q
```

## Running on a schedule

A sample GitHub Actions workflow is included in `.github/workflows/audit.yml`. Add `TAILSCALE_API_KEY` as a repository secret and it will run weekly and fail the job when high-severity issues are found.
