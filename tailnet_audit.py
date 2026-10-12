#!/usr/bin/env python3
"""
tailnet-audit: audit a Tailscale tailnet for device hygiene issues.

Pulls every device from the Tailscale API and flags:
  * node keys that are expired or expiring soon
  * devices that haven't been seen in a while (stale)
  * devices with a Tailscale client update available
  * devices waiting on authorization

Designed to run locally or as a scheduled CI job: exits non-zero when
high-severity findings exist, and can emit JSON for other tooling.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

import requests

API_BASE = "https://api.tailscale.com/api/v2"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


class TailscaleAPIError(Exception):
    """Raised when the Tailscale API returns an unrecoverable error."""


class TailscaleClient:
    """Minimal Tailscale API v2 client with retry handling for 429s and 5xx errors."""

    def __init__(
        self,
        api_key: str,
        tailnet: str = "-",
        session: requests.Session | None = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise ValueError("A Tailscale API key is required (set TAILSCALE_API_KEY).")
        self.tailnet = tailnet
        self.session = session or requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleep = sleep
        self._headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

    def list_devices(self) -> list[dict]:
        url = f"{API_BASE}/tailnet/{self.tailnet}/devices"
        resp = self._get(url, params={"fields": "all"})
        return resp.json().get("devices", [])

    def _get(self, url: str, params: dict | None = None) -> requests.Response:
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.get(url, headers=self._headers, params=params, timeout=self.timeout)
            except requests.ConnectionError as exc:
                if attempt == self.max_retries:
                    raise TailscaleAPIError(f"Could not reach Tailscale API: {exc}") from exc
                self._sleep(self._backoff(attempt))
                continue

            if resp.status_code in (401, 403):
                raise TailscaleAPIError(
                    f"Authentication failed ({resp.status_code}). Check the API key and its scopes."
                )
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == self.max_retries:
                    raise TailscaleAPIError(f"Tailscale API returned {resp.status_code} after retries.")
                self._sleep(self._retry_after(resp, attempt))
                continue
            if not resp.ok:
                raise TailscaleAPIError(f"Tailscale API returned {resp.status_code}: {resp.text[:200]}")
            return resp
        raise TailscaleAPIError("Exhausted retries.")  # pragma: no cover

    @staticmethod
    def _backoff(attempt: int) -> float:
        return float(2**attempt)

    def _retry_after(self, resp: requests.Response, attempt: int) -> float:
        header = resp.headers.get("Retry-After")
        try:
            return max(0.0, float(header)) if header else self._backoff(attempt)
        except ValueError:
            return self._backoff(attempt)


@dataclass
class Finding:
    device: str
    user: str
    severity: str
    issue: str
    detail: str


def parse_ts(value: str | None) -> datetime | None:
    """Parse Tailscale's RFC 3339 timestamps. Returns None for empty or zero values."""
    if not value or value.startswith("0001-01-01"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def audit_devices(
    devices: Iterable[dict],
    now: datetime,
    stale_days: int = 30,
    expiry_warn_days: int = 14,
) -> list[Finding]:
    findings: list[Finding] = []
    for d in devices:
        name = d.get("name") or d.get("hostname") or d.get("id", "unknown")
        user = d.get("user", "")

        def add(severity: str, issue: str, detail: str) -> None:
            findings.append(Finding(name, user, severity, issue, detail))

        if d.get("authorized") is False:
            add("medium", "unauthorized", "Device is waiting for admin approval.")

        if not d.get("keyExpiryDisabled"):
            expires = parse_ts(d.get("expires"))
            if expires:
                remaining = expires - now
                if remaining <= timedelta(0):
                    add("high", "key_expired", f"Node key expired {expires:%Y-%m-%d}.")
                elif remaining <= timedelta(days=expiry_warn_days):
                    add("medium", "key_expiring", f"Node key expires in {remaining.days} days ({expires:%Y-%m-%d}).")

        last_seen = parse_ts(d.get("lastSeen"))
        if last_seen and now - last_seen > timedelta(days=stale_days):
            add("low", "stale", f"Last seen {(now - last_seen).days} days ago.")

        if d.get("updateAvailable"):
            add("low", "update_available", f"Running {d.get('clientVersion', 'unknown version')}.")

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.device))
    return findings


def render_table(findings: list[Finding], device_count: int) -> str:
    if not findings:
        return f"Audited {device_count} devices. No issues found."
    rows = [("SEVERITY", "DEVICE", "ISSUE", "DETAIL")]
    rows += [(f.severity.upper(), f.device, f.issue, f.detail) for f in findings]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    lines = [
        f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[2]:<{widths[2]}}  {r[3]}" for r in rows
    ]
    summary = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines.append("")
    lines.append(
        f"Audited {device_count} devices: {summary['high']} high, {summary['medium']} medium, {summary['low']} low."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a Tailscale tailnet for device hygiene issues.")
    parser.add_argument("--tailnet", default=os.environ.get("TAILSCALE_TAILNET", "-"),
                        help="Tailnet name (default: '-' for the API key's default tailnet).")
    parser.add_argument("--stale-days", type=int, default=30, help="Flag devices unseen for this many days.")
    parser.add_argument("--expiry-days", type=int, default=14, help="Warn when node keys expire within this many days.")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON.")
    args = parser.parse_args(argv)

    try:
        client = TailscaleClient(os.environ.get("TAILSCALE_API_KEY", ""), tailnet=args.tailnet)
        devices = client.list_devices()
    except (ValueError, TailscaleAPIError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = audit_devices(devices, datetime.now(timezone.utc), args.stale_days, args.expiry_days)

    if args.json:
        print(json.dumps({"device_count": len(devices), "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(render_table(findings, len(devices)))

    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
