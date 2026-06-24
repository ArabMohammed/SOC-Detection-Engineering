#!/usr/bin/env python3
"""
Wazuh Health Monitor
====================
Checks the health of:
  - Wazuh Manager  (REST API + daemon status)
  - Wazuh Indexer  (OpenSearch cluster health)
  - Wazuh Dashboard (HTTP reachability)

Sends a Gmail alert when any component is degraded or unreachable.

Requirements:
  pip install requests urllib3

Configuration:
  Edit the CONFIG block below, or set environment variables.
"""

import os
import json
import logging
import smtplib
import socket
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────
#  CONFIGURATION  (edit here or use env vars)
# ──────────────────────────────────────────────
CONFIG = {
    # ── Wazuh Manager API ──────────────────────
    "manager_api_url":  os.getenv("WAZUH_API_URL",      "https://192.10.200.65:55000"),
    "manager_api_user": os.getenv("WAZUH_API_USER",     "wazuh-wui"),
    # the password is stored in /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    "manager_api_pass": os.getenv("WAZUH_API_PASS",     "****"),

    # ── Wazuh Indexer (OpenSearch) ─────────────
    "indexer_url":      os.getenv("WAZUH_INDEXER_URL",  "https://192.10.200.65:9200"),
    "indexer_user":     os.getenv("WAZUH_INDEXER_USER", "****"),
    "indexer_pass":     os.getenv("WAZUH_INDEXER_PASS", "****"),

    # ── Wazuh Dashboard ────────────────────────
    "dashboard_url":    os.getenv("WAZUH_DASHBOARD_URL","https://192.10.200.65:5601"),

    # ── Gmail (App Password) ───────────────────
    # Create an App Password at: https://myaccount.google.com/apppasswords
    "gmail_sender":     os.getenv("GMAIL_SENDER",       "*****@gmail.com"),
    "gmail_app_pass":   os.getenv("GMAIL_APP_PASS",     "*****"),
    "alert_recipients": os.getenv("ALERT_RECIPIENTS",   "*****").split(","),

    # ── Thresholds ─────────────────────────────
    "request_timeout":  int(os.getenv("REQUEST_TIMEOUT","10")),   # seconds
    # Manager daemons that MUST be running
    "required_daemons": [
        "wazuh-analysisd",
        "wazuh-remoted",
        "wazuh-db",
        "wazuh-modulesd",
        "wazuh-monitord",
    ],
    # Indexer cluster statuses considered healthy
    "healthy_cluster_statuses": ["green", "yellow"],  # red = alert
}

# ──────────────────────────────────────────────
#  LOGGING
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/wazuh_health_check.log", mode="a"),
    ],
)
log = logging.getLogger("wazuh-health")


# ──────────────────────────────────────────────
#  DATA CLASSES
# ──────────────────────────────────────────────
class ComponentStatus:
    """Holds health result for a single Wazuh component."""

    def __init__(self, name: str):
        self.name = name
        self.healthy = True
        self.issues: list[str] = []
        self.details: dict = {}

    def fail(self, reason: str):
        self.healthy = False
        self.issues.append(reason)
        log.warning("[%s] %s", self.name, reason)

    def ok(self, msg: str = ""):
        if msg:
            log.info("[%s] OK – %s", self.name, msg)


# ──────────────────────────────────────────────
#  HEALTH CHECK FUNCTIONS
# ──────────────────────────────────────────────
def check_manager(cfg: dict) -> ComponentStatus:
    """
    1. Authenticate to Wazuh Manager API via POST ?raw=true → raw JWT string.
       Equivalent to:
         curl -u "wazuh-wui:PASSWORD" -k -X POST
              "https://HOST:55000/security/user/authenticate?raw=true"
    2. Call GET / and GET /manager/status with the Bearer token.
    """
    status  = ComponentStatus("Wazuh Manager")
    url     = cfg["manager_api_url"]
    timeout = cfg["request_timeout"]
 
    # ── Step 1: Authenticate (POST + ?raw=true) ──
    try:
        auth_resp = requests.post(
            f"{url}/security/user/authenticate",
            params={"raw": "true"},
            auth=(cfg["manager_api_user"], cfg["manager_api_pass"]),
            verify=False,
            timeout=timeout,
        )
        auth_resp.raise_for_status()
        # ?raw=true returns the bare JWT string in the response body (no JSON wrapper)
        token = auth_resp.text.strip()
        if not token:
            status.fail("Authentication succeeded but returned an empty token")
            return status
        log.info("[Wazuh Manager] Authentication successful (POST ?raw=true)")
    except requests.exceptions.ConnectionError:
        status.fail(f"Cannot reach Manager API at {url} – connection refused or host unreachable")
        return status
    except requests.exceptions.Timeout:
        status.fail(f"Manager API at {url} timed out after {timeout}s")
        return status
    except Exception as exc:
        status.fail(f"Manager API authentication failed: {exc}")
        return status
 
    headers = {"Authorization": f"Bearer {token}"}
 
    # ── Step 2: Daemon status ─────────────────
    try:
        mgr_resp = requests.get(
            f"{url}/manager/status",
            headers=headers,
            verify=False,
            timeout=timeout,
        )
        mgr_resp.raise_for_status()
        daemon_data = mgr_resp.json().get("data", {}).get("affected_items", [{}])[0]
        status.details["daemons"] = daemon_data
 
        for daemon in cfg["required_daemons"]:
            state = daemon_data.get(daemon, "unknown")
            if state != "running":
                status.fail(f"Daemon '{daemon}' is '{state}' (expected: running)")
            else:
                log.info("[Wazuh Manager] %s → running", daemon)
 
        if status.healthy:
            status.ok("All required daemons running")
 
    except Exception as exc:
        status.fail(f"Failed to retrieve manager daemon status: {exc}")
 
    # ── Step 3: API version / info ────────────
    try:
        info_resp = requests.get(
            f"{url}/",
            headers=headers,
            verify=False,
            timeout=timeout,
        )
        info = info_resp.json().get("data", {})
        status.details["api_version"] = info.get("api_version", "unknown")
        status.details["hostname"]    = info.get("hostname", "unknown")
        log.info("[Wazuh Manager] API version: %s  host: %s",
                 status.details["api_version"], status.details["hostname"])
    except Exception:
        pass  # informational only
 
    return status
 

def check_indexer(cfg: dict) -> ComponentStatus:
    """
    Query OpenSearch /_cluster/health endpoint.
    Alert if cluster status is 'red' or if the endpoint is unreachable.
    """
    status  = ComponentStatus("Wazuh Indexer")
    url     = cfg["indexer_url"]
    timeout = cfg["request_timeout"]

    try:
        resp = requests.get(
            f"{url}/_cluster/health",
            auth=(cfg["indexer_user"], cfg["indexer_pass"]),
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
        health = resp.json()
        status.details = health

        cluster_status  = health.get("status", "unknown")
        cluster_name    = health.get("cluster_name", "unknown")
        nodes_total     = health.get("number_of_nodes", 0)
        nodes_data      = health.get("number_of_data_nodes", 0)
        active_shards   = health.get("active_shards", 0)
        unassigned      = health.get("unassigned_shards", 0)
        relocating      = health.get("relocating_shards", 0)

        log.info("[Wazuh Indexer] Cluster '%s' status=%s  nodes=%d/%d  "
                 "active_shards=%d  unassigned=%d",
                 cluster_name, cluster_status,
                 nodes_data, nodes_total,
                 active_shards, unassigned)

        if cluster_status not in cfg["healthy_cluster_statuses"]:
            status.fail(
                f"Cluster '{cluster_name}' status is '{cluster_status.upper()}' "
                f"(unassigned shards: {unassigned}, relocating: {relocating})"
            )

        if nodes_total == 0:
            status.fail("No indexer nodes reported in cluster health response")

        if unassigned > 0 and cluster_status == "red":
            status.fail(f"{unassigned} unassigned shards detected — data loss risk")

        if status.healthy:
            status.ok(f"Cluster '{cluster_name}' {cluster_status.upper()}, "
                      f"{nodes_total} node(s), {active_shards} active shards")

    except requests.exceptions.ConnectionError:
        status.fail(f"Cannot reach Indexer at {url} – connection refused or host unreachable")
    except requests.exceptions.Timeout:
        status.fail(f"Indexer at {url} timed out after {timeout}s")
    except requests.exceptions.HTTPError as exc:
        status.fail(f"Indexer returned HTTP error: {exc}")
    except Exception as exc:
        status.fail(f"Unexpected error checking Indexer: {exc}")

    return status


def check_dashboard(cfg: dict) -> ComponentStatus:
    """
    HTTP GET to the Wazuh Dashboard URL.
    Checks for HTTP 200/302/401 (all indicate the process is up).
    """
    status  = ComponentStatus("Wazuh Dashboard")
    url     = cfg["dashboard_url"]
    timeout = cfg["request_timeout"]

    try:
        resp = requests.get(
            url,
            verify=False,
            timeout=timeout,
            allow_redirects=True,
        )
        status.details["http_status"] = resp.status_code
        status.details["url"]         = url

        # 200 OK, 302 redirect to login, 401 Unauthorized → all mean the service is running
        if resp.status_code in (200, 302, 401, 403):
            status.ok(f"HTTP {resp.status_code} – Dashboard is reachable")
        else:
            status.fail(
                f"Dashboard returned unexpected HTTP {resp.status_code} "
                f"(expected 200/302/401)"
            )

    except requests.exceptions.ConnectionError:
        status.fail(f"Cannot reach Dashboard at {url} – service may be down")
    except requests.exceptions.Timeout:
        status.fail(f"Dashboard at {url} timed out after {timeout}s")
    except Exception as exc:
        status.fail(f"Unexpected error checking Dashboard: {exc}")

    return status


# ──────────────────────────────────────────────
#  EMAIL BUILDER
# ──────────────────────────────────────────────

def _status_badge(healthy: bool) -> str:
    return "✅ HEALTHY" if healthy else "❌ DEGRADED"


def build_email_html(results: list[ComponentStatus], hostname: str, ts: str) -> str:
    """Build a clean HTML email body."""

    def row_color(healthy: bool) -> str:
        return "#d4edda" if healthy else "#f8d7da"

    rows = ""
    for r in results:
        badge = _status_badge(r.healthy)
        issue_html = ""
        if r.issues:
            items = "".join(f"<li>{i}</li>" for i in r.issues)
            issue_html = f"<ul style='margin:4px 0 0 16px;padding:0'>{items}</ul>"
        rows += f"""
        <tr style="background:{row_color(r.healthy)}">
          <td style="padding:10px 14px;font-weight:bold">{r.name}</td>
          <td style="padding:10px 14px">{badge}</td>
          <td style="padding:10px 14px">{issue_html or "—"}</td>
        </tr>"""

    overall_healthy = all(r.healthy for r in results)
    banner_color    = "#28a745" if overall_healthy else "#dc3545"
    banner_text     = "All Wazuh components are healthy" if overall_healthy \
                      else "One or more Wazuh components require attention"

    return f"""
<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;font-size:14px;color:#212529;background:#f0f2f5;margin:0;padding:20px">
  <div style="max-width:720px;margin:auto;background:#fff;border-radius:8px;
              box-shadow:0 2px 8px rgba(0,0,0,.12);overflow:hidden">

    <!-- Header -->
    <div style="background:#1a1a2e;padding:20px 24px;display:flex;align-items:center">
      <div>
        <div style="color:#fff;font-size:18px;font-weight:bold">🛡️ Wazuh Health Monitor</div>
        <div style="color:#aab4c8;font-size:12px;margin-top:4px">
          Host: <strong style="color:#e0e6f0">{hostname}</strong> &nbsp;|&nbsp;
          Report time: <strong style="color:#e0e6f0">{ts}</strong>
        </div>
      </div>
    </div>

    <!-- Status banner -->
    <div style="background:{banner_color};color:#fff;padding:12px 24px;font-weight:bold;font-size:15px">
      {banner_text}
    </div>

    <!-- Table -->
    <div style="padding:20px 24px">
      <table width="100%" cellspacing="0" cellpadding="0"
             style="border-collapse:collapse;border:1px solid #dee2e6;border-radius:6px;overflow:hidden">
        <thead>
          <tr style="background:#343a40;color:#fff">
            <th style="padding:10px 14px;text-align:left">Component</th>
            <th style="padding:10px 14px;text-align:left">Status</th>
            <th style="padding:10px 14px;text-align:left">Issues</th>
          </tr>
        </thead>
        <tbody>{rows}
        </tbody>
      </table>
    </div>

    <!-- Details accordion (plain pre blocks) -->
    <div style="padding:0 24px 20px">
      <p style="font-weight:bold;margin-bottom:8px">Raw details</p>
      {''.join(
          f'<p style="margin:6px 0 2px;font-weight:bold">{r.name}</p>'
          f'<pre style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;'
          f'padding:10px;font-size:12px;white-space:pre-wrap;word-break:break-all">'
          f'{json.dumps(r.details, indent=2)}</pre>'
          for r in results
      )}
    </div>

    <!-- Footer -->
    <div style="background:#f8f9fa;border-top:1px solid #dee2e6;padding:12px 24px;
                color:#6c757d;font-size:12px">
      This alert was generated automatically by <strong>wazuh_health_check.py</strong>.
      Do not reply to this message.
    </div>
  </div>
</body>
</html>"""


def build_email_text(results: list[ComponentStatus], hostname: str, ts: str) -> str:
    """Plaintext fallback."""
    lines = [
        f"Wazuh Health Report",
        f"Host    : {hostname}",
        f"Time    : {ts}",
        "=" * 50,
    ]
    for r in results:
        lines.append(f"\n[{r.name}]  {_status_badge(r.healthy)}")
        if r.issues:
            for issue in r.issues:
                lines.append(f"  ✗ {issue}")
    lines.append("\n" + "=" * 50)
    lines.append("Generated by wazuh_health_check.py")
    return "\n".join(lines)


# ──────────────────────────────────────────────
#  EMAIL SENDER (Gmail App Password / SMTP TLS)
# ──────────────────────────────────────────────

def send_gmail_alert(
    results:    list[ComponentStatus],
    cfg:        dict,
    hostname:   str,
    ts:         str,
) -> bool:
    """
    Send alert email via Gmail SMTP using an App Password.

    Setup steps:
      1. Enable 2-Step Verification on your Google account.
      2. Go to https://myaccount.google.com/apppasswords
      3. Create an App Password (select 'Mail' + device name).
      4. Paste the 16-char password into cfg['gmail_app_pass'] or GMAIL_APP_PASS env var.
    """
    degraded = [r for r in results if not r.healthy]
    all_ok   = len(degraded) == 0

    subject = (
        f"[Wazuh] ✅ All components healthy – {hostname}"
        if all_ok
        else f"[Wazuh] ❌ {len(degraded)} component(s) DEGRADED – {hostname}"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg["gmail_sender"]
    msg["To"]      = ", ".join(cfg["alert_recipients"])

    msg.attach(MIMEText(build_email_text(results, hostname, ts), "plain"))
    msg.attach(MIMEText(build_email_html(results, hostname, ts), "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(cfg["gmail_sender"], cfg["gmail_app_pass"])
            smtp.sendmail(
                cfg["gmail_sender"],
                cfg["alert_recipients"],
                msg.as_string(),
            )
        log.info("Alert email sent → %s", cfg["alert_recipients"])
        return True
    except smtplib.SMTPAuthenticationError:
        log.error(
            "Gmail authentication failed. "
            "Check GMAIL_SENDER and GMAIL_APP_PASS. "
            "Make sure you're using an App Password, not your regular password. "
            "See: https://myaccount.google.com/apppasswords"
        )
    except smtplib.SMTPException as exc:
        log.error("SMTP error while sending alert: %s", exc)
    except Exception as exc:
        log.error("Unexpected error sending email: %s", exc)
    return False


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def main() -> int:
    hostname = socket.gethostname()
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    log.info("=" * 60)
    log.info("Wazuh Health Check started | host=%s | %s", hostname, ts)
    log.info("=" * 60)

    results: list[ComponentStatus] = []

    # ── Run checks ────────────────────────────
    log.info("--- Checking Wazuh Manager ---")
    results.append(check_manager(CONFIG))

    log.info("--- Checking Wazuh Indexer ---")
    results.append(check_indexer(CONFIG))

    log.info("--- Checking Wazuh Dashboard ---")
    results.append(check_dashboard(CONFIG))

    # ── Summary ───────────────────────────────
    log.info("=" * 60)
    all_healthy   = all(r.healthy for r in results)
    degraded_list = [r.name for r in results if not r.healthy]

    if all_healthy:
        log.info("RESULT: All components HEALTHY – no alert sent")
    else:
        log.warning("RESULT: DEGRADED components: %s", ", ".join(degraded_list))

    # ── Send email (always send; filter in cfg if needed) ────
    # Change condition to `if not all_healthy` to send only on failure
    if not all_healthy:
        send_gmail_alert(results, CONFIG, hostname, ts)
    else:
        log.info("All healthy – skipping email (set ALWAYS_NOTIFY=1 to override)")
        if os.getenv("ALWAYS_NOTIFY") == "1":
            send_gmail_alert(results, CONFIG, hostname, ts)

    log.info("=" * 60)
    return 0 if all_healthy else 1


if __name__ == "__main__":
    sys.exit(main())