# CTI Monitor

A lightweight, automated Cyber Threat Intelligence (CTI) collector and Discord push-notification ticker built with Python, `uv`, SQLite, and Apprise. It polls structured vulnerability feeds, ransomware leak trackers, vendor PSIRTs, threat research blogs, government CERTs, and breaking security news, enriches headlines with CISA KEV and FIRST EPSS data, and routes alerts into dedicated Discord channels.

## How It Works

1. **Source Ingestion (`feeds.json`):** Polls ~60 curated RSS, Atom, and JSON endpoints using `curl_cffi` (Chrome TLS impersonation) and `feedparser` with per-source timeouts and category routing.
2. **State & Deduplication (`cti_monitor.db`):** Stores seen item IDs in a local SQLite database so repeated cron runs never post duplicate alerts.
3. **CVE Enrichment (`kev_cache.json` + FIRST EPSS):** Automatically extracts `CVE-YYYY-NNNN` identifiers from incoming headlines, cross-references them against a locally cached copy of the CISA Known Exploited Vulnerabilities (KEV) catalog, and queries the FIRST EPSS API for exploitation probability scores.
4. **Dynamic Keyword & Escalation Routing (`keywords.json`):** Evaluates headlines against user-defined keywords, vendor watchlists, KEV matches, and EPSS thresholds. High-priority matches are cross-posted to `#active-exploitation`.
5. **Notification Delivery (`webhooks.json` + Apprise):** Formats clean, embed-suppressed Markdown links and delivers them to Discord (or any Apprise-supported service).
6. **Health Monitoring (`#bot-status`):** Tracks per-feed HTTP status, consecutive failures, and recovery events in SQLite, alerting after 3 consecutive failures and generating a daily health digest.

## Repository Structure

* `cti_monitor.py` — Main collector, enrichment engine, and health reporter.
* `feeds.json` — Master registry of intelligence sources, categories, and target channels.
* `keywords.json` — Dynamic keyword escalation rules, vendor watchlists, and EPSS thresholds.
* `webhooks.example.json` — Template for configuring Apprise notification URLs.
* `webhooks.json` — Live Apprise notification URLs *(ignored by Git)*.
* `cti_monitor.db` — Local SQLite deduplication and feed health database *(ignored by Git)*.
* `kev_cache.json` — Local cache of CISA KEV CVE IDs *(ignored by Git)*.

## Setup Guide (Ubuntu 24.04 LTS)

> **Platform Note:** These instructions target **Ubuntu 24.04 LTS** (x86_64 or ARM64). On RHEL/Rocky/Oracle Linux, replace `apt` commands with `dnf` equivalents.

### 1. Install `uv` and Sync Dependencies
Install `uv` into your user profile using the official standalone installer, then clone the repository and sync the isolated virtual environment:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.local/bin/env
git clone <your-repo-url> ~/cti-monitor
cd ~/cti-monitor
uv sync
```

### 2. Configure Webhooks (`webhooks.json`)
Copy the example template to `webhooks.json`, replace the placeholders with your Discord webhook credentials formatted for Apprise (`discord://WebhookID/WebhookToken`), and lock down file permissions:

```bash
cp webhooks.example.json webhooks.json
chmod 600 webhooks.json
nano webhooks.json
```

### 3. Seed the Database (`--init`)
Run an initial seed pass so existing articles are recorded in SQLite without flooding your Discord channels, then verify feed health:

```bash
uv run cti_monitor.py --init
uv run cti_monitor.py --health-report
```

### 4. Schedule with Cron
Verify your `uv` binary path (`which uv`), then add two entries via `crontab -e` to poll every 10 minutes and post a daily health digest at 13:00 UTC (8:00 AM EST):

```cron
*/10 * * * * /home/ubuntu/.local/bin/uv run --project /home/ubuntu/cti-monitor /home/ubuntu/cti-monitor/cti_monitor.py >> /home/ubuntu/cti-monitor/cron.log 2>&1
0 13 * * * /home/ubuntu/.local/bin/uv run --project /home/ubuntu/cti-monitor /home/ubuntu/cti-monitor/cti_monitor.py --health-report >> /home/ubuntu/cti-monitor/cron.log 2>&1
```

## Day-to-Day Management

* **Add or Edit Keywords / Vendors:** Edit `keywords.json` directly. Changes take effect automatically on the next 10-minute run without restarting anything.
* **Add, Disable, or Re-Route Feeds:** Edit `feeds.json`. Set `"enabled": false` to mute a noisy or broken source without deleting its entry.
* **Check Feed Health Manually:**
  ```bash
  uv run cti_monitor.py --health-report
  ```
* **Inspect Local SQLite Health Table:**
  ```bash
  sqlite3 cti_monitor.db "SELECT source_name, consecutive_failures, last_status, last_error FROM feed_health WHERE consecutive_failures > 0;"
  ```
* **View Execution Logs:**
  ```bash
  tail -n 50 ~/cti-monitor/cron.log
  ```

## Troubleshooting

* **Discord Rate Limits:** The script includes a `1.5s` delay between webhook posts to stay safely beneath Discord's 30 requests/minute webhook limit.
* **Cloudflare / WAF Blocks:** Requests use `curl_cffi` with Chrome TLS fingerprinting. If a publisher blocks datacenter IP ranges outright, disable the feed in `feeds.json` or route it via a Google News RSS query (`site:example.com`).
* **Resetting History:** To wipe seen articles and re-seed from scratch, delete `cti_monitor.db` and re-run `uv run cti_monitor.py --init`.
