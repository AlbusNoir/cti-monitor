#!/usr/bin/env python3
import argparse
import html
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import apprise
import feedparser
from curl_cffi import requests

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cti_monitor.db"
FEEDS_PATH = BASE_DIR / "feeds.json"
WEBHOOKS_PATH = BASE_DIR / "webhooks.json"
KEYWORDS_PATH = BASE_DIR / "keywords.json"
KEV_CACHE_PATH = BASE_DIR / "kev_cache.json"

REQUEST_TIMEOUT = 25
FAILURE_ALERT_THRESHOLD = 3
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DEDUPE_WINDOW_HOURS = 36
DEDUPE_SIMILARITY_THRESHOLD = 0.55
STOP_WORDS = {
    "the", "and", "for", "with", "from", "into", "over", "after", "under",
    "new", "update", "updates", "report", "reports", "warns", "warning",
    "flaw", "flaws", "vulnerability", "vulnerabilities", "bug", "bugs",
    "hackers", "attackers", "threat", "security", "researchers", "users",
    "patch", "patches", "critical", "high", "via", "now", "how", "why"
}
BT = chr(96)


def bt(text: str) -> str:
    return f"{BT}{text}{BT}"


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute('''
        CREATE TABLE IF NOT EXISTS seen_items (
            item_id TEXT PRIMARY KEY,
            source_name TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            link TEXT NOT NULL,
            seen_at TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS feed_health (
            source_name TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            category TEXT NOT NULL,
            channel TEXT NOT NULL,
            last_attempt TEXT,
            last_success TEXT,
            last_new_item TEXT,
            consecutive_failures INTEGER DEFAULT 0,
            last_status TEXT,
            last_error TEXT,
            alerted_down INTEGER DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS posted_headlines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel TEXT NOT NULL,
            source_name TEXT NOT NULL,
            title TEXT NOT NULL,
            tokens TEXT NOT NULL,
            cves TEXT NOT NULL,
            posted_at TEXT NOT NULL
        )
    ''')
    conn.commit()


def load_keywords_config() -> dict:
    if not KEYWORDS_PATH.exists():
        return {}
    try:
        return json.loads(KEYWORDS_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Failed to parse keywords.json: {exc}")
        return {}


def load_kev_cache() -> set:
    if not KEV_CACHE_PATH.exists():
        return set()
    try:
        return set(json.loads(KEV_CACHE_PATH.read_text(encoding="utf-8")))
    except Exception:
        return set()


def save_kev_cache(cve_set: set) -> None:
    try:
        KEV_CACHE_PATH.write_text(json.dumps(sorted(cve_set)), encoding="utf-8")
    except Exception as exc:
        print(f"[WARN] Could not save kev_cache.json: {exc}")


def sanitize_title(raw_title: str) -> str:
    clean = html.unescape(raw_title or "Untitled")
    clean = re.sub(r"<[^>]+>", "", clean)
    clean = " ".join(clean.split())
    clean = clean.replace("@everyone", "@\u200beveryone").replace("@here", "@\u200bhere")
    clean = clean.replace("<@", "<\u200b@")
    clean = clean.replace("[", "(").replace("]", ")")
    return clean[:220]


def is_valid_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def tokenize_headline(title: str) -> tuple:
    cves = sorted(set(m.upper() for m in CVE_REGEX.findall(title)))
    words = re.findall(r"[a-z0-9]{3,}", title.lower())
    tokens = sorted(set(w for w in words if w not in STOP_WORDS and not w.startswith("cve")))
    return tokens, cves


def is_channel_duplicate(conn: sqlite3.Connection, channel: str, title: str) -> str | None:
    tokens, cves = tokenize_headline(title)
    if not tokens and not cves:
        return None

    rows = conn.execute(
        """
        SELECT source_name, title, tokens, cves FROM posted_headlines
        WHERE channel = ? AND datetime(posted_at) >= datetime('now', ?)
        """,
        (channel, f"-{DEDUPE_WINDOW_HOURS} hours"),
    ).fetchall()

    token_set = set(tokens)
    cve_set = set(cves)

    for prev_source, prev_title, prev_tokens_json, prev_cves_json in rows:
        prev_cves = set(json.loads(prev_cves_json))
        if cve_set and prev_cves and (cve_set & prev_cves):
            return f"{prev_source}: {prev_title[:80]}"

        prev_tokens = set(json.loads(prev_tokens_json))
        if len(token_set) >= 3 and len(prev_tokens) >= 3:
            union = len(token_set | prev_tokens)
            if union > 0:
                jaccard = len(token_set & prev_tokens) / union
                if jaccard >= DEDUPE_SIMILARITY_THRESHOLD:
                    return f"{prev_source}: {prev_title[:80]}"
    return None


def record_posted_headline(conn: sqlite3.Connection, channel: str, source_name: str, title: str, now_iso: str) -> None:
    tokens, cves = tokenize_headline(title)
    conn.execute(
        "INSERT INTO posted_headlines (channel, source_name, title, tokens, cves, posted_at) VALUES (?, ?, ?, ?, ?, ?)",
        (channel, source_name, title, json.dumps(tokens), json.dumps(cves), now_iso),
    )
    conn.commit()


def build_notifiers(webhooks: dict) -> dict:
    notifiers = {}
    for channel, url in webhooks.items():
        if url:
            ap = apprise.Apprise()
            ap.add(url)
            notifiers[channel] = ap
    return notifiers


def send_discord(notifiers: dict, channel: str, message: str) -> bool:
    ap = notifiers.get(channel)
    if not ap:
        return False
    ok = ap.notify(body=message)
    time.sleep(1.5)
    return bool(ok)


def query_epss(cves: list) -> dict:
    if not cves:
        return {}
    try:
        cve_param = ",".join(cves[:5])
        api_url = "https://" + "api." + "first." + "org/data/v1/epss?cve=" + cve_param
        resp = requests.get(api_url, impersonate="chrome", timeout=8)
        if resp.status_code != 200:
            return {}
        payload = resp.json().get("data", [])
        scores = {}
        for row in payload:
            cve_id = row.get("cve", "").upper()
            epss_val = float(row.get("epss", 0.0)) * 100.0
            if cve_id:
                scores[cve_id] = round(epss_val, 1)
        return scores
    except Exception:
        return {}


def enrich_and_evaluate(title: str, source_type: str, kev_set: set, kw_cfg: dict) -> tuple:
    badges = []
    reasons = []
    title_lower = title.lower()

    found_cves = sorted(set(m.upper() for m in CVE_REGEX.findall(title)))
    if found_cves:
        in_kev = [c for c in found_cves if c in kev_set]
        if in_kev and source_type != "cisa_kev":
            badges.append(bt("🚨 IN CISA KEV"))
            if kw_cfg.get("auto_escalate_kev_cves", True):
                reasons.append(f"KEV: {', '.join(in_kev)}")

        epss_scores = query_epss(found_cves)
        threshold = float(kw_cfg.get("epss_threshold_percent", 50.0))
        for cve_id, pct in epss_scores.items():
            if pct >= 10.0:
                badges.append(bt(f"EPSS {cve_id}: {pct}%"))
            if pct >= threshold and kw_cfg.get("auto_escalate_kev_cves", True):
                reasons.append(f"High EPSS ({pct}%)")

    ignored = any(
        ig and ig.lower() in title_lower
        for ig in kw_cfg.get("ignore_escalation_keywords", [])
    )
    if not ignored:
        for kw in kw_cfg.get("escalate_keywords", []):
            if kw and kw.lower() in title_lower:
                reasons.append(f"Keyword: {kw}")
                break

    matched_vendor = None
    for vendor in kw_cfg.get("watch_vendors", []):
        if vendor and vendor.lower() in title_lower:
            matched_vendor = vendor
            badges.append(bt(f"🏷️ {vendor}"))
            break

    if matched_vendor and kw_cfg.get("escalate_watch_vendors", False):
        reasons.append(f"Vendor: {matched_vendor}")

    badge_str = (" " + " ".join(badges)) if badges else ""
    return badge_str, reasons


def fetch_cisa_kev(url: str) -> tuple:
    resp = requests.get(url, impersonate="chrome", timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])

    all_kev_cves = set()
    for v in vulns:
        c = v.get("cveID", "").strip().upper()
        if c:
            all_kev_cves.add(c)

    items = []
    for v in vulns[-40:]:
        cve = v.get("cveID", "").strip()
        vendor = v.get("vendorProject", "").strip()
        product = v.get("product", "").strip()
        name = v.get("vulnerabilityName", "").strip()
        if not cve:
            continue
        title = f"{cve}: {vendor} {product} - {name}"
        link = "https://" + "nvd." + "nist." + "gov/vuln/detail/" + cve
        items.append({"id": f"kev:{cve}", "title": title, "link": link})
    return items, all_kev_cves


def fetch_rss(url: str, source_name: str) -> list:
    resp = requests.get(url, impersonate="chrome", timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    parsed = feedparser.parse(resp.content)
    if parsed.bozo and not parsed.entries:
        raise ValueError(f"Malformed feed XML: {parsed.bozo_exception}")

    items = []
    for entry in parsed.entries[:35]:
        link = (entry.get("link") or "").strip()
        if not is_valid_http_url(link):
            continue
        raw_id = (entry.get("id") or entry.get("guid") or link).strip()
        if "://microsoft.com" in url and "#" in raw_id:
            raw_id = raw_id.split("#")[0]
        title = entry.get("title") or link
        items.append({"id": f"{source_name}:{raw_id}", "title": title, "link": link})
    return items


def update_health(conn: sqlite3.Connection, feed: dict, success: bool, error_msg: str, found_new: bool, notifiers: dict, init_mode: bool) -> None:
    now = datetime.now(timezone.utc).isoformat()
    name = feed["name"]
    row = conn.execute(
        "SELECT consecutive_failures, alerted_down, last_success, last_new_item FROM feed_health WHERE source_name = ?",
        (name,),
    ).fetchone()

    prev_failures = row[0] if row else 0
    alerted_down = row[1] if row else 0
    last_success = now if success else (row[2] if row else None)
    last_new_item = now if found_new else (row[3] if row else None)

    if success:
        failures = 0
        status = "OK"
        if alerted_down and not init_mode:
            send_discord(notifiers, "bot-status", f"✅ **Feed Recovered:** {bt(name)} is polling normally again.")
            alerted_down = 0
    else:
        failures = prev_failures + 1
        status = "ERROR"
        if failures >= FAILURE_ALERT_THRESHOLD and not alerted_down and not init_mode:
            send_discord(
                notifiers,
                "bot-status",
                f"⚠️ **Feed Down ({failures}x failures):** {bt(name)}\nError: {bt(error_msg[:180])}",
            )
            alerted_down = 1

    conn.execute('''
        INSERT INTO feed_health (
            source_name, url, category, channel, last_attempt, last_success,
            last_new_item, consecutive_failures, last_status, last_error, alerted_down
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
            url=excluded.url,
            category=excluded.category,
            channel=excluded.channel,
            last_attempt=excluded.last_attempt,
            last_success=excluded.last_success,
            last_new_item=excluded.last_new_item,
            consecutive_failures=excluded.consecutive_failures,
            last_status=excluded.last_status,
            last_error=excluded.last_error,
            alerted_down=excluded.alerted_down
    ''', (
        name, feed["url"], feed["category"], feed["channel"], now,
        last_success, last_new_item, failures, status, error_msg, alerted_down
    ))
    conn.commit()


def send_health_report(conn: sqlite3.Connection, notifiers: dict) -> None:
    total_feeds = conn.execute("SELECT COUNT(*) FROM feed_health").fetchone()[0]
    failing = conn.execute(
        "SELECT source_name, consecutive_failures, last_error FROM feed_health WHERE consecutive_failures > 0"
    ).fetchall()
    items_24h = conn.execute(
        "SELECT COUNT(*) FROM seen_items WHERE datetime(seen_at) >= datetime('now', '-1 day')"
    ).fetchone()[0]

    lines = [
        "📊 **CTI Monitor Daily Health Digest**",
        f"• **Active Sources:** {total_feeds - len(failing)}/{total_feeds} healthy",
        f"• **New Alerts (Last 24h):** {items_24h}",
    ]
    if failing:
        lines.append("• **Failing Sources:**")
        for name, count, err in failing:
            lines.append(f"  - {bt(name)} ({count}x): {bt(err[:100])}")
    else:
        lines.append("• **Failing Sources:** None 🎉")

    send_discord(notifiers, "bot-status", "\n".join(lines))


def run_poll(conn: sqlite3.Connection, feeds: list, notifiers: dict, init_mode: bool) -> None:
    now = datetime.now(timezone.utc).isoformat()
    kw_cfg = load_keywords_config()
    kev_set = load_kev_cache()
    total_seeded = 0

    for feed in feeds:
        if not feed.get("enabled", True):
            continue

        name = feed["name"]
        ftype = feed.get("type", "rss")
        url = feed["url"]
        channel = feed["channel"]
        category = feed["category"]

        try:
            if ftype == "cisa_kev":
                items, latest_kev_set = fetch_cisa_kev(url)
                if latest_kev_set:
                    kev_set = latest_kev_set
                    save_kev_cache(kev_set)
            else:
                items = fetch_rss(url, name)

            found_new = False
            for item in items:
                exists = conn.execute(
                    "SELECT 1 FROM seen_items WHERE item_id = ?", (item["id"],)
                ).fetchone()
                if exists:
                    continue

                clean_title = sanitize_title(item["title"])
                conn.execute(
                    "INSERT INTO seen_items (item_id, source_name, category, title, link, seen_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (item["id"], name, category, clean_title, item["link"], now),
                )
                conn.commit()
                found_new = True
                total_seeded += 1

                if not init_mode:
                    dup_match = is_channel_duplicate(conn, channel, clean_title)
                    if dup_match:
                        print(f"[DEDUPED] ({channel}) {name}: {clean_title} ~= {dup_match}")
                        continue

                    badges, reasons = enrich_and_evaluate(clean_title, ftype, kev_set, kw_cfg)
                    base_msg = f"**[{name}]** [{clean_title}](<{item['link']}>){badges}"
                    send_discord(notifiers, channel, base_msg)
                    record_posted_headline(conn, channel, name, clean_title, now)

                    if reasons and channel != "active-exploitation":
                        if not is_channel_duplicate(conn, "active-exploitation", clean_title):
                            ping = "@here " if kw_cfg.get("ping_here_on_escalation", False) else ""
                            reason_tag = ", ".join(reasons)
                            esc_msg = f"{ping}🔔 **[{reason_tag}]** **[{name}]** [{clean_title}](<{item['link']}>){badges}"
                            send_discord(notifiers, "active-exploitation", esc_msg)
                            record_posted_headline(conn, "active-exploitation", name, clean_title, now)

            update_health(conn, feed, True, "", found_new, notifiers, init_mode)

        except Exception as exc:
            print(f"[ERROR] {name}: {exc}")
            update_health(conn, feed, False, str(exc), False, notifiers, init_mode)

    if init_mode:
        print(f"Initialization complete. Seeded {total_seeded} baseline items across {len(feeds)} sources.")
        send_discord(
            notifiers,
            "bot-status",
            f"🚀 **CTI Monitor Initialized:** Seeded **{total_seeded}** baseline items across **{len(feeds)}** sources.",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="CTI Monitor Collector")
    parser.add_argument("--init", action="store_true", help="Seed SQLite DB without flooding Discord")
    parser.add_argument("--health-report", action="store_true", help="Post daily health digest to #bot-status")
    args = parser.parse_args()

    feeds = json.loads(FEEDS_PATH.read_text(encoding="utf-8"))
    webhooks = json.loads(WEBHOOKS_PATH.read_text(encoding="utf-8"))
    notifiers = build_notifiers(webhooks)

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    try:
        if args.health_report:
            send_health_report(conn, notifiers)
        else:
            run_poll(conn, feeds, notifiers, init_mode=args.init)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
