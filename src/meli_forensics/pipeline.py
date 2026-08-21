from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import duckdb

AUTOMATION_SQL = "lower(http_user_agent) = 'crawler4j' OR lower(http_user_agent) = 'wget' OR lower(http_user_agent) LIKE 'scrapy/%'"


def fingerprint(value: str, label: str) -> str:
    return f"{label}_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]}"


def mask_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.version == 4:
        parts = value.split(".")
        return ".".join(parts[:3] + ["x"])
    return f"{ip.exploded.split(':')[0]}:{ip.exploded.split(':')[1]}::/32"


def build_database(csv_path: Path, database_path: Path) -> dict[str, Any]:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(database_path))
    con.execute("PRAGMA threads=4")
    con.execute(
        """
        CREATE OR REPLACE TABLE logs_raw AS
        SELECT * FROM read_csv(?, header=true, all_varchar=true,
                               ignore_errors=false, sample_size=-1)
        """,
        [str(csv_path)],
    )
    con.execute(
        """
        CREATE OR REPLACE TABLE logs AS
        SELECT
          try_strptime(timestamp, '%Y-%d-%mT%H:%M') AS event_ts,
          timestamp AS timestamp_raw,
          try_cast(http_staus AS INTEGER) AS http_status,
          http_host,
          split_part(http_uri, '?', 1) AS endpoint,
          http_uri,
          http_method,
          http_referer,
          http_user_agent,
          source_ip,
          nullif(regexp_extract(http_uri, '(?:[?&])invoice_id=([^&]*)', 1), '') AS invoice_id,
          nullif(regexp_extract(http_uri, '(?:[?&])site_id=([^&]*)', 1), '') AS site_id,
          nullif(regexp_extract(http_uri, '(?:[?&])authtoken=([^&]*)', 1), '') AS authtoken
        FROM logs_raw
        """
    )
    row = con.execute(
        """
        SELECT count(*), count(*) FILTER (WHERE event_ts IS NULL),
               min(event_ts), max(event_ts)
        FROM logs
        """
    ).fetchone()
    con.close()
    return {
        "rows": row[0],
        "invalid_timestamps": row[1],
        "first_event": row[2].isoformat() if row[2] else None,
        "last_event": row[3].isoformat() if row[3] else None,
    }


def _query(con: duckdb.DuckDBPyConnection, sql: str) -> tuple[list[str], list[tuple[Any, ...]]]:
    cursor = con.execute(sql)
    return [column[0] for column in cursor.description], cursor.fetchall()


def _write_csv(path: Path, columns: list[str], rows: Iterable[Iterable[Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(columns)
        writer.writerows(rows)


def _as_dicts(columns: list[str], rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        item = {}
        for key, value in zip(columns, row):
            if isinstance(value, (datetime,)):
                value = value.isoformat()
            item[key] = value
        output.append(item)
    return output


def _geolocate(ips: list[str], cache_path: Path | None) -> dict[str, dict[str, Any]]:
    import requests

    cache: dict[str, dict[str, Any]] = {}
    if cache_path and cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    for ip in ips:
        if ip in cache:
            continue
        response = requests.get(f"https://ipwho.is/{ip}", timeout=20)
        response.raise_for_status()
        payload = response.json()
        connection = payload.get("connection") or {}
        cache[ip] = {
            "country": payload.get("country"),
            "country_code": payload.get("country_code"),
            "asn": connection.get("asn"),
            "asn_org": connection.get("org"),
            "lookup_success": bool(payload.get("success")),
        }
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    return cache


def export_results(
    database_path: Path,
    public_dir: Path,
    restricted_dir: Path | None = None,
    geo_cache: Path | None = None,
    geolocate: bool = True,
) -> dict[str, Any]:
    public_dir.mkdir(parents=True, exist_ok=True)
    if restricted_dir:
        restricted_dir.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(database_path), read_only=True)

    queries = {
        "top_20_ips": """
          SELECT source_ip, count(*) AS requests,
                 count(DISTINCT invoice_id) AS unique_invoices,
                 count(DISTINCT authtoken) AS unique_tokens,
                 count(*) FILTER (WHERE http_status = 200) AS status_200,
                 round(100.0 * count(*) FILTER (WHERE http_status BETWEEN 200 AND 299) / count(*), 2) AS success_2xx_pct,
                 min(event_ts) AS first_seen, max(event_ts) AS last_seen
          FROM logs WHERE endpoint = '/invoices/search'
          GROUP BY source_ip ORDER BY requests DESC LIMIT 20
        """,
        "top_10_tokens": """
          SELECT authtoken, count(*) AS requests,
                 count(DISTINCT source_ip) AS unique_ips,
                 count(DISTINCT invoice_id) AS unique_invoices,
                 round(100.0 * count(*) FILTER (WHERE http_status BETWEEN 200 AND 299) / count(*), 2) AS success_2xx_pct
          FROM logs GROUP BY authtoken ORDER BY requests DESC LIMIT 10
        """,
        "site_impact": """
          SELECT site_id, count(*) AS requests,
                 count(DISTINCT invoice_id) AS unique_invoices,
                 count(DISTINCT source_ip) AS unique_ips,
                 count(*) FILTER (WHERE http_status = 200) AS status_200,
                 round(100.0 * count(*) FILTER (WHERE http_status BETWEEN 200 AND 299) / count(*), 2) AS success_2xx_pct
          FROM logs GROUP BY site_id ORDER BY requests DESC
        """,
        "daily_timeline": f"""
          SELECT date_trunc('day', event_ts) AS event_date,
                 count(*) AS requests,
                 count(DISTINCT source_ip) AS unique_ips,
                 count(DISTINCT invoice_id) AS unique_invoices,
                 count(*) FILTER (WHERE {AUTOMATION_SQL}) AS automated_requests
          FROM logs GROUP BY event_date ORDER BY event_date
        """,
        "status_by_top_ip": """
          WITH top AS (SELECT source_ip FROM logs GROUP BY source_ip ORDER BY count(*) DESC LIMIT 20)
          SELECT l.source_ip, l.http_status, count(*) AS requests
          FROM logs l JOIN top t USING (source_ip)
          GROUP BY l.source_ip, l.http_status ORDER BY l.source_ip, l.http_status
        """,
    }

    raw: dict[str, tuple[list[str], list[tuple[Any, ...]]]] = {
        name: _query(con, sql) for name, sql in queries.items()
    }
    top_ips = [row[0] for row in raw["top_20_ips"][1]]
    geo = _geolocate(top_ips, geo_cache) if geolocate else {}

    if restricted_dir:
        for name, (columns, rows) in raw.items():
            _write_csv(restricted_dir / f"{name}.csv", columns, rows)

    for name, (columns, rows) in raw.items():
        safe_columns = list(columns)
        safe_rows = []
        for row in rows:
            row = list(row)
            if "source_ip" in columns:
                index = columns.index("source_ip")
                value = str(row[index])
                row[index] = mask_ip(value)
                if "ip_fingerprint" not in safe_columns:
                    safe_columns.insert(index + 1, "ip_fingerprint")
                row.insert(index + 1, fingerprint(value, "ip"))
            if "authtoken" in columns:
                index = safe_columns.index("authtoken")
                row[index] = fingerprint(str(row[index]), "token")
            safe_rows.append(row)
        _write_csv(public_dir / f"{name}.csv", safe_columns, safe_rows)

    top_geo_rows = []
    for position, row in enumerate(raw["top_20_ips"][1], 1):
        ip, requests = row[0], row[1]
        item = geo.get(ip, {})
        top_geo_rows.append(
            [position, mask_ip(ip), fingerprint(ip, "ip"), requests, item.get("country"),
             item.get("country_code"), item.get("asn"), item.get("asn_org")]
        )
    _write_csv(
        public_dir / "top_20_ip_enrichment.csv",
        ["rank", "source_ip_masked", "ip_fingerprint", "requests", "country", "country_code", "asn", "asn_org"],
        top_geo_rows,
    )

    overview_columns, overview_rows = _query(
        con,
        """
        SELECT count(*) AS row_count, count(*) FILTER (WHERE event_ts IS NULL) AS invalid_timestamps,
               min(event_ts) AS first_event, max(event_ts) AS last_event,
               count(DISTINCT source_ip) AS unique_ips,
               count(DISTINCT invoice_id) AS unique_invoices,
               count(DISTINCT authtoken) AS unique_tokens,
               count(DISTINCT site_id) AS unique_sites
        FROM logs
        """,
    )
    overview = _as_dicts(overview_columns, overview_rows)[0]

    suspect_sql = f"""
      WITH ip_stats AS (
        SELECT source_ip, count(*) AS requests,
               count(DISTINCT invoice_id) AS unique_invoices,
               count(DISTINCT authtoken) AS unique_tokens,
               count(*) FILTER (WHERE http_status = 200) AS status_200,
               count(DISTINCT invoice_id) FILTER (WHERE http_status = 200) AS invoices_status_200,
               count(*) FILTER (WHERE http_status BETWEEN 200 AND 299) AS status_2xx,
               count(*) FILTER (WHERE {AUTOMATION_SQL}) AS automation_requests
        FROM logs GROUP BY source_ip
      ), suspects AS (
        SELECT source_ip FROM ip_stats
        WHERE automation_requests = requests AND requests >= 1000 AND unique_invoices >= 1000
      )
      SELECT count(DISTINCT source_ip) AS suspect_ips, count(*) AS requests,
             count(DISTINCT invoice_id) AS unique_invoices,
             count(DISTINCT authtoken) AS unique_tokens,
             count(*) FILTER (WHERE http_status = 200) AS status_200,
             count(DISTINCT invoice_id) FILTER (WHERE http_status = 200) AS invoices_status_200,
             count(*) FILTER (WHERE http_status BETWEEN 200 AND 299) AS status_2xx,
             min(event_ts) AS first_seen, max(event_ts) AS last_seen
      FROM logs JOIN suspects USING (source_ip)
    """
    suspect_columns, suspect_rows = _query(con, suspect_sql)
    suspect = _as_dicts(suspect_columns, suspect_rows)[0]

    month_columns, month_rows = _query(
        con,
        f"""
        WITH suspects AS (
          SELECT source_ip FROM logs GROUP BY source_ip
          HAVING count(*) >= 1000 AND count(DISTINCT invoice_id) >= 1000
             AND count(*) FILTER (WHERE {AUTOMATION_SQL}) = count(*)
        )
        SELECT strftime(event_ts, '%Y-%m') AS month, count(*) AS requests,
               count(DISTINCT invoice_id) AS unique_invoices,
               count(*) FILTER (WHERE http_status = 200) AS status_200
        FROM logs JOIN suspects USING (source_ip)
        GROUP BY month ORDER BY month
        """,
    )
    monthly = _as_dicts(month_columns, month_rows)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "HIGH confidence of automated IDOR exploitation; MEDIUM confidence of PII disclosure",
        "overview": overview,
        "suspected_exploitation": suspect,
        "monthly_suspected_activity": monthly,
        "site_by_request_volume": _as_dicts(*raw["site_impact"])[0],
        "site_by_unique_invoice": max(_as_dicts(*raw["site_impact"]), key=lambda item: item["unique_invoices"]),
        "privacy_note": "Public outputs mask IP addresses and SHA-256 fingerprint auth tokens; restricted raw rankings are not committed.",
        "geo_source": (
            "ipwho.is point-in-time lookup; enrichment is contextual, not attribution evidence"
            if geolocate
            else "geolocation skipped"
        ),
    }
    (public_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    con.close()
    return summary


def build_charts(public_dir: Path, charts_dir: Path) -> None:
    import matplotlib.pyplot as plt

    charts_dir.mkdir(parents=True, exist_ok=True)
    with (public_dir / "daily_timeline.csv").open(encoding="utf-8") as stream:
        daily = list(csv.DictReader(stream))
    dates = [datetime.fromisoformat(item["event_date"]).date() for item in daily]
    automated = [int(item["automated_requests"]) for item in daily]
    fig, ax = plt.subplots(figsize=(11, 4.8))
    ax.plot(dates, automated, color="#3483FA", linewidth=2.2)
    ax.fill_between(dates, automated, color="#3483FA", alpha=0.18)
    ax.set(title="Requisições automatizadas suspeitas por dia", ylabel="Requisições", xlabel="Data do evento")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(charts_dir / "suspicious_daily_volume.png", dpi=180)
    plt.close(fig)

    with (public_dir / "top_20_ips.csv").open(encoding="utf-8") as stream:
        top = list(csv.DictReader(stream))
    labels = [f"{item['source_ip']} ({item['ip_fingerprint'][-6:]})" for item in reversed(top)]
    values = [int(item["requests"]) for item in reversed(top)]
    colors = ["#FFE600" if value >= 10000 else "#3483FA" for value in values]
    fig, ax = plt.subplots(figsize=(10, 7))
    ax.barh(labels, values, color=colors)
    ax.set(title="Top 20 IPs de origem (visão pública mascarada)", xlabel="Requisições")
    ax.grid(axis="x", alpha=0.2)
    fig.tight_layout()
    fig.savefig(charts_dir / "top_20_ips.png", dpi=180)
    plt.close(fig)
