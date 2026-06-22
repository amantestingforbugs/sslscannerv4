"""
db/database.py
Persistent SQLite layer. Per-thread connection pool, WAL mode, batch writes.
Extended with subfinder_jobs and subfinder_hosts tables.
"""

import os, sqlite3, json, uuid, threading, logging, zlib
from itertools import islice
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", "data/sentinel.db"))
_local = threading.local()


def _conn():
    if not getattr(_local, "c", None):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        cache_kib = max(1024, int(os.getenv("SQLITE_CACHE_KIB", "8192") or 8192))
        mmap_size = max(0, int(os.getenv("SQLITE_MMAP_SIZE", "0") or 0))
        c.execute(f"PRAGMA cache_size=-{cache_kib}")
        c.execute("PRAGMA temp_store=FILE")
        c.execute(f"PRAGMA mmap_size={mmap_size}")
        c.execute("PRAGMA foreign_keys=ON")
        _local.c = c
    return _local.c


def x(sql, p=()):  return _conn().execute(sql, p)
def xm(sql, rows): return _conn().executemany(sql, rows)
def commit():       _conn().commit()
def now():          return datetime.now(timezone.utc).isoformat()
def uid():          return str(uuid.uuid4())



def _env_int(name: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        value = int(os.getenv(name, str(default)) or default)
    except (TypeError, ValueError):
        value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _trim_text(text: str, max_chars: int) -> str:
    if not text or max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n…truncated; original length {len(text)} chars…"

def _compress_text(text: str):
    if not text:
        return None
    return sqlite3.Binary(zlib.compress(text.encode("utf-8"), level=6))


def _decompress_text(blob):
    if not blob:
        return ""
    try:
        return zlib.decompress(blob).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _chunked(items, size=500):
    it = iter(items)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn().executescript("""
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '', hosts_file TEXT DEFAULT '',
        host_count INTEGER DEFAULT 0, scan_interval_minutes INTEGER DEFAULT 60,
        subfinder_interval_minutes INTEGER DEFAULT 30,
        subfinder_enabled INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
        status TEXT DEFAULT 'running', triggered_by TEXT DEFAULT 'manual',
        total INTEGER DEFAULT 0, done INTEGER DEFAULT 0,
        mismatches INTEGER DEFAULT 0, expired INTEGER DEFAULT 0,
        expiring INTEGER DEFAULT 0, errors INTEGER DEFAULT 0, ok INTEGER DEFAULT 0,
        started_at TEXT, finished_at TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS results (
        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, project_id TEXT NOT NULL,
        hostname TEXT NOT NULL, cn TEXT DEFAULT '', sans TEXT DEFAULT '[]',
        issuer TEXT DEFAULT '', expiry TEXT DEFAULT '', not_before TEXT DEFAULT '', days_left INTEGER,
        serial_number TEXT DEFAULT '', fingerprint_sha256 TEXT DEFAULT '',
        tls_version TEXT DEFAULT '', cipher_suite TEXT DEFAULT '', cipher_bits INTEGER DEFAULT 0,
        signature_algorithm TEXT DEFAULT '', key_algorithm TEXT DEFAULT '', key_bits INTEGER DEFAULT 0,
        san_count INTEGER DEFAULT 0,
        match_found INTEGER DEFAULT 0, same_base INTEGER DEFAULT 0,
        is_mismatch INTEGER DEFAULT 0, is_expired INTEGER DEFAULT 0,
        is_expiring INTEGER DEFAULT 0, is_ok INTEGER DEFAULT 0,
        error TEXT DEFAULT '', checked_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL, scan_id TEXT DEFAULT '',
        hostname TEXT NOT NULL, issue_type TEXT NOT NULL, details TEXT DEFAULT '',
        mismatch_scope TEXT DEFAULT '',
        dedup_key TEXT NOT NULL UNIQUE, sent INTEGER DEFAULT 0,
        seen INTEGER DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alert_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        telegram_enabled INTEGER DEFAULT 0,
        telegram_bot_token TEXT DEFAULT '',
        telegram_chat_id TEXT DEFAULT '',
        slack_enabled INTEGER DEFAULT 0,
        slack_webhook_url TEXT DEFAULT '',
        discord_enabled INTEGER DEFAULT 0,
        discord_webhook_url TEXT DEFAULT '',
        rule_mismatch INTEGER DEFAULT 1,
        rule_expired INTEGER DEFAULT 1,
        rule_expiring INTEGER DEFAULT 1,
        rule_error INTEGER DEFAULT 0,
        mismatch_scope_filter TEXT DEFAULT 'all',
        minimum_days_left INTEGER DEFAULT 30,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS subfinder_jobs (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        domains_input TEXT DEFAULT '',
        raw_output_path TEXT DEFAULT '',
        new_count INTEGER DEFAULT 0,
        total_found INTEGER DEFAULT 0,
        triggered_by TEXT DEFAULT 'scheduler',
        started_at TEXT NOT NULL, finished_at TEXT
    );
    CREATE TABLE IF NOT EXISTS subfinder_raw_results (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        root_domain TEXT NOT NULL,
        command TEXT DEFAULT '',
        status TEXT DEFAULT 'running',
        exit_code INTEGER,
        total_found INTEGER DEFAULT 0,
        stdout_text TEXT DEFAULT '',
        stderr_text TEXT DEFAULT '',
        stdout_z BLOB,
        stderr_z BLOB,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        FOREIGN KEY(job_id) REFERENCES subfinder_jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS subfinder_hosts (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
        hostname TEXT NOT NULL, source TEXT DEFAULT 'subfinder',
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        ssl_scanned INTEGER DEFAULT 0,
        UNIQUE(project_id, hostname)
    );
    CREATE TABLE IF NOT EXISTS subfinder_new_discoveries (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        UNIQUE(job_id, hostname),
        FOREIGN KEY(job_id) REFERENCES subfinder_jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS subfinder_httpx_results (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        status_code INTEGER,
        page_title TEXT DEFAULT '',
        redirect_location TEXT DEFAULT '',
        final_url TEXT DEFAULT '',
        scheme TEXT DEFAULT '',
        is_active INTEGER DEFAULT 0,
        source_job_id TEXT DEFAULT '',
        last_checked TEXT NOT NULL,
        UNIQUE(project_id, hostname)
    );
    CREATE TABLE IF NOT EXISTS domain_enum_scans (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        triggered_by TEXT DEFAULT 'manual',
        tool_summary TEXT DEFAULT '',
        total_found INTEGER DEFAULT 0,
        started_at TEXT NOT NULL,
        finished_at TEXT
    );
    CREATE TABLE IF NOT EXISTS domain_enum_results (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        hostname TEXT NOT NULL,
        source TEXT DEFAULT '',
        discovered_at TEXT NOT NULL,
        UNIQUE(scan_id, hostname),
        FOREIGN KEY(scan_id) REFERENCES domain_enum_scans(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS openssl_results (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        status TEXT DEFAULT '',
        subject TEXT DEFAULT '',
        error TEXT DEFAULT '',
        exit_code INTEGER,
        source TEXT DEFAULT 'manual',
        last_checked TEXT NOT NULL,
        UNIQUE(project_id, hostname)
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        project_id TEXT DEFAULT '',
        status TEXT DEFAULT 'queued',
        progress INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0,
        done INTEGER DEFAULT 0,
        source TEXT DEFAULT '',
        payload_json TEXT DEFAULT '{}',
        started_at TEXT,
        finished_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS job_events (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        event TEXT NOT NULL,
        payload_json TEXT DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS job_controls (
        job_id TEXT NOT NULL,
        action TEXT NOT NULL,
        requested INTEGER DEFAULT 0,
        reason TEXT DEFAULT '',
        updated_at TEXT NOT NULL,
        PRIMARY KEY(job_id, action),
        FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        value TEXT NOT NULL,
        exposure TEXT DEFAULT 'unknown',
        source TEXT DEFAULT '',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        metadata TEXT DEFAULT '{}',
        UNIQUE(project_id, asset_type, value)
    );
    CREATE TABLE IF NOT EXISTS asset_relationships (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        source_asset_id TEXT NOT NULL,
        target_asset_id TEXT DEFAULT '',
        relationship_type TEXT NOT NULL,
        target_value TEXT DEFAULT '',
        metadata TEXT DEFAULT '{}',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(project_id, source_asset_id, relationship_type, target_asset_id, target_value)
    );
    CREATE TABLE IF NOT EXISTS asset_observations (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        source TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        port INTEGER,
        protocol TEXT DEFAULT '',
        data TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS asset_findings (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        source TEXT NOT NULL,
        severity TEXT DEFAULT '',
        title TEXT DEFAULT '',
        finding_key TEXT NOT NULL,
        details TEXT DEFAULT '{}',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(project_id, asset_id, source, finding_key)
    );
    CREATE INDEX IF NOT EXISTS idx_res_scan  ON results(scan_id);
    CREATE INDEX IF NOT EXISTS idx_res_proj  ON results(project_id);
    CREATE INDEX IF NOT EXISTS idx_res_mis   ON results(scan_id, is_mismatch);
    CREATE INDEX IF NOT EXISTS idx_scans_proj ON scans(project_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_dd ON alerts(dedup_key);
    CREATE INDEX IF NOT EXISTS idx_alerts_seen_created ON alerts(seen, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sfhosts_proj ON subfinder_hosts(project_id);
    CREATE INDEX IF NOT EXISTS idx_sfraw_job ON subfinder_raw_results(job_id);
    CREATE INDEX IF NOT EXISTS idx_sfraw_project ON subfinder_raw_results(project_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sfnew_job ON subfinder_new_discoveries(job_id);
    CREATE INDEX IF NOT EXISTS idx_sfnew_project ON subfinder_new_discoveries(project_id, discovered_at DESC);
    CREATE INDEX IF NOT EXISTS idx_results_proj_host_checked ON results(project_id, hostname, checked_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_triggered_by ON scans(triggered_by);
    CREATE INDEX IF NOT EXISTS idx_sfjobs_proj_started ON subfinder_jobs(project_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sfnew_proj_job_host ON subfinder_new_discoveries(project_id, job_id, hostname);
    CREATE INDEX IF NOT EXISTS idx_sfhttpx_proj_checked ON subfinder_httpx_results(project_id, last_checked DESC);
    CREATE INDEX IF NOT EXISTS idx_openssl_proj_checked ON openssl_results(project_id, last_checked DESC);
    CREATE INDEX IF NOT EXISTS idx_jobs_type_status ON jobs(type, status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_jobs_project ON jobs(project_id, type, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_job_events_job_rowid ON job_events(job_id);
    CREATE INDEX IF NOT EXISTS idx_assets_proj_seen ON assets(project_id, last_seen DESC);
    CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
    CREATE INDEX IF NOT EXISTS idx_asset_rel_source ON asset_relationships(source_asset_id, relationship_type);
    CREATE INDEX IF NOT EXISTS idx_asset_obs_asset_seen ON asset_observations(asset_id, observed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_asset_findings_asset_seen ON asset_findings(asset_id, last_seen DESC);
    CREATE INDEX IF NOT EXISTS idx_den_scans_domain_started ON domain_enum_scans(domain, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_den_results_scan ON domain_enum_results(scan_id);
    CREATE INDEX IF NOT EXISTS idx_den_results_domain_host ON domain_enum_results(domain, hostname);
    """)
    # Lightweight migrations for existing DBs
    try:
        x("ALTER TABLE subfinder_jobs ADD COLUMN raw_output_path TEXT DEFAULT ''")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE alerts ADD COLUMN mismatch_scope TEXT DEFAULT ''")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE alert_settings ADD COLUMN rule_error INTEGER DEFAULT 0")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE alert_settings ADD COLUMN minimum_days_left INTEGER DEFAULT 30")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE subfinder_raw_results ADD COLUMN stdout_z BLOB")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE subfinder_raw_results ADD COLUMN stderr_z BLOB")
        commit()
    except sqlite3.OperationalError:
        pass
    for column, ddl in {
        "not_before": "TEXT DEFAULT ''",
        "serial_number": "TEXT DEFAULT ''",
        "fingerprint_sha256": "TEXT DEFAULT ''",
        "tls_version": "TEXT DEFAULT ''",
        "cipher_suite": "TEXT DEFAULT ''",
        "cipher_bits": "INTEGER DEFAULT 0",
        "signature_algorithm": "TEXT DEFAULT ''",
        "key_algorithm": "TEXT DEFAULT ''",
        "key_bits": "INTEGER DEFAULT 0",
        "san_count": "INTEGER DEFAULT 0",
    }.items():
        try:
            x(f"ALTER TABLE results ADD COLUMN {column} {ddl}")
            commit()
        except sqlite3.OperationalError:
            pass
    # Data cleanup for old DBs: keep only the latest duplicate rows.
    x(
        """
        DELETE FROM alerts
        WHERE id IN (
          SELECT a.id
          FROM alerts a
          JOIN alerts newer
            ON newer.dedup_key = a.dedup_key
           AND (newer.created_at > a.created_at OR (newer.created_at = a.created_at AND newer.id > a.id))
        )
        """
    )
    x(
        """
        DELETE FROM subfinder_raw_results
        WHERE id IN (
          SELECT r.id
          FROM subfinder_raw_results r
          JOIN subfinder_raw_results newer
            ON newer.job_id = r.job_id
           AND newer.root_domain = r.root_domain
           AND (newer.started_at > r.started_at OR (newer.started_at = r.started_at AND newer.id > r.id))
        )
        """
    )
    x(
        """
        DELETE FROM subfinder_new_discoveries
        WHERE id IN (
          SELECT n.id
          FROM subfinder_new_discoveries n
          JOIN subfinder_new_discoveries newer
            ON newer.project_id = n.project_id
           AND newer.hostname = n.hostname
           AND (newer.discovered_at > n.discovered_at OR (newer.discovered_at = n.discovered_at AND newer.id > n.id))
        )
        """
    )
    try:
        x("CREATE UNIQUE INDEX IF NOT EXISTS idx_sfraw_job_root_unique ON subfinder_raw_results(job_id, root_domain)")
    except sqlite3.IntegrityError:
        pass
    try:
        x("CREATE UNIQUE INDEX IF NOT EXISTS idx_sfnew_project_host_unique ON subfinder_new_discoveries(project_id, hostname)")
    except sqlite3.IntegrityError:
        pass
    x("UPDATE jobs SET status='stopped', finished_at=COALESCE(finished_at, ?), updated_at=? WHERE status IN ('queued','preparing','running','paused','stopping')", (now(), now()))
    x(
        """
        INSERT OR IGNORE INTO alert_settings(
            id, telegram_enabled, telegram_bot_token, telegram_chat_id,
            slack_enabled, slack_webhook_url, discord_enabled, discord_webhook_url,
            rule_mismatch, rule_expired, rule_expiring, rule_error,
            mismatch_scope_filter, minimum_days_left, updated_at
        ) VALUES(1,0,'','',0,'',0,'',1,1,1,0,'all',30,?)
        """,
        (now(),),
    )
    commit()
    log.info("DB ready at %s", DB_PATH)


# ── Projects ──────────────────────────────────────────────────────────────────

PROJECT_INTERVAL_MINUTES_MIN = 5
PROJECT_INTERVAL_MINUTES_MAX = 10080


def _clamp_project_interval(value, default=60):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(PROJECT_INTERVAL_MINUTES_MIN, min(PROJECT_INTERVAL_MINUTES_MAX, parsed))


def project_create(name, description="", scan_interval=60, subfinder_interval=30):
    scan_interval = _clamp_project_interval(scan_interval, 60)
    subfinder_interval = _clamp_project_interval(subfinder_interval, 30)
    pid, n = uid(), now()
    x("INSERT INTO projects(id,name,description,scan_interval_minutes,subfinder_interval_minutes,created_at,updated_at)"
      " VALUES(?,?,?,?,?,?,?)", (pid, name, description, scan_interval, subfinder_interval, n, n))
    commit()
    return project_get(pid)

def project_get(pid):
    r = x(
        "SELECT id,name,description,host_count,scan_interval_minutes,"
        "subfinder_interval_minutes,subfinder_enabled,enabled,created_at,updated_at "
        "FROM projects WHERE id=?",
        (pid,),
    ).fetchone()
    return dict(r) if r else None

def project_get_by_name(name):
    r = x("SELECT * FROM projects WHERE name=?", (name,)).fetchone()
    return dict(r) if r else None

def project_list():
    return [
        dict(r)
        for r in x(
            "SELECT id,name,description,host_count,scan_interval_minutes,"
            "subfinder_interval_minutes,subfinder_enabled,enabled,created_at,updated_at "
            "FROM projects ORDER BY created_at DESC"
        )
    ]

def project_update(pid, **kw):
    if "scan_interval_minutes" in kw:
        kw["scan_interval_minutes"] = _clamp_project_interval(kw["scan_interval_minutes"], 60)
    if "subfinder_interval_minutes" in kw:
        kw["subfinder_interval_minutes"] = _clamp_project_interval(kw["subfinder_interval_minutes"], 30)
    kw["updated_at"] = now()
    sets = ",".join(f"{k}=?" for k in kw)
    x(f"UPDATE projects SET {sets} WHERE id=?", [*kw.values(), pid])
    commit()

def project_delete(pid):
    for t in ("job_events","job_controls","jobs","asset_findings","asset_observations","asset_relationships","assets","results","alerts","scans","subfinder_jobs","subfinder_hosts","subfinder_new_discoveries","openssl_results"):
        x(f"DELETE FROM {t} WHERE project_id=?", (pid,)) if t not in {"job_events", "job_controls"} else None
    x("DELETE FROM projects WHERE id=?", (pid,))
    commit()

def project_hosts(pid):
    r = x("SELECT hosts_file FROM projects WHERE id=?", (pid,)).fetchone()
    if not r or not r["hosts_file"]:
        return []
    return [h.strip() for h in r["hosts_file"].splitlines() if h.strip()]

def project_save_hosts(pid, hosts):
    project_update(pid, hosts_file="\n".join(hosts), host_count=len(hosts))


# ── Scans ─────────────────────────────────────────────────────────────────────

def scan_create(pid, total, by="manual"):
    sid, n = uid(), now()
    x("INSERT INTO scans(id,project_id,total,triggered_by,started_at,created_at) VALUES(?,?,?,?,?,?)",
      (sid, pid, total, by, n, n))
    commit()
    return scan_get(sid)

def scan_get(sid):
    r = x("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None

def scan_update(sid, **kw):
    sets = ",".join(f"{k}=?" for k in kw)
    x(f"UPDATE scans SET {sets} WHERE id=?", [*kw.values(), sid])
    commit()

def scan_progress(sid, done):
    x("UPDATE scans SET done=? WHERE id=?", (done, sid))
    commit()

def scan_finish(sid):
    r = x("SELECT COUNT(*) t, SUM(is_mismatch) mis, SUM(is_expired) exp,"
          " SUM(is_expiring) expi, SUM(is_ok) ok,"
          " SUM(CASE WHEN error!='' THEN 1 ELSE 0 END) err"
          " FROM results WHERE scan_id=?", (sid,)).fetchone()
    x("UPDATE scans SET status='done',finished_at=?,done=?,mismatches=?,expired=?,"
      "expiring=?,ok=?,errors=? WHERE id=?",
      (now(), r["t"], r["mis"] or 0, r["exp"] or 0,
       r["expi"] or 0, r["ok"] or 0, r["err"] or 0, sid))
    commit()

def scan_list(pid, limit=20):
    return [dict(r) for r in x(
        "SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (pid, limit))]

def scan_latest(pid):
    r = x("SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT 1", (pid,)).fetchone()
    return dict(r) if r else None


def _delete_by_ids(table: str, id_column: str, ids: list[str]) -> int:
    deleted = 0
    for chunk in _chunked(ids, 500):
        placeholders = ",".join(["?"] * len(chunk))
        deleted += x(f"DELETE FROM {table} WHERE {id_column} IN ({placeholders})", chunk).rowcount or 0
    return deleted


def _checkpoint_and_vacuum(should_vacuum: bool = False):
    # Flush WAL pages so the on-disk size visible to hosts/containers drops after cleanup.
    try:
        x("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        pass
    if should_vacuum:
        try:
            x("VACUUM")
        except sqlite3.OperationalError as exc:
            log.warning("SQLite VACUUM skipped: %s", exc)


def storage_prune(
    scan_days: int = 7,
    raw_days: int = 2,
    max_scans_per_project: int = 50,
    max_domain_enum_scans: int = 200,
    vacuum: bool = False,
) -> dict:
    """Delete old high-volume history so DB and raw-output storage stay bounded."""
    keep_scan_days = max(1, int(scan_days or 7))
    keep_raw_days = max(1, int(raw_days or 2))
    max_scans = max(1, int(max_scans_per_project or 50))
    max_domain_enum = max(1, int(max_domain_enum_scans or 200))
    scan_cutoff = x("SELECT datetime('now', ?)", (f"-{keep_scan_days} days",)).fetchone()[0]
    raw_cutoff = x("SELECT datetime('now', ?)", (f"-{keep_raw_days} days",)).fetchone()[0]

    old_scan_ids = {r["id"] for r in x("SELECT id FROM scans WHERE created_at < ?", (scan_cutoff,)).fetchall()}
    overflow_scan_ids = {
        r["id"]
        for r in x(
            """
            SELECT id FROM (
              SELECT id, ROW_NUMBER() OVER (PARTITION BY project_id ORDER BY created_at DESC, id DESC) AS rn
              FROM scans
            ) WHERE rn > ?
            """,
            (max_scans,),
        ).fetchall()
    }
    scan_ids = sorted(old_scan_ids | overflow_scan_ids)

    results_deleted = 0
    alerts_deleted = 0
    scans_deleted = 0
    if scan_ids:
        results_deleted = _delete_by_ids("results", "scan_id", scan_ids)
        alerts_deleted = _delete_by_ids("alerts", "scan_id", scan_ids)
        scans_deleted = _delete_by_ids("scans", "id", scan_ids)

    raw_job_rows = x("SELECT id, raw_output_path FROM subfinder_jobs WHERE started_at < ?", (raw_cutoff,)).fetchall()
    raw_job_ids = {r["id"] for r in raw_job_rows}
    old_raw_paths = [r["raw_output_path"] for r in raw_job_rows if r["raw_output_path"]]
    raw_result_ids = {
        r["id"]
        for r in x(
            """
            SELECT id FROM subfinder_raw_results
            WHERE started_at < ?
               OR (job_id IN (SELECT id FROM subfinder_jobs WHERE started_at < ?))
            """,
            (raw_cutoff, raw_cutoff),
        ).fetchall()
    }
    discoveries_deleted = _delete_by_ids("subfinder_new_discoveries", "job_id", sorted(raw_job_ids)) if raw_job_ids else 0
    raw_results_deleted = _delete_by_ids("subfinder_raw_results", "id", sorted(raw_result_ids)) if raw_result_ids else 0
    subfinder_jobs_deleted = _delete_by_ids("subfinder_jobs", "id", sorted(raw_job_ids)) if raw_job_ids else 0

    raw_files_deleted = 0
    for raw_path in old_raw_paths:
        try:
            path = Path(raw_path)
            if path.exists() and path.is_file():
                path.unlink()
                raw_files_deleted += 1
        except OSError as exc:
            log.warning("Unable to delete raw subfinder file %s: %s", raw_path, exc)

    stale_domain_ids = {r["id"] for r in x("SELECT id FROM domain_enum_scans WHERE started_at < ?", (scan_cutoff,)).fetchall()}
    overflow_domain_ids = {
        r["id"]
        for r in x(
            """
            SELECT id FROM (
              SELECT id, ROW_NUMBER() OVER (ORDER BY started_at DESC, id DESC) AS rn
              FROM domain_enum_scans
            ) WHERE rn > ?
            """,
            (max_domain_enum,),
        ).fetchall()
    }
    domain_ids = sorted(stale_domain_ids | overflow_domain_ids)
    domain_results_deleted = _delete_by_ids("domain_enum_results", "scan_id", domain_ids) if domain_ids else 0
    domain_scans_deleted = _delete_by_ids("domain_enum_scans", "id", domain_ids) if domain_ids else 0

    commit()
    deleted_total = sum([
        results_deleted, alerts_deleted, scans_deleted, discoveries_deleted, raw_results_deleted,
        subfinder_jobs_deleted, domain_results_deleted, domain_scans_deleted, raw_files_deleted,
    ])
    _checkpoint_and_vacuum(should_vacuum=vacuum and deleted_total > 0)
    return {
        "scan_cutoff": scan_cutoff,
        "raw_cutoff": raw_cutoff,
        "scans_deleted": scans_deleted,
        "results_deleted": results_deleted,
        "alerts_deleted": alerts_deleted,
        "subfinder_jobs_deleted": subfinder_jobs_deleted,
        "subfinder_raw_results_deleted": raw_results_deleted,
        "subfinder_discoveries_deleted": discoveries_deleted,
        "subfinder_raw_files_deleted": raw_files_deleted,
        "domain_enum_scans_deleted": domain_scans_deleted,
        "domain_enum_results_deleted": domain_results_deleted,
    }


def scans_prune_older_than(days: int = 7) -> dict:
    """Backward-compatible scan retention wrapper used by tests/older callers."""
    stats = storage_prune(
        scan_days=days,
        raw_days=_env_int("RAW_RETENTION_DAYS", 2, minimum=1),
        max_scans_per_project=_env_int("MAX_SCANS_PER_PROJECT", 50, minimum=1),
        max_domain_enum_scans=_env_int("MAX_DOMAIN_ENUM_SCANS", 200, minimum=1),
        vacuum=False,
    )
    stats["cutoff"] = stats.get("scan_cutoff")
    return stats


# ── Results (batch) ───────────────────────────────────────────────────────────

def results_batch_save(sid, pid, batch, *, backfill_assets=True):
    n = now()
    rows = [(uid(), sid, pid,
             r.get("hostname",""), r.get("cn",""), json.dumps(r.get("sans",[])),
             r.get("issuer",""), r.get("expiry",""), r.get("not_before", ""), r.get("days_left"),
             r.get("serial_number", ""), r.get("fingerprint_sha256", ""),
             r.get("tls_version", ""), r.get("cipher_suite", ""), int(r.get("cipher_bits") or 0),
             r.get("signature_algorithm", ""), r.get("key_algorithm", ""), int(r.get("key_bits") or 0),
             int(r.get("san_count") or len(r.get("sans", []) or [])),
             1 if r.get("match_found") else 0, 1 if r.get("same_base") else 0,
             1 if r.get("is_mismatch") else 0, 1 if r.get("is_expired") else 0,
             1 if r.get("is_expiring_soon") else 0, 1 if r.get("is_ok") else 0,
             r.get("error","") or "", n) for r in batch]
    xm("INSERT INTO results(id,scan_id,project_id,hostname,cn,sans,issuer,expiry,not_before,"
       "days_left,serial_number,fingerprint_sha256,tls_version,cipher_suite,cipher_bits,"
       "signature_algorithm,key_algorithm,key_bits,san_count,match_found,same_base,"
       "is_mismatch,is_expired,is_expiring,is_ok,error,checked_at)"
       " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    if backfill_assets:
        asset_backfill_project(pid)
    commit()

def results_get(sid, flt="all", page=1, per_page=500):
    base, p = "FROM results WHERE scan_id=?", [sid]
    if flt == "mismatch":  base += " AND is_mismatch=1"
    elif flt == "expired":  base += " AND is_expired=1"
    elif flt == "expiring": base += " AND is_expiring=1"
    elif flt == "ok":       base += " AND is_ok=1"
    elif flt == "errors":   base += " AND error!='' AND error IS NOT NULL"
    total = x(f"SELECT COUNT(*) {base}", p).fetchone()[0]
    offset = (page - 1) * per_page
    rows = x(f"SELECT * {base} ORDER BY is_mismatch DESC,is_expired DESC,hostname"
             f" LIMIT ? OFFSET ?", p + [per_page, offset]).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        try: d["sans"] = json.loads(d.get("sans") or "[]")
        except: d["sans"] = []
        out.append(d)
    return {"results": out, "total": total, "page": page,
            "pages": max(1,(total+per_page-1)//per_page), "per_page": per_page}

def scan_results_all(sid, flt="all"):
    base, p = "FROM results WHERE scan_id=?", [sid]
    if flt == "mismatch":  base += " AND is_mismatch=1"
    elif flt == "expired":  base += " AND is_expired=1"
    elif flt == "expiring": base += " AND is_expiring=1"
    elif flt == "ok":       base += " AND is_ok=1"
    elif flt == "errors":   base += " AND error!='' AND error IS NOT NULL"
    rows = x(f"SELECT * {base} ORDER BY is_mismatch DESC,is_expired DESC,hostname", p).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        try:
            d["sans"] = json.loads(d.get("sans") or "[]")
        except Exception:
            d["sans"] = []
        out.append(d)
    return out


def scan_compare(current_sid, previous_sid=None):
    current_scan = scan_get(current_sid)
    if not current_scan:
        return None
    if not previous_sid:
        prev = x(
            "SELECT id FROM scans WHERE project_id=? AND created_at < ? ORDER BY created_at DESC LIMIT 1",
            (current_scan["project_id"], current_scan["created_at"]),
        ).fetchone()
        previous_sid = prev["id"] if prev else None
    previous_scan = scan_get(previous_sid) if previous_sid else None

    current_rows = {r["hostname"]: dict(r) for r in x("SELECT * FROM results WHERE scan_id=?", (current_sid,)).fetchall()}
    previous_rows = {r["hostname"]: dict(r) for r in x("SELECT * FROM results WHERE scan_id=?", (previous_sid,)).fetchall()} if previous_sid else {}

    current_hosts = set(current_rows)
    previous_hosts = set(previous_rows)
    added_hosts = sorted(current_hosts - previous_hosts)
    removed_hosts = sorted(previous_hosts - current_hosts)
    common_hosts = current_hosts & previous_hosts

    def issue_key(row):
        if not row:
            return "missing"
        if row.get("error"):
            return f"error:{row.get('error')}"
        if row.get("is_expired"):
            return "expired"
        if row.get("is_mismatch"):
            return "mismatch"
        if row.get("is_expiring"):
            return "expiring"
        if row.get("is_ok"):
            return "ok"
        return "unknown"

    changed = []
    renewed = []
    for host in sorted(common_hosts):
        cur = current_rows[host]
        prev = previous_rows[host]
        if issue_key(cur) != issue_key(prev):
            changed.append({
                "hostname": host,
                "from": issue_key(prev),
                "to": issue_key(cur),
                "previous_expiry": prev.get("expiry") or "",
                "current_expiry": cur.get("expiry") or "",
            })
        if (cur.get("fingerprint_sha256") and prev.get("fingerprint_sha256")
                and cur.get("fingerprint_sha256") != prev.get("fingerprint_sha256")):
            renewed.append({
                "hostname": host,
                "previous_expiry": prev.get("expiry") or "",
                "current_expiry": cur.get("expiry") or "",
                "previous_fingerprint": prev.get("fingerprint_sha256") or "",
                "current_fingerprint": cur.get("fingerprint_sha256") or "",
            })

    return {
        "current_scan": current_scan,
        "previous_scan": previous_scan,
        "summary": {
            "added_hosts": len(added_hosts),
            "removed_hosts": len(removed_hosts),
            "changed_status": len(changed),
            "renewed_certificates": len(renewed),
            "current_total": len(current_rows),
            "previous_total": len(previous_rows),
        },
        "added_hosts": added_hosts[:500],
        "removed_hosts": removed_hosts[:500],
        "changed_status": changed[:500],
        "renewed_certificates": renewed[:500],
    }


# ── Alerts ────────────────────────────────────────────────────────────────────

def alert_add(pid, hostname, issue, detail, scan_id="", mismatch_scope=""):
    host = (hostname or "").strip().lower()
    dedup = f"{pid}:{host}:{issue}"
    existing = x("SELECT id FROM alerts WHERE dedup_key=?", (dedup,)).fetchone()
    if existing:
        # Refresh existing alert so recurring issues show up again in the Alerts feed
        # and can be re-dispatched to configured channels.
        x("UPDATE alerts SET scan_id=?,details=?,mismatch_scope=?,seen=0,sent=0,created_at=? WHERE id=?",
          (scan_id, detail, mismatch_scope or "", now(), existing["id"]))
        commit()
        return False
    x("INSERT INTO alerts(id,project_id,scan_id,hostname,issue_type,details,mismatch_scope,dedup_key,created_at)"
      " VALUES(?,?,?,?,?,?,?,?,?)", (uid(), pid, scan_id, host, issue, detail, mismatch_scope or "", dedup, now()))
    commit()
    return True

def alerts_get(search="", mismatch_scope="all", project_id="", page=1, per_page=200):
    clauses = ["1=1"]
    params = []
    if search:
        clauses.append("LOWER(a.hostname) LIKE ?")
        params.append(f"%{search.lower()}%")
    if mismatch_scope in ("same_domain", "different_domain"):
        clauses.append("a.mismatch_scope=?")
        params.append(mismatch_scope)
    if project_id:
        clauses.append("a.project_id=?")
        params.append(project_id)
    where = " AND ".join(clauses)
    dedup_sql = (
        "SELECT * FROM ("
        " SELECT a.*, ROW_NUMBER() OVER ("
        "   PARTITION BY a.project_id, a.hostname, a.issue_type"
        "   ORDER BY a.created_at DESC, a.id DESC"
        " ) AS rn"
        " FROM alerts a"
        ") WHERE rn=1"
    )
    total = x(
        f"SELECT COUNT(*) FROM ({dedup_sql}) a"
        f" JOIN projects p ON p.id=a.project_id WHERE {where}",
        params,
    ).fetchone()[0]
    offset = (page - 1) * per_page
    rows = [dict(r) for r in x(
        f"SELECT a.*,p.name project_name FROM ({dedup_sql}) a"
        f" JOIN projects p ON p.id=a.project_id WHERE {where}"
        " ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    )]
    return {
        "alerts": rows,
        "total": total,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "per_page": per_page,
    }

def alerts_unseen_count():
    return x("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0]

def alerts_mark_all_seen():
    x("UPDATE alerts SET seen=1"); commit()

def alerts_clear():
    x("DELETE FROM alerts"); commit()

def alerts_unsent():
    return [dict(r) for r in x(
        "SELECT a.*,p.name project_name FROM alerts a"
        " JOIN projects p ON p.id=a.project_id WHERE a.sent=0")]

def alert_mark_sent(aid):
    x("UPDATE alerts SET sent=1 WHERE id=?", (aid,)); commit()

def alerts_mark_all_unsent():
    x("UPDATE alerts SET sent=0")
    commit()


def alert_mark_seen(aid):
    x("UPDATE alerts SET seen=1 WHERE id=?", (aid,))
    commit()


def alert_settings_get():
    row = x("SELECT * FROM alert_settings WHERE id=1").fetchone()
    if not row:
        return {
            "telegram_enabled": 0,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "slack_enabled": 0,
            "slack_webhook_url": "",
            "discord_enabled": 0,
            "discord_webhook_url": "",
            "rule_mismatch": 1,
            "rule_expired": 1,
            "rule_expiring": 1,
            "rule_error": 0,
            "mismatch_scope_filter": "all",
            "minimum_days_left": 30,
            "updated_at": now(),
        }
    return dict(row)


def alert_settings_update(**kw):
    allowed = {
        "telegram_enabled",
        "telegram_bot_token",
        "telegram_chat_id",
        "slack_enabled",
        "slack_webhook_url",
        "discord_enabled",
        "discord_webhook_url",
        "rule_mismatch",
        "rule_expired",
        "rule_expiring",
        "rule_error",
        "mismatch_scope_filter",
        "minimum_days_left",
    }
    data = {k: v for k, v in kw.items() if k in allowed}
    for key in (
        "telegram_enabled",
        "slack_enabled",
        "discord_enabled",
        "rule_mismatch",
        "rule_expired",
        "rule_expiring",
        "rule_error",
    ):
        if key in data:
            data[key] = 1 if bool(data[key]) else 0
    if "mismatch_scope_filter" in data and data["mismatch_scope_filter"] not in {"all", "same_domain", "different_domain"}:
        data["mismatch_scope_filter"] = "all"
    if "minimum_days_left" in data:
        data["minimum_days_left"] = max(1, min(365, int(data["minimum_days_left"] or 30)))
    data["updated_at"] = now()
    sets = ",".join(f"{k}=?" for k in data.keys())
    params = list(data.values()) + [1]
    x(f"UPDATE alert_settings SET {sets} WHERE id=?", params)
    commit()
    return alert_settings_get()


# ── Subfinder ─────────────────────────────────────────────────────────────────

def subfinder_job_create(pid, domains_input, by="scheduler"):
    jid = uid()
    x("INSERT INTO subfinder_jobs(id,project_id,domains_input,triggered_by,started_at)"
      " VALUES(?,?,?,?,?)", (jid, pid, domains_input, by, now()))
    commit()
    return jid

def subfinder_job_finish(jid, new_count, total_found, raw_output_path=""):
    x("UPDATE subfinder_jobs SET status='done',finished_at=?,new_count=?,total_found=?,raw_output_path=? WHERE id=?",
      (now(), new_count, total_found, raw_output_path or "", jid))
    commit()

def subfinder_job_error(jid, msg):
    x("UPDATE subfinder_jobs SET status='error',finished_at=? WHERE id=?", (now(), jid))
    commit()

def subfinder_jobs_list(pid, limit=20):
    return [dict(r) for r in x(
        "SELECT * FROM subfinder_jobs WHERE project_id=? ORDER BY started_at DESC LIMIT ?",
        (pid, limit))]

def subfinder_hosts_add_batch(pid, hostnames):
    """Insert new hostnames, ignore duplicates. Returns (count, new_hostnames)."""
    n = now()
    deduped = sorted({(h or "").strip().lower() for h in hostnames if (h or "").strip()})
    if not deduped:
        return 0, []

    existing = set()
    # SQLite has a hard cap on bound SQL variables per statement.
    for chunk in _chunked(deduped, 500):
        placeholders = ",".join(["?"] * len(chunk))
        rows = x(
            f"SELECT hostname FROM subfinder_hosts WHERE project_id=? AND hostname IN ({placeholders})",
            [pid, *chunk],
        ).fetchall()
        existing.update(r["hostname"] for r in rows)

    new_hosts = [h for h in deduped if h not in existing]
    rows = [(uid(), pid, h, "subfinder", n, n) for h in deduped]
    xm("INSERT OR IGNORE INTO subfinder_hosts(id,project_id,hostname,source,first_seen,last_seen)"
       " VALUES(?,?,?,?,?,?)", rows)
    xm("UPDATE subfinder_hosts SET last_seen=? WHERE project_id=? AND hostname=?", [(n, pid, h) for h in deduped])
    asset_backfill_project(pid)
    commit()
    return len(new_hosts), new_hosts

def subfinder_hosts_new_unsscanned(pid):
    """Hostnames discovered by subfinder but not yet SSL-scanned."""
    return [r["hostname"] for r in x(
        "SELECT hostname FROM subfinder_hosts WHERE project_id=? AND ssl_scanned=0", (pid,))]

def subfinder_hosts_mark_scanned(pid, hostnames):
    xm("UPDATE subfinder_hosts SET ssl_scanned=1 WHERE project_id=? AND hostname=?",
       [(pid, h) for h in hostnames])
    commit()

def subfinder_hosts_list(pid, page=1, per_page=500):
    total = x("SELECT COUNT(*) FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchone()[0]
    offset = (page-1)*per_page
    rows = x("SELECT * FROM subfinder_hosts WHERE project_id=? ORDER BY first_seen DESC LIMIT ? OFFSET ?",
             (pid, per_page, offset)).fetchall()
    return {"hosts": [dict(r) for r in rows], "total": total, "page": page,
            "pages": max(1,(total+per_page-1)//per_page)}


def subfinder_new_discoveries_add_batch(job_id, pid, hostnames):
    deduped = sorted({(h or "").strip().lower() for h in hostnames if (h or "").strip()})
    if not deduped:
        return 0
    ts = now()
    rows = [(uid(), job_id, pid, h, ts) for h in deduped]
    xm("INSERT OR IGNORE INTO subfinder_new_discoveries(id,job_id,project_id,hostname,discovered_at)"
       " VALUES(?,?,?,?,?)", rows)
    commit()
    return x(
        "SELECT COUNT(*) FROM subfinder_new_discoveries WHERE job_id=?",
        (job_id,),
    ).fetchone()[0]


def subfinder_discoveries(pid, page=1, per_page=200, search="", mode="all"):
    search_like = f"%{search.lower()}%"
    if mode == "latest":
        where = "WHERE h.project_id=? AND EXISTS (SELECT 1 FROM subfinder_new_discoveries n WHERE n.project_id=h.project_id AND n.hostname=h.hostname)"
        params = [pid]
    elif mode == "last_job":
        where = (
            "WHERE h.project_id=? AND EXISTS ("
            "SELECT 1 FROM subfinder_new_discoveries n "
            "WHERE n.project_id=h.project_id AND n.hostname=h.hostname "
            "AND n.job_id=(SELECT j.id FROM subfinder_jobs j WHERE j.project_id=? ORDER BY j.started_at DESC LIMIT 1)"
            ")"
        )
        params = [pid, pid]
    else:
        where = "WHERE h.project_id=?"
        params = [pid]
    if search:
        where += " AND LOWER(h.hostname) LIKE ?"
        params.append(search_like)
    total = x(f"SELECT COUNT(*) FROM subfinder_hosts h {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = x(
        f"""
        WITH filtered_hosts AS (
          SELECT
            h.project_id,
            h.hostname,
            h.first_seen,
            h.last_seen,
            h.ssl_scanned
          FROM subfinder_hosts h
          {where}
          ORDER BY h.first_seen DESC
          LIMIT ? OFFSET ?
        ),
        latest_result AS (
          SELECT
            fh.project_id,
            fh.hostname,
            (
              SELECT rr.id
              FROM results rr
              JOIN scans ss ON ss.id = rr.scan_id
              WHERE rr.project_id = fh.project_id
                AND rr.hostname = fh.hostname
                AND ss.triggered_by LIKE 'subfinder:%'
              ORDER BY rr.checked_at DESC
              LIMIT 1
            ) AS result_id
          FROM filtered_hosts fh
        )
        SELECT
          fh.hostname,
          fh.first_seen,
          fh.last_seen,
          fh.ssl_scanned,
          r.cn,
          r.issuer,
          r.expiry,
          r.days_left,
          r.is_mismatch,
          r.same_base,
          r.is_expired,
          r.is_expiring,
          r.is_ok,
          r.error,
          r.checked_at,
          hx.status_code AS http_status_code,
          hx.page_title AS http_page_title,
          hx.redirect_location AS http_redirect_location,
          hx.final_url AS http_final_url,
          hx.scheme AS http_scheme,
          hx.is_active AS http_is_active,
          hx.last_checked AS http_checked_at
        FROM filtered_hosts fh
        LEFT JOIN latest_result lr
          ON lr.project_id = fh.project_id
         AND lr.hostname = fh.hostname
        LEFT JOIN results r ON r.id = lr.result_id
        LEFT JOIN subfinder_httpx_results hx
          ON hx.project_id = fh.project_id
         AND hx.hostname = fh.hostname
        ORDER BY fh.first_seen DESC
        """,
        params + [per_page, offset],
    ).fetchall()
    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


def subfinder_httpx_results_upsert_batch(project_id, job_id, rows):
    clean_rows = []
    ts = now()
    for row in rows or []:
        hostname = (row.get("hostname") or "").strip().lower()
        if not hostname:
            continue
        clean_rows.append(
            (
                uid(),
                project_id,
                hostname,
                row.get("status_code"),
                (row.get("page_title") or "").strip(),
                (row.get("redirect_location") or "").strip(),
                (row.get("final_url") or "").strip(),
                (row.get("scheme") or "").strip(),
                1 if row.get("is_active") else 0,
                job_id or "",
                ts,
            )
        )
    if not clean_rows:
        return 0
    xm(
        """
        INSERT INTO subfinder_httpx_results(
            id,project_id,hostname,status_code,page_title,redirect_location,final_url,scheme,is_active,source_job_id,last_checked
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(project_id, hostname) DO UPDATE SET
            status_code=excluded.status_code,
            page_title=excluded.page_title,
            redirect_location=excluded.redirect_location,
            final_url=excluded.final_url,
            scheme=excluded.scheme,
            is_active=excluded.is_active,
            source_job_id=excluded.source_job_id,
            last_checked=excluded.last_checked
        """,
        clean_rows,
    )
    asset_backfill_project(project_id)
    commit()
    return len(clean_rows)


def subfinder_raw_result_add(job_id, project_id, root_domain, command, started_at=None):
    rid = uid()
    x(
        "INSERT OR REPLACE INTO subfinder_raw_results(id,job_id,project_id,root_domain,command,status,started_at)"
        " VALUES(?,?,?,?,?,'running',?)",
        (rid, job_id, project_id, root_domain, command, started_at or now()),
    )
    commit()
    return rid


def subfinder_raw_result_finish(
    rid,
    status,
    exit_code,
    total_found,
    stdout_text,
    stderr_text,
):
    max_stdout = _env_int("SUBFINDER_RAW_STDOUT_MAX_CHARS", 65536, minimum=0)
    max_stderr = _env_int("SUBFINDER_RAW_STDERR_MAX_CHARS", 16384, minimum=0)
    stdout_preview = _trim_text(stdout_text or "", max_stdout)
    stderr_preview = _trim_text(stderr_text or "", max_stderr)
    x(
        "UPDATE subfinder_raw_results "
        "SET status=?,exit_code=?,total_found=?,stdout_text='',stderr_text='',stdout_z=?,stderr_z=?,finished_at=? "
        "WHERE id=?",
        (
            status,
            exit_code,
            total_found,
            _compress_text(stdout_preview),
            _compress_text(stderr_preview),
            now(),
            rid,
        ),
    )
    commit()


def subfinder_raw_results_list(pid, limit=20, preview_chars=4000):
    rows = x(
        "SELECT * FROM subfinder_raw_results WHERE project_id=? ORDER BY started_at DESC LIMIT ?",
        (pid, limit),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        out_text = d.get("stdout_text") or _decompress_text(d.get("stdout_z"))
        err_text = d.get("stderr_text") or _decompress_text(d.get("stderr_z"))
        if preview_chars and len(out_text) > preview_chars:
            out_text = out_text[:preview_chars] + "\n…truncated for UI performance…"
        d["raw_preview"] = out_text
        raw_lines = [ln for ln in out_text.splitlines() if ln.strip()]
        if preview_chars:
            raw_lines = raw_lines[:250]
        d["raw_lines"] = raw_lines
        d["stderr_preview"] = err_text[:preview_chars] if preview_chars else err_text
        d.pop("stdout_z", None)
        d.pop("stderr_z", None)
        out.append(d)
    return out


def domain_enum_scan_create(domain, triggered_by="manual", tool_summary=""):
    sid = uid()
    x(
        "INSERT INTO domain_enum_scans(id,domain,status,triggered_by,tool_summary,started_at) VALUES(?,?,?,?,?,?)",
        (sid, (domain or "").strip().lower(), "running", triggered_by, tool_summary, now()),
    )
    commit()
    return sid


def domain_enum_scan_finish(scan_id, status, total_found):
    x(
        "UPDATE domain_enum_scans SET status=?, total_found=?, finished_at=? WHERE id=?",
        (status, int(total_found or 0), now(), scan_id),
    )
    commit()


def domain_enum_results_add_batch(scan_id, domain, hostnames, source="mixed"):
    clean = sorted({(h or "").strip().lower() for h in (hostnames or []) if (h or "").strip()})
    if not clean:
        return 0
    ts = now()
    rows = [(uid(), scan_id, domain, h, source, ts) for h in clean]
    xm(
        """
        INSERT INTO domain_enum_results(id,scan_id,domain,hostname,source,discovered_at)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(scan_id, hostname) DO UPDATE SET
          source = CASE
            WHEN domain_enum_results.source IS NULL OR domain_enum_results.source = '' THEN excluded.source
            WHEN excluded.source IS NULL OR excluded.source = '' THEN domain_enum_results.source
            WHEN instr(',' || domain_enum_results.source || ',', ',' || excluded.source || ',') > 0 THEN domain_enum_results.source
            ELSE domain_enum_results.source || ',' || excluded.source
          END
        """,
        rows,
    )
    commit()
    return len(clean)


def domain_enum_scans_list():
    return [dict(r) for r in x("SELECT * FROM domain_enum_scans ORDER BY started_at DESC LIMIT 300").fetchall()]


def domain_enum_scan_get(scan_id):
    row = x("SELECT * FROM domain_enum_scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def domain_enum_results_by_scan(scan_id):
    rows = x(
        "SELECT hostname, source, discovered_at FROM domain_enum_results WHERE scan_id=? ORDER BY hostname ASC",
        (scan_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def domain_enum_scan_delete(scan_id):
    x("DELETE FROM domain_enum_scans WHERE id=?", (scan_id,))
    commit()


# ── OpenSSL live results ─────────────────────────────────────────────────────

def openssl_results_upsert_batch(pid, rows, source="manual"):
    ts = now()
    payload = [
        (
            uid(),
            pid,
            (r.get("hostname") or "").strip().lower(),
            r.get("status", "") or "",
            r.get("subject", "") or "",
            r.get("error", "") or "",
            r.get("exit_code"),
            source,
            ts,
        )
        for r in rows
        if (r.get("hostname") or "").strip()
    ]
    if not payload:
        return 0
    xm(
        """
        INSERT INTO openssl_results(id, project_id, hostname, status, subject, error, exit_code, source, last_checked)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(project_id, hostname) DO UPDATE SET
          status=excluded.status,
          subject=excluded.subject,
          error=excluded.error,
          exit_code=excluded.exit_code,
          source=excluded.source,
          last_checked=excluded.last_checked
        """,
        payload,
    )
    commit()
    return len(payload)


def openssl_results_list(pid, search="", limit=2000):
    params = [pid]
    where = "WHERE project_id=?"
    if search:
        where += " AND hostname LIKE ?"
        params.append(f"%{search.strip().lower()}%")
    params.append(max(1, min(5000, int(limit or 2000))))
    rows = x(
        f"SELECT hostname,status,subject,error,exit_code,source,last_checked "
        f"FROM openssl_results {where} ORDER BY hostname ASC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


# ── Normalized asset inventory ───────────────────────────────────────────────

def _asset_value(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")

def _json_dump(data) -> str:
    try:
        return json.dumps(data or {}, sort_keys=True)
    except Exception:
        return "{}"

def asset_upsert(project_id: str, asset_type: str, value: str, source: str = "", exposure: str = "unknown", metadata=None, seen_at: str | None = None):
    value = _asset_value(value)
    if not project_id or not value:
        return None
    ts = seen_at or now()
    aid = uid()
    x("""
        INSERT INTO assets(id,project_id,asset_type,value,exposure,source,first_seen,last_seen,metadata)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(project_id, asset_type, value) DO UPDATE SET
          exposure=CASE WHEN excluded.exposure!='unknown' THEN excluded.exposure ELSE assets.exposure END,
          source=CASE WHEN instr(',' || assets.source || ',', ',' || excluded.source || ',') > 0 OR excluded.source='' THEN assets.source WHEN assets.source='' THEN excluded.source ELSE assets.source || ',' || excluded.source END,
          last_seen=excluded.last_seen,
          metadata=CASE WHEN excluded.metadata!='{}' THEN excluded.metadata ELSE assets.metadata END
    """, (aid, project_id, asset_type, value, exposure or "unknown", source or "", ts, ts, _json_dump(metadata)))
    row = x("SELECT * FROM assets WHERE project_id=? AND asset_type=? AND value=?", (project_id, asset_type, value)).fetchone()
    return dict(row) if row else None

def asset_relationship_upsert(project_id: str, source_asset_id: str, relationship_type: str, target_asset_id: str | None = None, target_value: str = "", metadata=None):
    if not project_id or not source_asset_id or not relationship_type:
        return
    ts = now()
    x("""
        INSERT INTO asset_relationships(id,project_id,source_asset_id,target_asset_id,relationship_type,target_value,metadata,first_seen,last_seen)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(project_id, source_asset_id, relationship_type, target_asset_id, target_value) DO UPDATE SET
          metadata=excluded.metadata,last_seen=excluded.last_seen
    """, (uid(), project_id, source_asset_id, target_asset_id or "", relationship_type, target_value or "", _json_dump(metadata), ts, ts))

def asset_observation_add(asset_id: str, project_id: str, source: str, port=None, protocol: str = "", data=None, observed_at: str | None = None):
    if not asset_id or not project_id:
        return
    x("INSERT INTO asset_observations(id,asset_id,project_id,source,observed_at,port,protocol,data) VALUES(?,?,?,?,?,?,?,?)",
      (uid(), asset_id, project_id, source, observed_at or now(), port, protocol or "", _json_dump(data)))

def asset_finding_upsert(project_id: str, asset_id: str, source: str, finding_key: str, severity: str = "", title: str = "", details=None):
    if not project_id or not asset_id or not finding_key:
        return
    ts = now()
    x("""
        INSERT INTO asset_findings(id,asset_id,project_id,source,severity,title,finding_key,details,first_seen,last_seen)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(project_id, asset_id, source, finding_key) DO UPDATE SET
          severity=excluded.severity,title=excluded.title,details=excluded.details,last_seen=excluded.last_seen
    """, (uid(), asset_id, project_id, source, severity or "", title or "", finding_key, _json_dump(details), ts, ts))
    asset_relationship_upsert(project_id, asset_id, "has_finding", None, finding_key, {"source": source, "severity": severity, "title": title})

def asset_backfill_project(project_id: str):
    if not project_id:
        return {"assets": 0}
    count = 0
    for h in project_hosts(project_id):
        a = asset_upsert(project_id, "host", h, "project_hosts", "configured")
        if a:
            asset_relationship_upsert(project_id, a["id"], "belongs_to_project", None, project_id)
            count += 1
    for r in x("SELECT hostname,source,first_seen,last_seen FROM subfinder_hosts WHERE project_id=?", (project_id,)).fetchall():
        a = asset_upsert(project_id, "host", r["hostname"], r["source"] or "subfinder", "discovered", seen_at=r["last_seen"])
        if a:
            asset_relationship_upsert(project_id, a["id"], "belongs_to_project", None, project_id)
            asset_observation_add(a["id"], project_id, "subfinder", data=dict(r), observed_at=r["last_seen"])
            count += 1
    for r in x("SELECT * FROM subfinder_httpx_results WHERE project_id=?", (project_id,)).fetchall():
        a = asset_upsert(project_id, "host", r["hostname"], "httpx", "internet" if r["is_active"] else "observed", seen_at=r["last_checked"], metadata={"status_code": r["status_code"], "title": r["page_title"], "url": r["final_url"]})
        if a:
            port = 443 if (r["scheme"] or "").lower() == "https" else 80 if (r["scheme"] or "").lower() == "http" else None
            asset_observation_add(a["id"], project_id, "httpx", port=port, protocol=r["scheme"] or "http", data=dict(r), observed_at=r["last_checked"])
            if port:
                asset_relationship_upsert(project_id, a["id"], "observed_on_port", None, str(port), {"scheme": r["scheme"], "status_code": r["status_code"]})
            final_host = _asset_value((r["final_url"] or "").split("://")[-1].split("/")[0].split(":")[0])
            if final_host and final_host != _asset_value(r["hostname"]):
                target = asset_upsert(project_id, "host", final_host, "httpx", "internet", seen_at=r["last_checked"])
                if target:
                    asset_relationship_upsert(project_id, a["id"], "resolves_to", target["id"], final_host, {"via": "httpx_final_url"})
            count += 1
    for r in x("SELECT * FROM results WHERE project_id=?", (project_id,)).fetchall():
        a = asset_upsert(project_id, "host", r["hostname"], "tls_scan", "tls", seen_at=r["checked_at"], metadata={"cn": r["cn"], "expiry": r["expiry"], "issuer": r["issuer"]})
        if a:
            asset_observation_add(a["id"], project_id, "tls_scan", port=443, protocol="tls", data=dict(r), observed_at=r["checked_at"])
            asset_relationship_upsert(project_id, a["id"], "observed_on_port", None, "443", {"protocol": "tls"})
            if r["fingerprint_sha256"]:
                cert = asset_upsert(project_id, "certificate", r["fingerprint_sha256"], "tls_scan", "certificate", seen_at=r["checked_at"], metadata={"cn": r["cn"], "issuer": r["issuer"], "expiry": r["expiry"]})
                if cert:
                    asset_relationship_upsert(project_id, a["id"], "served_by_certificate", cert["id"], r["fingerprint_sha256"])
            if r["is_mismatch"] or r["is_expired"] or r["is_expiring"] or r["error"]:
                key = "tls:" + ("error" if r["error"] else "expired" if r["is_expired"] else "mismatch" if r["is_mismatch"] else "expiring")
                asset_finding_upsert(project_id, a["id"], "tls_scan", key, "high" if r["is_expired"] or r["error"] else "medium", key.replace("tls:", "TLS "), dict(r))
            count += 1
    commit()
    return {"assets": count}

def asset_record_nuclei_findings(project_id: str, findings: list[dict], scan_id: str = ""):
    for f in findings or []:
        host = _asset_value(f.get("host") or f.get("matched") or f.get("url") or f.get("target") or "")
        if "://" in host:
            try:
                from urllib.parse import urlparse
                host = urlparse(host).hostname or host
            except Exception:
                pass
        a = asset_upsert(project_id, "host", host, "nuclei", "internet", metadata={"scan_id": scan_id})
        if not a:
            continue
        key = f.get("template_id") or f.get("matcher_name") or f.get("name") or f.get("matched") or _json_dump(f)[:120]
        title = f.get("name") or f.get("template_id") or "Nuclei finding"
        asset_finding_upsert(project_id, a["id"], "nuclei", str(key), f.get("severity") or "", title, {**f, "scan_id": scan_id})
        asset_observation_add(a["id"], project_id, "nuclei", data=f)
    commit()

def assets_list(project_id="", search="", page=1, per_page=100):
    clauses, params = ["1=1"], []
    if project_id:
        clauses.append("a.project_id=?"); params.append(project_id)
    if search:
        clauses.append("LOWER(a.value) LIKE ?"); params.append(f"%{search.lower()}%")
    where = " AND ".join(clauses)
    total = x(f"SELECT COUNT(*) FROM assets a WHERE {where}", params).fetchone()[0]
    offset = (page-1)*per_page
    rows = x(f"""
      SELECT a.*, p.name project_name,
        (SELECT COUNT(*) FROM asset_findings f WHERE f.asset_id=a.id) findings_count,
        (SELECT title FROM asset_findings f WHERE f.asset_id=a.id ORDER BY f.last_seen DESC LIMIT 1) latest_finding,
        (SELECT severity FROM asset_findings f WHERE f.asset_id=a.id ORDER BY f.last_seen DESC LIMIT 1) latest_severity
      FROM assets a JOIN projects p ON p.id=a.project_id
      WHERE {where}
      ORDER BY a.last_seen DESC LIMIT ? OFFSET ?
    """, params + [per_page, offset]).fetchall()
    return {"assets": [dict(r) for r in rows], "total": total, "page": page, "pages": max(1,(total+per_page-1)//per_page)}

def asset_get(asset_id: str):
    r = x("SELECT a.*,p.name project_name FROM assets a JOIN projects p ON p.id=a.project_id WHERE a.id=?", (asset_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["observations"] = [dict(o) for o in x("SELECT * FROM asset_observations WHERE asset_id=? ORDER BY observed_at DESC LIMIT 100", (asset_id,)).fetchall()]
    d["findings"] = [dict(f) for f in x("SELECT * FROM asset_findings WHERE asset_id=? ORDER BY last_seen DESC LIMIT 100", (asset_id,)).fetchall()]
    return d

def asset_relationships_get(asset_id: str):
    rows = x("""
      SELECT r.*, ta.asset_type target_asset_type, ta.value target_asset_value
      FROM asset_relationships r
      LEFT JOIN assets ta ON ta.id=r.target_asset_id
      WHERE r.source_asset_id=? OR r.target_asset_id=?
      ORDER BY r.last_seen DESC
    """, (asset_id, asset_id)).fetchall()
    return [dict(r) for r in rows]


# ── Global stats ──────────────────────────────────────────────────────────────

def stats_global():
    projects = x("SELECT COUNT(*) FROM projects WHERE enabled=1").fetchone()[0]
    unseen = alerts_unseen_count()
    r = x("""SELECT SUM(s.total) th, SUM(s.mismatches) mis,
                    SUM(s.expired) exp, SUM(s.expiring) expi, SUM(s.ok) ok
             FROM scans s JOIN (
               SELECT project_id, MAX(finished_at) mf FROM scans
               WHERE status='done' GROUP BY project_id
             ) l ON s.project_id=l.project_id AND s.finished_at=l.mf""").fetchone()
    sf_hosts = x("SELECT COUNT(*) FROM subfinder_hosts").fetchone()[0]
    active_scans = x("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
    return {"projects": projects, "hosts": r["th"] or 0,
            "mismatches": r["mis"] or 0, "expired": r["exp"] or 0,
            "expiring": r["expi"] or 0, "ok": r["ok"] or 0,
            "unseen_alerts": unseen, "subfinder_hosts": sf_hosts,
            "active_scans": active_scans}

# ── Durable jobs ──────────────────────────────────────────────────────────────

def _job_decode(row):
    if not row:
        return None
    d = dict(row)
    try:
        d["payload"] = json.loads(d.get("payload_json") or "{}")
    except Exception:
        d["payload"] = {}
    d.pop("payload_json", None)
    return d


def job_create(job_type, payload=None, **fields):
    jid = fields.pop("id", None) or uid()
    n = now()
    status = fields.pop("status", "queued")
    if job_get(jid):
        update = {
            "type": job_type,
            "project_id": fields.pop("project_id", "") or "",
            "status": status,
            "progress": int(fields.pop("progress", 0) or 0),
            "total": int(fields.pop("total", 0) or 0),
            "done": int(fields.pop("done", 0) or 0),
            "source": fields.pop("source", "") or fields.pop("triggered_by", "") or "",
            "payload": payload or {},
            "started_at": fields.pop("started_at", n),
            "finished_at": fields.pop("finished_at", None),
        }
        return job_update(jid, **update)
    x(
        """
        INSERT INTO jobs(id,type,project_id,status,progress,total,done,source,payload_json,
                         started_at,finished_at,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            jid,
            job_type,
            fields.pop("project_id", "") or "",
            status,
            int(fields.pop("progress", 0) or 0),
            int(fields.pop("total", 0) or 0),
            int(fields.pop("done", 0) or 0),
            fields.pop("source", "") or fields.pop("triggered_by", "") or "",
            json.dumps(payload or {}, separators=(",", ":")),
            fields.pop("started_at", n),
            fields.pop("finished_at", None),
            n,
            n,
        ),
    )
    x("INSERT OR IGNORE INTO job_controls(job_id,action,requested,updated_at) VALUES(?,?,0,?)", (jid, "pause", n))
    x("INSERT OR IGNORE INTO job_controls(job_id,action,requested,updated_at) VALUES(?,?,0,?)", (jid, "cancel", n))
    commit()
    return job_get(jid)


def job_get(job_id):
    return _job_decode(x("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def job_list(job_type=None, project_id=None, statuses=None, active=None, limit=100):
    where, params = [], []
    if job_type:
        where.append("type=?"); params.append(job_type)
    if project_id:
        where.append("project_id=?"); params.append(project_id)
    if active is not None:
        statuses = ["queued", "preparing", "running", "paused", "stopping"] if active else ["done", "error", "stopped", "cancelled"]
    if statuses:
        where.append("status IN (%s)" % ",".join("?" for _ in statuses)); params.extend(statuses)
    sql = "SELECT * FROM jobs" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY created_at DESC LIMIT ?"
    params.append(int(limit or 100))
    return [_job_decode(r) for r in x(sql, params).fetchall()]


def job_update(job_id, **kw):
    if not kw:
        return job_get(job_id)
    if "payload" in kw:
        kw["payload_json"] = json.dumps(kw.pop("payload") or {}, separators=(",", ":"))
    kw["updated_at"] = now()
    sets = ",".join(f"{k}=?" for k in kw)
    x(f"UPDATE jobs SET {sets} WHERE id=?", [*kw.values(), job_id])
    commit()
    return job_get(job_id)


def job_event_append(job_id, event, data=None):
    eid, n = uid(), now()
    x("INSERT INTO job_events(id,job_id,event,payload_json,created_at) VALUES(?,?,?,?,?)", (eid, job_id, event, json.dumps(data or {}, separators=(",", ":")), n))
    commit()
    row = x("SELECT rowid,* FROM job_events WHERE id=?", (eid,)).fetchone()
    d = dict(row)
    d["payload"] = json.loads(d.pop("payload_json") or "{}")
    return d


def job_events_since(last_id=0, limit=100):
    rows = x("SELECT rowid,* FROM job_events WHERE rowid>? ORDER BY rowid ASC LIMIT ?", (int(last_id or 0), int(limit or 100))).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try: d["payload"] = json.loads(d.pop("payload_json") or "{}")
        except Exception: d["payload"] = {}
        out.append(d)
    return out


def job_control_request(job_id, action, reason=""):
    n = now()
    if action == "resume":
        x("UPDATE job_controls SET requested=0, updated_at=?, reason=? WHERE job_id=? AND action='pause'", (n, reason, job_id))
        job_update(job_id, status="running")
    elif action == "pause":
        x("INSERT INTO job_controls(job_id,action,requested,reason,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(job_id,action) DO UPDATE SET requested=1,reason=excluded.reason,updated_at=excluded.updated_at", (job_id, "pause", 1, reason, n))
        job_update(job_id, status="paused")
    elif action in {"cancel", "stop"}:
        x("INSERT INTO job_controls(job_id,action,requested,reason,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(job_id,action) DO UPDATE SET requested=1,reason=excluded.reason,updated_at=excluded.updated_at", (job_id, "cancel", 1, reason, n))
        job_update(job_id, status="stopping")
    commit()
    return True


def job_control_get(job_id):
    rows = x("SELECT action,requested FROM job_controls WHERE job_id=?", (job_id,)).fetchall()
    return {r["action"]: bool(r["requested"]) for r in rows}
