from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import db.database as db
from api.routes import _analyze_hosts_text, _result_status


def reset_db(tmp_path, monkeypatch):
    db_path = tmp_path / "sentinel.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    if getattr(db._local, "c", None):
        db._local.c.close()
        db._local.c = None
    db.init_db()
    return db_path


def test_host_preview_normalizes_duplicates_and_rejects_private_hosts():
    analysis = _analyze_hosts_text("""
    https://Example.com/path
    example.com
    localhost
    10.0.0.1
    api.example.com:443
    bad_host
    """)

    assert analysis["hosts"] == ["example.com", "api.example.com"]
    assert analysis["duplicate_count"] == 1
    assert analysis["invalid_count"] == 3


def test_results_metadata_is_persisted_and_compare_detects_renewal(tmp_path, monkeypatch):
    reset_db(tmp_path, monkeypatch)
    project = db.project_create("metadata-project")
    previous = db.scan_create(project["id"], 1, "manual")
    current = db.scan_create(project["id"], 2, "manual")

    db.results_batch_save(previous["id"], project["id"], [{
        "hostname": "www.example.com",
        "cn": "www.example.com",
        "sans": ["www.example.com"],
        "issuer": "Test CA",
        "expiry": "2026-01-01",
        "not_before": "2025-01-01",
        "days_left": 10,
        "match_found": True,
        "same_base": True,
        "is_expiring_soon": True,
        "fingerprint_sha256": "oldfp",
        "tls_version": "TLSv1.2",
        "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
        "cipher_bits": 128,
        "key_algorithm": "RSA",
        "key_bits": 2048,
        "signature_algorithm": "sha256",
        "san_count": 1,
    }])
    db.results_batch_save(current["id"], project["id"], [{
        "hostname": "www.example.com",
        "cn": "www.example.com",
        "sans": ["www.example.com", "example.com"],
        "issuer": "Test CA",
        "expiry": "2027-01-01",
        "not_before": "2026-01-01",
        "days_left": 365,
        "match_found": True,
        "same_base": True,
        "is_ok": True,
        "fingerprint_sha256": "newfp",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "key_algorithm": "EC",
        "key_bits": 256,
        "signature_algorithm": "sha384",
        "san_count": 2,
    }, {
        "hostname": "new.example.com",
        "cn": "new.example.com",
        "sans": ["new.example.com"],
        "issuer": "Test CA",
        "expiry": "2027-01-01",
        "days_left": 365,
        "match_found": True,
        "same_base": True,
        "is_ok": True,
    }])

    rows = db.scan_results_all(current["id"])
    main = next(r for r in rows if r["hostname"] == "www.example.com")
    assert main["tls_version"] == "TLSv1.3"
    assert main["key_algorithm"] == "EC"
    assert main["san_count"] == 2
    assert _result_status(main) == "ok"

    comparison = db.scan_compare(current["id"], previous["id"])
    assert comparison["summary"]["added_hosts"] == 1
    assert comparison["summary"]["changed_status"] == 1
    assert comparison["summary"]["renewed_certificates"] == 1
    assert comparison["renewed_certificates"][0]["hostname"] == "www.example.com"


def test_project_scan_defers_asset_backfill_until_after_batches(tmp_path, monkeypatch):
    reset_db(tmp_path, monkeypatch)
    project = db.project_create("large-scan")
    db.project_save_hosts(project["id"], [f"www{i}.example.com" for i in range(3)])

    import core.ssl_checker as ssl_checker
    import scheduler.runner as runner

    backfill_calls = []
    original_backfill = db.asset_backfill_project

    def fake_backfill(project_id):
        backfill_calls.append(project_id)
        return original_backfill(project_id)

    def fake_run_checker(hosts, max_workers=50, progress_callback=None, **kwargs):
        for idx, host in enumerate(hosts, start=1):
            progress_callback(idx, len(hosts), {
                "hostname": host,
                "cn": host,
                "sans": [host],
                "issuer": "Test CA",
                "expiry": "2027-01-01",
                "days_left": 365,
                "match_found": True,
                "same_base": True,
                "is_ok": True,
            })
        return []

    monkeypatch.setattr(runner, "BATCH_SIZE", 1)
    monkeypatch.setattr(ssl_checker, "run_checker", fake_run_checker)
    monkeypatch.setattr(db, "asset_backfill_project", fake_backfill)

    sid = runner.run_project_scan(project["id"], triggered_by="test")

    assert sid
    assert len(db.scan_results_all(sid)) == 3
    assert backfill_calls == [project["id"]]
