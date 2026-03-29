# SSL Sentinel Pro

Professional SSL monitoring and recon platform with continuous Subfinder discovery, real-time observability, and risk-based alerting.

## Architecture

- **Flask API/UI (`app.py`, `api/routes.py`)**: REST + SSE streaming for real-time dashboard updates.
- **Schedulers (`scheduler/runner.py`, `subfinder/runner.py`)**:
  - SSL scheduler executes every project interval (clamped to **10–30 min**).
  - Subfinder scheduler executes every project interval (clamped to **10–30 min**).
  - Both run in background threads to avoid UI/API blocking.
- **Scanner core (`core/ssl_checker.py`)**:
  - Concurrent SSL checks with retries for transient network failures.
  - Risk classification (`HIGH` / `MEDIUM` / `LOW`).
  - Issuer organization extraction.
  - CNAME-based takeover risk heuristic.
- **Data layer (`db/database.py`)**:
  - SQLite (WAL mode), deduplicated alerts, discovery history, latest scan analytics.
  - Export scan results as CSV/JSON.

## Key feature behavior

1. **Subfinder workflow**
   - Root domains are auto-extracted from project host list.
   - Only discovered *new* subdomains are persisted.
   - Only unscanned new subdomains are fed into SSL scan.
2. **Observability**
   - Live logs for `subfinder` and `ssl_scan` via `/api/sse` and `/api/logs`.
   - Running/idle/failed states emitted in structured events.
3. **Alerts**
   - Duplicate suppression with severity + mismatch type aware dedup keys.
   - Filtering by hostname, mismatch type, and severity.
4. **Insights & historical diff**
   - Compare latest scan vs previous scan (new issues / fixed issues).
5. **Frontend redesign**
   - SaaS-style layout, responsive cards/tables, dark/light mode persisted in local storage.
   - Advanced data tables (search/filter/sort/pagination), live notifications, new discoveries tab.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Optional: install subfinder binary

```bash
# Example with Go
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Ensure `subfinder` is available on PATH.

