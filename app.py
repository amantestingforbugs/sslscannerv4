import os
import sys
import logging
from pathlib import Path
from flask import Flask, render_template

# ✅ PRO SAFE log path setup
log_path = Path(os.getenv("SENTINEL_LOG_PATH", "data/sentinel.log"))

sys.path.insert(0, str(Path(__file__).parent))

from db.database import init_db
from api.routes import api
from scheduler.runner import start_scheduler
from subfinder.runner import start_subfinder_scheduler

# ✅ Logging setup
def _logging_handlers() -> list[logging.Handler]:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path))
    except OSError as exc:
        # Some deployment targets mount the application directory read-only.
        # Keep the web process alive and continue logging to stdout/stderr.
        print(f"Warning: file logging disabled for {log_path}: {exc}", file=sys.stderr)
    return handlers


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=_logging_handlers(),
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024))),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").strip().lower() not in {"0", "false", "no", "off"},
)
app.register_blueprint(api)

_BOOTSTRAPPED = False


def bootstrap_runtime() -> None:
    """Initialize runtime services once for both dev and WSGI servers."""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    init_db()
    start_scheduler()
    start_subfinder_scheduler()
    _BOOTSTRAPPED = True


bootstrap_runtime()



@app.after_request
def add_security_headers(response):
    """Add baseline browser hardening headers for company deployments."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
    return response

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/favicon.ico")
def favicon():
    return "", 204

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
