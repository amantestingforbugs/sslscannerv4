import os
bind = f"0.0.0.0:{os.getenv('PORT','5000')}"
workers = 1
worker_class = "gthread"
threads = 8
timeout = 120
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Runtime initialization is performed from app.bootstrap_runtime() when the
# Flask application is imported by the worker process.  Do not start database
# setup or background scheduler threads in Gunicorn's master process: master
# hooks can leave deployment platforms waiting on orphaned non-worker runtime
# work during shutdown/restart, which presents as a sudden post-deploy crash.
