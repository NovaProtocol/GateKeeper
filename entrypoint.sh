#!/bin/sh
# Fix volume ownership on startup (named volumes retain root ownership
# from the pre-non-root era — the build-time chown is hidden by the
# volume mount at runtime).
chown -R appuser:appuser /data 2>/dev/null || true
exec "$@"
