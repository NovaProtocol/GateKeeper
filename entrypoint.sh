#!/bin/sh
# Volume ownership on startup (named volumes retain root ownership
# from the pre-non-root era — the build-time chown is hidden by the
# volume mount at runtime). Runs as root, fixes /data, then drops
# privileges before handing over to the server.
set -eu
chown -R appuser:appuser /data 2>/dev/null || true
exec setpriv --reuid=appuser --regid=appuser --clear-groups "$@"
