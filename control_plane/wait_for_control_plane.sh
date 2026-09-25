#!/bin/sh
set -e
python - <<'PY'
import time
import urllib.request

for _ in range(60):
    try:
        urllib.request.urlopen("http://control_plane:8000/api/audit-events/", timeout=2)
        break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("control_plane did not become ready in time")
PY
