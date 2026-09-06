#!/bin/sh
# Requires Python 3.9+ and its standard library only; no proprietary tool is run.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
    echo 'QK-CARD-APPLET FAIL Python3Unavailable' >&2
    exit 1
fi
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 -I "$repo_root/bench/card-applet/canonical-cap.py" check "$repo_root"
