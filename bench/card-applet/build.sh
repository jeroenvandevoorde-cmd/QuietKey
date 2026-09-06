#!/bin/sh
# QK-DEC-162. Python 3.9+; check runs pure tests, never an Oracle/card tool.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
    echo 'QK-CARD-APPLET FAIL Python3Unavailable' >&2
    exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I -B "$script_dir/canonical-cap.py" "$@"
