#!/usr/bin/env bash
# Installed as /usr/local/sbin/reality-panel-update by install.sh.
set -euo pipefail

installer="/usr/local/lib/reality-panel/install.sh"
[ -x "$installer" ] || { printf '[FAIL] Reality Panel installer is not present at %s\n' "$installer" >&2; exit 1; }
exec "$installer" update "$@"
