#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=public-panel-url.sh
source "$ROOT/scripts/public-panel-url.sh"

accept() { valid_public_panel_url "$1" || { echo "expected accepted: $1" >&2; exit 1; }; }
reject() { ! valid_public_panel_url "$1" || { echo "expected rejected: $1" >&2; exit 1; }; }

accept ""
accept "http://1.2.3.4:18888"
accept "https://panel.example.com"
accept "https://[2001:db8::1]:18888"
reject "panel.example.com"
reject "ftp://panel.example.com"
reject "https://user:password@panel.example.com"
reject "https://panel.example.com/path"
reject "https://panel.example.com?query=value"
reject "https://panel.example.com#fragment"
reject "http://:18888"
reject "https://panel.example.com:65536"

echo "PUBLIC_PANEL_URL validation: PASS"
