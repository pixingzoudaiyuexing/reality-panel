#!/usr/bin/env bash
#
# RelayPanel one-line installer for Linux (Debian / Ubuntu).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/<release-ref>/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/<release-ref>/install.sh | bash -s -- uninstall
#

# Touch: trigger script-check CI on version-only PRs (paths filter otherwise skips it).
# What it does:
#   1. Verifies Linux + root
#   2. Installs git, curl, ca-certificates, openssl (apt)
#   3. Clones (or updates) the repo into /opt/relay-panel (quiet by default;
#      set DEBUG=1 to see raw git output)
#   4. Runs deploy.sh inside that directory
#
# NOTE: This is the one-line PANEL installer. It is distinct from
# scripts/relay-node-install.sh, which installs only the relay-node binary on
# a forwarding node. This script was accidentally emptied in commit b03ae7a
# and shipped empty through v0.1.7; restored verbatim from f184fb8 in v0.1.8.
#
set -euo pipefail

INSTALL_DIR="/opt/relay-panel"
REPO_URL="https://github.com/pixingzoudaiyuexing/relay-panel.git"
RELEASE_REF="${RELAYPANEL_RELEASE_REF:-RELEASE_REF_REQUIRED}"
RELEASE_VERSION="${RELAYPANEL_RELEASE_VERSION:-RELEASE_VERSION_REQUIRED}"

# DEBUG=1 shows full git output during clone/pull (default: quiet, clean status
# lines only). Most users want a clean install log without a wall of git diff
# stats, so quiet is the default.
DEBUG="${DEBUG:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  install.sh                 Install or upgrade RelayPanel
  install.sh uninstall       Remove this local RelayPanel deployment
  install.sh uninstall --yes Remove without the interactive confirmation
EOF
}

confirm_uninstall() {
    local answer=""
    echo ""
    warn "RelayPanel uninstall will permanently delete this Panel's local database, configuration, and secrets."
    warn "Rule exports are NOT created automatically. Export important Rules before continuing."
    warn "Remote Relay nodes, DNS records, and Reality backends will NOT be touched."
    echo ""
    printf "Type DELETE to remove the local RelayPanel deployment: "
    if [ -t 0 ]; then
        read -r answer
    elif { read -r answer < /dev/tty; } 2>/dev/null; then
        :
    elif ! read -r answer; then
        fail "No interactive terminal is available. Re-run with uninstall --yes only after reviewing the warning."
    fi
    [ "$answer" = "DELETE" ] || {
        info "Uninstall cancelled. Nothing was deleted."
        exit 0
    }
}

uninstall_panel() {
    local yes=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --yes) yes=1 ;;
            -h|--help) usage; exit 0 ;;
            *) fail "Unknown uninstall option: $1" ;;
        esac
        shift
    done

    # This script owns one fixed deployment root. Never permit a caller-supplied
    # path or a glob here: uninstall is intentionally local-panel only.
    [ "$INSTALL_DIR" = "/opt/relay-panel" ] || fail "Unexpected RelayPanel install root; refusing uninstall."

    if [ ! -e "$INSTALL_DIR" ]; then
        info "RelayPanel is already absent at ${INSTALL_DIR}. Nothing to uninstall."
        exit 0
    fi

    if [ "$yes" -ne 1 ]; then
        confirm_uninstall
    fi

    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        # Both files describe the same fixed project root. Running down for each
        # makes a partially completed source/release deployment recoverable while
        # Compose limits deletion to project-scoped containers, networks, and the
        # named volumes declared by that file.
        for compose_file in docker-compose.release.yaml docker-compose.yaml; do
            if [ -f "$INSTALL_DIR/$compose_file" ]; then
                info "Removing RelayPanel Compose resources from ${compose_file} ..."
                if ! docker compose --project-directory "$INSTALL_DIR" -f "$INSTALL_DIR/$compose_file" down --volumes --remove-orphans; then
                    warn "Compose cleanup for ${compose_file} did not complete; continuing with local file cleanup."
                fi
            fi
        done
    else
        warn "Docker Compose is unavailable; no containers or volumes can be removed by this run."
    fi

    # The path is fixed and checked above. This removes only the clone, .env,
    # runtime files, and local node-assets belonging to this Panel installation.
    rm -rf -- "$INSTALL_DIR"
    info "Local RelayPanel deployment removed. Remote Relay nodes were not contacted."
}

# Uninstall is handled before platform/dependency installation or git cloning.
# This keeps an already-absent or partial deployment idempotent and avoids any
# unrelated package changes during removal.
case "${1:-}" in
    uninstall)
        shift
        uninstall_panel "$@"
        exit 0
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    "")
        ;;
    *)
        fail "Unknown command: $1 (use uninstall or --help)"
        ;;
esac

# Quiet git flags: suppress the file-change stat dump (the `Foo | 123 +++`
# block) that looks like an error to non-technical users. When DEBUG=1 we drop
# --quiet so the full output is visible for troubleshooting.
if [ "$DEBUG" = "1" ]; then
    GIT_QUIET=""
else
    GIT_QUIET="--quiet"
fi

# ---------- 1. Platform check ----------
if [ "$(uname -s)" != "Linux" ]; then
    fail "This installer only runs on Linux. Current OS: $(uname -s)"
fi

if [ "$(id -u)" -ne 0 ]; then
    warn "Not running as root. Re-run with sudo if you hit permission errors."
    warn "Install target is ${INSTALL_DIR} (needs root to write)."
fi

# ---------- 2. Install base deps ----------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

# Detect package manager
PKG_MANAGER=""
if need_cmd apt-get; then
    PKG_MANAGER="apt"
elif need_cmd dnf; then
    PKG_MANAGER="dnf"
elif need_cmd yum; then
    PKG_MANAGER="yum"
else
    fail "No supported package manager found (apt/dnf/yum). Currently only Debian/Ubuntu is supported."
fi

if [ "$PKG_MANAGER" != "apt" ]; then
    warn "Detected ${PKG_MANAGER}. This installer is tested on Debian/Ubuntu."
    warn "Proceeding, but dependency names may differ."
fi

MISSING=""
for cmd in git curl ca-certificates openssl; do
    # ca-certificates is a package name, not a command - check differently
    if [ "$cmd" = "ca-certificates" ] || [ "$cmd" = "openssl" ]; then
        if [ "$cmd" = "ca-certificates" ] && [ ! -d /usr/share/ca-certificates ] && [ ! -d /etc/ssl/certs ]; then
            MISSING="$MISSING $cmd"
        elif [ "$cmd" = "openssl" ] && ! need_cmd openssl; then
            MISSING="$MISSING $cmd"
        fi
    elif ! need_cmd "$cmd"; then
        MISSING="$MISSING $cmd"
    fi
done

if [ -n "$MISSING" ]; then
    info "Installing missing dependencies:${MISSING}"
    case "$PKG_MANAGER" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq git curl ca-certificates openssl
            ;;
        dnf)
            dnf install -y git curl ca-certificates openssl
            ;;
        yum)
            yum install -y git curl ca-certificates openssl
            ;;
    esac
    info "Dependencies installed."
else
    info "All base dependencies present."
fi

# ---------- 3. Clone or update repo ----------
# Git output is kept quiet by default (see GIT_QUIET above): the file-change
# stat block that `git pull` prints looks like an error to most users, and the
# one-line status below is all they need. Set DEBUG=1 to see raw git output.
if [ -d "$INSTALL_DIR" ]; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Repository exists at ${INSTALL_DIR} - checking for updates ..."
        cd "$INSTALL_DIR"
        before=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
        # --ff-only: never create a merge commit during an automated update.
        # Capture stderr so a failure (e.g. diverged history) prints the real
        # git message instead of a generic "update failed".
        if ! git pull --ff-only $GIT_QUIET 2>/tmp/relaypanel-git-err; then
            echo -e "${RED}[FAIL]${NC} Repository update failed. git output:" >&2
            cat /tmp/relaypanel-git-err >&2
            rm -f /tmp/relaypanel-git-err
            fail "git pull failed. If your local branch diverged, reset with: git -C $INSTALL_DIR reset --hard origin/main"
        fi
        rm -f /tmp/relaypanel-git-err
        after=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
        if [ "$before" = "$after" ]; then
            info "Repository already up to date. ($after)"
        else
            info "Repository updated: $before -> $after"
        fi
    else
        fail "${INSTALL_DIR} exists but is not a git repository. \
Back it up or remove it, then re-run this script. Refusing to overwrite."
    fi
else
    if [ "$RELEASE_REF" = "RELEASE_REF_REQUIRED" ] || [ "$RELEASE_VERSION" = "RELEASE_VERSION_REQUIRED" ]; then
        fail "Fresh installs require RELAYPANEL_RELEASE_REF and RELAYPANEL_RELEASE_VERSION for a compatible release. Set both explicitly; no unpinned main install is allowed."
    fi
    info "Cloning ${REPO_URL} into ${INSTALL_DIR} ..."
    if ! git clone --depth 1 --branch "$RELEASE_REF" $GIT_QUIET "$REPO_URL" "$INSTALL_DIR" 2>/tmp/relaypanel-git-err; then
        echo -e "${RED}[FAIL]${NC} Clone failed. git output:" >&2
        cat /tmp/relaypanel-git-err >&2
        rm -f /tmp/relaypanel-git-err
        fail "git clone failed. Check your network and that the repo URL is reachable."
    fi
    rm -f /tmp/relaypanel-git-err
    cd "$INSTALL_DIR"
    info "Cloned at $(git rev-parse --short HEAD 2>/dev/null || echo '?')"
fi

# Existing installations retain the release identity recorded by deploy.sh;
# callers may explicitly provide a new pinned ref/version for an upgrade.
if [ "$RELEASE_REF" = "RELEASE_REF_REQUIRED" ]; then
    RELEASE_REF=$(grep -E '^RELAYPANEL_RELEASE_REF=' .env 2>/dev/null | tail -n1 | cut -d= -f2- || true)
    RELEASE_REF="${RELEASE_REF:-RELEASE_REF_REQUIRED}"
fi
if [ "$RELEASE_VERSION" = "RELEASE_VERSION_REQUIRED" ]; then
    RELEASE_VERSION=$(grep -E '^RELAYPANEL_RELEASE_VERSION=' .env 2>/dev/null | tail -n1 | cut -d= -f2- || true)
    RELEASE_VERSION="${RELEASE_VERSION:-RELEASE_VERSION_REQUIRED}"
fi

export RELAYPANEL_RELEASE_REF="$RELEASE_REF"
export RELAYPANEL_RELEASE_VERSION="$RELEASE_VERSION"

# ---------- 4. Hand off to deploy.sh ----------
if [ ! -f deploy.sh ]; then
    fail "deploy.sh not found in ${INSTALL_DIR}. Repository may be incomplete."
fi

chmod +x deploy.sh
info "Starting deploy.sh ..."
exec ./deploy.sh "$INSTALL_DIR"
# maintenance comment to retrigger script-check
