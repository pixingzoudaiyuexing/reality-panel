#!/usr/bin/env bash
# Shared, side-effect-free PUBLIC_PANEL_URL origin validation for deploy.sh.

valid_public_panel_url() {
    local url="$1" authority host port
    [ -z "$url" ] && return 0
    [[ "$url" =~ ^https?://[^/@[:space:]?#]+/?$ ]] || return 1
    authority="${url#*://}"
    authority="${authority%/}"
    if [[ "$authority" == \[*\]* ]]; then
        host="${authority%%\]*}]"
        host="${host#\[}"
        port="${authority#*\]}"
        [ -n "$host" ] && [[ "$host" == *:* ]] || return 1
        if [ -n "$port" ]; then
            [[ "$port" =~ ^:[0-9]{1,5}$ ]] || return 1
            [ "${port#:}" -le 65535 ] || return 1
        fi
    else
        [[ "$authority" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || return 1
        port="${authority##*:}"
        if [[ "$authority" == *:* ]]; then
            [ "$port" -le 65535 ] || return 1
        fi
    fi
}
