#!/usr/bin/env bash

set -o pipefail

# Runs once per monitor bar, spawned by waybar via `sh -c`. waybar doesn't always
# kill this when it reloads/crashes, which used to leak a `cava` process (and its
# open PulseAudio capture stream) indefinitely. Fix: track our own waybar
# ancestor's PID directly and self-terminate the moment it's gone, rather than
# trying to spot stale siblings after the fact.

WAYBAR_PID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')

exec 3< <(cava)
CAVA_PID=$!

cleanup() {
    kill -9 "$CAVA_PID" "$WATCHDOG_PID" 2>/dev/null
    exit 0
}
trap cleanup INT TERM PIPE EXIT

WATCHDOG_PID=""
if [ -n "$WAYBAR_PID" ]; then
    (
        while kill -0 "$WAYBAR_PID" 2>/dev/null; do
            sleep 2
        done
        kill -TERM "$$" 2>/dev/null
    ) &
    WATCHDOG_PID=$!
fi

while read -r line <&3; do
    out=""

    for v in ${line//;/ }; do
        case $v in
            0) out+="▁";;
            1) out+="▁";;
            2) out+="▂";;
            3) out+="▃";;
            4) out+="▄";;
            5) out+="▅";;
            6) out+="▆";;
            7) out+="█";;
        esac
    done

    echo "$out" 2>/dev/null || exit 0
done
