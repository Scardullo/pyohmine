#!/usr/bin/env bash

set -o pipefail

# waybar doesn't reliably kill the previous instance of this script when it
# reloads (e.g. on monitor hotplug), which leaks a `cava` process every time.
# Reap instances left behind by a waybar generation that's no longer running,
# but leave sibling instances alone (one runs per monitor bar, all under the
# same live waybar).
current_waybar_pid=$(pgrep -f '^waybar$' 2>/dev/null | head -1)
for pid in $(pgrep -f '^bash .*/waybar/scripts/cava\.sh' 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    wrapper_ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    grandparent=$(ps -o ppid= -p "$wrapper_ppid" 2>/dev/null | tr -d ' ')
    if [ -n "$grandparent" ] && [ "$grandparent" != "$current_waybar_pid" ]; then
        pkill -9 -P "$pid" 2>/dev/null
        kill -9 "$pid" 2>/dev/null
    fi
done

cleanup() {
    pkill -9 -P $$ 2>/dev/null
    exit 0
}
trap cleanup INT TERM PIPE EXIT

cava | while read -r line; do
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
