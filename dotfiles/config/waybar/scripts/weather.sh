#!/bin/bash
# Prints the current temperature from wttr.in for the waybar weather module.
# Retries so a slow network or wttr.in hiccup at login doesn't hide the module
# for a whole polling interval (an empty result makes waybar hide the module).

for i in 1 2 3 4 5 6; do
    t=$(curl -sf -m 10 'wttr.in/?format=%t')
    if [[ $t =~ ^[+-]?[0-9]+°[CF]$ ]]; then
        echo "${t#+}"
        exit 0
    fi
    sleep 10
done
exit 0
