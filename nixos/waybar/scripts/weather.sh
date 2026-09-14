#!/usr/bin/env bash

set -o pipefail

# Auto-detect location via IP, then fetch current temp from Open-Meteo.
loc=$(curl -s --max-time 5 'https://ipwho.is/')
lat=$(echo "$loc" | python3 -c "import sys,json; print(json.load(sys.stdin).get('latitude',''))" 2>/dev/null)
lon=$(echo "$loc" | python3 -c "import sys,json; print(json.load(sys.stdin).get('longitude',''))" 2>/dev/null)

if [ -z "$lat" ] || [ -z "$lon" ]; then
    echo "N/A"
    exit 0
fi

weather=$(curl -s --max-time 5 "https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current=temperature_2m&temperature_unit=fahrenheit")
temp=$(echo "$weather" | python3 -c "import sys,json; print(round(json.load(sys.stdin)['current']['temperature_2m']))" 2>/dev/null)

if [ -z "$temp" ]; then
    echo "N/A"
else
    echo "${temp}°F"
fi
