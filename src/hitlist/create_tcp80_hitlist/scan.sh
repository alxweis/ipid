#!/bin/bash

OUTPUT="ips.txt"

echo "[*] Starting HTTP scan on port 80..."
# shellcheck disable=SC2046
zmap -p 80 -M tcp_synscan -o $OUTPUT -f "saddr" --bandwidth=100M --max-targets=0 --seed=$(date +%s) --cooldown-time=3
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "[!] Zmap scan failed."
    exit 1
fi

awk '!seen[$0]++' $OUTPUT > temp && mv temp $OUTPUT

echo "[*] Results saved in $OUTPUT."