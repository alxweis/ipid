#!/bin/bash

TMP_OUTPUT="ips.json"
OUTPUT="ips.txt"

echo "[*] Starting DNS scan on port 53..."
# shellcheck disable=SC2046
zmap -M dns -p 53 -O json -o $TMP_OUTPUT -f "saddr,success" --bandwidth=100M --max-targets=0 --seed=$(date +%s) --cooldown-time=3
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "[!] Zmap scan failed."
    exit 1
fi

jq -r 'select(.success == true) | .saddr' $TMP_OUTPUT | awk '!seen[$0]++' > $OUTPUT

rm $TMP_OUTPUT

echo "[*] Results saved in $OUTPUT."