#!/bin/bash

OUTPUT="ips.txt"

cleanup() {
    awk '!seen[$0]++' $OUTPUT > temp && mv temp $OUTPUT
    echo "[*] Results saved in $OUTPUT."
}

trap cleanup SIGINT SIGTERM

echo "[*] Starting ICMP Echo scan..."
# shellcheck disable=SC2046
zmap -M icmp_echoscan -o $OUTPUT -f "saddr" --bandwidth=100M --max-targets=0 --seed=$(date +%s) --cooldown-time=3
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "[!] Zmap scan failed."
    cleanup
    exit 1
fi

cleanup