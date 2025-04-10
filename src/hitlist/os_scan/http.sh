#!/bin/bash

INPUT_FILE="$1"

source src/hitlist/os_scan/setup.sh "$INPUT_FILE"
trap 'source src/hitlist/os_scan/cleanup.sh "$INPUT_FILE" "$TEMP_FILE"' EXIT

zgrab2 http --port 80 --input-file="$INPUT_FILE" --timeout 5 | \
jq -r --arg regex "$OS_REGEX" '. |
  select(.data? != null) |
  select(.data.http? != null) |
  select(.data.http.result? != null) |
  select(.data.http.result.response? != null) |
  select(.data.http.result.response.headers? != null) |
  select(.data.http.result.response.headers.server? != null) |
  select(.data.http.result.response.headers.server | map(ascii_downcase) | join(",") | test($regex)) |
  "\(.ip),\(.data.http.result.response.headers.server)"' >> "$TEMP_FILE"

source src/hitlist/os_scan/cleanup.sh "$INPUT_FILE" "$TEMP_FILE"
