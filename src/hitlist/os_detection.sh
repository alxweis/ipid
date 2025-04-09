#!/bin/bash

# Input file
INPUT_FILE="$1"
TEMP_FILE=$(mktemp "${INPUT_FILE}.os_detection.XXXXXX" -p .)

# Variables for extracting values
PROTOCOL=""
PORT=""
SERVICE=""

# Extract information based on the path structure
if [[ "$INPUT_FILE" =~ /tcp/([0-9]+)/ ]]; then
    PROTOCOL="tcp"
    PORT="${BASH_REMATCH[1]}"
elif [[ "$INPUT_FILE" =~ /udp/([0-9]+)/([^/]+)/ ]]; then
    PROTOCOL="udp"
    PORT="${BASH_REMATCH[1]}"
    SERVICE="${BASH_REMATCH[2]}"
else
    echo "Unknown path or protocol!"
    exit 1
fi

# Output the extracted variables
echo "Protocol: $PROTOCOL"
echo "Port: $PORT"
echo "Service: $SERVICE"

# OS detection regex
OS_REGEX="ubuntu|centos|debian|redhat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos|openembedded|yocto|utm|gaia|router"

# Function to count lines in a file
count_lines() {
    wc -l < "$1"
}

# Decompress the input file if it's compressed (xz format)
decompress_file() {
    if [[ "$INPUT_FILE" =~ \.xz$ ]]; then
        echo "Decompressing $INPUT_FILE..."
        xz -d "$INPUT_FILE" || { echo "Failed to decompress file"; exit 1; }
        INPUT_FILE="${INPUT_FILE%.xz}" # Remove the .xz extension
    fi
}

# Remove the header row from the input file, leaving only IPv4 addresses
remove_header() {
    echo "Removing header from $INPUT_FILE..."
    sed -i '1d' "$INPUT_FILE" || { echo "Failed to remove header"; exit 1; }
}

# Count initial number of IPs in the input file
initial_count=$(count_lines "$INPUT_FILE")

# Decompress and clean the input file
decompress_file
remove_header

echo "Running OS detection..."
start_detection=$(date +%s)

# Perform OS detection based on protocol and service
if [[ "$PORT" == "80" ]]; then
  # Perform HTTP banner grabbing with ZGrab2 for TCP port 80
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
elif [[ "$PORT" == "53" ]]; then
  # Parallel DNS OS detection
  process_ip() {
      ip=$1
      os_name=$(dig @"$ip" version.bind CH TXT +short +retry=0 +time=1 | tr '[:upper:]' '[:lower:]' | tr -d '"')

      if [[ $? -eq 0 && -n "$os_name" && "$os_name" != *"error"* && "$os_name" =~ $OS_REGEX ]]; then
          echo "[*] IP: $ip - Result: $os_name"
          echo "$ip,$os_name" >> "$TEMP_FILE"
      fi
  }

  export -f process_ip
  export TEMP_FILE OS_REGEX

  # Run parallel processing on IPs from the input file
  parallel -a "$INPUT_FILE" -j 30 process_ip

else
  echo "Protocol or service not supported for OS detection."
fi

# Replace the original file with the results
mv "$TEMP_FILE" "$INPUT_FILE"

end_detection=$(date +%s)
detection_time=$((end_detection - start_detection))

# Count the number of lines (IPs) in the detection output
detection_count=$(count_lines "$INPUT_FILE")
detection_diff=$((initial_count - detection_count))

# Output the results of the OS detection
echo "OS Detection: detected_count=$detection_count not_detected_count=$detection_diff runtime=$detection_time seconds"

# Add a header to the output file
sed -i '1i IP,OS' "$INPUT_FILE"

# Compress the output file
xz -9 "$INPUT_FILE"

echo "Results saved in $INPUT_FILE"
exit 0
