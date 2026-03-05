#!/bin/bash
# Enrichment Module for IPs from Masscan - One-by-One Processing with Detailed Progress

# Auto-detect the Backend directory from this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCANNER_BASE:-$(dirname "$SCRIPT_DIR")}"
LOG_DIR="$BASE_DIR/logs/scanner"
ALL_FILE="$LOG_DIR/all.txt"
ENRICHED_DIR="$LOG_DIR/enriched"
ENPROCESSED_IPS="$LOG_DIR/processed_ips.txt"
CRACKED_DIR="$LOG_DIR/cracked"

# Ensure the cracked directory exists and is writable
mkdir -p "$CRACKED_DIR"
if [ "$(id -u)" -eq 0 ]; then
    chmod -R 777 "$CRACKED_DIR"
fi
ENRICHED_FILE="$ENRICHED_DIR/enriched.csv"
LOCK_FILE="$ENRICHED_DIR/enriched.lock"

# Create directories and files
mkdir -p "$ENRICHED_DIR"
touch "$ENRICHED_FILE" "$LOCK_FILE"

# If running as root (sudo), make sure the user can write to these files
if [ "$(id -u)" -eq 0 ]; then
    chmod -R 777 "$ENRICHED_DIR"
fi

# Write CSV header if the file is empty
if [[ ! -s "$ENRICHED_FILE" ]]; then
    echo "ip,port,hostname,organization,country,banner" > "$ENRICHED_FILE"
fi

echo "Starting enrichment module at $(date) - Watching $ALL_FILE"

# Function to sanitize strings for CSV
sanitize_csv() {
    local input="$1"
    echo -n "$input" | sed 's/"/""/g' | tr -d '\n\r' | tr -s ' ' | sed 's/[^[:print:]]//g'
}

# Function to process a single ip:port with detailed logging
process_entry() {
    local ip="$1"
    local port="$2"
    local line_num="$3"
    local total_lines="$4"
    local session_processed="$5"

    if [[ -z "$ip" || -z "$port" ]]; then
        echo "Skipping invalid entry at line $line_num: ip=$ip, port=$port"
        echo "============================================================================================="
        return
    fi

    if grep -q "^\"$ip\",\"$port\"," "$ENRICHED_FILE"; then
        echo "Skipping already enriched at line $line_num: $ip:$port"
        echo "Progress: Processed $((session_processed + 1)) IPs in this session, $((total_lines - line_num)) remaining in current file"
        echo "============================================================================================="
        return
    fi

    echo "Processing IP $ip:$port at line $line_num..."
    echo "Running dig command for hostname lookup on $ip: dig @8.8.8.8 -x $ip +short +time=1"
    hostname=$(dig @8.8.8.8 -x "$ip" +short +time=1 2>/dev/null || dig @1.1.1.1 -x "$ip" +short +time=1 2>/dev/null || echo "error fetching")
    if [[ "$hostname" =~ ";;" || "$hostname" =~ "communications error" || "$hostname" =~ "no servers could be reached" ]]; then
        echo "Dig returned error, setting hostname to 'error fetching'"
        hostname="error fetching"
    fi
    [[ -z "$hostname" ]] && hostname="N/A"
    hostname=$(sanitize_csv "$hostname")
    echo "Hostname result: $hostname"

    echo "Running whois command for organization lookup on $ip: whois $ip"
    organization=$(whois "$ip" 2>/dev/null | grep -Ei 'orgname|org-name|organization|netname' | head -n 1 | awk -F: '{print $2}' | xargs || echo "N/A")
    [[ -z "$organization" ]] && organization="N/A"
    organization=$(sanitize_csv "$organization")
    echo "Organization result: $organization"

    echo "Running geoiplookup command for country lookup on $ip: geoiplookup $ip"
    country=$(geoiplookup "$ip" 2>/dev/null | grep -o 'GeoIP Country Edition:.*' | awk -F', ' '{print $2}' || echo "N/A")
    [[ -z "$country" ]] && country="N/A"
    country=$(sanitize_csv "$country")
    echo "Country result: $country"

    echo "Running banner fetch command for port $port on $ip..."
    banner="N/A"
    case "$port" in
        80)
            echo "Executing: timeout 1 curl -s -I --connect-timeout 1 http://${ip}:${port}"
            banner=$(timeout 1 curl -s -I --connect-timeout 1 "http://${ip}:${port}" 2>/dev/null | tr '\r\n' ' ' || echo "N/A")
            if [[ "$banner" == "N/A" ]]; then
                echo "Banner fetch failed or timed out for port 80"
            fi
            ;;
        443)
            echo "Executing: timeout 1 curl -s -I --connect-timeout 1 https://${ip}:${port} --insecure"
            banner=$(timeout 1 curl -s -I --connect-timeout 1 "https://${ip}:${port}" --insecure 2>/dev/null | tr '\r\n' ' ' || echo "N/A")
            if [[ "$banner" == "N/A" ]]; then
                echo "Banner fetch failed or timed out for port 443"
            fi
            ;;
        110|143)
            echo "Executing: timeout 1 nc $ip $port"
            banner=$(timeout 1 nc "$ip" "$port" 2>/dev/null | head -n 1 | tr '\r\n' ' ' || echo "N/A")
            if [[ "$banner" == "N/A" ]]; then
                echo "Banner fetch failed or timed out for port $port"
            fi
            ;;
        22|21|23)
            echo "Executing: timeout 1 nc $ip $port"
            banner=$(timeout 1 nc "$ip" "$port" 2>/dev/null | head -n 1 | tr '\r\n' ' ' || echo "N/A")
            if [[ "$banner" == "N/A" ]]; then
                echo "Banner fetch failed or timed out for port $port"
            fi
            ;;
        *)
            echo "Executing: timeout 0.5 nc $ip $port"
            banner=$(timeout 0.5 nc "$ip" "$port" 2>/dev/null | head -n 1 | tr '\r\n' ' ' || echo "N/A")
            if [[ "$banner" == "N/A" ]]; then
                echo "Banner fetch failed or timed out for port $port"
            fi
            ;;
    esac
    [[ -z "$banner" ]] && banner="N/A"
    banner=$(sanitize_csv "$banner")
    echo "Banner result: $banner"

    (
        flock -x 200
        echo "Writing to enriched.csv: \"$ip\",\"$port\",\"$hostname\",\"$organization\",\"$country\",\"$banner\""
        echo "\"$ip\",\"$port\",\"$hostname\",\"$organization\",\"$country\",\"$banner\"" >> "$ENRICHED_FILE"
    ) 200>"$LOCK_FILE"

    enriched_count=$(wc -l < "$ENRICHED_FILE")
    if [ $((enriched_count - 1)) -ge 500 ]; then  # Restored original 500-entry limit
        echo "Reached 500 entries, emptying enriched.csv"
        echo "ip,port,hostname,organization,country,banner" > "$ENRICHED_FILE"
        enriched_count=1
    fi

    safe_banner="$banner"
    echo "Enriched at line $line_num: $ip:$port - $hostname, $organization, $country, $safe_banner"
    echo "Progress: Processed $((session_processed + 1)) IPs in this session, $((total_lines - line_num)) remaining in current file"
    echo "============================================================================================="
}

# Process IPs one by one
current_line=1
session_processed=0
last_file_size=$(wc -l < "$ALL_FILE" 2>/dev/null || echo 0)
wait_counter=0

while true; do
    current_file_size=$(wc -l < "$ALL_FILE" 2>/dev/null || echo 0)

    # Check for truncation or file reset
    if [ "$current_file_size" -lt "$last_file_size" ]; then
        echo "File $ALL_FILE truncated, resetting to start (previous size: $last_file_size, new size: $current_file_size)"
        current_line=1
        session_processed=0
    elif [ "$current_file_size" -gt "$last_file_size" ]; then
        echo "New IPs detected in $ALL_FILE, updating to size: $current_file_size"
    fi

    # Check if there are lines to process
    if [ "$current_line" -le "$current_file_size" ]; then
        # Read the current line
        line=$(sed -n "${current_line}p" "$ALL_FILE")
        if [[ -n "$line" ]]; then
            IFS=':' read -r ip port _ <<< "$line"
            if [[ -n "$ip" && -n "$port" ]]; then
                process_entry "$ip" "$port" "$current_line" "$current_file_size" "$session_processed"
                session_processed=$((session_processed + 1))
            fi
        fi
        current_line=$((current_line + 1))
    else
        # Wait for new entries, but print message less frequently
        wait_counter=$((wait_counter + 1))
        if [ $((wait_counter % 5)) -eq 0 ]; then
            echo "Waiting for new entries in $ALL_FILE at line $current_line... Processed $session_processed IPs in this session"
        fi
        sleep 1
    fi

    last_file_size="$current_file_size"
done