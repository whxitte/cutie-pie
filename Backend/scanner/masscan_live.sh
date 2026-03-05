#!/bin/bash
# Live Internet Scanner with Masscan - Infinite Loop with File Size Management and Dynamic Service Handling

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions with colors
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_debug() {
    echo -e "${YELLOW}[DEBUG]${NC} $1"
}

log_change() {
    echo -e "${GREEN}[CHANGE]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Separator function
print_separator() {
    echo "===================================="
}

# Auto-detect the Backend directory from this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCANNER_BASE:-$(dirname "$SCRIPT_DIR")}"
log_info "BASE_DIR: $BASE_DIR"
LOG_DIR="$BASE_DIR/logs/scanner"
CONFIG_DIR="$BASE_DIR/config"
EXCLUDE_FILE="$CONFIG_DIR/masscan_exclude.conf"
PORTS_FILE="$CONFIG_DIR/ports.conf"
SIGNAL_FILE="$CONFIG_DIR/.ports_changed"
OUTPUT_DIR="$LOG_DIR/classified"
ALL_FILE="$LOG_DIR/all.txt"
PID_FILE="$CONFIG_DIR/masscan.pid"

# Create output directories and ensure they are writable by the frontend
mkdir -p "$OUTPUT_DIR"
mkdir -p "$LOG_DIR/enriched"
mkdir -p "$LOG_DIR/cracked"
# If running as root (sudo), make sure the user can write to these directories
if [ "$(id -u)" -eq 0 ]; then
    chmod -R 777 "$LOG_DIR"
fi

# Initialize PORTS globally
PORTS=""

# Compute a hash of ports.conf content for change detection
compute_ports_hash() {
    grep -v '^#' "$PORTS_FILE" | grep -v '^$' | sha256sum | awk '{print $1}'
}

# Function to create classified files based on ports.conf and update PORTS globally
create_classified_files() {
    local temp_ports=()
    while IFS=' #' read -r port service; do
        if [[ -z "$port" || "$port" =~ ^# ]]; then
            continue
        fi
        service=$(grep -E "^$port[[:space:]]+#" "$PORTS_FILE" | sed -E "s/^$port[[:space:]]+#//" | tr -d '\n' | tr -d ' ' | tr -s '()' '-' | tr -s '/' '-')
        if [[ -z "$service" ]]; then
            service="port-$port"
        fi
        service=$(echo "$service" | tr '[:upper:]' '[:lower:]' | tr -d ' ' | tr -s '()' '-' | tr -s '/' '-')
        log_debug "Creating classified file for port $port with service name: $service"
        touch "$OUTPUT_DIR/$service.txt"
        temp_ports+=("$port")
    done < <(grep -v '^#' "$PORTS_FILE" | grep -v '^$')
    if [[ ${#temp_ports[@]} -gt 0 ]]; then
        printf -v PORTS "%s," "${temp_ports[@]}"
        PORTS=${PORTS%,}
    else
        PORTS=""
    fi
    log_debug "Updated PORTS: $PORTS"
}

# Function to clean up orphaned classified files
cleanup_orphaned_files() {
    declare -A current_services
    while IFS=' #' read -r port service; do
        if [[ -z "$port" || "$port" =~ ^# ]]; then
            continue
        fi
        service=$(grep -E "^$port[[:space:]]+#" "$PORTS_FILE" | sed -E "s/^$port[[:space:]]+#//" | tr -d '\n' | tr -d ' ' | tr -s '()' '-' | tr -s '/' '-')
        if [[ -z "$service" ]]; then
            service="port-$port"
        fi
        service=$(echo "$service" | tr '[:upper:]' '[:lower:]' | tr -d ' ' | tr -s '()' '-' | tr -s '/' '-')
        current_services["$service"]=1
    done < <(grep -v '^#' "$PORTS_FILE" | grep -v '^$')

    for file in "$OUTPUT_DIR"/*.txt; do
        if [[ -f "$file" ]]; then
            service=$(basename "$file" .txt)
            if [[ -z "${current_services[$service]}" ]]; then
                log_info "Removing orphaned classified file: $file at $(date)"
                rm -f "$file"
            fi
        fi
    done
}

# Initial creation of classified files
create_classified_files
log_info "Ports to scan: $PORTS"

# Get initial modification time and hash of ports.conf
last_mod_time=$(stat -c %Y "$PORTS_FILE" 2>/dev/null || echo 0)
last_hash=$(compute_ports_hash)
log_debug "Initial last_mod_time: $last_mod_time, Initial hash: $last_hash"

# Counter to periodically check for updates
counter=0

# Trap Ctrl+C to clean up
trap 'log_info "Scan interrupted at $(date) - Exiting..."; rm -f "$SIGNAL_FILE" "$PID_FILE"; exit 1' INT

# Infinite loop to restart scan
while true; do
    print_separator
    log_info "Starting live internet scan at $(date) with ports: $PORTS"
    if [[ -n "$PORTS" ]]; then
        # Update classified files before running masscan
        create_classified_files
        cleanup_orphaned_files
        log_debug "Running masscan with ports: $PORTS"
        # Run masscan and process output (removed 2>/dev/null to see errors)
        {
            stdbuf -o0 masscan -p"$PORTS" 0.0.0.0/0 --excludefile "$EXCLUDE_FILE" --rate=1000 -oG - &
            masscan_pid=$!
            echo "$masscan_pid" > "$PID_FILE"
            wait $masscan_pid
        } | while IFS= read -r line; do
            echo "$line"

            # Check for changes during scan
            current_mod_time=$(stat -c %Y "$PORTS_FILE" 2>/dev/null || echo 0)
            current_hash=$(compute_ports_hash)
            log_debug "Current mod time: $current_mod_time, Last mod time: $last_mod_time, Current hash: $current_hash, Last hash: $last_hash"
            if [ -f "$SIGNAL_FILE" ] || [ "$current_mod_time" -gt "$last_mod_time" ] || [ "$current_hash" != "$last_hash" ]; then
                print_separator
                log_change "Change detected in $PORTS_FILE at $(date) - Waiting to process..."
                # Update last_mod_time and last_hash in a temp file to persist to parent scope
                echo "$current_mod_time" > "$CONFIG_DIR/last_mod_time"
                echo "$current_hash" > "$CONFIG_DIR/last_hash"
                rm -f "$SIGNAL_FILE"  # Ensure signal file is cleared
                # Kill masscan using the PID from the file
                if [ -f "$PID_FILE" ]; then
                    masscan_pid=$(cat "$PID_FILE")
                    kill -9 "$masscan_pid" 2>/dev/null
                    rm -f "$PID_FILE"
                fi
                break  # Exit the inner loop
            fi

            # Process Host lines
            if [[ "$line" =~ "Host:" ]]; then
                ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
                port=$(echo "$line" | grep -oE 'Ports: [0-9]+' | grep -oE '[0-9]+' | head -1)
                timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

                if [ -n "$ip" ] && [ -n "$port" ]; then
                    echo "$ip:$port:$timestamp" | stdbuf -o0 tee -a "$ALL_FILE" > /dev/null
                    log_debug "Processing IP: ip=$ip, port=$port, timestamp=$timestamp"

                    while IFS=' #' read -r conf_port service; do
                        if [[ -z "$conf_port" || "$conf_port" =~ ^# ]]; then
                            continue
                        fi
                        service=$(grep -E "^$conf_port[[:space:]]+#" "$PORTS_FILE" | sed -E "s/^$conf_port[[:space:]]+#//" | tr -d '\n' | tr -d ' ' | tr -s '()' '-' | tr -s '/' '-')
                        if [[ -z "$service" ]]; then
                            service="port-$conf_port"
                        fi
                        service=$(echo "$service" | tr '[:upper:]' '[:lower:]' | tr -d ' ' | tr -s '()' '-' | tr -s '/' '-')
                        if [[ "$port" == "$conf_port" ]]; then
                            log_debug "Writing IP $ip to $OUTPUT_DIR/$service.txt for port $port"
                            echo "$ip:$port:$timestamp" | stdbuf -o0 tee -a "$OUTPUT_DIR/$service.txt" > /dev/null
                            break
                        fi
                    done < <(grep -v '^#' "$PORTS_FILE" | grep -v '^$')
                fi

                # Check file sizes
                for file in "$ALL_FILE" "$OUTPUT_DIR"/*.txt; do
                    if [[ -f "$file" ]]; then
                        line_count=$(wc -l < "$file")
                        if [[ "$line_count" -ge 500 ]]; then
                            log_info "Clearing $file (reached $line_count lines) at $(date)"
                            truncate -s 0 "$file"
                        fi
                    fi
                done

                ((counter++))
                if [[ "$counter" -ge 100 ]]; then
                    create_classified_files
                    cleanup_orphaned_files
                    log_info "Periodic update: Ports to scan: $PORTS"
                    counter=0
                fi
            fi
        done

        # Update last_mod_time and last_hash in the parent scope
        if [ -f "$CONFIG_DIR/last_mod_time" ]; then
            last_mod_time=$(cat "$CONFIG_DIR/last_mod_time")
            rm -f "$CONFIG_DIR/last_mod_time"
        fi
        if [ -f "$CONFIG_DIR/last_hash" ]; then
            last_hash=$(cat "$CONFIG_DIR/last_hash")
            rm -f "$CONFIG_DIR/last_hash"
        fi

        print_separator
        log_info "Scan completed at $(date) - Restarting..."
        sleep 3  # Increased delay to prevent immediate re-detection
    else
        # No ports: wait and check for changes periodically
        log_info "No ports to scan, checking for updates every 5 seconds..."
        for ((i=0; i<5; i++)); do
            sleep 1
            current_mod_time=$(stat -c %Y "$PORTS_FILE" 2>/dev/null || echo 0)
            current_hash=$(compute_ports_hash)
            log_debug "Current mod time: $current_mod_time, Last mod time: $last_mod_time, Current hash: $current_hash, Last hash: $last_hash"
            if [ -f "$SIGNAL_FILE" ] || [ "$current_mod_time" -gt "$last_mod_time" ] || [ "$current_hash" != "$last_hash" ]; then
                print_separator
                log_change "Detected change in $PORTS_FILE at $(date) - Restarting scan..."
                last_mod_time="$current_mod_time"
                last_hash="$current_hash"
                rm -f "$SIGNAL_FILE"
                create_classified_files
                log_info "Updated ports to scan: $PORTS"
                cleanup_orphaned_files
                break
            fi
        done
        print_separator
        log_info "Scan completed at $(date) - Restarting..."
    fi
done