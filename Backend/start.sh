#!/bin/bash
# Set SCANNER_BASE to the Backend directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCANNER_BASE="$SCRIPT_DIR"