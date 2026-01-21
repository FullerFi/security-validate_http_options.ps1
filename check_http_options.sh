#!/bin/sh
set -eu

# ============================================================
# Configuration
# ============================================================
PORTS="80 443"
INCLUDE_NO_FINDINGS_CSV="no"

# Debug flag
DEBUG="no"
[ "${2:-}" = "--debug" ] && DEBUG="yes"

# ============================================================
# Color setup (POSIX-safe)
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    status="$1"
    shift
    msg="$*"
    case "$status" in
        SUCCESS) printf "%b\n" "${GREEN}[✓]${NC} $msg" ;;
        FAILED)  printf "%b\n" "${RED}[✗]${NC} $msg" ;;
        WARNING) printf "%b\n" "${YELLOW}[!]${NC} $msg" ;;
        INFO)    printf "%b\n" "${BLUE}[i]${NC} $msg" ;;
        DEBUG)   [ "$DEBUG" = "yes" ] && printf "%b\n" "${BLUE}[debug]${NC} $msg" ;;
        *)       printf "%s\n" "$msg" ;;
    esac
}

# ============================================================
# Input Validation
# ============================================================
TARGETS_FILE="${1:-}"

[ -z "$TARGETS_FILE" ] && {
    print_status FAILED "Usage: $0 <targets-file> [--debug]"
    exit 1
}

[ ! -f "$TARGETS_FILE" ] && {
    print_status FAILED "Target file not found: $TARGETS_FILE"
    exit 1
}

command -v nmap >/dev/null 2>&1 || {
    print_status FAILED "nmap is not installed"
    exit 1
}

# ============================================================
# Environment Detection
# ============================================================
ENVIRONMENT=$(basename "$TARGETS_FILE" | sed -E 's/targets-?|\.txt//g')
[ -z "$ENVIRONMENT" ] && ENVIRONMENT="env"

BASE_DIR="nmap_http_methods_results/$ENVIRONMENT"
RAW_DIR="$BASE_DIR/raw"
SUMMARY_DIR="$BASE_DIR/summaries"

mkdir -p "$RAW_DIR" "$SUMMARY_DIR"

SUMMARY_TXT="$SUMMARY_DIR/options_enabled_hosts.txt"
SUMMARY_CSV="$SUMMARY_DIR/options_enabled_hosts.csv"

: > "$SUMMARY_TXT"
echo "timestamp,environment,host,checked_ports,options_on_80,options_on_443,ports_with_options,os_guess,os_accuracy" \
  > "$SUMMARY_CSV"

RUN_TS="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

print_status INFO "Environment     : $ENVIRONMENT"
print_status INFO "Targets file    : $TARGETS_FILE"
print_status INFO "Ports scanned   : 80,443"
print_status INFO "Timestamp (UTC) : $RUN_TS"
print_status INFO "Debug mode      : $DEBUG"
echo

# ============================================================
# Helpers
# ============================================================
is_ip() {
    case "$1" in
        *[!0-9.]*|'') return 1 ;;
        *) return 0 ;;
    esac
}

extract_supported_methods() {
    file="$1"
    grep 'Supported Methods:' "$file" | \
        head -n1 | sed 's/.*Supported Methods:[[:space:]]*//'
}

# ============================================================
# Scan host:port (FIXED options detection)
# ============================================================
scan_host_port() {
    host="$1"
    port="$2"

    outfile="$RAW_DIR/${host}_p${port}_http_methods.txt"
    methodsfile="$RAW_DIR/${host}_p${port}_methods.txt"

    script_args=""
    [ "$port" = "443" ] && script_args="http.ssl=true"
    if ! is_ip "$host"; then
        script_args="${script_args:+$script_args,}http.host=$host"
    fi

    print_status DEBUG "Running nmap http-methods on $host:$port (args: $script_args)"

    if [ -n "$script_args" ]; then
        nmap -p "$port" --script http-methods \
             --script-args "$script_args" \
             -T4 "$host" -oN "$outfile" >/dev/null 2>&1 || true
    else
        nmap -p "$port" --script http-methods \
             -T4 "$host" -oN "$outfile" >/dev/null 2>&1 || true
    fi

    methods="$(extract_supported_methods "$outfile" || true)"
    printf "%s\n" "$methods" > "$methodsfile"

    if [ -z "$methods" ]; then
        print_status DEBUG "$host:$port no 'Supported Methods' found"
        return 1
    fi

    print_status DEBUG "$host:$port methods detected: $methods"

    if printf "%s" "$methods" | grep -qw "OPTIONS"; then
        return 0
    fi

    print_status DEBUG "$host:$port excluded (OPTIONS not present)"
    return 1
}

# ============================================================
# OS Detection
# ============================================================
os_detect_host() {
    host="$1"
    os_out="$RAW_DIR/${host}_os.txt"
    os_guess="unknown"
    os_acc=""

    nmap -O -Pn -T4 "$host" -oN "$os_out" >/dev/null 2>&1 || true

    if grep -q "^OS details:" "$os_out"; then
        os_guess="$(grep '^OS details:' "$os_out" | head -n1 | sed 's/^OS details:[[:space:]]*//')"
    elif grep -q "^Running:" "$os_out"; then
        os_guess="$(grep '^Running:' "$os_out" | head -n1 | sed 's/^Running:[[:space:]]*//')"
    elif grep -q "^Aggressive OS guesses:" "$os_out"; then
        os_guess="$(grep '^Aggressive OS guesses:' "$os_out" | \
                    head -n1 | sed 's/^Aggressive OS guesses:[[:space:]]*//' | cut -d',' -f1)"
    fi

    case "$os_guess" in
        *"("*"%"*")"*)
            os_acc="$(echo "$os_guess" | sed -n 's/.*(\([0-9]\{1,3\}%\)).*/\1/p')"
            os_guess="$(echo "$os_guess" | sed 's/[[:space:]]*(\([0-9]\{1,3\}%\))//')"
            ;;
    esac

    os_guess="$(printf "%s" "$os_guess" | sed 's/\"/'"'"'/g')"
    printf "%s|%s" "$os_guess" "$os_acc"
}

# ============================================================
# Main Loop
# ============================================================
while IFS= read -r host; do
    [ -z "$host" ] && continue
    case "$host" in \#*) continue ;; esac

    print_status INFO "Scanning $host"

    options_on_80="no"
    options_on_443="no"
    ports_with_options=""

    for p in $PORTS; do
        if scan_host_port "$host" "$p"; then
            print_status WARNING "OPTIONS enabled on $host:$p"
            ports_with_options="${ports_with_options:+$ports_with_options/}$p"
            [ "$p" = "80" ] && options_on_80="yes"
            [ "$p" = "443" ] && options_on_443="yes"
        else
            methods="$(cat "$RAW_DIR/${host}_p${p}_methods.txt" 2>/dev/null || true)"
            print_status DEBUG "Excluded $host:$p → methods=[$methods]"
            print_status SUCCESS "No OPTIONS on $host:$p"
        fi
    done

    os_info="$(os_detect_host "$host")"
    os_guess="$(printf "%s" "$os_info" | cut -d'|' -f1)"
    os_acc="$(printf "%s" "$os_info" | cut -d'|' -f2)"

    if [ -n "$ports_with_options" ]; then
        echo "$host" >> "$SUMMARY_TXT"
        echo "$RUN_TS,$ENVIRONMENT,$host,\"80,443\",$options_on_80,$options_on_443,$ports_with_options,\"$os_guess\",$os_acc" \
            >> "$SUMMARY_CSV"
        print_status DEBUG "$host INCLUDED in summary (ports: $ports_with_options)"
    else
        print_status DEBUG "$host excluded from summary (no OPTIONS found)"
        [ "$INCLUDE_NO_FINDINGS_CSV" = "yes" ] && \
            echo "$RUN_TS,$ENVIRONMENT,$host,\"80,443\",no,no,none,\"$os_guess\",$os_acc" >> "$SUMMARY_CSV"
    fi

    echo
done < "$TARGETS_FILE"

# ============================================================
# Completion
# ============================================================
print_status SUCCESS "Scan complete"
print_status INFO "TXT summary : $SUMMARY_TXT"
print_status INFO "CSV summary : $SUMMARY_CSV"
print_status INFO "Raw output  : $RAW_DIR"
