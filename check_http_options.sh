#!/bin/sh
set -eu

# ============================================================
# Configuration
# ============================================================
PORTS="80 443"
INCLUDE_NO_FINDINGS="no"   # Change to "yes" if you want ALL hosts in CSVs
DEBUG="no"
[ "${2:-}" = "--debug" ] && DEBUG="yes"

# ============================================================
# Colorized Output
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

if [ -z "$TARGETS_FILE" ]; then
    print_status FAILED "Usage: $0 <targets-file> [--debug]"
    exit 1
fi

if [ ! -f "$TARGETS_FILE" ]; then
    print_status FAILED "Target file not found: $TARGETS_FILE"
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    print_status FAILED "nmap is not installed"
    exit 1
fi

# ============================================================
# Parse Environment name (prod / dev / qa)
# ============================================================
ENVIRONMENT=$(basename "$TARGETS_FILE" | sed -E 's/targets-?|\.txt//g')
[ -z "$ENVIRONMENT" ] && ENVIRONMENT="env"

BASE_DIR="nmap_http_methods_results/$ENVIRONMENT"
RAW_DIR="$BASE_DIR/raw"
SUMMARY_DIR="$BASE_DIR/summaries"

mkdir -p "$RAW_DIR" "$SUMMARY_DIR"

# OS split CSVs
WIN_CSV="$SUMMARY_DIR/windows_${ENVIRONMENT}.csv"
LIN_CSV="$SUMMARY_DIR/linux_${ENVIRONMENT}.csv"
UNK_CSV="$SUMMARY_DIR/unknown_${ENVIRONMENT}.csv"

echo "timestamp,environment,host,checked_ports,options_on_80,options_on_443,ports_with_options,os_guess,os_accuracy" > "$WIN_CSV"
echo "timestamp,environment,host,checked_ports,options_on_80,options_on_443,ports_with_options,os_guess,os_accuracy" > "$LIN_CSV"
echo "timestamp,environment,host,checked_ports,options_on_80,options_on_443,ports_with_options,os_guess,os_accuracy" > "$UNK_CSV"

RUN_TS="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

print_status INFO "Environment     : $ENVIRONMENT"
print_status INFO "Targets file    : $TARGETS_FILE"
print_status INFO "Ports scanned   : 80,443"
print_status INFO "Timestamp (UTC) : $RUN_TS"
print_status INFO "Debug mode      : $DEBUG"
echo

# ============================================================
# Helper Functions
# ============================================================
strip_cr() {
    printf "%s" "$1" | tr -d '\r'
}

is_ip() {
    case "$1" in *[!0-9.]*|'') return 1 ;; esac
    return 0
}

extract_supported_methods() {
    file="$1"
    grep 'Supported Methods:' "$file" | head -n1 | sed 's/.*Supported Methods:[[:space:]]*//'
}

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

    print_status DEBUG "Running nmap on $host:$port with args: $script_args"

    if [ -n "$script_args" ]; then
        nmap -p "$port" --script http-methods --script-args "$script_args" -T4 "$host" \
            -oN "$outfile" >/dev/null 2>&1 || true
    else
        nmap -p "$port" --script http-methods -T4 "$host" \
            -oN "$outfile" >/dev/null 2>&1 || true
    fi

    methods="$(extract_supported_methods "$outfile" || true)"
    printf "%s\n" "$methods" > "$methodsfile"

    if [ -z "$methods" ]; then
        print_status DEBUG "$host:$port → No Supported Methods found"
        return 1
    fi

    print_status DEBUG "$host:$port methods = $methods"

    if printf "%s" "$methods" | grep -qw "OPTIONS"; then
        return 0
    fi

    return 1
}

# OS detection
os_detect_host() {
    host="$1"
    os_out="$RAW_DIR/${host}_os.txt"
    os_guess="unknown"
    os_accuracy=""

    nmap -O -Pn -T4 "$host" -oN "$os_out" >/dev/null 2>&1 || true

    if grep -q "^OS details:" "$os_out"; then
        os_guess="$(grep '^OS details:' "$os_out" | head -n1 | sed 's/^OS details:[[:space:]]*//')"
    elif grep -q "^Running:" "$os_out"; then
        os_guess="$(grep '^Running:' "$os_out" | head -n1 | sed 's/^Running:[[:space:]]*//')"
    elif grep -q "^Aggressive OS guesses:" "$os_out"; then
        os_guess="$(grep '^Aggressive OS guesses:' "$os_out" | head -n1 | sed 's/^Aggressive OS guesses:[[:space:]]*//' | cut -d',' -f1)"
    fi

    case "$os_guess" in *"("*"%"*")"* )
        os_accuracy="$(printf "%s" "$os_guess" | sed -n 's/.*(\([0-9]\{1,3\}%\)).*/\1/p')"
        os_guess="$(printf "%s" "$os_guess" | sed 's/[[:space:]]*(\([0-9]\{1,3\}%\))//')"
    esac

    os_guess="$(printf "%s" "$os_guess" | sed 's/\"/'"'"'/g')"

    printf "%s|%s" "$os_guess" "$os_accuracy"
}

# ============================================================
# Main Loop
# ============================================================
while IFS= read -r line; do
    host="$(strip_cr "$line")"
    [ -z "$host" ] && continue
    case "$host" in \#*) continue ;; esac

    print_status INFO "Scanning $host"

    options_on_80="no"
    options_on_443="no"
    ports_found=""

    for p in $PORTS; do
        if scan_host_port "$host" "$p"; then
            print_status WARNING "OPTIONS enabled on $host:$p"
            ports_found="${ports_found:+$ports_found/}$p"
            [ "$p" = "80" ] && options_on_80="yes"
            [ "$p" = "443" ] && options_on_443="yes"
        else
            print_status SUCCESS "No OPTIONS on $host:$p"
        fi
    done

    os_info="$(os_detect_host "$host")"
    os_guess="$(printf "%s" "$os_info" | cut -d'|' -f1)"
    os_accuracy="$(printf "%s" "$os_info" | cut -d'|' -f2)"

    include_csv="no"
    [ -n "$ports_found" ] && include_csv="yes"
    [ "$INCLUDE_NO_FINDINGS" = "yes" ] && include_csv="yes"

    if [ "$include_csv" = "yes" ]; then
        row="$RUN_TS,$ENVIRONMENT,$host,\"80,443\",$options_on_80,$options_on_443,${ports_found:-none},\"$os_guess\",$os_accuracy"

        case "$os_guess" in
            *[Ww]indow* ) echo "$row" >> "$WIN_CSV" ;;
            *[Ll]inux*  ) echo "$row" >> "$LIN_CSV" ;;
            *           ) echo "$row" >> "$UNK_CSV" ;;
        esac
    fi

    echo

done < "$TARGETS_FILE"

print_status SUCCESS "Scan complete."
print_status INFO "Windows summary : $WIN_CSV"
print_status INFO "Linux summary   : $LIN_CSV"
print_status INFO "Unknown summary : $UNK_CSV"
