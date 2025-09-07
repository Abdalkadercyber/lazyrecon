#!/usr/bin/env bash
set -euo pipefail

# Lazy Recon (Bash) - Enhanced Version
# Author: You (AbCyber). License: MIT.
# Requires: bash, nmap, dig (dnsutils), whois. Optional: subfinder|assetfinder|amass, httpx|httprobe, whatweb, gobuster|ffuf, dnsenum, nuclei.

usage() {
  cat <<'USAGE'
Usage:
  ./lazyrecon.sh -d example.com           # Domain mode (subdomains + web enum + ports)
  ./lazyrecon.sh -i 10.10.10.10           # IP mode (ports + web enum if http discovered)
Options:
  -d DOMAIN        Target domain
  -i IP            Target IP
  -w WORDLIST      Wordlist for dir brute (default: /usr/share/wordlists/dirb/common.txt)
  -p PORTS         Nmap ports (default: top-1000). Examples: "80,443,8080" or "-" for full: 1-65535
  -o OUTBASE       Output base dir (default: ./recon)
  --full           Also run full TCP sweep (-p- fast) before service scan
  --no-web         Skip web enumeration
  --no-sub         Skip subdomain enumeration
  --rate N         Nmap min rate (default 2000 for full sweep)
  --threads N      Threads for directory brute (default: 50)
  --fresh          Ignore previous scans and start fresh
USAGE
  exit 1
}

# Defaults
DOMAIN=""
IP=""
WORDLIST="/usr/share/wordlists/dirb/common.txt"
PORTS="top-1000"
OUTBASE="./recon"
FULL=false
WEB=true
SUB=true
MINRATE=2000
THREADS=50
FRESH=false

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2;;
    -i) IP="$2"; shift 2;;
    -w) WORDLIST="$2"; shift 2;;
    -p) PORTS="$2"; shift 2;;
    -o) OUTBASE="$2"; shift 2;;
    --full) FULL=true; shift;;
    --no-web) WEB=false; shift;;
    --no-sub) SUB=false; shift;;
    --rate) MINRATE="$2"; shift 2;;
    --threads) THREADS="$2"; shift 2;;
    --fresh) FRESH=true; shift;;
    -h|--help) usage;;
    *) echo "[!] Unknown option: $1"; usage;;
  esac
done

if [[ -z "$DOMAIN" && -z "$IP" ]]; then
  echo "[!] Provide -d DOMAIN or -i IP"
  usage
fi

# Tool checks with better error handling
check_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[!] Missing tool: $1 - some features may be disabled"
    return 1
  fi
  return 0
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[!] Missing required tool: $1 - please install it"
    exit 1
  fi
}

# Check required tools
require_tool nmap
require_tool dig
require_tool whois

# Check optional tools
check_tool subfinder
check_tool assetfinder
check_tool amass
check_tool httpx
check_tool httprobe
check_tool whatweb
check_tool gobuster
check_tool ffuf
check_tool dnsenum
check_tool nuclei

# Workspace
TARGET="${DOMAIN:-$IP}"
STAMP="$(date +%Y%m%d_%H%M%S)"
ROOT="${OUTBASE%/}/$TARGET/$STAMP"
DIR_WHOIS="$ROOT/whois"
DIR_DNS="$ROOT/dns"
DIR_SUB="$ROOT/subdomains"
DIR_PORTS="$ROOT/ports"
DIR_WEB="$ROOT/web"
mkdir -p "$DIR_WHOIS" "$DIR_DNS" "$DIR_SUB" "$DIR_PORTS" "$DIR_WEB"
SUMMARY="$ROOT/summary.txt"
HTML_REPORT="$ROOT/report.html"
touch "$SUMMARY"

log() { echo -e "[*] $*"; }
note() { echo -e "$*" | tee -a "$SUMMARY" >/dev/null; }

# 1) WHOIS + DNS (domain only) - PARALLEL EXECUTION
if [[ -n "$DOMAIN" ]]; then
  log "Running parallel WHOIS and DNS enumeration..."
  
  # Run WHOIS and DNS in parallel
  (
    # WHOIS
    log "WHOIS: $DOMAIN (background)"
    if whois "$DOMAIN" > "$DIR_WHOIS/whois.txt" 2>&1; then
      echo "[+] WHOIS completed" 
    else
      echo "[!] WHOIS lookup failed for $DOMAIN"
    fi
    
    # DNS records in parallel
    for t in A AAAA MX TXT NS SOA CNAME; do
      (
        if dig +short "$DOMAIN" "$t" > "$DIR_DNS/${t}.txt" 2>&1; then
          echo "[+] DNS $t records completed"
        fi
      ) &
    done
    
    wait
  ) &
  
  # DNSenum if available
  if command -v dnsenum >/dev/null 2>&1; then
    log "Running dnsenum: $DOMAIN (background)"
    dnsenum --noreverse "$DOMAIN" > "$DIR_DNS/dnsenum.txt" 2>&1 || true &
  fi
fi

# 2) Subdomain enumeration (domain only)
SUBS_FILE="$DIR_SUB/subdomains_raw.txt"
LIVE_FILE="$DIR_SUB/subdomains_live.txt"

if [[ -n "$DOMAIN" && "$SUB" == true ]]; then
  log "Subdomain enumeration: $DOMAIN"
  
  # Use multiple tools if available for better coverage
  : > "$SUBS_FILE.tmp"
  
  if command -v subfinder >/dev/null 2>&1; then
    log "Running subfinder..."
    subfinder -silent -d "$DOMAIN" >> "$SUBS_FILE.tmp" 2>/dev/null || true
  fi
  
  if command -v assetfinder >/dev/null 2>&1; then
    log "Running assetfinder..."
    assetfinder --subs-only "$DOMAIN" >> "$SUBS_FILE.tmp" 2>/dev/null || true
  fi
  
  if command -v amass >/dev/null 2>&1; then
    log "Running amass (passive)..."
    amass enum -passive -d "$DOMAIN" >> "$SUBS_FILE.tmp" 2>/dev/null || true
  fi
  
  # Add common subdomains as fallback
  if [[ ! -s "$SUBS_FILE.tmp" ]]; then
    log "No subdomain tools found, using common subdomains..."
    for sub in www mail ftp admin test api blog shop store; do
      echo "${sub}.${DOMAIN}" >> "$SUBS_FILE.tmp"
    done
  fi
  
  # Sort and deduplicate
  sort -u "$SUBS_FILE.tmp" > "$SUBS_FILE"
  rm -f "$SUBS_FILE.tmp"
  
  count_subs=$(wc -l < "$SUBS_FILE" 2>/dev/null | tr -d ' ' || echo 0)
  note "Subdomains found: $count_subs (subdomains/subdomains_raw.txt)"

  # Probe live subdomains
  if [[ "$count_subs" -gt 0 ]]; then
    if command -v httpx >/dev/null 2>&1; then
      log "Probing live subdomains with httpx"
      cat "$SUBS_FILE" | httpx -silent -follow-redirects -status-code -title -tech-detect -o "$DIR_SUB/httpx.txt" 2>/dev/null || true
      awk '{print $1}' "$DIR_SUB/httpx.txt" > "$LIVE_FILE" 2>/dev/null || true
    elif command -v httprobe >/dev/null 2>&1; then
      log "Probing live subdomains with httprobe"
      cat "$SUBS_FILE" | httprobe -c 50 -t 3000 > "$LIVE_FILE" 2>/dev/null || true
    else
      log "No httpx/httprobe available, using curl for basic probing..."
      : > "$LIVE_FILE"
      while read -r sub; do
        if curl -s -I --connect-timeout 3 "http://$sub" >/dev/null 2>&1 || \
           curl -s -I --connect-timeout 3 "https://$sub" >/dev/null 2>&1; then
          echo "$sub" >> "$LIVE_FILE"
        fi
      done < "$SUBS_FILE"
    fi
    note "Live hosts saved: subdomains/subdomains_live.txt"
  fi
fi

# Wait for background DNS tasks to complete
wait
log "Parallel DNS tasks completed"

# 3) Port scanning - INTELLIGENT TIMING BASED ON TARGET RESPONSIVENESS
TARGET_FOR_NMAP="$TARGET"
if [[ -n "$DOMAIN" ]]; then
  dig +short "$DOMAIN" A > "$DIR_PORTS/domain_A.txt" 2>/dev/null || true
fi

# Detect target responsiveness for intelligent timing
log "Testing target responsiveness for optimal scanning..."
if ping -c 2 -W 2 "$TARGET_FOR_NMAP" >/dev/null 2>&1; then
    NMAP_TIMING="-T4"
    log "Target is responsive, using aggressive timing (-T4)"
else
    NMAP_TIMING="-T2"
    log "Target is slow/unresponsive, using cautious timing (-T2)"
fi

log "Nmap scanning: $TARGET_FOR_NMAP"
PORTLIST=""

if [[ "$FULL" == true ]]; then
  log "Full TCP sweep (-p-), min-rate=$MINRATE"
  if nmap -Pn $NMAP_TIMING --min-rate "$MINRATE" -p- -oA "$DIR_PORTS/full" "$TARGET_FOR_NMAP" >/dev/null 2>&1; then
    # Extract open ports from full scan
    if [[ -f "$DIR_PORTS/full.gnmap" ]]; then
      PORTLIST=$(grep -Eo '^[0-9]+/tcp +open' "$DIR_PORTS/full.gnmap" 2>/dev/null | \
                cut -d/ -f1 | tr '\n' ',' | sed 's/,$//') || PORTLIST=""
    fi
  fi
fi

# Service/version scan
log "Service/version detection"

MAX_RETRIES="--max-retries 2"

if [[ -n "$PORTLIST" && "$PORTLIST" != "" ]]; then
    # Use ports from full scan
    nmap_cmd="nmap -sC -sV -O -Pn $NMAP_TIMING $MAX_RETRIES -p $PORTLIST -oA $DIR_PORTS/services $TARGET_FOR_NMAP"
elif [[ "$PORTS" == "-" ]]; then
    # User requested full port scan
    nmap_cmd="nmap -sC -sV -O -Pn $NMAP_TIMING $MAX_RETRIES -p- -oA $DIR_PORTS/services $TARGET_FOR_NMAP"
elif [[ "$PORTS" == "top-1000" ]]; then
    # Default top-1000 ports using proper syntax
    nmap_cmd="nmap -sC -sV -O -Pn $NMAP_TIMING $MAX_RETRIES --top-ports 1000 -oA $DIR_PORTS/services $TARGET_FOR_NMAP"
else
    # Use specified custom ports
    nmap_cmd="nmap -sC -sV -O -Pn $NMAP_TIMING $MAX_RETRIES -p $PORTS -oA $DIR_PORTS/services $TARGET_FOR_NMAP"
fi

# Execute silently with output only to files
log "Running Nmap scan (output suppressed)..."
if eval "$nmap_cmd" >/dev/null 2>&1; then
    log "Nmap service scan completed successfully"
else
    echo "[!] Nmap service scan failed"
    
    # Fallback to basic scan
    log "Attempting fallback scan..."
    nmap -Pn -T2 --top-ports 100 "$TARGET_FOR_NMAP" -oA "$DIR_PORTS/fallback" >/dev/null 2>&1 || true
fi

note "Nmap outputs: ports/{services.*,fallback.*}"

# 4) Web enumeration
WEB_TARGETS_FILE="$DIR_WEB/targets.txt"
: > "$WEB_TARGETS_FILE"

# Domain mode: use live subdomains and root domain
if [[ -n "$DOMAIN" ]]; then
  # Add live subdomains
  if [[ -f "$LIVE_FILE" && -s "$LIVE_FILE" ]]; then
    while read -r sub; do
      echo "http://$sub" >> "$WEB_TARGETS_FILE"
      echo "https://$sub" >> "$WEB_TARGETS_FILE"
    done < "$LIVE_FILE"
  fi
  
  # Add root domain
  echo "http://$DOMAIN" >> "$WEB_TARGETS_FILE"
  echo "https://$DOMAIN" >> "$WEB_TARGETS_FILE"
fi

# IP mode: extract HTTP services from nmap
if [[ -n "$IP" && -f "$DIR_PORTS/services.gnmap" ]]; then
  grep '/open/' "$DIR_PORTS/services.gnmap" | while read -r line; do
    port=$(echo "$line" | grep -Eo '[0-9]+/open' | cut -d/ -f1)
    if [[ -n "$port" ]]; then
      # Check if it's likely an HTTP service
      if echo "$line" | grep -q "http\|www\|web"; then
        scheme="http"
        [[ "$port" == "443" ]] && scheme="https"
        echo "${scheme}://$IP:$port" >> "$WEB_TARGETS_FILE"
      elif [[ "$port" =~ ^(80|443|8080|8443|8000|8008|8888)$ ]]; then
        scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        echo "${scheme}://$IP:$port" >> "$WEB_TARGETS_FILE"
      fi
    fi
  done
fi

# Deduplicate and clean
sort -u -o "$WEB_TARGETS_FILE" "$WEB_TARGETS_FILE"
sed -i '/^$/d' "$WEB_TARGETS_FILE"

# Enhanced Gobuster directory brute-forcing (silent mode) with NUCLEI INTEGRATION
if [[ "$WEB" == true && -s "$WEB_TARGETS_FILE" ]]; then
  total_targets=$(wc -l < "$WEB_TARGETS_FILE")
  log "Web enumeration on $total_targets targets"
  
  while read -r url; do
    safe=$(echo "$url" | sed 's#https\?://##; s/[^A-Za-z0-9._:-]/_/g')
    dest="$DIR_WEB/$safe"
    mkdir -p "$dest"
    
    log "Scanning: $url"
    
    # WhatWeb scan
    if command -v whatweb >/dev/null 2>&1; then
      timeout 60 whatweb --no-errors --color=never -a 3 "$url" > "$dest/whatweb.txt" 2>&1 || true
    fi
    
    # NUCLEI VULNERABILITY SCANNING
    if command -v nuclei >/dev/null 2>&1; then
      log "Running Nuclei vulnerability scan (background)..."
      (
        timeout 300 nuclei -u "$url" -silent -severity medium,high,critical \
          -o "$dest/nuclei.txt" 2>/dev/null || true
        echo "[+] Nuclei completed for $url"
      ) &
    fi
    
    # Enhanced Gobuster scanning with multiple extensions (silent mode)
    if [[ -f "$WORDLIST" ]] && [[ "$url" =~ ^https?:// ]]; then
      if command -v gobuster >/dev/null 2>&1; then
        log "Running Gobuster directory scan (output suppressed)..."
        
        # Main directory scan (silent)
        timeout 600 gobuster dir -u "$url" -w "$WORDLIST" -q -t "$THREADS" -o "$dest/gobuster_dirs.txt" >/dev/null 2>&1 || true
        
        # Common file extensions scan (silent)
        timeout 300 gobuster dir -u "$url" -w "$WORDLIST" -q -t "$THREADS" -x php,txt,html,js -o "$dest/gobuster_extensions.txt" >/dev/null 2>&1 || true
        
        # Backup files scan (silent)
        timeout 300 gobuster dir -u "$url" -w "$WORDLIST" -q -t "$THREADS" -x bak,old,tmp -o "$dest/gobuster_backups.txt" >/dev/null 2>&1 || true
        
      elif command -v ffuf >/dev/null 2>&1; then
        log "Running FFUF directory scan (output suppressed)..."
        timeout 600 ffuf -u "$url/FUZZ" -w "$WORDLIST" -mc all -fs 0 -t "$THREADS" -of md -o "$dest/ffuf.md" >/dev/null 2>&1 || true
      fi
    fi
    
  done < "$WEB_TARGETS_FILE"
  
  # Wait for all Nuclei scans to complete
  wait
  note "Web enum saved under: web/"
else
  note "Web enum skipped or no web targets found."
fi

# 5) HTML REPORT GENERATION
generate_html_report() {
    log "Generating HTML report..."
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - $TARGET</title>
    <style>
        body { font-family: 'Monaco', 'Consolas', monospace; margin: 40px; background: #0d1117; color: #c9d1d9; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #161b22; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: #161b22; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .success { color: #3fb950; }
        .warning { color: #d29922; }
        .danger { color: #f85149; }
        .info { color: #58a6ff; }
        pre { background: #0d1117; padding: 15px; border-radius: 5px; overflow-x: auto; }
        h1, h2, h3 { color: #58a6ff; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ Reconnaissance Report</h1>
            <p><strong>Target:</strong> <span class="info">$TARGET</span></p>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Scan ID:</strong> $STAMP</p>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <pre>$(cat "$SUMMARY" 2>/dev/null || echo "No summary available")</pre>
        </div>

        <div class="section">
            <h2>🌐 Domain Information</h2>
            <pre>$(ls -la "$DIR_DNS"/*.txt 2>/dev/null | wc -l) DNS record files found</pre>
            <pre>$(cat "$DIR_SUB/subdomains_raw.txt" 2>/dev/null | wc -l) subdomains discovered</pre>
        </div>

        <div class="section">
            <h2>🚪 Open Ports & Services</h2>
            <pre>$(grep '/open/' "$DIR_PORTS/services.gnmap" 2>/dev/null | head -n 10 || echo "No open ports found")</pre>
        </div>

        <div class="section">
            <h2>🔍 Web Application Findings</h2>
            <pre>$(find "$DIR_WEB" -name "*.txt" -exec cat {} \; 2>/dev/null | grep -i "vulnerable\|vulnerability\|risk\|issue" | head -n 5 || echo "No critical vulnerabilities found")</pre>
        </div>

        <div class="section">
            <h2>📁 Files Generated</h2>
            <pre>$(find "$ROOT" -type f -name "*.txt" -o -name "*.xml" -o -name "*.gnmap" | head -n 10)</pre>
            <p>Total files: $(find "$ROOT" -type f | wc -l)</p>
        </div>
    </div>
</body>
</html>
EOF
}

generate_html_report
note "HTML report generated: $HTML_REPORT"

# 6) Final summary
log "Building summary"
{
  echo "=== LAZY RECON SUMMARY ==="
  echo "Target: $TARGET"
  echo "Date: $(date)"
  echo "Mode: $([[ -n "$DOMAIN" ]] && echo "Domain" || echo "IP")"
  echo "Scan Duration: ~$((SECONDS/60)) minutes"
  echo ""
  
  if [[ -n "$DOMAIN" ]]; then
    echo "=== DOMAIN INFO ==="
    echo "A records: $(tr '\n' ' ' < "$DIR_PORTS/domain_A.txt" 2>/dev/null || echo "None")"
    echo "Subdomains found: $(wc -l < "$SUBS_FILE" 2>/dev/null || echo 0)"
    echo "Live subdomains: $(wc -l < "$LIVE_FILE" 2>/dev/null || echo 0)"
    echo ""
  fi
  
  echo "=== OPEN PORTS ==="
  if [[ -f "$DIR_PORTS/services.gnmap" ]]; then
    grep '/open/' "$DIR_PORTS/services.gnmap" | head -n 10 | awk '{print "  " $0}'
  else
    echo "  No port scan results found"
  fi
  echo ""
  
  echo "=== WEB TARGETS ==="
  if [[ -s "$WEB_TARGETS_FILE" ]]; then
    head -n 5 "$WEB_TARGETS_FILE" | awk '{print "  " $0}'
    [[ $(wc -l < "$WEB_TARGETS_FILE") -gt 5 ]] && echo "  ... and $(( $(wc -l < "$WEB_TARGETS_FILE") - 5 )) more"
  else
    echo "  No web targets found"
  fi
  
  echo ""
  echo "=== VULNERABILITY SCAN RESULTS ==="
  nuclei_count=$(find "$DIR_WEB" -name "nuclei.txt" -exec cat {} \; 2>/dev/null | wc -l || echo 0)
  echo "Nuclei findings: $nuclei_count"
  
  echo ""
  echo "=== TOOLS USED ==="
  echo "Nmap, Dig, Whois"
  command -v dnsenum >/dev/null 2>&1 && echo "DNSenum"
  command -v gobuster >/dev/null 2>&1 && echo "Gobuster"
  command -v whatweb >/dev/null 2>&1 && echo "WhatWeb"
  command -v nuclei >/dev/null 2>&1 && echo "Nuclei"
  
} > "$SUMMARY" 2>/dev/null

log "Recon completed successfully!"
log "Results saved to: $ROOT"
log "Summary: $SUMMARY"
log "HTML Report: $HTML_REPORT"
echo ""
echo "Quick tips:"
echo "  grep -R \"200\" \"$ROOT/web\" 2>/dev/null | head -n 5"
echo "  grep -R \"admin\" \"$ROOT/web\" 2>/dev/null | head -n 5"
echo "  cat \"$SUMMARY\""
echo "  open \"$HTML_REPORT\"  # View HTML report"
