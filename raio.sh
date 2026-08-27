#!/usr/bin/env bash
#
#  raio.sh  -  RAIO: Recon All In One — one-command cybersecurity recon suite
#  ------------------------------------------------------------
#  Runs nmap, whois, dig, subdomain enumeration, and content
#  discovery in PARALLEL, renders a gorgeous terminal dashboard,
#  and dumps every artifact into a timestamped "Loot Folder".
#
#  Usage:
#    ./raio.sh <domain-or-ip> [options]
#
#  Examples:
#    ./raio.sh example.com
#    ./raio.sh 8.8.8.8 --skip-nmap
#    ./raio.sh example.com --wordlist /usr/share/wordlists/dirb/common.txt
#
#  Designed for AUTHORIZED security testing only.
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Colors / styling
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
  C_WHITE=$'\033[37m'; C_GRAY=$'\033[90m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""
  C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""; C_GRAY=""
fi
R="${C_RED}" G="${C_GREEN}" Y="${C_YELLOW}" B="${C_BLUE}"
M="${C_MAGENTA}" C="${C_CYAN}" W="${C_WHITE}" D="${C_DIM}" RST="${C_RESET}"
BD="${C_BOLD}"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
banner() {
  local t="${1:-target}"
  cat <<EOF

${C_CYAN}${BD}  ╔══════════════════════════════════════════════════════════╗
  ║                  RAIO · Recon All In One                 ║
  ╚══════════════════════════════════════════════════════════╝${RST}
  ${D}one-command parallel recon  ·  nmap · whois · dns · subs · loot${RST}
  ${W}target:${RST} ${BD}${t}${RST}
EOF
}

# ---------------------------------------------------------------------------
# Dashboard helpers
# ---------------------------------------------------------------------------
hr() { printf "${C_GRAY}%.0s─${RST}" $(seq 1 "$(tput cols)"); echo; }
section() {
  local s="${1}"
  echo "${C_CYAN}${BD}▌ ${s}${RST}"
}
status_ok()   { printf "${G}✔${RST} %s\n" "$1"; }
status_skip() { printf "${Y}⏭${RST} %s\n" "$1"; }
status_fail() { printf "${R}✘ %s${RST}\n" "$1"; }

# ---------------------------------------------------------------------------
# Config / state
# ---------------------------------------------------------------------------
TARGET=""
SKIP_NMAP=0; SKIP_WHOIS=0; SKIP_DNS=0; SKIP_SUBS=0; SKIP_FUZZ=0
WORDLIST=""
TIMEOUT=600
STATE_DIR="/tmp/recon_$$"; mkdir -p "$STATE_DIR"
# Modules communicate status (0/1/2) + summary via files (subshells can't
# mutate the parent's associative arrays).
set_st()  { printf '%s' "$2" >"$STATE_DIR/$1.st"; }
set_sum() { printf '%s' "$2" >"$STATE_DIR/$1.sum"; }
get_st()  { [[ -f "$STATE_DIR/$1.st" ]] && cat "$STATE_DIR/$1.st" || echo 2; }
get_sum() { [[ -f "$STATE_DIR/$1.sum" ]] && cat "$STATE_DIR/$1.sum" || echo ""; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-nmap) SKIP_NMAP=1 ;;
    --skip-whois) SKIP_WHOIS=1 ;;
    --skip-dns) SKIP_DNS=1 ;;
    --skip-subs) SKIP_SUBS=1 ;;
    --skip-fuzz) SKIP_FUZZ=1 ;;
    --wordlist|-w) WORDLIST="$2"; shift ;;
    -t|--timeout) TIMEOUT="$2"; shift ;;
    -h|--help)
      banner "target"
      grep -E '^#' "$0" | sed 's/^#\s*//' | sed -n '1,40p'
      exit 0 ;;
    -*)
      echo "${R}unknown option: $1${RST}" >&2; exit 2 ;;
    *)
      if [[ -z "$TARGET" ]]; then TARGET="$1"; else
        echo "${R}unexpected arg: $1${RST}" >&2; exit 2
      fi ;;
  esac
  shift
done

[[ -z "$TARGET" ]] && { echo "${R}usage: $0 <domain|ip> [--skip-...]${RST}"; exit 2; }
TARGET="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*##')"

# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# Fetch a URL to stdout using whatever is available.
fetch() {
  if have curl; then curl -sL "$1"
  elif have wget; then wget -qO- "$1"
  else return 1; fi
}

# ---------------------------------------------------------------------------
# Loot folder
# ---------------------------------------------------------------------------
TS="$(date +%Y%m%d_%H%M%S)"
LOOT_ROOT="${RECON_LOOT:-./loot}"
LOOT="${LOOT_ROOT}/${TARGET}/${TS}"
RAW="${LOOT}/raw"
mkdir -p "$RAW"

log() { printf "${D}[%s]${RST} %s\n" "$(date +%H:%M:%S)" "$*"; }

# ---------------------------------------------------------------------------
# Module: WHOIS
# ---------------------------------------------------------------------------
mod_whois() {
  local out="$RAW/whois.txt"; local sum="no whois data"
  if (( SKIP_WHOIS )); then set_st whois 2; set_sum whois "skipped"; return; fi
  if ! have whois && ! have curl && ! have wget; then set_st whois 2; set_sum whois "no tool"; return; fi

  if have whois; then
    timeout "$TIMEOUT" whois "$TARGET" >"$out" 2>/dev/null
  else
    # Try several RDAP endpoints (no whois binary available).
    local tld="${TARGET##*.}"
    local urls=(
      "https://rdap.org/$TARGET"
      "https://rdap.org/domain/$TARGET"
      "https://rdap.verisign.com/$tld/v1/domain/$TARGET"
    )
    for u in "${urls[@]}"; do
      timeout "$TIMEOUT" fetch "$u" 2>/dev/null >"$out"
      [[ -s "$out" ]] && break
    done
  fi

  if [[ -s "$out" ]]; then
    local org reg
    if grep -q '^{' "$out" 2>/dev/null; then
      # RDAP JSON output
      org="$(jq -r '.entities[]? | .vcardArray[1][]? | select(.[0]=="fn") | .[3]' "$out" 2>/dev/null | head -1)"
      reg="$(jq -r '.registrarName // .entities[]?.roles' "$out" 2>/dev/null | head -1)"
    else
      org="$(grep -iE 'Registrant Organization|OrgName|organization' "$out" | head -1 | cut -d: -f2- | xargs)"
      reg="$(grep -iE 'Registrar:|registrar' "$out" | head -1 | cut -d: -f2- | xargs)"
    fi
    sum="$(echo "org=${org:-?} registrar=${reg:-?}" | cut -c1-60)"
    set_st whois 0
  else
    set_st whois 1; sum="lookup failed"
  fi
  set_sum whois "$sum"
}

# ---------------------------------------------------------------------------
# Module: DNS (dig)
# ---------------------------------------------------------------------------
mod_dns() {
  local out="$RAW/dns.txt"; local sum="no dns data"
  if (( SKIP_DNS )); then set_st dns 2; set_sum dns "skipped"; return; fi
  if ! have dig; then set_st dns 2; set_sum dns "no dig"; return; fi

  : >"$out"
  local r
  for r in A AAAA MX NS TXT SOA CNAME; do
    dig +short "$TARGET" "$r" 2>/dev/null | sed "s/^/[$r] /" >>"$out"
  done
  if [[ -s "$out" ]]; then
    local ips; ips="$(grep -c '^\[A\]' "$out")"
    sum="$(grep '^\[A\]' "$out" | head -3 | tr '\n' ' ' | cut -c1-50)"
    set_st dns 0
  else
    set_st dns 1; sum="no records"
  fi
  set_sum dns "$sum"
}

# ---------------------------------------------------------------------------
# Module: Subdomain enumeration
#   Prefers subfinder/amass; falls back to crt.sh via curl.
# ---------------------------------------------------------------------------
mod_subs() {
  local out="$RAW/subdomains.txt"; local sum="no subs"
  if (( SKIP_SUBS )); then set_st subs 2; set_sum subs "skipped"; return; fi

  : >"$out"
  if have subfinder; then
    timeout "$TIMEOUT" subfinder -d "$TARGET" -silent >>"$out" 2>/dev/null
  fi
  if have amass; then
    timeout "$TIMEOUT" amass enum -passive -d "$TARGET" 2>/dev/null | grep -E "^[a-z0-9.-]+\.$TARGET\$" >>"$out"
  fi
  # Passive fallback: crt.sh
  if [[ ! -s "$out" ]] && ( have curl || have wget ); then
    timeout "$TIMEOUT" fetch "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
      | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//' | sort -u >>"$out"
  fi

  if [[ -s "$out" ]]; then
    sort -u "$out" -o "$out"
    local n; n="$(wc -l <"$out")"
    sum="$n subdomains found"
    set_st subs 0
  else
    set_st subs 1; sum="enum failed"
  fi
  set_sum subs "$sum"
}

# ---------------------------------------------------------------------------
# Module: NMAP
# ---------------------------------------------------------------------------
mod_nmap() {
  local out="$RAW/nmap.txt"; local sum="no scan"
  if (( SKIP_NMAP )); then set_st nmap 2; set_sum nmap "skipped"; return; fi
  if ! have nmap; then set_st nmap 2; set_sum nmap "no nmap"; return; fi

  timeout "$TIMEOUT" nmap -T4 -sC -sV -Pn --top-ports 1000 "$TARGET" >"$out" 2>/dev/null
  if [[ -s "$out" ]]; then
    local open; open="$(grep -c '/open' "$out")"
    sum="$open open ports"
    set_st nmap 0
  else
    set_st nmap 1; sum="scan failed"
  fi
  set_sum nmap "$sum"
}

# ---------------------------------------------------------------------------
# Module: Content discovery (ffuf / feroxbuster / curl fallback)
# ---------------------------------------------------------------------------
mod_fuzz() {
  local out="$RAW/ffuf.txt"; local sum="no fuzz"
  if (( SKIP_FUZZ )); then set_st fuzz 2; set_sum fuzz "skipped"; return; fi

  local url="http://${TARGET}"
  if have ffuf; then
    local wl="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
    if [[ ! -f "$wl" ]]; then wl="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"; fi
    timeout "$TIMEOUT" ffuf -u "${url}/FUZZ" -w "$wl" -mc 200,204,301,302,307,401,403 -s >"$out" 2>/dev/null
  elif have feroxbuster; then
    timeout "$TIMEOUT" feroxbuster -u "$url" -q -o "$out" 2>/dev/null
  else
    set_st fuzz 2; set_sum fuzz "no ffuf/ferox"; return
  fi

  if [[ -s "$out" ]]; then
    local n; n="$(wc -l <"$out")"
    sum="$n paths discovered"
    set_st fuzz 0
  else
    set_st fuzz 1; sum="none found"
  fi
  set_sum fuzz "$sum"
}

# ---------------------------------------------------------------------------
# Runner: launch all modules in parallel
# ---------------------------------------------------------------------------
run_module() {
  local name="$1" fn="$2"
  log "launching ${BD}$name${RST}"
  ( $fn ) &
  echo $! >"/tmp/recon_${name}.pid"
}

banner "$TARGET"
hr
log "loot folder: ${W}${LOOT}${RST}"
hr

# Spawn all modules concurrently
run_module whois mod_whois
run_module dns   mod_dns
run_module subs  mod_subs
run_module nmap  mod_nmap
run_module fuzz  mod_fuzz

# Wait for completion with a tiny spinner-ish progress line
wait
echo

# ---------------------------------------------------------------------------
# Dashboard render
# ---------------------------------------------------------------------------
hr
echo "${BD}${W}  R E C O N   D A S H B O A R D${RST}   ${D}${TARGET} · ${TS}${RST}"
hr

render_row() {
  local key="$1" label="$2"
  local st="$(get_st "$key")"; local s="$(get_sum "$key")"
  local icon
  case "$st" in
    0) icon="${G}✔${RST}" ;;
    1) icon="${R}✘${RST}" ;;
    2) icon="${Y}⏭${RST}" ;;
  esac
  printf "  %-10s %-6s %s\n" "${BD}$label${RST}" "$icon" "${D}${s}${RST}"
}

section "Modules"
render_row whois "WHOIS"
render_row dns   "DNS"
render_row subs  "SUBS"
render_row nmap  "NMAP"
render_row fuzz  "FUZZ"
hr

# Show notable findings inline
if [[ -s "$RAW/subdomains.txt" ]]; then
  section "Top subdomains"
  head -10 "$RAW/subdomains.txt" | sed 's/^/    /'
  hr
fi
if [[ -s "$RAW/nmap.txt" ]]; then
  section "Open ports"
  grep -E '^[0-9]+/(tcp|udp)' "$RAW/nmap.txt" | awk '{print "    " $1 "  " $2 "  " $3}' | head -15
  hr
fi
if [[ -s "$RAW/ffuf.txt" ]]; then
  section "Discovered paths"
  head -15 "$RAW/ffuf.txt" | sed 's#^#    /#' | sed "s#^#    #"
  hr
fi

# ---------------------------------------------------------------------------
# Generate markdown report
# ---------------------------------------------------------------------------
REPORT="${LOOT}/recon-report.md"
{
  echo "# Recon Report — ${TARGET}"
  echo "_Generated: $(date)_"
  echo
  echo "## Summary"
  echo
  echo "| Module | Status | Detail |"
  echo "|--------|--------|--------|"
  for k in whois dns subs nmap fuzz; do
    st="$(get_st "$k")"
    case "$st" in 0) stxt="ok";; 1) stxt="fail";; 2) stxt="skip";; esac
    echo "| $k | $stxt | $(get_sum "$k") |"
  done
  echo
  echo "## Raw artifacts"
  echo
  echo "- whois: \`raw/whois.txt\`"
  echo "- dns: \`raw/dns.txt\`"
  echo "- subdomains: \`raw/subdomains.txt\`"
  echo "- nmap: \`raw/nmap.txt\`"
  echo "- fuzz: \`raw/ffuf.txt\`"
} >"$REPORT"

# ---------------------------------------------------------------------------
# Finish
# ---------------------------------------------------------------------------
echo "${G}${BD}✓ Recon complete.${RST}  Loot: ${W}${LOOT}${RST}"
echo "${D}  report: ${REPORT}${RST}"
hr

# Missing-tools hint
missing=()
have nmap   || missing+=(nmap)
have whois  || missing+=(whois)
have ffuf   || missing+=(ffuf)
have subfinder || have amass || true
(( ${#missing[@]} )) && \
  echo "${Y}tip: missing tools -> ${missing[*]}  install: sudo apt install ${missing[*]}${RST}"
