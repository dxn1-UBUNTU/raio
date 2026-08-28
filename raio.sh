#!/usr/bin/env bash
#
#  raio.sh  -  RAIO: Recon All In One — one-command cybersecurity recon suite
#  ------------------------------------------------------------
#  Runs nmap, whois, dig, subdomain enumeration, and content
#  discovery in PARALLEL, renders a gorgeous terminal dashboard,
#  and dumps every artifact into a timestamped "Loot Folder".
#
#  Modes:
#    ./raio.sh                         interactive TUI (arrow keys + space)
#    ./raio.sh <domain|ip>             one-shot recon + dashboard
#    ./raio.sh <target> --gui [port]   launch the Flask web GUI
#    ./raio.sh <target> --json         emit a JSON report (machine readable)
#    ./raio.sh <target> --status-file  write live JSON progress (for the GUI)
#
#  Examples:
#    ./raio.sh example.com
#    ./raio.sh 8.8.8.8 --skip-nmap
#    ./raio.sh example.com --gui 8080
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
section() { echo "${C_CYAN}${BD}▌ ${1}${RST}"; }

# ---------------------------------------------------------------------------
# Config / state
# ---------------------------------------------------------------------------
TARGET=""
SKIP_NMAP=0; SKIP_WHOIS=0; SKIP_DNS=0; SKIP_SUBS=0; SKIP_FUZZ=0
WORDLIST=""
TIMEOUT=600
DO_TUI=0; DO_GUI=0; DO_JSON=0; GUI_PORT=8080; STATUS_FILE=""
RAIO_DONE=0
STATE_DIR="/tmp/recon_$$"; mkdir -p "$STATE_DIR"
# Modules communicate status (0/1/2) + summary via files (subshells can't
# mutate the parent's associative arrays).
set_st()  { printf '%s' "$2" >"$STATE_DIR/$1.st"; }
set_sum() { printf '%s' "$2" >"$STATE_DIR/$1.sum"; }
get_st()  { [[ -f "$STATE_DIR/$1.st" ]] && cat "$STATE_DIR/$1.st" || echo 2; }
get_sum() { [[ -f "$STATE_DIR/$1.sum" ]] && cat "$STATE_DIR/$1.sum" || echo ""; }

json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '; }

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
    --tui) DO_TUI=1 ;;
    --gui) DO_GUI=1 ;;
    --gui=*) DO_GUI=1; GUI_PORT="${1#--gui=}" ;;
    --json) DO_JSON=1 ;;
    --status-file) STATUS_FILE="$2"; shift ;;
    -w|--wordlist) WORDLIST="$2"; shift ;;
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

# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

fetch() {
  if have curl; then curl -sL "$1"
  elif have wget; then wget -qO- "$1"
  else return 1; fi
}

# ---------------------------------------------------------------------------
# Interactive TUI (arrow keys + space to toggle, enter to run)
# ---------------------------------------------------------------------------
tui() {
  tput civis
  local mods=(whois dns subs nmap fuzz)
  local labels=("WHOIS" "DNS" "SUBS" "NMAP" "FUZZ")
  local sel=(1 1 1 1 1)
  local idx=0 k rest
  clear; banner "interactive"
  echo
  read -r -p "${W}target (domain or IP): ${RST}" TARGET
  [[ -z "$TARGET" ]] && { tput cnorm; echo "${R}no target${RST}"; exit 2; }
  TARGET="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*##')"
  while true; do
    clear; banner "interactive"
    echo; echo "  ${W}target:${RST} ${BD}$TARGET${RST}"
    echo; echo "  ${D}↑/↓ move   space toggle   enter run   q quit${RST}"
    echo
    for i in "${!mods[@]}"; do
      local mark=" " chk="${Y}[ ]${RST}"
      (( i==idx )) && mark="${C_CYAN}▶${RST}"
      (( sel[i] )) && chk="${G}[✔]${RST}"
      printf "    %s %s %s\n" "$mark" "$chk" "${BD}${labels[$i]}${RST}"
    done
    read -rsn1 k
    case "$k" in
      $'\x1b')
        read -rsn2 -t 0.001 rest
        [[ "$rest" == "[A" && idx -gt 0 ]] && (( idx-- ))
        [[ "$rest" == "[B" && idx -lt ${#mods[@]}-1 ]] && (( idx++ )) ;;
      ' ') sel[idx]=$(( 1 - sel[idx] )) ;;
      '') break ;;
      q|Q) tput cnorm; echo; exit 0 ;;
    esac
  done
  tput cnorm
  (( sel[0] )) || SKIP_WHOIS=1
  (( sel[1] )) || SKIP_DNS=1
  (( sel[2] )) || SKIP_SUBS=1
  (( sel[3] )) || SKIP_NMAP=1
  (( sel[4] )) || SKIP_FUZZ=1
}

# ---------------------------------------------------------------------------
# GUI launcher (Flask)
# ---------------------------------------------------------------------------
launch_gui() {
  local DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local SCRIPT="$DIR/raio.sh"
  local PORT="${GUI_PORT:-8080}"
  if ! python3 -c 'import flask' 2>/dev/null; then
    echo "${Y}flask not found — attempting install...${RST}"
    python3 -m pip install --user flask >/dev/null 2>&1 || pip install flask >/dev/null 2>&1 \
      || { echo "${R}could not install flask (need: pip install flask)${RST}"; exit 1; }
  fi
  echo "${G}${BD}RAIO GUI → http://localhost:${PORT}${RST}  (Ctrl+C to stop)"
  exec python3 "$DIR/raio_gui.py" --port "$PORT" --script "$SCRIPT"
}

# ---------------------------------------------------------------------------
# Resolve target / mode
# ---------------------------------------------------------------------------
if (( DO_GUI )); then launch_gui; exit 0; fi
if (( DO_TUI )) || [[ -z "$TARGET" ]]; then
  [[ -t 0 ]] || { echo "${R}no target given and stdin is not a TTY${RST}" >&2; exit 2; }
  tui
fi
[[ -z "$TARGET" ]] && { echo "${R}usage: $0 <domain|ip> [--skip-...|--gui|--tui|--json]${RST}"; exit 2; }
TARGET="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*##')"

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
    sum="$(grep '^\[A\]' "$out" | head -3 | tr '\n' ' ' | cut -c1-50)"
    set_st dns 0
  else
    set_st dns 1; sum="no records"
  fi
  set_sum dns "$sum"
}

# ---------------------------------------------------------------------------
# Module: Subdomain enumeration
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
  if [[ ! -s "$out" ]] && ( have curl || have wget ); then
    timeout "$TIMEOUT" fetch "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
      | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//' | sort -u >>"$out"
  fi

  if [[ -s "$out" ]]; then
    sort -u "$out" -o "$out"
    sum="$(wc -l <"$out") subdomains found"
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
    sum="$(grep -c '/open' "$out") open ports"
    set_st nmap 0
  else
    set_st nmap 1; sum="scan failed"
  fi
  set_sum nmap "$sum"
}

# ---------------------------------------------------------------------------
# Module: Content discovery (ffuf / feroxbuster)
# ---------------------------------------------------------------------------
mod_fuzz() {
  local out="$RAW/ffuf.txt"; local sum="no fuzz"
  if (( SKIP_FUZZ )); then set_st fuzz 2; set_sum fuzz "skipped"; return; fi

  local url="http://${TARGET}"
  if have ffuf; then
    local wl="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
    [[ ! -f "$wl" ]] && wl="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    timeout "$TIMEOUT" ffuf -u "${url}/FUZZ" -w "$wl" -mc 200,204,301,302,307,401,403 -s >"$out" 2>/dev/null
  elif have feroxbuster; then
    timeout "$TIMEOUT" feroxbuster -u "$url" -q -o "$out" 2>/dev/null
  else
    set_st fuzz 2; set_sum fuzz "no ffuf/ferox"; return
  fi

  if [[ -s "$out" ]]; then
    sum="$(wc -l <"$out") paths discovered"
    set_st fuzz 0
  else
    set_st fuzz 1; sum="none found"
  fi
  set_sum fuzz "$sum"
}

# ---------------------------------------------------------------------------
# Live status JSON (for the GUI) + final JSON report
# ---------------------------------------------------------------------------
MODULES=(whois dns subs nmap fuzz)

write_status() {
  [[ -z "$STATUS_FILE" ]] && return
  local running="true"; (( RAIO_DONE )) && running="false"
  {
    echo "{"
    echo "  \"target\": \"$(json_esc "$TARGET")\","
    echo "  \"running\": $running,"
    echo "  \"loot\": \"$(json_esc "$LOOT")\","
    echo "  \"modules\": {"
    local i=0
    for k in "${MODULES[@]}"; do
      ((i++)); local sep=","; (( i == ${#MODULES[@]} )) && sep=""
      printf '    "%s": {"status": %s, "summary": "%s"}%s\n' "$k" "$(get_st "$k")" "$(json_esc "$(get_sum "$k")")" "$sep"
    done
    echo "  }"
    echo "}"
  } >"$STATUS_FILE"
}

emit_json() {
  local j="$LOOT/recon.json"
  local subs="" ports="" dns=""
  [[ -s "$RAW/subdomains.txt" ]] && subs="$(grep -v '^$' "$RAW/subdomains.txt" | sed 's/"/\\"/g' | awk '{printf "\"%s\",",$0}' | sed 's/,$//')"
  [[ -s "$RAW/nmap.txt" ]] && ports="$(grep -E '^[0-9]+/(tcp|udp)' "$RAW/nmap.txt" | awk '{printf "{\"port\":\"%s\",\"state\":\"%s\",\"svc\":\"%s\"},",$1,$2,$3}' | sed 's/,$//')"
  [[ -s "$RAW/dns.txt" ]] && dns="$(sed 's/"/\\"/g' "$RAW/dns.txt" | awk '{printf "\"%s\",",$0}' | sed 's/,$//')"
  {
    echo "{"
    echo "  \"target\": \"$(json_esc "$TARGET")\","
    echo "  \"timestamp\": \"$TS\","
    echo "  \"loot\": \"$(json_esc "$LOOT")\","
    echo "  \"modules\": {"
    local i=0
    for k in "${MODULES[@]}"; do
      ((i++)); local sep=","; (( i == ${#MODULES[@]} )) && sep=""
      printf '    "%s": {"status": %s, "summary": "%s"}%s\n' "$k" "$(get_st "$k")" "$(json_esc "$(get_sum "$k")")" "$sep"
    done
    echo "  },"
    echo "  \"findings\": {"
    echo "    \"subdomains\": [${subs}],"
    echo "    \"open_ports\": [${ports}],"
    echo "    \"dns\": [${dns}]"
    echo "  }"
    echo "}"
  } >"$j"
  echo "$j"
}

# ---------------------------------------------------------------------------
# Runner: launch all modules in parallel, poll for live status
# ---------------------------------------------------------------------------
run_module() {
  local name="$1" fn="$2"
  log "launching ${BD}$name${RST}"
  ( $fn ) &
}

banner "$TARGET"
hr
log "loot folder: ${W}${LOOT}${RST}"
hr

run_module whois mod_whois
run_module dns   mod_dns
run_module subs  mod_subs
run_module nmap  mod_nmap
run_module fuzz  mod_fuzz

# Poll until every module has written its status file (live JSON for GUI),
# then reap children.
while true; do
  done=0; for k in "${MODULES[@]}"; do [[ -f "$STATE_DIR/$k.st" ]] && ((done++)); done
  write_status
  (( done >= ${#MODULES[@]} )) && break
  sleep 1
done
wait
emit_json >/dev/null
RAIO_DONE=1
write_status

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
  head -15 "$RAW/ffuf.txt" | sed 's#^#    /#'
  hr
fi

# ---------------------------------------------------------------------------
# Generate markdown report + JSON report
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
  for k in "${MODULES[@]}"; do
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

JSON_FILE="$(emit_json)"
if (( DO_JSON )); then
  cat "$JSON_FILE"
fi

# ---------------------------------------------------------------------------
# Finish
# ---------------------------------------------------------------------------
echo "${G}${BD}✓ Recon complete.${RST}  Loot: ${W}${LOOT}${RST}"
echo "${D}  report: ${REPORT}${RST}"
hr

missing=()
have nmap   || missing+=(nmap)
have whois  || missing+=(whois)
have ffuf   || missing+=(ffuf)
(( ${#missing[@]} )) && \
  echo "${Y}tip: missing tools -> ${missing[*]}  install: sudo apt install ${missing[*]}${RST}"
