<div align="center">

![RAIO](https://img.shields.io/badge/RAIO-Recon%20All%20In%20One-00d9ff?style=for-the-badge&logo=shields&logoColor=white)
[![Version](https://img.shields.io/badge/version-1.0.0-00d9ff?style=for-the-badge)](https://github.com/dxn1-UBUNTU/raio/releases)

# RAIO

### *Recon All In One*
### *The only command you run after finding an IP.*

[![Stars](https://img.shields.io/github/stars/dxn1-UBUNTU/raio?style=for-the-badge&logo=github&color=yellow)](https://github.com/dxn1-UBUNTU/raio/stargazers)
[![Forks](https://img.shields.io/github/forks/dxn1-UBUNTU/raio?style=for-the-badge&logo=github&color=blue)](https://github.com/dxn1-UBUNTU/raio/network/members)
[![Issues](https://img.shields.io/github/issues/dxn1-UBUNTU/raio?style=for-the-badge&logo=github&color=red)](https://github.com/dxn1-UBUNTU/raio/issues)
[![License](https://img.shields.io/github/license/dxn1-UBUNTU/raio?style=for-the-badge&color=green)](https://github.com/dxn1-UBUNTU/raio/blob/main/LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/dxn1-UBUNTU/raio?style=for-the-badge&color=purple)](https://github.com/dxn1-UBUNTU/raio/commits/main)
[![Repo Size](https://img.shields.io/github/repo-size/dxn1-UBUNTU/raio?style=for-the-badge&color=orange)](https://github.com/dxn1-UBUNTU/raio)
[![Bash](https://img.shields.io/badge/made%20with-Bash-1f425f?style=for-the-badge&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20macOS-2ea44f?style=for-the-badge)](https://github.com/dxn1-UBUNTU/raio)
[![Passive](https://img.shields.io/badge/mode-Parallel%20%26%20Passive-9cf?style=for-the-badge)](https://github.com/dxn1-UBUNTU/raio)

</div>

---

A single Bash script that runs the full recon grind **in parallel**:

- `whois` / RDAP (with curl→wget fallback)
- `dig` DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Subdomain enumeration (subfinder / amass, with **crt.sh** passive fallback)
- `nmap` service/version scan
- Content discovery (`ffuf` / `feroxbuster`)

It renders a **gorgeous terminal dashboard** and dumps every artifact into a
timestamped **Loot Folder** plus a Markdown report.

## Usage

```bash
chmod +x raio.sh

# Interactive TUI (arrow keys + space to toggle modules, enter to run)
./raio.sh

# One-shot recon + terminal dashboard
./raio.sh example.com
./raio.sh 8.8.8.8 --skip-nmap
./raio.sh example.com --wordlist /path/to/wordlist.txt

# Web GUI (Flask) — opens http://localhost:8080
./raio.sh --gui
./raio.sh example.com --gui 9000

# The GUI has a live dashboard, a searchable Dependencies manager
# (install nmap/whois/dig/ffuf/... with one click), and will prompt
# to download a missing tool before running the module that needs it.

# Machine-readable output
./raio.sh example.com --json
```

### Options

| Flag | Meaning |
|------|---------|
| `--tui` | force the interactive terminal UI |
| `--gui [port]` | launch the Flask web GUI (auto-installs flask if missing) |
| `--json` | print a JSON report to stdout |
| `--status-file FILE` | write live JSON progress (used by the GUI) |
| `--skip-nmap` `--skip-whois` `--skip-dns` `--skip-subs` `--skip-fuzz` | disable a module |
| `-w, --wordlist FILE` | wordlist for content discovery |
| `-t, --timeout SEC` | per-module timeout (default 600) |
| `-h, --help` | show help |

## Install optional tools

```bash
sudo apt install nmap whois ffuf       # Debian/Ubuntu
# or: subfinder, amass, feroxbuster    # go install ...
```

Missing tools are auto-detected; the script degrades gracefully (module shows
`⏭` / `✘` in the dashboard and notes what to install).

## Output

```
loot/<target>/<timestamp>/
  raw/whois.txt
  raw/dns.txt
  raw/subdomains.txt
  raw/nmap.txt
  raw/ffuf.txt
  recon-report.md
```

Set `RECON_LOOT=/path` to relocate the loot root.

> For **authorized** security testing only.
