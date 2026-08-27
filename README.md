# recon.sh — One-Command Cybersecurity Recon Suite

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
chmod +x recon.sh
./recon.sh example.com
./recon.sh 8.8.8.8 --skip-nmap
./recon.sh example.com --wordlist /path/to/wordlist.txt
```

### Options

| Flag | Meaning |
|------|---------|
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
