#!/usr/bin/env python3
"""RAIO GUI — Flask web front-end for raio.sh.

Launched by `raio.sh --gui`. Features:
  * Target + module selector
  * Live dashboard (modules flip ✔/✘/⏭ as they finish)
  * Dependencies manager: searchable list of recon tools, one-click install
  * Missing-dependency gating: running a module without its tool prompts to
    download it first, then runs.
"""
import argparse
import json
import os
import shutil
import subprocess
import threading
import uuid
from flask import (
    Flask, request, render_template_string, send_from_directory, jsonify,
)

app = Flask(__name__)
TASKS = {}
INSTALLS = {}
SCRIPT = ""

# tool name -> apt package + the raio module it backs
TOOLS = {
    "nmap":        {"pkg": "nmap",        "mod": "nmap", "desc": "port & service scanner"},
    "whois":       {"pkg": "whois",       "mod": "whois", "desc": "whois / RDAP lookup"},
    "dig":         {"pkg": "dnsutils",    "mod": "dns", "desc": "DNS enumeration (dig)"},
    "subfinder":   {"pkg": "subfinder",   "mod": "subs", "desc": "subdomain discovery"},
    "amass":       {"pkg": "amass",       "mod": "subs", "desc": "subdomain discovery (passive)"},
    "ffuf":        {"pkg": "ffuf",        "mod": "fuzz", "desc": "web content discovery"},
    "feroxbuster": {"pkg": "feroxbuster", "mod": "fuzz", "desc": "web content discovery"},
}

# module -> list of tool binaries that satisfy it
MOD_TOOLS = {
    "whois": ["whois"],
    "dns": ["dig"],
    "subs": ["subfinder", "amass"],
    "nmap": ["nmap"],
    "fuzz": ["ffuf", "feroxbuster"],
}


def tool_installed(name):
    return shutil.which(name) is not None


INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RAIO · Recon All In One</title>
<style>
  :root{--bg:#0b0f14;--panel:#121821;--line:#1f2a36;--cyan:#00d9ff;--green:#39ff8b;
        --red:#ff5c5c;--yellow:#ffd166;--txt:#cdd9e5;--dim:#6b7c8f;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 'Segoe UI',system-ui,sans-serif}
  header{background:linear-gradient(90deg,#0b0f14,#0f1b24);border-bottom:1px solid var(--line);
         padding:16px 26px;display:flex;align-items:center;gap:14px}
  header h1{margin:0;font-size:22px;letter-spacing:2px;color:var(--cyan)}
  header span{color:var(--dim);font-size:13px}
  .wrap{max-width:1040px;margin:0 auto;padding:22px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:20px}
  label{display:block;margin:10px 0 4px;color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:1px}
  input[type=text]{width:100%;padding:10px 12px;background:#0a0e13;border:1px solid var(--line);
        border-radius:6px;color:var(--txt);font-size:15px}
  .mods{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}
  .mod{display:flex;align-items:center;gap:6px;background:#0a0e13;border:1px solid var(--line);
       padding:8px 12px;border-radius:20px;cursor:pointer;user-select:none}
  .mod input{accent-color:var(--cyan)}
  .row{display:flex;gap:12px;align-items:center}
  button{background:var(--cyan);color:#04121a;border:0;border-radius:6px;
          padding:11px 20px;font-size:14px;font-weight:700;cursor:pointer;letter-spacing:1px}
  button:hover{filter:brightness(1.1)}
  button.ghost{background:transparent;color:var(--cyan);border:1px solid var(--cyan)}
  button:disabled{opacity:.45;cursor:not-allowed}
  h2{color:var(--cyan);font-size:15px;letter-spacing:1px;margin:0 0 12px}
  .dep{display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:center;
       padding:10px 0;border-bottom:1px solid var(--line)}
  .dep .name{font-weight:700}
  .dep .desc{color:var(--dim);font-size:12px}
  .badge{padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700}
  .ok{background:rgba(57,255,139,.15);color:var(--green)}
  .no{background:rgba(255,92,92,.15);color:var(--red)}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid var(--line);
        border-top-color:var(--cyan);border-radius:50%;animation:sp 1s linear infinite;vertical-align:-2px}
  @keyframes sp{to{transform:rotate(360deg)}}
  #result{display:none}
  .module{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}
  pre{background:#070b0f;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;max-height:320px}
  a{color:var(--cyan)}
  .modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;z-index:50}
  .modal{background:var(--panel);border:1px solid var(--cyan);border-radius:12px;padding:26px;max-width:460px}
  .modal h3{margin:0 0 10px;color:var(--yellow)}
  .modal p{color:var(--dim)}
  .modal .acts{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}
  #toast{position:fixed;bottom:18px;right:18px;background:var(--panel);border:1px solid var(--cyan);
         padding:10px 16px;border-radius:8px;display:none;z-index:60}
</style>
</head>
<body>
<header><h1>RAIO</h1><span>Recon All In One · the only command you run after finding an IP</span></header>
<div class="wrap">

  <div class="card" id="form">
    <form id="reconForm">
      <label>Target (domain or IP)</label>
      <input type="text" id="target" name="target" placeholder="example.com" required>
      <label>Modules</label>
      <div class="mods">
        {% for m in ["whois","dns","subs","nmap","fuzz"] %}
        <label class="mod"><input type="checkbox" name="modules" value="{{m}}" checked> {{m.upper()}}</label>
        {% endfor %}
      </div>
      <label>Wordlist (optional)</label>
      <input type="text" name="wordlist" placeholder="/usr/share/wordlists/dirb/common.txt">
      <label>Timeout seconds</label>
      <input type="text" name="timeout" value="600">
      <div class="row" style="margin-top:18px">
        <button type="submit">▶ RUN RECON</button>
        <button type="button" class="ghost" onclick="refreshDeps()">↻ Refresh tools</button>
      </div>
    </form>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between">
      <h2>Dependencies</h2>
      <input type="text" id="depSearch" placeholder="search tools…" style="width:240px" oninput="renderDeps()">
    </div>
    <div id="deps"></div>
  </div>

  <div class="card" id="result">
    <div id="statusLine"><span class="spin"></span> <span id="statusText">running…</span></div>
    <div id="modules"></div>
    <div id="findings"></div>
  </div>
</div>

<div class="modal-bg" id="modalBg">
  <div class="modal">
    <h3 id="modalTitle">Missing tools</h3>
    <p id="modalBody"></p>
    <div class="acts">
      <button class="ghost" onclick="closeModal();doRun()">Run anyway</button>
      <button onclick="installAndRun()">⬇ Install &amp; Run</button>
    </div>
  </div>
</div>
<div class="modal-bg" id="pwModalBg">
  <div class="modal">
    <h3>Sudo password</h3>
    <p>Enter your sudo password to install tools (sent to localhost only).</p>
    <input type="password" id="sudoPw" style="width:100%;padding:10px;background:#0a0e13;border:1px solid var(--line);border-radius:6px;color:var(--txt)">
    <div class="acts">
      <button class="ghost" onclick="closePw()">Cancel</button>
      <button onclick="confirmPw()">OK</button>
    </div>
  </div>
</div>
<div id="toast"></div>

<script>
const $=s=>document.querySelector(s);
let PENDING_MODULES=[];

function toast(msg){const t=$('#toast');t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',3500);}

let _sudoPW="";
let _pwCb=null;
function askPassword(cb){_pwCb=cb;$('#sudoPw').value='';$('#pwModalBg').style.display='flex';}
function closePw(){$('#pwModalBg').style.display='none';const c=_pwCb;_pwCb=null;if(c)c(null);}
function confirmPw(){_sudoPW=$('#sudoPw').value;$('#pwModalBg').style.display='none';const c=_pwCb;_pwCb=null;if(c)c(_sudoPW);}

async function refreshDeps(){
  const d=await (await fetch('/api/deps')).json();
  window._deps=d; renderDeps();
}
function renderDeps(){
  const q=($('#depSearch').value||'').toLowerCase();
  const d=window._deps||[];
  const html=d.filter(t=>t.name.includes(q)||t.desc.toLowerCase().includes(q)).map(t=>{
    const cls=t.installed?'ok':'no';
    const txt=t.installed?'installed':'missing';
    const btn=t.installed?'':`<button onclick="installTool('${t.name}')">Install</button>`;
    return `<div class="dep"><div><div class="name">${t.name} <span style="color:var(--dim);font-weight:400">(${t.pkg})</span></div>
            <div class="desc">${t.desc} · module: ${t.mod}</div></div>
            <div><span class="badge ${cls}">${txt}</span></div><div>${btn}</div></div>`;
  }).join('');
  $('#deps').innerHTML=html||'<p style="color:var(--dim)">no tools match.</p>';
}
async function installTool(name){
  const go=async (pw)=>{
    const r=await fetch('/install',{method:'POST',body:new URLSearchParams({tool:name,password:pw||''})});
    const j=await r.json(); if(j.error){toast(j.error);return;}
    toast('installing '+name+'…');
    while(true){
      const s=await (await fetch('/install/'+j.id)).json();
      if(!s.running){ toast(s.exit===0?name+' installed ✔':'install failed (bad password?)'); break; }
      await new Promise(r=>setTimeout(r,1500));
    }
    refreshDeps();
  };
  if(_sudoPW) return go(_sudoPW);
  askPassword(pw=>{ if(pw===null) return; go(pw); });
}

$('#reconForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const fd=new FormData(e.target);
  PENDING_MODULES=fd.getAll('modules');
  const d=await (await fetch('/api/deps')).json();
  const installed=new Set(d.filter(t=>t.installed).map(t=>t.name));
  const missing=[];
  for(const m of PENDING_MODULES){
    const tools={'whois':['whois'],'dns':['dig'],'subs':['subfinder','amass'],
                 'nmap':['nmap'],'fuzz':['ffuf','feroxbuster']}[m];
    if(!tools.some(t=>installed.has(t))) missing.push(m);
  }
  if(missing.length){
    $('#modalBody').innerHTML='These modules need tools you don\'t have: <b>'+
      missing.map(m=>m.toUpperCase()).join(', ')+'</b>.<br>Download them now?';
    $('#modalBg').style.display='flex';
  } else { doRun(); }
});
function closeModal(){$('#modalBg').style.display='none';}

async function installAndRun(){
  closeModal();
  const doIt=async ()=>{
    const d=await (await fetch('/api/deps')).json();
    const installed=new Set(d.filter(t=>t.installed).map(t=>t.name));
    const needed=[];
    for(const m of PENDING_MODULES){
      const tools={'whois':['whois'],'dns':['dig'],'subs':['subfinder','amass'],
                   'nmap':['nmap'],'fuzz':['ffuf','feroxbuster']}[m];
      tools.forEach(t=>{ if(!installed.has(t)) needed.push(t); });
    }
    for(const t of [...new Set(needed)]){
      const r=await fetch('/install',{method:'POST',body:new URLSearchParams({tool:t,password:_sudoPW})});
      const j=await r.json(); if(j.error)continue;
      while(true){const s=await (await fetch('/install/'+j.id)).json(); if(!s.running)break; await new Promise(r=>setTimeout(r,1500));}
    }
    toast('tools ready — launching recon');
    doRun();
  };
  if(_sudoPW) return doIt();
  askPassword(pw=>{ if(pw===null) return; doIt(); });
}

async function doRun(){
  const fd=new FormData($('#reconForm'));
  const r=await fetch('/run',{method:'POST',body:fd});
  const j=await r.json();
  $('#form').style.display='none'; document.querySelectorAll('.card')[1].style.display='none';
  $('#result').style.display='block';
  poll(j.task);
}
async function poll(task){
  const st=await (await fetch('/api/'+task)).json();
  render(st);
  if(st.running) setTimeout(()=>poll(task),1500);
}
function render(st){
  $('#statusText').textContent=st.running?'running…':'complete';
  let h='';
  for(const [k,v] of Object.entries(st.modules||{})){
    const cls=v.status==0?'ok':v.status==1?'fail':'skip';
    const ico=v.status==0?'✔':v.status==1?'✘':'⏭';
    h+=`<div class="module"><span class="badge ${cls}">${ico} ${k}</span>
        <span style="color:var(--dim)">${v.summary||''}</span></div>`;
  }
  $('#modules').innerHTML='<h2>Modules</h2>'+h;
  let f=''; const loot=st.loot;
  if(st.findings){
    if(st.findings.subdomains&&st.findings.subdomains.length)
      f+='<h2>Subdomains ('+st.findings.subdomains.length+')</h2><pre>'+st.findings.subdomains.join('\n')+'</pre>';
    if(st.findings.open_ports&&st.findings.open_ports.length)
      f+='<h2>Open ports</h2><pre>'+st.findings.open_ports.map(p=>p.port+' '+p.state+' '+p.svc).join('\n')+'</pre>';
    if(st.findings.dns&&st.findings.dns.length)
      f+='<h2>DNS</h2><pre>'+st.findings.dns.join('\n')+'</pre>';
  }
  if(loot)
    f+='<h2>Loot</h2><pre>'+loot+'\nreport: <a href="/loot?root='+encodeURIComponent(loot)+'&path=recon-report.md" target="_blank">recon-report.md</a>\njson:   <a href="/loot?root='+encodeURIComponent(loot)+'&path=recon.json" target="_blank">recon.json</a></pre>';
  $('#findings').innerHTML=f;
}
refreshDeps();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/deps")
def deps():
    out = []
    for name, spec in TOOLS.items():
        out.append({
            "name": name, "pkg": spec["pkg"], "mod": spec["mod"],
            "desc": spec["desc"], "installed": tool_installed(name),
        })
    return jsonify(out)


@app.route("/install", methods=["POST"])
def install():
    tool = request.form.get("tool")
    spec = TOOLS.get(tool)
    if not spec:
        return jsonify({"error": "unknown tool"}), 400
    pw = request.form.get("password", "") or os.environ.get("RAIO_SUDO_PASS", "")
    iid = uuid.uuid4().hex
    logf = "/tmp/raio_install_%s.log" % iid
    INSTALLS[iid] = {"running": True, "log": logf, "code": None}

    if pw:
        # password supplied by the web UI -> feed sudo via stdin
        cmd = ["sudo", "-S", "apt-get", "install", "-y", spec["pkg"]]

        def worker():
            try:
                with open(logf, "w") as f:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                         stdout=f, stderr=subprocess.STDOUT)
                    p.communicate((pw + "\n").encode())
                    INSTALLS[iid]["code"] = p.returncode
            except Exception as e:
                open(logf, "a").write(str(e))
            INSTALLS[iid]["running"] = False
    else:
        # no password: try a graphical/agent prompt
        runner = "pkexec" if shutil.which("pkexec") else "sudo"
        cmd = [runner, "apt-get", "install", "-y", spec["pkg"]]
        if not shutil.which(runner):
            cmd = ["apt-get", "install", "-y", spec["pkg"]]

        def worker():
            try:
                with open(logf, "w") as f:
                    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
                    INSTALLS[iid]["code"] = p.wait()
            except Exception as e:
                open(logf, "a").write(str(e))
            INSTALLS[iid]["running"] = False

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"id": iid})


@app.route("/install/<iid>")
def install_status(iid):
    d = INSTALLS.get(iid)
    if not d:
        return jsonify({"error": "unknown"}), 404
    try:
        log = open(d["log"]).read()[-3000:]
    except Exception:
        log = ""
    return jsonify({"running": d["running"], "log": log, "exit": d.get("code")})


@app.route("/run", methods=["POST"])
def run():
    target = (request.form.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    mods = request.form.getlist("modules")
    args = [SCRIPT, target]
    for m in ["whois", "dns", "subs", "nmap", "fuzz"]:
        if m not in mods:
            args.append("--skip-" + m)
    if request.form.get("wordlist"):
        args += ["-w", request.form["wordlist"]]
    if request.form.get("timeout"):
        args += ["-t", request.form["timeout"]]
    status_file = "/tmp/raio_gui_%s.json" % uuid.uuid4().hex
    args += ["--status-file", status_file, "--json"]
    tid = uuid.uuid4().hex
    TASKS[tid] = {"status_file": status_file, "loot": None}

    def worker():
        subprocess.run(args)
        try:
            st = json.load(open(status_file))
            TASKS[tid]["loot"] = st.get("loot")
        except Exception:
            pass

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"task": tid})


@app.route("/api/<tid>")
def api(tid):
    t = TASKS.get(tid)
    if not t:
        return jsonify({"error": "unknown task"}), 404
    try:
        st = json.load(open(t["status_file"]))
    except Exception:
        st = {"running": True, "modules": {}, "findings": {}}
    st["loot"] = t["loot"] or st.get("loot")
    if not st.get("running") and st.get("loot"):
        try:
            full = json.load(open(os.path.join(st["loot"], "recon.json")))
            st["findings"] = full.get("findings", {})
        except Exception:
            pass
    return jsonify(st)


@app.route("/loot")
def loot():
    root = request.args.get("root", "")
    path = request.args.get("path", "")
    if not root or not path or ".." in path:
        return "nope", 400
    return send_from_directory(root, path)


def main():
    global SCRIPT
    p = argparse.ArgumentParser()
    p.add_argument("--port", default=8080, type=int)
    p.add_argument("--script", required=True)
    p.add_argument("--sudo-pass", default="", help="sudo password (falls back to RAIO_SUDO_PASS env)")
    a = p.parse_args()
    SCRIPT = a.script
    if a.sudo_pass:
        os.environ["RAIO_SUDO_PASS"] = a.sudo_pass
    app.run(host="0.0.0.0", port=a.port, debug=False)


if __name__ == "__main__":
    main()
