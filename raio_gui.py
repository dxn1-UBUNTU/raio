#!/usr/bin/env python3
"""RAIO GUI — Flask web front-end for raio.sh.

Launched by `raio.sh --gui`. Runs recon in the background and polls the
JSON status file raio.sh writes, then renders a dashboard with the loot.
"""
import argparse
import json
import os
import subprocess
import threading
import uuid
from flask import (
    Flask, request, render_template_string, send_from_directory, jsonify,
)

app = Flask(__name__)
TASKS = {}
SCRIPT = ""

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
         padding:18px 26px;display:flex;align-items:center;gap:14px}
  header h1{margin:0;font-size:22px;letter-spacing:2px;color:var(--cyan)}
  header span{color:var(--dim);font-size:13px}
  .wrap{max-width:1000px;margin:0 auto;padding:24px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:20px}
  label{display:block;margin:10px 0 4px;color:var(--dim);font-size:13px;text-transform:uppercase;letter-spacing:1px}
  input[type=text]{width:100%;padding:10px 12px;background:#0a0e13;border:1px solid var(--line);
        border-radius:6px;color:var(--txt);font-size:15px}
  .mods{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}
  .mod{display:flex;align-items:center;gap:6px;background:#0a0e13;border:1px solid var(--line);
       padding:8px 12px;border-radius:20px;cursor:pointer;user-select:none}
  .mod input{accent-color:var(--cyan)}
  button{margin-top:18px;background:var(--cyan);color:#04121a;border:0;border-radius:6px;
          padding:12px 22px;font-size:15px;font-weight:700;cursor:pointer;letter-spacing:1px}
  button:hover{filter:brightness(1.1)}
  #result{display:none}
  .module{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}
  .badge{padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700}
  .ok{background:rgba(57,255,139,.15);color:var(--green)}
  .fail{background:rgba(255,92,92,.15);color:var(--red)}
  .skip{background:rgba(255,209,102,.15);color:var(--yellow)}
  .dot{width:9px;height:9px;border-radius:50%}
  pre{background:#070b0f;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;max-height:340px}
  a{color:var(--cyan)}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);
        border-top-color:var(--cyan);border-radius:50%;animation:sp 1s linear infinite;vertical-align:-2px}
  @keyframes sp{to{transform:rotate(360deg)}}
  h2{color:var(--cyan);font-size:16px;letter-spacing:1px;margin:18px 0 8px}
</style>
</head>
<body>
<header><h1>RAIO</h1><span>Recon All In One · the only command you run after finding an IP</span></header>
<div class="wrap">
  <div class="card" id="form">
    <form id="reconForm">
      <label>Target (domain or IP)</label>
      <input type="text" name="target" placeholder="example.com" required>
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
      <button type="submit">▶ RUN RECON</button>
    </form>
  </div>

  <div class="card" id="result">
    <div id="statusLine"><span class="spin"></span> <span id="statusText">running…</span></div>
    <div id="modules"></div>
    <div id="findings"></div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
$('#reconForm').addEventListener('submit', async e=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/run',{method:'POST',body:fd});
  const j = await r.json();
  $('#form').style.display='none';
  $('#result').style.display='block';
  poll(j.task);
});

async function poll(task){
  const st = await (await fetch('/api/'+task)).json();
  render(st);
  if(st.running){ setTimeout(()=>poll(task),1500); }
}
function render(st){
  $('#statusText').textContent = st.running ? 'running…' : 'complete';
  let h='';
  for(const [k,v] of Object.entries(st.modules||{})){
    const cls = v.status==0?'ok':v.status==1?'fail':'skip';
    const ico = v.status==0?'✔':v.status==1?'✘':'⏭';
    h+=`<div class="module"><span class="badge ${cls}">${ico} ${k}</span>
        <span style="color:var(--dim)">${v.summary||''}</span></div>`;
  }
  $('#modules').innerHTML='<h2>Modules</h2>'+h;
  let f='';
  const loot = st.loot;
  if(st.findings){
    if(st.findings.subdomains && st.findings.subdomains.length){
      f+='<h2>Subdomains ('+st.findings.subdomains.length+')</h2><pre>'+st.findings.subdomains.join('\n')+'</pre>';
    }
    if(st.findings.open_ports && st.findings.open_ports.length){
      f+='<h2>Open ports</h2><pre>'+st.findings.open_ports.map(p=>p.port+' '+p.state+' '+p.svc).join('\n')+'</pre>';
    }
    if(st.findings.dns && st.findings.dns.length){
      f+='<h2>DNS</h2><pre>'+st.findings.dns.join('\n')+'</pre>';
    }
  }
  if(loot){
    f+='<h2>Loot</h2><pre>'+loot+'\nreport: <a href="/loot?root='+encodeURIComponent(loot)+'&path=recon-report.md" target="_blank">recon-report.md</a>\njson:   <a href="/loot?root='+encodeURIComponent(loot)+'&path=recon.json" target="_blank">recon.json</a></pre>';
  }
  $('#findings').innerHTML=f;
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/run", methods=["POST"])
def run():
    target = request.form.get("target", "").strip()
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
    # attach findings from the final recon.json once finished
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
    a = p.parse_args()
    SCRIPT = a.script
    app.run(host="0.0.0.0", port=a.port, debug=False)

if __name__ == "__main__":
    main()
