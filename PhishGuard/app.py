"""PhishGuard server: connect Gmail/Outlook, scan new mail, quarantine suspicious messages for review."""
import json, os, secrets, sqlite3, threading, time
from dotenv import load_dotenv
load_dotenv()

from cryptography.fernet import Fernet
from flask import Flask, abort, redirect, render_template_string, request, session, url_for, jsonify
import providers as P
from scanner import analyze

app = Flask(__name__); app.secret_key = os.environ["SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
fer = Fernet(os.environ["TOKEN_KEY"]); THR = int(os.getenv("THRESHOLD", 50)); DB = "phishguard.db"
lock = threading.Lock()

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
with db() as c:
    c.executescript("""CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, provider TEXT, email TEXT, rt BLOB, UNIQUE(provider,email));
    CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, account INTEGER, pid TEXT, sender TEXT, subject TEXT, score INT, status TEXT, result TEXT, UNIQUE(account,pid));""")

def access_for(a):
    t = P.refresh(a["provider"], fer.decrypt(a["rt"]).decode())
    if t.get("refresh_token"):  # providers may rotate refresh tokens
        with db() as c: c.execute("UPDATE accounts SET rt=? WHERE id=?", (fer.encrypt(t["refresh_token"].encode()), a["id"]))
    return t["access_token"]

def scan_account(aid):
    with lock, db() as c:
        a = c.execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
        if not a: return
        box = P.mailbox(a["provider"], access_for(a))
        for pid in box.list_new():
            if c.execute("SELECT 1 FROM msgs WHERE account=? AND pid=?", (aid, pid)).fetchone(): continue
            r = analyze(box.raw(pid)); status = "clean"
            if r["score"] >= THR: pid, status = box.quarantine(pid), "quarantined"
            c.execute("INSERT OR IGNORE INTO msgs(account,pid,sender,subject,score,status,result) VALUES(?,?,?,?,?,?,?)",
                      (aid, pid, r["from"], r["subject"], r["score"], status, json.dumps(r)))

def loop(n):
    while True:
        time.sleep(n)
        with db() as c: ids = [r["id"] for r in c.execute("SELECT id FROM accounts")]
        for i in ids:
            try: scan_account(i)
            except Exception as e: app.logger.warning("scan failed: %s", e)

def csrf():
    session.setdefault("csrf", secrets.token_urlsafe(16)); return session["csrf"]
def check():
    if request.form.get("csrf") != session.get("csrf"): abort(400)

PAGE = """<!doctype html><title>PhishGuard</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font:15px system-ui;max-width:960px;margin:20px auto;padding:0 14px;color:#1b1f27}table{width:100%;border-collapse:collapse}
td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}.q{background:#fdecec}button,a.b{padding:6px 10px;border:1px solid #aaa;border-radius:8px;background:#fff;text-decoration:none;color:inherit;font:inherit}
details{margin-top:4px}.s{color:#667085;font-size:13px}form{display:inline}</style>
<h1>🛡️ PhishGuard</h1>
<p>{% if not accts %}No mailbox connected.{% endif %}
{% for a in accts %}<b>{{a.email}}</b> <span class=s>({{a.provider}})</span>
<form method=post action="{{url_for('scan',aid=a.id)}}"><input type=hidden name=csrf value="{{t}}"><button>Scan now</button></form>
<form method=post action="{{url_for('disconnect',aid=a.id)}}" onsubmit="return confirm('Disconnect and erase stored data for this mailbox?')"><input type=hidden name=csrf value="{{t}}"><button>Disconnect</button></form><br>{% endfor %}</p>
<p><a class=b href="{{url_for('connect',p='google')}}">Connect Gmail</a> <a class=b href="{{url_for('connect',p='microsoft')}}">Connect Outlook</a></p>
<h2>Quarantine ({{q|length}})</h2>
<table>{% for m in q %}<tr class=q><td>{{m.score}}</td><td><b>{{m.subject}}</b><div class=s>{{m.sender}}</div>
<details><summary>Why it was flagged</summary>{% for f in m.r.flags %}<div>• {{f.t}}</div>{% endfor %}
{% if m.r.ai %}<div><b>AI: {{m.r.ai.verdict}}</b> {{m.r.ai.reasons|join('; ')}}</div>{% endif %}
{% for u in m.r.links %}<div class=s>{{u|replace('http','hxxp',1)|replace('.','[.]')}}</div>{% endfor %}</details></td>
<td>{% for act,lbl in [('release','Not phishing: release'),('confirm','Confirm phishing')] %}<form method=post action="{{url_for('act',mid=m.id,action=act)}}"><input type=hidden name=csrf value="{{t}}"><button>{{lbl}}</button></form> {% endfor %}</td></tr>
{% else %}<tr><td>Nothing in quarantine.</td></tr>{% endfor %}</table>
<h2>Recently scanned</h2><table>{% for m in rest %}<tr><td>{{m.score}}</td><td>{{m.subject}}<div class=s>{{m.sender}}</div></td><td class=s>{{m.status}}</td></tr>{% endfor %}</table>"""

@app.get("/")
def home():
    with db() as c:
        accts = c.execute("SELECT id,provider,email FROM accounts").fetchall()
        rows = [dict(r, r=json.loads(r["result"])) for r in c.execute("SELECT * FROM msgs ORDER BY id DESC LIMIT 200")]
    return render_template_string(PAGE, accts=accts, t=csrf(), q=[r for r in rows if r["status"] == "quarantined"],
                                  rest=[r for r in rows if r["status"] != "quarantined"][:50])

@app.get("/connect/<p>")
def connect(p):
    if p not in P.CFG: abort(404)
    session["state"] = secrets.token_urlsafe(24); session["prov"] = p
    return redirect(P.auth_url(p, session["state"]))

@app.get("/callback/<p>")
def callback(p):
    if p not in P.CFG or request.args.get("state") != session.pop("state", None) or session.pop("prov", None) != p: abort(400)
    if "code" not in request.args: return "Authorization was cancelled.", 400
    t = P.exchange(p, request.args["code"])
    if not t.get("refresh_token"): return "No refresh token returned; remove the app from your account permissions and retry.", 400
    email = P.whoami(p, t["access_token"])
    with db() as c:
        c.execute("INSERT INTO accounts(provider,email,rt) VALUES(?,?,?) ON CONFLICT(provider,email) DO UPDATE SET rt=excluded.rt",
                  (p, email, fer.encrypt(t["refresh_token"].encode())))
    return redirect(url_for("home"))

@app.post("/scan/<int:aid>")
def scan(aid):
    check(); scan_account(aid); return redirect(url_for("home"))

@app.post("/msg/<int:mid>/<action>")
def act(mid, action):
    check()
    with db() as c:
        m = c.execute("SELECT * FROM msgs WHERE id=?", (mid,)).fetchone(); a = c.execute("SELECT * FROM accounts WHERE id=?", (m["account"],)).fetchone() if m else None
        if not m or action not in ("release", "confirm"): abort(404)
        if action == "release":
            new = P.mailbox(a["provider"], access_for(a)).release(m["pid"])
            c.execute("UPDATE msgs SET status='released', pid=? WHERE id=?", (new, mid))
        else:  # stays in the quarantine folder; nothing is permanently deleted automatically
            c.execute("UPDATE msgs SET status='confirmed_phishing' WHERE id=?", (mid,))
    return redirect(url_for("home"))

@app.post("/disconnect/<int:aid>")
def disconnect(aid):
    check()
    with db() as c: c.execute("DELETE FROM msgs WHERE account=?", (aid,)); c.execute("DELETE FROM accounts WHERE id=?", (aid,))
    return redirect(url_for("home"))

@app.post("/api/analyse")
def analyse_email():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    raw_email = data.get("email")

    if not isinstance(raw_email, str) or not raw_email.strip():
        return jsonify({"error": "Email content is required"}), 400

    if len(raw_email.encode("utf-8")) > 100_000:
        return jsonify({"error": "Email is too large"}), 413

    result = analyze(raw_email.encode("utf-8"))

    return jsonify(result), 200

if __name__ == "__main__":
    if int(os.getenv("SCAN_INTERVAL", 0)) > 0: threading.Thread(target=loop, args=(int(os.environ["SCAN_INTERVAL"]),), daemon=True).start()
    app.run(host="127.0.0.1", port=5000)
