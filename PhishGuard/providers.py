"""OAuth 2.0 + mailbox adapters for Gmail and Outlook (Microsoft Graph)."""
import base64, os, requests
from urllib.parse import urlencode

CFG = {
    "google": dict(auth="https://accounts.google.com/o/oauth2/v2/auth", token="https://oauth2.googleapis.com/token",
                   scope="openid email https://www.googleapis.com/auth/gmail.modify",
                   id="GOOGLE_CLIENT_ID", secret="GOOGLE_CLIENT_SECRET", extra=dict(access_type="offline", prompt="consent")),
    "microsoft": dict(auth="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                      token="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                      scope="openid email offline_access User.Read Mail.ReadWrite",
                      id="MS_CLIENT_ID", secret="MS_CLIENT_SECRET", extra=dict(response_mode="query")),
}
redirect = lambda p: os.environ.get("BASE_URL", "http://localhost:5000") + "/callback/" + p

def auth_url(p, state):
    c = CFG[p]
    return c["auth"] + "?" + urlencode(dict(client_id=os.environ[c["id"]], redirect_uri=redirect(p), response_type="code",
                                            scope=c["scope"], state=state, **c["extra"]))

def _token(p, data):
    c = CFG[p]
    r = requests.post(c["token"], data=dict(client_id=os.environ[c["id"]], client_secret=os.environ[c["secret"]], **data), timeout=20)
    r.raise_for_status(); return r.json()

def exchange(p, code): return _token(p, dict(grant_type="authorization_code", code=code, redirect_uri=redirect(p)))
def refresh(p, rt): return _token(p, dict(grant_type="refresh_token", refresh_token=rt, scope=CFG[p]["scope"]))

def whoami(p, access):
    h = {"Authorization": "Bearer " + access}
    if p == "google":
        return requests.get("https://openidconnect.googleapis.com/v1/userinfo", headers=h, timeout=20).json()["email"]
    j = requests.get("https://graph.microsoft.com/v1.0/me", headers=h, timeout=20).json()
    return j.get("mail") or j["userPrincipalName"]

class Base:
    def __init__(s, access): s.h = {"Authorization": "Bearer " + access}
    def call(s, method, url, **kw):
        r = requests.request(method, url, headers=s.h, timeout=30, **kw); r.raise_for_status(); return r

class Gmail(Base):
    B = "https://gmail.googleapis.com/gmail/v1/users/me"
    def list_new(s, n=25):
        return [m["id"] for m in s.call("GET", s.B + "/messages", params=dict(labelIds="INBOX", maxResults=n)).json().get("messages", [])]
    def raw(s, i):
        return base64.urlsafe_b64decode(s.call("GET", f"{s.B}/messages/{i}", params=dict(format="raw")).json()["raw"] + "==")
    def _label(s):
        for l in s.call("GET", s.B + "/labels").json()["labels"]:
            if l["name"] == "PhishGuard/Quarantine": return l["id"]
        return s.call("POST", s.B + "/labels", json=dict(name="PhishGuard/Quarantine")).json()["id"]
    def _mod(s, i, add, rem):
        s.call("POST", f"{s.B}/messages/{i}/modify", json=dict(addLabelIds=add, removeLabelIds=rem)); return i
    def quarantine(s, i): return s._mod(i, [s._label()], ["INBOX"])
    def release(s, i): return s._mod(i, ["INBOX"], [s._label()])

class Outlook(Base):
    B = "https://graph.microsoft.com/v1.0/me"
    def list_new(s, n=25):
        return [m["id"] for m in s.call("GET", s.B + "/mailFolders/inbox/messages",
                params={"$top": n, "$select": "id", "$orderby": "receivedDateTime desc"}).json()["value"]]
    def raw(s, i): return s.call("GET", f"{s.B}/messages/{i}/$value").content
    def _folder(s):
        v = s.call("GET", s.B + "/mailFolders", params={"$filter": "displayName eq 'PhishGuard Quarantine'"}).json()["value"]
        return v[0]["id"] if v else s.call("POST", s.B + "/mailFolders", json=dict(displayName="PhishGuard Quarantine")).json()["id"]
    def _move(s, i, dest): return s.call("POST", f"{s.B}/messages/{i}/move", json=dict(destinationId=dest)).json()["id"]  # id changes on move
    def quarantine(s, i): return s._move(i, s._folder())
    def release(s, i): return s._move(i, "inbox")

def mailbox(p, access): return (Gmail if p == "google" else Outlook)(access)
