# Legacy PhishGuard prototype: Gmail & Outlook connection

This directory is a separate historical rules/Claude prototype. The active capstone application uses `backend/app.py`, the saved V1 model and the root `phishguard-frontend.html`; follow the [main setup guide](../README.md) for that application. Its read-only Gmail demonstration and test evidence do not establish that this prototype's provider or Claude integration works with a live account.

Scans new inbox mail with rule checks plus Claude, moves suspicious messages into a **quarantine** label/folder, and lets you review, release, or confirm them. Nothing is deleted automatically.

## Setup
1. `pip install -r requirements.txt`, then copy `.env.example` to `.env` and fill it in (`set -a; . ./.env; set +a`).
2. **Gmail:** Google Cloud Console → enable *Gmail API* → OAuth consent screen (add yourself as a test user) → create an *OAuth client ID (Web)* with redirect URI `http://localhost:5000/callback/google`. Scope used: `gmail.modify` (a restricted scope: public release needs Google's verification and security assessment).
3. **Outlook:** Entra ID (Azure) → App registrations → new, "Accounts in any org directory and personal Microsoft accounts" → redirect URI (Web) `http://localhost:5000/callback/microsoft` → add a client secret → delegated permissions `Mail.ReadWrite`, `User.Read`, `offline_access`.
4. `python app.py`, open http://localhost:5000, click **Connect Gmail / Outlook**, then **Scan now** (or set `SCAN_INTERVAL`).

The example contains no usable credentials. Generate a random `SECRET_KEY` and a separate Fernet `TOKEN_KEY`, then keep both in the private `.env` file. For example:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

These setup steps belong to this prototype and can change real mailbox labels/folders when it is connected. They are not needed for the active application's read-only Gmail scan.

## How it works
- OAuth 2.0 authorization-code flow with a `state` check; refresh tokens are encrypted at rest (Fernet) and access tokens are never stored.
- Both providers are fetched as raw RFC 822, so one analyzer handles both.
- Gmail quarantine = add label `PhishGuard/Quarantine`, remove `INBOX`. Outlook = move to folder `PhishGuard Quarantine` (the message id changes on move; the app tracks this).
- Email content is sent to Claude as untrusted data; the score is 40% rules, 60% AI (rules only if the API call fails).

## Security notes
- Runs on `127.0.0.1` with CSRF tokens and no login of its own. Put real authentication in front of it before hosting it anywhere.
- Mail content is sent to the Anthropic API for analysis. Tell users and get their consent.
- **Disconnect** erases local data; also revoke access at myaccount.google.com/permissions or account.live.com/consent/Manage.
- Failed provider/scanner operations log the exception type without copying private exception text into logs.

## Offline regression checks

From the repository root, in a development environment with pytest and this prototype's dependencies installed:

```bash
python -m pytest -q PhishGuard/tests
```

The tests block network access, disable dotenv loading, use synthetic session keys and a temporary SQLite database, and replace provider/Claude calls. They check CSRF rejection, malformed-link handling and exception-log privacy. Passing these tests does not verify real Gmail, Outlook or Claude access.
