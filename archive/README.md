# Earlier interface prototype

`PhishGuard_UI_Prototype.html` preserves the original standalone, heuristic browser demonstration. It is not the dashboard served by `backend/app.py` and does not run the saved V1 classifier. Open `http://127.0.0.1:5000/gmail/app` for the current final project.

The separate `PhishGuard/` Python prototype also uses a different architecture: mailbox modification and an optional external Claude service. Its behavior must not be described as implemented by the current read-only Gmail/V1 workflow.

The outdated root `files.zip` duplicated an earlier version of `PhishGuard/` and was removed during the final audit; its previous bytes remain in Git history. The editable source is the maintained reference.
