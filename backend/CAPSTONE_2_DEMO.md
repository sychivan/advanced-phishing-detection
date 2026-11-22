# PhishGuard Capstone 2 backend demonstration

**Victoria University · NIT3004 Capstone Project 2 · Latest recorded rehearsal: 22 November 2026 (Sydney)**

> **Reading this record:** the sections below preserve earlier Windows rehearsals and their original evidence. For the current checkout, use the [root README](../README.md) and `scripts/verify_project.py`. The E11 totals include experimental suites that were never committed; current counts are recorded separately. PR #6 has since been merged into `main` (merge commit `929790ec4b22c6dafc1e7ac39026fad0ad75efa0`).

## Individual backend contribution

I secured the Flask routes that read or change stored email and preserved the dashboard's message and statistics formats. I connected V1 predictions to SQLite storage using the model version and artifact hash. I hardened the read-only Gmail flow around Google consent, sessions, message retrieval and local V1 scoring. The automated tests cover these integration boundaries using synthetic input.

Further dataset development, classifier training, calibration and scoring improvements are handed over to **Phuoc Thinh Ngo**. This closeout covers Backend and Integration. The demonstration uses the original V1 artifact and cutoff of 50.

PhishGuard was built by a three-member Victoria University capstone team for educational use. Frontend work covers the interface and navigation. Backend work covers APIs, workflows, and V1 integration. The ML and database work covers model development and storage.

| Area | Contribution |
|---|---|
| Backend and API | Demo login and logout, bearer authentication, administrator-only feedback review, request validation and JSON errors |
| Dashboard integration | Authenticated dashboard counts and message workflows, same-origin Flask hosting and a configurable CORS allowlist for local frontend development |
| V1 integration | Model request and response validation, explicit unavailable and manual-review outcomes, model registration and persistence through the existing SQLite layer |
| Gmail integration | OAuth state and PKCE, read-only consent, protected scan and disconnect requests, bounded inbox retrieval and transient results |
| Verification | Backend unit and integration tests, synthetic email inputs and a separate live-Gmail checklist |

## Prepare the demonstration

1. Follow the [interpreter setup](../README.md#select-the-interpreter-in-each-demo-terminal) and use the synthetic database in the [startup instructions](../README.md#run-locally).
2. Confirm both services respond using [V1 health](http://127.0.0.1:5001/health) and [Flask health](http://127.0.0.1:5000/api/health).
3. For the Gmail segment, configure the Google **Testing** app and populate a dedicated inbox with up to five synthetic messages. Keep the credential prompts and browser authorization details out of the recording.

## Final cleanup and fresh start

**22 November 2026 (Sydney).** Verified the Flask and V1 process command lines and workspace paths, restarted only those services, and left them running on standard loopback ports. They loaded the existing local authentication and Gmail settings from disk. Flask uses `.venv/phishguard-capstone-final-20261122.sqlite3`, which contains two synthetic messages. The original `database/analysis.db` still has five emails, five analyses and four feedback rows. The V1 artifact, API and archived report hashes matched.

| Checked now | Result |
|---|---|
| Flask, V1 and dashboard | Both health endpoints and the served dashboard returned HTTP 200. |
| Analysis and display data | Submitted synthetic mail through `POST /api/analyse-email` to V1. Saved predictions were **Phishing 85.92** with two reasons and **Safe 40.24**. The served dashboard adapter retrieved the same Overview counts and My Mail details over real HTTP in a JavaScript VM. |
| Storage and access controls | Verified successful and invalid login, approved synthetic feedback, quarantine and restore with identical score, prediction and reasons, deletion of a third disposable synthetic record, CORS preflight, and HTTP 401 after logout. |
| Score bands | Overview reports stored-score bands below 40, 40 to below 70, and 70 or above. The two samples occupy Moderate and High bands. The Safe prediction at 40.24 exposed an incorrect Low-band assumption in the initial rehearsal harness. The final check used the observed prediction and score. The UI displays the V1 prediction separately in message details. |
| Browser | Windows Computer Use could not connect to its native pipe. Browser actions and new screenshots were unavailable. Earlier Chrome observations below describe the earlier UI only. |
| Gmail | The fresh service returned HTTP 302 to Google with the exact callback, state, PKCE S256 and Gmail read-only scope. An unconnected scan returned HTTP 401. No Google account was opened in this pass. The account owner still needs to verify the live callback, scan and disconnect/reconnect. Gmail scans do not add Overview records. |

[Sanitized final evidence](evidence/final-cleanup-2026-11-22.json) · [Cleanup summary](evidence/cleanup-summary-2026-11-22.md)

The documentation review checked the original cleanup record against the README, confirmed all 14 listed recovery copies, and ran SQLite's integrity check on the recovery database. The two database counts and the V1, model API and archived evaluation hashes still matched the recorded evidence. Both health endpoints and the dashboard responded with HTTP 200. Gmail connect returned HTTP 302 to Google; the redirect was inspected locally and left unfollowed.

### Final test commands and results

Select the interpreter in the README. Run the shared checks from an isolated copy with a disposable `PHISHGUARD_DB_PATH` and no private configuration. The tests set fixture values and mock Google.

```powershell
& $DemoPython -m pytest backend -q --tb=short -p no:cacheprovider
node --test backend/test_gmail_dashboard.cjs
```

**E11 recorded 74 Python tests, 12 subtests and eight dashboard JavaScript tests passed**, with zero failures or skips. Both standalone SQLite checks passed and all exit codes were 0. E11 ran a broader command containing local ML regression suites that are outside this handoff. Its copied workspace had no private configuration. Google and fetch were mocked. The legacy scripts ran in a temporary copy of their original layout, separate from the disposable `PHISHGUARD_DB_PATH` used for `database.check_storage`. E11 did not run the seven corpus scripts under `ml/tests`, any training, or model searches. [Reviewed E11 logs](evidence/E11-20261122-122951-share/README.md)

### Browser acceptance reported by the project owner

- The owner reported signing in, viewing a prediction and its reasons, quarantining and restoring a synthetic record, signing out, and seeing HTTP 401 for a request without authentication.
- The owner reported connecting Gmail, scanning five messages, disconnecting, reconnecting and scanning again. These are owner-reported browser results. The E11 Gmail checks used mocked services.
- For another presentation run, confirm a single Flask and V1 listener using the [startup instructions](../README.md#run-locally), and capture only synthetic content or non-identifying aggregates.

## Backend closeout results · 22 November 2026 (Sydney)

| Check | Observed result |
|---|---|
| Automated tests | **40 Python tests, 12 subtests and six dashboard JavaScript tests passed.** Python covered the backend suite and synthetic inference-input parity. Gmail transport was mocked. |
| Runtime and startup | Python 3.15.2 ran from the Git-ignored workspace fallback, using the installed dependencies. Started V1 and Flask on their standard loopback ports. Both health endpoints and the served dashboard returned HTTP 200. |
| Disposable SQLite workflow | An authenticated synthetic submission returned **Phishing, 85.92/100**, two reasons and an analysis ID. The saved message retained the score and reasons. Quarantine moved it out of the inbox. Restore returned it with the same score. Logout invalidated the bearer and the next request returned HTTP 401. |
| Protection and cleanup | V1 artifact, API and archived evaluation hashes matched. The V1 cutoff is 50. The verification child processes were stopped and their disposable database removed. |

The exact startup commands, run from the repository root after the interpreter and environment setup above, were:

```powershell
# Model terminal
& $DemoPython ml/model_api.py

# Backend terminal with PHISHGUARD_DB_PATH and AI_MODEL_URL configured
& $DemoPython -m backend.setup_db
& $DemoPython backend/app.py
```

The HTTP verification used generated local demo credentials and a new SQLite file. It did not open a browser or contact Google. The test commands are in the [README](../README.md#tests).

### Earlier acceptance evidence

- Chrome previously showed Overview after demo sign-in, **86/100** and reasons in My Mail, message movement through Quarantine and back, and a return to Sign in after logout. That run used alternate loopback ports because the standard ones were occupied.
- Earlier access-control checks confirmed HTTP 401 for invalid login and rejected an unlisted CORS origin. The project owner previously confirmed Google consent and retrieval of five messages from the dedicated test inbox.

### Remaining browser checks

- Open [the standard dashboard](http://127.0.0.1:5000/gmail/app) after starting the services. In the demonstration browser, confirm the synthetic message shows the score and reasons, moves through Quarantine and back to My Mail, and is inaccessible after sign-out.
- Complete the dedicated Gmail test-account checks below in the demonstration browser. Google consent settings, account authorization and the visible inbox state require manual verification.

## Practical rehearsal · 22 November 2026 (Sydney)

| Evidence type | Result in this rehearsal |
|---|---|
| Existing services | Flask and V1 returned healthy responses on 5000 and 5001. Flask served the dashboard with HTTP 200. The existing processes and their stored messages were left alone. |
| Synthetic API workflow | An isolated copy of Flask on loopback port 56150 reused the running V1 and started with a disposable SQLite database. Demo login and `POST /api/analyse-email` succeeded. V1 returned **Phishing, 85.92/100**, two reasons, and an analysis ID. Inbox detail retained the score and reasons. Overview reported one stored message. Quarantine moved it out of the inbox, restore returned it with its original prediction and score, and the revoked bearer returned HTTP 401. |
| Dashboard integration | The JavaScript adapter extracted directly from the served dashboard ran in Node.js against the isolated backend over HTTP. Login, Overview data, My Mail detail, quarantine, restore, logout and expired-session navigation passed. |
| Actual browser | The Windows Computer Use bridge could not connect to its native pipe. Browser interaction and screenshots were unavailable in this run. The earlier Chrome evidence above remains a separate result. |
| Gmail | Existing `/gmail/connect?view=dashboard` returned **503** with “Gmail sign-in is not configured.” Automated Gmail tests used mocked Google responses. This rehearsal did not contact Google or read an inbox. The five-message live result above was previously reported by the project owner. |

The isolated Flask process was stopped and its temporary database was removed. The live services remained healthy. The [rehearsal evidence](evidence/rehearsal-2026-11-22.json) records HTTP outcomes, counts, score, checksums and configuration presence. It contains no message bodies, credentials or tokens.

An earlier run with Python 3.15.2 produced **40 Python passes, 12 subtest passes and six dashboard JavaScript passes**, with zero failures. Its Python command included the local inference-parity test. For runnable checks on this branch, use the [shared test commands](../README.md#tests).


### Gmail configuration handoff

The running Flask process lacked the three Google settings. Its existing session secret was configured. The previous startup depended on values inherited from its PowerShell session, so entering them in another session did not configure that process.

| Setting | Before the restart | After the restart |
|---|---|---|
| `GOOGLE_CLIENT_ID` | Missing | Configured |
| `GOOGLE_CLIENT_SECRET` | Missing | Configured |
| `GOOGLE_REDIRECT_URI` | Missing | Configured |
| `PHISHGUARD_SESSION_SECRET` | Configured | Same setting preserved |

The latest local export for the existing Google Web client listed the exact callback `http://127.0.0.1:5000/gmail/callback`. Startup now loads a Git-ignored workspace settings file while respecting process environment overrides. The file preserves the working demo login, model URL and existing database selection. After reopening VS Code, select `$DemoPython` and run `& $DemoPython backend/app.py`. [Local setup instructions](../README.md#gmail-test-inbox)

Only Flask was restarted. V1 stayed on the same process. Flask health, the dashboard and the original demo credentials passed verification, and read-only database counts remained at five messages and five analyses. Gmail connect now returns HTTP 302 to Google with the exact callback, OAuth state, PKCE S256 and the read-only Gmail scope. An unconnected scan returned HTTP 401. The clean startup and disposable synthetic workflow passed, as did **44 Python tests, 12 subtests and six dashboard JavaScript tests**. [Configuration and rehearsal evidence](evidence/gmail-configuration-2026-11-22.json)

Open the [Gmail consent link](http://127.0.0.1:5000/gmail/connect?view=dashboard) and complete Google login, two-factor authentication and consent with the dedicated test account. Then follow the [live Gmail checklist](#live-gmail-follow-up-checklist). The browser bridge was unavailable. Google Cloud's current Gmail API and test-user settings, live callback, inbox retrieval and disconnect were not verified in this run. If the existing client prompts for a test-user authorization, check the test-account list in Google Cloud. Sign in to the demo dashboard again after the Flask restart. Keep Google pages, credentials and inbox contents out of the recording.

## Walkthrough

### Six-minute English demonstration script

Use the two existing synthetic records in the demo database. Complete Google consent privately before presenting the Gmail segment. If you submit a new synthetic message, show the score it actually returns, since the subject can affect the prediction.

| Time | Action and English narration | Ghi chú tiếng Việt |
|---|---|---|
| 0:00–0:45 | Open both health pages. “My contribution is the Flask backend, API integration, read-only Gmail integration, and connecting the existing V1 model. Flask validates requests, calls the local model, and stores successful manual analyses in SQLite with the model version and hash.” | Mở hai trang health check và nêu phạm vi cá nhân. |
| 0:45–1:30 | Sign in and open Overview. “The demonstration uses a separate database with synthetic messages. These percentages show the share of stored messages in each score band. Measuring model accuracy requires labelled evaluation data.” | Overview hiển thị tỷ lệ thư theo dải điểm. |
| 1:30–2:30 | In My Mail, open the 85.92 record and show its prediction and two reasons. Then open the 40.24 record. “V1 predicted Phishing for the first example and Safe for the second. The second belongs to the Moderate display band. PhishGuard shows the prediction and band separately.” | Phân biệt nhãn V1 với dải điểm. |
| 2:30–3:30 | Quarantine the 85.92 record and restore it. “This changes the location of the local record. The model prediction, score, and reasons are preserved. Gmail messages stay in their inbox.” | Chỉ thao tác trên thư giả lập. |
| 3:30–4:15 | Explain feedback. “Users can suggest a classification, and an administrator can approve or reject it. The API rehearsal submitted a synthetic suggestion and checked that the decision was stored. The demo keeps the original V1 artifact.” | Duyệt phản hồi là thao tác lưu dữ liệu. |
| 4:15–5:15 | If current Gmail acceptance passed, scan the dedicated test inbox and expand **Why this score?**. “Gmail access is read-only. Results stay in the scan view and leave SQLite Overview totals unchanged.” If live verification is pending, state that the redirect and mocked Gmail tests passed and the connected workflow still needs confirmation. | Chỉ dùng hộp thư thử nghiệm. Tách chuyển hướng, kiểm thử giả lập và Gmail thật. |
| 5:15–6:00 | Sign out and show the evidence. “The final rehearsal passed 74 Python tests, 12 subtests, eight JavaScript tests, and two SQLite checks. The HTTP verification rejected a revoked token with 401. V1 scores text and can make mistakes. Further model work belongs to Phuoc Thinh Ngo.” | Đây là kết quả lần kiểm thử đã lưu, không phải kiểm thử trình duyệt mới. |

### Submit a synthetic message

Enter the same credentials you configured for the backend. The commands keep the bearer in the shell and print selected analysis fields. The unique subject identifies the new rehearsal record in My Mail. The displayed score can differ from the saved evidence because the subject is part of the model input. Leave the pre-existing records in place.

```powershell
$base = "http://127.0.0.1:5000/api"
$demo = Get-Credential -Message "Enter your local PhishGuard demo credentials" -UserName "demo@example.test"
$login = Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType "application/json" -Body (@{
    email = $demo.UserName
    password = $demo.GetNetworkCredential().Password
} | ConvertTo-Json)
Remove-Variable demo
$headers = @{ Authorization = "Bearer $($login.token)" }
$demoSubject = "DEMO ONLY: urgent password verification " + [guid]::NewGuid().ToString('N').Substring(0, 8)

$prediction = Invoke-RestMethod -Method Post -Uri "$base/analyse-email" -Headers $headers -ContentType "application/json" -Body (@{
    sender = "synthetic@example.test"
    subject = $demoSubject
    body = "Your account will be suspended immediately. Verify your account password now to restore access."
} | ConvertTo-Json)
$demoSubject
$prediction | Select-Object classification, risk_score, model_status, analysis_id, reasons

try {
    Invoke-RestMethod -Uri "$base/messages" -ErrorAction Stop
} catch {
    [int]$_.Exception.Response.StatusCode
}
```

Submit feedback against the returned analysis ID. If you configured the demo account as administrator, approve that feedback before signing out.

```powershell
$label = if ($prediction.classification -eq "Phishing") { "Safe" } else { "Phishing" }
$feedback = Invoke-RestMethod -Method Post -Uri "$base/feedback" -Headers $headers -ContentType "application/json" -Body (@{
    analysis_id = $prediction.analysis_id
    suggested_label = $label
} | ConvertTo-Json)
$feedback | Select-Object feedback_id, review_status

$review = Invoke-RestMethod -Method Post -Uri "$base/feedback/$($feedback.feedback_id)/review" -Headers $headers -ContentType "application/json" -Body '{"decision":"approved"}'
$review | Select-Object feedback_id, review_status
```

End the API session and clear the bearer from the shell variables.

```powershell
Invoke-RestMethod -Method Post -Uri "$base/auth/logout" -Headers $headers
Remove-Variable login, headers
```

### API reference

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| GET | `/api/health` | Public | Check Flask health |
| POST | `/api/auth/login` | Public | Exchange demo credentials for a bearer token |
| POST | `/api/auth/logout` | Public | Revoke the supplied bearer token |
| POST | `/api/analyse-email` | Bearer | Classify and store a submitted email |
| GET | `/api/stats` | Bearer | Retrieve stored-message score bands and quarantine counts |
| GET | `/api/messages?status=inbox` | Bearer | List inbox or quarantine records |
| GET | `/api/messages/<id>` | Bearer | Retrieve a message, prediction and reasons |
| POST | `/api/messages/<id>/quarantine` | Bearer | Quarantine a local record |
| POST | `/api/messages/<id>/restore` | Bearer | Return a quarantined record to the inbox |
| DELETE | `/api/messages/<id>` | Bearer | Delete a local message and associated records |
| POST | `/api/feedback` | Bearer | Submit a suggested classification |
| GET | `/api/feedback/<id>` | Bearer | Retrieve feedback |
| POST | `/api/feedback/<id>/review` | Admin bearer | Approve or reject pending feedback |

Send `Authorization: Bearer <token>` for protected routes. Demo tokens expire after one hour or end at logout or Flask restart. To enable admin review, `ADMIN_EMAIL` must match the demo login. The analysis request takes nonblank `sender`, `subject`, and `body` strings. Limits are 500 characters for sender or subject, 12,000 for body and 200,000 bytes for the request. Configure the model URL with an explicit port and a loopback IP address.

| Status | Meaning |
|---|---|
| 400 | Invalid JSON or input |
| 401 | Invalid, missing or expired demo credentials or bearer |
| 403 | Admin access required for the operation |
| 404 | Record or route unavailable |
| 413 | Request exceeds the size limit |
| 422 | V1 found no recognized text, requiring manual review |
| 502 | Model service failed or returned an invalid response |
| 503 | Demo authentication or model service is unconfigured |

`GET /gmail/session` reports connection state. `POST /gmail/scan` and `POST /gmail/disconnect` use the Gmail session cookie and a form CSRF token. Separate frontend development can set `PHISHGUARD_CORS_ORIGINS` to comma-separated exact origins. The default allows `http://127.0.0.1:5500` and `http://localhost:5500`. If using a static server, serve only the dashboard file from a separate document root.

### Live Gmail acceptance and false positives

The offline overnight comparison produced three fewer historical false alarms and eight more missed phishing messages than V1. Keep the original V1 cutoff of 50 for the demonstration. No independently verified fresh commercial-mail holdout is available to check the reported Gmail false positives. The experimental files remain local.

In the reported live run, V1 predicted Phishing for five out of five retrieved messages. Several appeared to be routine promotional messages and are possible false positives. Their true labels were not independently verified, so this small, unlabelled inbox scan cannot estimate V1's false-positive rate. The V1 artifact and classification threshold of 50 were preserved. V1 scores text patterns and does not verify sender authenticity or attachments. Review unexpected flags independently before acting.

The application requests Gmail's read-only scope and uses Gmail GET requests for listing and retrieving messages. The test suite checks the scope and request methods. **Disconnect Gmail** clears PhishGuard's local session and stops new scans with that session. A new connection requires the Google sign-in flow. Google may reuse an existing grant. Remove the grant separately in Google Account settings if you want to withdraw access there.

The automated tests check a separate explanation for each of five synthetic messages, a fallback when V1 supplies no explanation, and the reconnect flow after logout or expiry. Run the dashboard checks with `node --test backend/test_gmail_dashboard.cjs`.

### Live Gmail follow-up checklist

1. Follow the [Gmail configuration instructions](../README.md#gmail-test-inbox) to configure the OAuth client as **Testing**, add the dedicated inbox as a test user, enable the Gmail API, and set the backend's OAuth environment variables locally.
2. Start V1 and Flask with those settings. Check [V1 health](http://127.0.0.1:5001/health) and [Flask health](http://127.0.0.1:5000/api/health).
3. Open the [Gmail consent entry point](http://127.0.0.1:5000/gmail/connect?view=dashboard) and personally authorize read-only access with the dedicated Google test account. Set the Google Cloud client's authorized redirect URI to exactly `http://127.0.0.1:5000/gmail/callback`. Google redirects to this callback, and Flask returns to the [dashboard](http://127.0.0.1:5000/gmail/app#/overview).
4. Choose **Scan up to 5 messages**, compare the rows with the synthetic inbox, then choose **Disconnect Gmail**. Reload and confirm scanning requires a new connection.

- [x] The project owner completed live Google consent and confirmed five messages appeared in PhishGuard.
- [ ] After loading the updated dashboard, expand **Why this score?** for each scored message and confirm the warning is visible.
- [ ] Compare the test inbox before and after a scan, including labels and unread state.
- [ ] Select **Disconnect Gmail**, reload, and reconnect through Google before trying another scan. Check both plain-text and HTML synthetic messages if available.

If Google reports a redirect mismatch, compare the configured URI with the browser host, port and callback path. If V1 is unavailable, check its health and the Flask terminal's `AI_MODEL_URL`. If the dashboard is empty, submit the synthetic example and confirm that Flask uses the database initialized by `backend.setup_db`.
