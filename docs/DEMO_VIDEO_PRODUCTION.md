# PhishGuard final demonstration video - filming plan

**This is the filming guide for an actual screen recording, not proof that footage already exists.** The sample video supplied with the submission kit uses previously captured synthetic-email screenshots and must be described as an *evidence walkthrough*, not a newly recorded interactive demo.

## One recording, around 4 minutes

Use the tested local revision, a dedicated synthetic SQLite database and (optionally) a dedicated Gmail test inbox. Record at 1920x1080 with Windows Snipping Tool screen recording or OBS Studio. Speak English clearly through a microphone, at a comfortable pace. Never display credentials, OAuth consent URLs/tokens, real account addresses, browser password-manager prompts, or private inbox messages.

| Time | View / action | Voice narration |
| --- | --- | --- |
| 0:00-0:20 | Title and overview page | Introduce PhishGuard, scope and three workstreams. |
| 0:20-0:45 | Two health pages or architecture slide | Explain browser to Flask to saved V1; submitted analyses go to SQLite. |
| 0:45-1:15 | Local My Mail, open suspicious synthetic sample | Identify Phishing label, score 85.92, contributing text-pattern reasons. |
| 1:15-1:40 | Open ordinary synthetic sample | Show Safe 40.24 and Moderate **display band**, distinct from binary cutoff 50. |
| 1:40-2:20 | Move ordinary sample to local Quarantine and restore | Show changed location, retained score, label and explanations. |
| 2:20-2:40 | Show unauthenticated `/api/stats` curl command returning HTTP 401 | State this verifies access control for the tested endpoint, not complete security. |
| 2:40-3:05 | Open aggregate E13 test logs | State 80 Python cases plus 39 subtests, 18 JavaScript cases and separate SQLite and HTTP checks, from the checked revision. |
| 3:05-3:30 | Optional Gmail with **dedicated synthetic inbox only** | Read-only scan up to five; never show private mailbox or OAuth consent screens. |
| 3:30-4:00 | Conclusion and limitations | Explain false positives, no sender authentication or attachment scan, and distinction between local Quarantine and Gmail Flagged. |

The runtime demo data can only be recreated with the **exact same subject, body and model artifact**. If new scores differ, show the actual output; do not edit the screenshot or say all five Gmail messages are verified phishing.

## Recording preparation (Windows)

1. Coordinate one laptop and recording operator. Rehearse the 4-minute workflow once without recording.
2. Fetch the approved `main` revision; preserve uncommitted files. Install Python and Node according to `README.md`.
3. Run the saved V1 API and Flask in separate terminals; verify model health on port 5001 and Flask health on port 5000.
4. Create **two synthetic messages**, confirm both display the expected labels and reasons, and ensure there are no unrelated records in the demo database.
5. Hide notifications, close messaging tabs and enable Do Not Disturb. Set display scaling so each detail panel is readable.
6. In OBS Studio: add Display Capture or Window Capture; choose 1920x1080, 30 fps, microphone capture and an MKV recording. Use **File > Remux Recordings** to export MP4. In Windows Snipping Tool, choose the screen-recording icon, select the browser window, record and save the video.
7. Record one complete run, keeping terminal authentication entries, Google account chooser, private data and tokens **off-screen**. Prefer a dedicated test inbox or omit live Gmail if it cannot be sanitised.
8. Review the full video. Verify audio, no cursor movement covering scores, no exposed secrets or real email subjects, and that the timeline stays within the teacher's video instructions (none were specified in the supplied rubric).
9. Trim pauses, add a brief introduction and legible captions. Export MP4 1080p H.264 with AAC audio; test playback on another computer.
10. Ask **all three team members** to check correctness, names and role attributions before the leader uploads. Retain a local original recording and exported copy.

## For the separate 10-minute oral assessment

The oral presentation is **10 minutes of presentation + 5 minutes of Q&A**. Each slide must visibly name its responsible team member. Do not spend the full oral time playing a four-minute video *and* then repeat the entire live demo; choose a short live sequence or a clipped backup while covering architecture, tests and limits.

## High-grade acceptance checklist

- Narration is human and understandable; audible at consistent volume.
- Actual interactions are visible from start to finish (not only retrospective screenshots).
- Show at least one successful flow and one clear failure-handling outcome.
- Do not mislabel the model score as a calibrated probability or synthetic tests as real-world accuracy.
- Protect accounts, secrets and mailbox data.
- Include a caption or end card stating tested commit and that V1 has not been retrained.
