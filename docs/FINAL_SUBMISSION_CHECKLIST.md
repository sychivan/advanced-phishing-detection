# Final delivery audit checklist - NIT3004 PhishGuard

**Use the University's 22 November 2026 23:59 deadline for FINAL DELIVERY.** The leader submits the deliverable package; each student separately submits the official Team Evaluation Form. The oral assessment is a separate 10-minute presentation + 5-minute Q&A, with due date shown as 24 November 2026 23:59.

| Criterion | Points | What to provide | Evidence or remaining action |
| --- | ---: | --- | --- |
| Complete code and user manual | 25 | Source at a pinned commit, Python/Node requirements, clean README, independently usable manual with screenshots | Current `main` and `scripts/verify_project.py`; ask a teammate to follow the installation from a fresh directory |
| Technical Implementation Document | 30 | TID detailing architecture, major function inputs/outputs, logic, methods, validations, integrations, code snippets and tests | Keep TID PDF separate from the broad final group report; check snippets against the submitted code revision |
| E-poster | 5 | Concise one-page PDF with readable design, problem/method/results/limits and team credits | A1 landscape draft exists outside Git; confirm correct final names and test every embedded hyperlink/QR |
| Demonstration video | 5 | **Real recorded application** with clear audio, successful local review flow and failure case | Record with dedicated synthetic messages using `docs/DEMO_VIDEO_PRODUCTION.md`. The screenshot-based walkthrough is only a labelled backup |
| Individual team evaluation | 5 | Official form **submitted separately by each student** with honest peer scores | Do not submit an invented rating or assume the proposed 40/30/30 effort split is a 1-5 peer score |

## Code evidence

Canonical program: `backend/app.py`, `ml/model_api.py`, `phishguard-frontend.html`, `database/`. The earlier `PhishGuard/` prototype and `archive/` are historical reference, not the current demo runtime. Keep secrets, private Gmail content, local SQLite files, datasets, `.venv` and credentials out of public Git.

Run `python scripts/verify_project.py` from a configured environment, reviewing its `verification-results` logs and nonzero error exit codes. Earlier checked E13 evidence: **80 Python cases + 39 subtests, 18 JavaScript cases, two SQLite smoke paths and Flask-to-V1-to-SQLite HTTP flow**. **Never present older E11 totals as the latest re-run, and do not claim GitHub CI passed until a workflow has actually passed.**

## Known honest limitations

V1 is a text-based TF-IDF/Logistic Regression classifier. Its binary cutoff is 50; Overview display bands split at 40 and 70. Scores are not independently proven calibrated probabilities for current Gmail. Local quarantine moves SQLite records; Gmail Flagged only presents transient scan results and does not move Gmail messages. The model does not verify sender identity or inspect attachments. The original feature proposal extends beyond the delivered MVP; any deferred requirements should be stated in the TID and Q&A.

## Team and sign-off

- Sy Chi Van (s8080942): backend, API and Gmail/V1 integration.
- Xavier McGregor: frontend; **student ID to confirm**.
- Phuoc Thinh Ngo: ML/database; **student ID to confirm**.
- Proposed effort shares 40/30/30 are **not confirmed peer ratings** and need explicit team agreement.
- Course code, campus, supervisor and formal submission destination should be checked from the assessment portal.
- Verify that the report/manual/poster/video all cite the same Git revision and contain no private mailbox screenshots.

## Final handoff

- [ ] Source code downloaded as clean ZIP from **Code > Download ZIP** of the approved GitHub revision (or cloned from a pinned commit).
- [ ] User manual PDF checked on a second machine.
- [ ] TID PDF code paths and test totals match code.
- [ ] Poster PDF inspected at 100% zoom.
- [ ] **Final real demo MP4** watched end to end and voice audible.
- [ ] Leader submitted all five team deliverables by 23:59 on 22 Nov 2026.
- [ ] Each student submitted the official Team Evaluation Form.
- [ ] Oral slides show slide owner names and complete within ten minutes.
