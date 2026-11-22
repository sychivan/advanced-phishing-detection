# E11 test evidence

The isolated local run took place on **22 November 2026, 12:29:51 to 12:30:07 AEDT**. The workspace copy excluded private configuration, real mail, corpus inputs and existing databases. The Gmail tests mocked Google, the dashboard tests mocked fetch, and the standalone SQLite checks used separate disposable databases.

| Evidence | Recorded outcome |
|---|---|
| [E11A — Python](E11A-Python.txt) | 74 tests and 12 subtests passed. Zero failures or skips. Exit 0. |
| [E11B — JavaScript](E11B-JavaScript.txt) | Eight tests passed. Zero failures or skips. Exit 0. |
| [E11C — SQLite](E11C-SQLite.txt) | Configured save/read/rollback check and legacy initialization/write/read check both passed. All exits 0. |

Personal interpreter and temporary directory paths were replaced with placeholders in these share copies. The [summary](summary.json) contains the same redaction. The timestamps, commands, observed outcomes and exit codes were retained. The original logs remain local.

The recorded Python command includes additional local ML regression files outside the backend handoff. Use the [project test commands](../../../README.md#tests) to run the shared suites. E11 is automated evidence. The project owner's browser and live Gmail results are recorded separately in the [demo guide](../../CAPSTONE_2_DEMO.md#browser-acceptance-reported-by-the-project-owner).
