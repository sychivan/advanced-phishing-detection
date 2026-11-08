PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS model_versions (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL UNIQUE,
    artifact_hash TEXT NOT NULL,
    trained_at TEXT,
    metrics_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id),
    model_version_id INTEGER NOT NULL REFERENCES model_versions(id),
    classification TEXT NOT NULL
        CHECK (classification IN ('Safe', 'Suspicious', 'Phishing')),
    risk_score REAL NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    reasons_json TEXT NOT NULL,
    analysed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY,
    analysis_id INTEGER NOT NULL REFERENCES analysis_results(id),
    submitted_by TEXT NOT NULL,
    suggested_label TEXT NOT NULL
        CHECK (suggested_label IN ('Safe', 'Phishing')),
    review_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (review_status IN ('pending', 'approved', 'rejected')),
    reviewed_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    CHECK (
        (review_status = 'pending'
            AND reviewed_by IS NULL AND reviewed_at IS NULL)
        OR
        (review_status IN ('approved', 'rejected')
            AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_analysis_email
    ON analysis_results(email_id);

CREATE INDEX IF NOT EXISTS idx_analysis_model
    ON analysis_results(model_version_id);

CREATE INDEX IF NOT EXISTS idx_feedback_analysis
    ON feedback(analysis_id);