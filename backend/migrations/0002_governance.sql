-- Governance persistence (Phase 3). Additive only: existing analyses rows are untouched.
-- Account rule configuration and risk exceptions arrive in Phase 6.

CREATE TABLE aws_accounts (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    aws_account_id   CHAR(12) NOT NULL,
    alias            VARCHAR(100),
    -- 'ambient' = the server's own credential chain; 'assume_role' reserved for later.
    credential_mode  VARCHAR(20) NOT NULL DEFAULT 'ambient'
                     CHECK (credential_mode IN ('ambient', 'assume_role')),
    role_arn         TEXT,
    external_id      TEXT,  -- never returned by the API; no static access keys are stored
    enabled_regions  TEXT[] NOT NULL DEFAULT '{}',
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, aws_account_id)
);

CREATE TABLE governance_rules (
    rule_id           VARCHAR(40) NOT NULL,
    version           INTEGER NOT NULL,
    name              TEXT NOT NULL,
    category          VARCHAR(20) NOT NULL,
    default_severity  VARCHAR(10) NOT NULL,
    scope             VARCHAR(10) NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE governance_scans (
    id                 SERIAL PRIMARY KEY,
    account_id         INTEGER NOT NULL REFERENCES aws_accounts(id) ON DELETE CASCADE,
    analysis_id        INTEGER REFERENCES analyses(id) ON DELETE SET NULL,
    region             VARCHAR(50) NOT NULL,
    include_iam        BOOLEAN NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'running'
                       CHECK (status IN ('running', 'completed', 'partial', 'failed')),
    error              TEXT,
    started_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    finished_at        TIMESTAMP WITH TIME ZONE,
    posture_score      NUMERIC(5, 1),
    coverage           NUMERIC(4, 3),
    overall_status     VARCHAR(20),
    posture            JSONB,
    collector_summary  JSONB,
    rule_versions      JSONB
);

CREATE INDEX idx_governance_scans_account ON governance_scans(account_id, started_at DESC);
CREATE INDEX idx_governance_scans_analysis ON governance_scans(analysis_id);

CREATE TABLE governance_evaluations (
    id               BIGSERIAL PRIMARY KEY,
    scan_id          INTEGER NOT NULL REFERENCES governance_scans(id) ON DELETE CASCADE,
    rule_id          VARCHAR(40) NOT NULL,
    rule_version     INTEGER NOT NULL,
    rule_name        TEXT NOT NULL,
    category         VARCHAR(20) NOT NULL,
    scope            VARCHAR(10) NOT NULL,
    severity         VARCHAR(10) NOT NULL,
    region           VARCHAR(50),  -- NULL for account-global rules (IAM)
    resource_type    VARCHAR(50) NOT NULL,
    resource_id      TEXT NOT NULL,
    resource_name    TEXT,
    status           VARCHAR(20) NOT NULL
                     CHECK (status IN ('pass', 'fail', 'not_applicable', 'unknown')),
    kind             VARCHAR(20),
    message          TEXT NOT NULL,
    evidence         JSONB NOT NULL DEFAULT '{}',
    unknown_reason   VARCHAR(40),
    remediation_ref  VARCHAR(80),
    exception_id     INTEGER,
    explanation      TEXT,
    details          JSONB NOT NULL DEFAULT '{}',
    evaluated_at     TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX ux_governance_evaluations_key
    ON governance_evaluations(scan_id, rule_id, resource_id, COALESCE(region, ''));
CREATE INDEX idx_governance_evaluations_filter
    ON governance_evaluations(scan_id, status, severity);

ALTER TABLE analyses
    ADD COLUMN IF NOT EXISTS aws_account_id INTEGER REFERENCES aws_accounts(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS governance_status VARCHAR(20);
