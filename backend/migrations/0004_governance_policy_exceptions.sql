-- Phase 6: per-account governance policy and accepted-risk exceptions.

-- One validated policy document per AWS account (see governance/policy_config.py).
-- No row = defaults. Stored as a whole so a scan reads one consistent version.
CREATE TABLE account_policies (
    account_id   INTEGER PRIMARY KEY REFERENCES aws_accounts(id) ON DELETE CASCADE,
    settings     JSONB NOT NULL,
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_by   INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Accepted risks. Always scoped to one rule on one resource, always with a reason
-- and an expiry. Revoking keeps the row so the decision history stays auditable.
CREATE TABLE risk_exceptions (
    id           SERIAL PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES aws_accounts(id) ON DELETE CASCADE,
    rule_id      VARCHAR(40) NOT NULL,
    resource_id  TEXT NOT NULL CHECK (resource_id <> '' AND resource_id <> '*'),
    reason       TEXT NOT NULL CHECK (length(reason) >= 10),
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at   TIMESTAMP WITH TIME ZONE,
    revoked_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    CHECK (expires_at > created_at)
);

-- At most one live (unrevoked) exception per rule/resource in an account.
CREATE UNIQUE INDEX ux_risk_exceptions_live
    ON risk_exceptions(account_id, rule_id, resource_id) WHERE revoked_at IS NULL;

ALTER TABLE governance_evaluations
    ADD CONSTRAINT fk_governance_evaluations_exception
    FOREIGN KEY (exception_id) REFERENCES risk_exceptions(id) ON DELETE SET NULL;
