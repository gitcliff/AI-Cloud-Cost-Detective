-- Phase 4: record whether AI explanations were produced for a governance scan.
-- Explanations are optional and non-authoritative; a scan is complete without them.

ALTER TABLE governance_scans
    ADD COLUMN IF NOT EXISTS ai_status VARCHAR(20),
    ADD COLUMN IF NOT EXISTS ai_error TEXT;
