-- Layer 8: Tamper-Proof Cryptographic Merkle Forensic Incident Ledger
CREATE TABLE IF NOT EXISTS forensic_incident_ledger (
    incident_id UUID PRIMARY KEY,
    source_ip VARCHAR(64) NOT NULL,
    target_service VARCHAR(64) NOT NULL,
    mitre_tactic_id VARCHAR(32) NOT NULL,
    threat_score NUMERIC(4, 2) NOT NULL,
    remediation_action VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    merkle_hash VARCHAR(64) UNIQUE NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Transactional Outbox for Guaranteed SOAR Playbook Dispatch
CREATE TABLE IF NOT EXISTS outbox_events (
    event_id UUID PRIMARY KEY,
    aggregate_type VARCHAR(50) NOT NULL,
    aggregate_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    payload TEXT NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_forensic_ip ON forensic_incident_ledger(source_ip);
CREATE INDEX idx_outbox_unprocessed ON outbox_events(processed) WHERE processed = FALSE;
