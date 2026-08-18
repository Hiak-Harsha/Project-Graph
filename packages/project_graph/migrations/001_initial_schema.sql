-- =============================================================================
-- Migration 001: Initial Project Graph & Audit Universe Schema
-- Purpose: Production relational schema for Project Graph nodes, edges, checks,
--          tasks, cryptographic evidence vault, findings, and release verdicts.
-- =============================================================================

CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    repository_url VARCHAR(1024),
    default_branch VARCHAR(128) DEFAULT 'main',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS project_revisions (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    commit_sha VARCHAR(64) NOT NULL,
    branch VARCHAR(128) DEFAULT 'main',
    source_path VARCHAR(1024) NOT NULL,
    file_inventory_hash VARCHAR(64),
    replay_token VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_revisions_project_id ON project_revisions(project_id);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    node_type VARCHAR(32) NOT NULL,
    name VARCHAR(512) NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    static_status VARCHAR(32) DEFAULT 'UNVERIFIED',
    runtime_status VARCHAR(32) DEFAULT 'UNVERIFIED',
    audit_status VARCHAR(32) DEFAULT 'UNVERIFIED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, revision_id)
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(revision_id, node_type);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_status ON graph_nodes(revision_id, audit_status);

CREATE TABLE IF NOT EXISTS graph_edges (
    id SERIAL PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    source_id VARCHAR(64) NOT NULL,
    relationship VARCHAR(32) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    static_evidence BOOLEAN DEFAULT FALSE,
    runtime_evidence BOOLEAN DEFAULT FALSE,
    confidence REAL DEFAULT 1.0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(revision_id, source_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(revision_id, target_id);

CREATE TABLE IF NOT EXISTS audit_checks (
    id VARCHAR(128) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    execution_tier VARCHAR(32) NOT NULL,
    status VARCHAR(32) DEFAULT 'PENDING',
    required BOOLEAN DEFAULT TRUE,
    execution_method VARCHAR(64) NOT NULL,
    preconditions JSONB DEFAULT '[]'::jsonb,
    inputs JSONB DEFAULT '{}'::jsonb,
    expected_observations JSONB DEFAULT '[]'::jsonb,
    success_conditions JSONB DEFAULT '[]'::jsonb,
    failure_conditions JSONB DEFAULT '[]'::jsonb,
    evidence_requirements JSONB DEFAULT '[]'::jsonb,
    timeout INTEGER DEFAULT 10,
    risk_level VARCHAR(32) DEFAULT 'READ_ONLY',
    destructive BOOLEAN DEFAULT FALSE,
    unverified_reason TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, revision_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_checks_target ON audit_checks(revision_id, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_checks_status ON audit_checks(revision_id, status);

CREATE TABLE IF NOT EXISTS audit_tasks (
    id VARCHAR(128) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    task_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    required_checks JSONB DEFAULT '[]'::jsonb,
    status VARCHAR(32) DEFAULT 'PENDING',
    dependencies JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, revision_id)
);

CREATE TABLE IF NOT EXISTS evidence_vault (
    id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL,
    evidence_type VARCHAR(64) NOT NULL,
    summary TEXT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    source_location VARCHAR(512),
    timestamp DOUBLE PRECISION NOT NULL,
    payload JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, revision_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence_vault(revision_id, target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence_vault(sha256_hash);

CREATE TABLE IF NOT EXISTS audit_findings (
    id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    title VARCHAR(512) NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    status VARCHAR(32) DEFAULT 'CONFIRMED',
    confidence REAL DEFAULT 1.0,
    affected_feature VARCHAR(255),
    affected_nodes JSONB DEFAULT '[]'::jsonb,
    description TEXT NOT NULL,
    observed_behavior TEXT,
    expected_behavior TEXT,
    evidence_ids JSONB DEFAULT '[]'::jsonb,
    root_cause TEXT,
    recommendation TEXT,
    reproduction_steps JSONB DEFAULT '[]'::jsonb,
    adversarial_verdict VARCHAR(32),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, revision_id)
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    revision_id VARCHAR(64) NOT NULL REFERENCES project_revisions(id) ON DELETE CASCADE,
    certification_state VARCHAR(64) NOT NULL,
    verdict_status VARCHAR(64) NOT NULL,
    status_badge VARCHAR(32) NOT NULL,
    summary_statement TEXT NOT NULL,
    overall_score REAL NOT NULL,
    production_gates JSONB DEFAULT '[]'::jsonb,
    domain_scores JSONB DEFAULT '{}'::jsonb,
    check_summary JSONB DEFAULT '{}'::jsonb,
    findings_summary JSONB DEFAULT '{}'::jsonb,
    top_blockers JSONB DEFAULT '[]'::jsonb,
    elapsed_seconds REAL DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_runs_project ON audit_runs(project_id, created_at DESC);
