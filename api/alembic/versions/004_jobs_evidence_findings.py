"""jobs, raw_evidence, findings redesign

Revision ID: 004
Revises: 003
Create Date: 2026-01-06

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clean up any orphaned indexes first
    op.execute("DROP INDEX IF EXISTS ix_jobs_workspace_status")
    op.execute("DROP INDEX IF EXISTS ix_jobs_target")
    op.execute("DROP INDEX IF EXISTS ix_jobs_target_status")
    op.execute("DROP INDEX IF EXISTS ix_jobs_idempotency")
    op.execute("DROP INDEX IF EXISTS ix_jobs_job_type")
    op.execute("DROP INDEX IF EXISTS ix_jobs_status")
    op.execute("DROP INDEX IF EXISTS ix_raw_evidence_job")
    op.execute("DROP INDEX IF EXISTS ix_raw_evidence_sha256")
    op.execute("DROP INDEX IF EXISTS ix_raw_evidence_workspace")
    op.execute("DROP INDEX IF EXISTS ix_findings_workspace_type")
    op.execute("DROP INDEX IF EXISTS ix_findings_subject")
    op.execute("DROP INDEX IF EXISTS ix_findings_job")
    op.execute("DROP INDEX IF EXISTS ix_findings_target")
    op.execute("DROP INDEX IF EXISTS ix_findings_finding_type")
    
    # Drop old tables (CASCADE to remove any FKs)
    op.execute("DROP TABLE IF EXISTS findings CASCADE")
    op.execute("DROP TABLE IF EXISTS raw_evidence CASCADE")
    op.execute("DROP TABLE IF EXISTS jobs CASCADE")
    
    # Create new jobs table with full schema
    op.execute("""
        CREATE TABLE jobs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            investigation_id UUID,
            target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            technique_code VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'CREATED',
            priority INTEGER NOT NULL DEFAULT 5,
            attempt INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            idempotency_key VARCHAR(64) NOT NULL UNIQUE,
            params_json JSONB NOT NULL DEFAULT '{}',
            scheduled_at TIMESTAMP WITH TIME ZONE,
            started_at TIMESTAMP WITH TIME ZONE,
            finished_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            error_code VARCHAR(50),
            error_message TEXT,
            trace_id VARCHAR(36),
            celery_task_id VARCHAR(36),
            CONSTRAINT ck_jobs_status CHECK (status IN ('CREATED', 'QUEUED', 'RUNNING', 'RETRYING', 'SUCCEEDED', 'FAILED', 'DEAD_LETTER', 'CANCELLED'))
        )
    """)
    
    # Create indexes for jobs
    op.execute("CREATE INDEX ix_jobs_technique_code ON jobs(technique_code)")
    op.execute("CREATE INDEX ix_jobs_status ON jobs(status)")
    op.execute("CREATE INDEX ix_jobs_idempotency_key ON jobs(idempotency_key)")
    op.execute("CREATE INDEX ix_jobs_workspace_status ON jobs(workspace_id, status)")
    op.execute("CREATE INDEX ix_jobs_target ON jobs(target_id)")
    
    # Create raw_evidence table
    op.execute("""
        CREATE TABLE raw_evidence (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            storage_uri VARCHAR(500) NOT NULL,
            content_type VARCHAR(100) NOT NULL DEFAULT 'application/json',
            sha256 VARCHAR(64) NOT NULL,
            size_bytes INTEGER,
            source VARCHAR(100) NOT NULL,
            retrieval_meta_json JSONB NOT NULL DEFAULT '{}',
            captured_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
    """)
    
    # Create indexes for raw_evidence
    op.execute("CREATE INDEX ix_raw_evidence_job ON raw_evidence(job_id)")
    op.execute("CREATE INDEX ix_raw_evidence_sha256 ON raw_evidence(sha256)")
    op.execute("CREATE INDEX ix_raw_evidence_workspace ON raw_evidence(workspace_id)")
    
    # Create findings table
    op.execute("""
        CREATE TABLE findings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            investigation_id UUID,
            target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            finding_type VARCHAR(50) NOT NULL,
            subject VARCHAR(500) NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 50,
            data_json JSONB NOT NULL DEFAULT '{}',
            finding_fingerprint VARCHAR(64) NOT NULL,
            first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_findings_fingerprint UNIQUE (workspace_id, finding_fingerprint)
        )
    """)
    
    # Create indexes for findings
    op.execute("CREATE INDEX ix_findings_workspace_type ON findings(workspace_id, finding_type)")
    op.execute("CREATE INDEX ix_findings_subject ON findings(subject)")
    op.execute("CREATE INDEX ix_findings_job ON findings(job_id)")
    op.execute("CREATE INDEX ix_findings_target ON findings(target_id)")
    op.execute("CREATE INDEX ix_findings_finding_type ON findings(finding_type)")


def downgrade() -> None:
    # Drop tables in reverse order
    op.execute("DROP TABLE IF EXISTS findings CASCADE")
    op.execute("DROP TABLE IF EXISTS raw_evidence CASCADE")
    op.execute("DROP TABLE IF EXISTS jobs CASCADE")
    
    # Recreate old jobs table (simplified - matches migration 003)
    op.execute("""
        CREATE TABLE jobs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
            target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            created_by UUID NOT NULL,
            job_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            idempotency_key VARCHAR(32) NOT NULL UNIQUE,
            celery_task_id VARCHAR(36),
            config JSONB NOT NULL DEFAULT '{}',
            result JSONB,
            result_fingerprint VARCHAR(16),
            error_message TEXT,
            raw_evidence_path VARCHAR(500),
            retry_count INTEGER NOT NULL DEFAULT 0,
            max_retries INTEGER NOT NULL DEFAULT 3,
            timeout INTEGER NOT NULL DEFAULT 300,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            queued_at TIMESTAMP WITH TIME ZONE,
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE
        )
    """)
