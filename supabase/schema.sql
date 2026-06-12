create table if not exists audit_jobs (
  id text primary key,
  payer text not null,
  network text not null check (network in ('mainnet', 'testnet')),
  package_id text not null,
  package_summary jsonb not null,
  snapshot_hash text not null,
  status text not null check (status in ('prepared', 'paid', 'queued', 'running', 'completed', 'failed')),
  sui_job_object_id text not null,
  sui_transaction_digest text not null,
  report_object_id text,
  finalized_digest text,
  artifacts jsonb,
  report jsonb,
  public_report_markdown text,
  private_report_markdown text,
  verification jsonb,
  source_context jsonb,
  source_url text,
  attempts integer not null default 0,
  max_attempts integer not null default 3,
  locked_by text,
  locked_at timestamptz,
  lock_expires_at timestamptz,
  last_error text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null,
  updated_at timestamptz not null default now()
);

create index if not exists audit_jobs_payer_created_at_idx
  on audit_jobs (payer, created_at desc);

create unique index if not exists audit_jobs_sui_job_object_id_idx
  on audit_jobs (sui_job_object_id);

create index if not exists audit_jobs_queue_claim_idx
  on audit_jobs (status, lock_expires_at, created_at);
