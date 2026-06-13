/* global console, process */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { Pool } from "pg";

loadLocalEnvFiles();

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required to apply the schema.");
}

const schema = readFileSync(resolve(process.cwd(), "../../supabase/schema.sql"), "utf8").replace(
  /create index if not exists audit_jobs_queue_claim_idx\s+on audit_jobs \(status, lock_expires_at, created_at\);\s*/m,
  "",
);
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: { rejectUnauthorized: false },
});

const refreshStatusConstraint = `
alter table audit_jobs add column if not exists attempts integer not null default 0;
alter table audit_jobs add column if not exists max_attempts integer not null default 3;
alter table audit_jobs add column if not exists locked_by text;
alter table audit_jobs add column if not exists locked_at timestamptz;
alter table audit_jobs add column if not exists lock_expires_at timestamptz;
alter table audit_jobs add column if not exists last_error text;
alter table audit_jobs add column if not exists started_at timestamptz;
alter table audit_jobs add column if not exists completed_at timestamptz;
alter table audit_jobs add column if not exists source_context jsonb;
alter table audit_jobs add column if not exists source_url text;
alter table audit_jobs drop constraint if exists audit_jobs_status_check;
alter table audit_jobs add constraint audit_jobs_status_check
  check (status in ('prepared', 'paid', 'queued', 'running', 'completed', 'failed'));
create index if not exists audit_jobs_queue_claim_idx
  on audit_jobs (status, lock_expires_at, created_at);
`;

const client = await pool.connect();
try {
  await client.query("begin");
  await client.query(schema);
  await client.query(refreshStatusConstraint);
  await client.query("commit");
  console.log("Supabase schema applied: audit_jobs table, queued status, and indexes.");
} catch (error) {
  await client.query("rollback");
  throw error;
} finally {
  client.release();
  await pool.end();
}

function loadLocalEnvFiles() {
  const protectedKeys = new Set(Object.keys(process.env));
  for (const file of [".env"]) {
    const path = resolve(process.cwd(), file);
    if (!existsSync(path)) continue;
    for (const [key, value] of Object.entries(parseEnvFile(readFileSync(path, "utf8")))) {
      if (!protectedKeys.has(key)) {
        process.env[key] = value;
      }
    }
  }
}

function parseEnvFile(contents) {
  const values = {};
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    values[match[1]] = normalizeEnvValue(match[2] ?? "");
  }
  return values;
}

function normalizeEnvValue(raw) {
  const value = raw.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1).replaceAll("\\n", "\n");
  }
  const commentStart = value.indexOf(" #");
  return commentStart === -1 ? value : value.slice(0, commentStart).trim();
}
