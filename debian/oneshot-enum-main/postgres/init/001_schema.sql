-- Schema for oneshot-enum (idempotent)

CREATE TABLE IF NOT EXISTS scans (
  id         SERIAL PRIMARY KEY,
  target     TEXT NOT NULL,
  metadata   JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scans_target_idx ON scans(target);

CREATE TABLE IF NOT EXISTS httpx_pages (
  id          SERIAL PRIMARY KEY,
  scan_id     INT REFERENCES scans(id) ON DELETE CASCADE,
  url         TEXT,
  title       TEXT,
  status_code INT,
  tech        JSONB,
  headers     JSONB,
  raw         JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nuclei_findings (
  id          SERIAL PRIMARY KEY,
  scan_id     INT REFERENCES scans(id) ON DELETE CASCADE,
  template    TEXT,
  severity    TEXT,
  matcher     TEXT,
  evidence    JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS artifacts (
  id          SERIAL PRIMARY KEY,
  scan_id     INT REFERENCES scans(id) ON DELETE CASCADE,
  name        TEXT,
  path        TEXT,
  size_bytes  BIGINT,
  sha256      TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

