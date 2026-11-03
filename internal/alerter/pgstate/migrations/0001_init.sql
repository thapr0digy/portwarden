-- Portwarden alerter state: the outbox of pages, dedupe marks and the last probe result
-- per listener. Shares a database with the inventory or not; its own tables and
-- migrations table (alerter_schema_migrations).
CREATE TABLE IF NOT EXISTS alerter_pages (
	id           text PRIMARY KEY,
	kind         text NOT NULL,
	host         text NOT NULL DEFAULT '',
	payload      jsonb NOT NULL,
	created_at   timestamptz NOT NULL DEFAULT now(),
	attempts     integer NOT NULL DEFAULT 0,
	next_attempt timestamptz NOT NULL DEFAULT now(),
	delivered_at timestamptz,
	gave_up_at   timestamptz,
	last_error   text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerter_pages_due ON alerter_pages (next_attempt) WHERE delivered_at IS NULL AND gave_up_at IS NULL;

CREATE TABLE IF NOT EXISTS alerter_dedupe (
	key      text PRIMARY KEY,
	paged_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS alerter_probe (
	key    text PRIMARY KEY,
	result text NOT NULL,
	at     timestamptz NOT NULL
);
