-- M5 fix wave: run ordering by boot id and run counter, quarantined messages.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS boot_id text NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS run_number bigint NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS retired_runs text[] NOT NULL DEFAULT '{}';

-- Messages the inventory will never apply (undecodable, rejected by the database,
-- forged origins, or still failing on their last delivery), kept raw for inspection.
CREATE TABLE IF NOT EXISTS quarantine (
	id         bigserial PRIMARY KEY,
	stream_seq bigint NOT NULL,
	subject    text NOT NULL,
	error      text NOT NULL,
	data       bytea NOT NULL,
	at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS listeners_probe ON listeners (probe_at) WHERE level >= 2;
