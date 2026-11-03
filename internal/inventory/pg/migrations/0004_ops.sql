-- M8: each host's latest tamper status (inventory.TamperView as JSON) and the stream time
-- it arrived; both NULL until an agent sent one.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS tamper jsonb;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS tamper_at timestamptz;

-- M8: hosts an operator forgot, with the stream sequence of the pwb.inventory.<host>.forgotten
-- announcement: the host's messages stored before it are skipped; later ones make it a
-- new host. Kept after the host comes back (the watermark still applies).
CREATE TABLE IF NOT EXISTS forgotten_hosts (
	host_id      text PRIMARY KEY,
	stream_seq   bigint NOT NULL,
	forgotten_at timestamptz NOT NULL DEFAULT now()
);

-- M8 retention: age-ordered batch deletes.
CREATE INDEX IF NOT EXISTS exposure_history_at ON exposure_history (at);
CREATE INDEX IF NOT EXISTS quarantine_at ON quarantine (at);
