-- M8: hosts an operator forgot (pwb.inventory.<host>.forgotten), with the announcement's
-- stream sequence and the stream's identity (its creation time): the host's messages
-- stored before it are skipped (the heartbeat consumer's start-up replay included); later
-- ones are a new host. back: the host has sent an agent message since (until then cloud
-- and verifier verdicts about it are skipped). Marks of another stream, or past its last
-- sequence, are dropped at start.
CREATE TABLE IF NOT EXISTS alerter_forgotten (
	host           text PRIMARY KEY,
	stream_seq     bigint NOT NULL,
	stream_created timestamptz NOT NULL,
	back           boolean NOT NULL DEFAULT false,
	at             timestamptz NOT NULL DEFAULT now()
);
-- ClearProbes looks probe results up by literal prefix (<host>/) with LIKE.
CREATE INDEX IF NOT EXISTS alerter_probe_key_prefix ON alerter_probe (key text_pattern_ops);
