-- M11: each host's current agent run, for agent_restarted_unclean: the run's id, boot id
-- and counter, the version it reported (identity: it reported one, so it sends a
-- clean-shutdown marker), and whether that marker arrived.
CREATE TABLE IF NOT EXISTS alerter_runs (
	host       text PRIMARY KEY,
	run_id     text NOT NULL,
	boot_id    text NOT NULL,
	run_number bigint NOT NULL,
	version    text NOT NULL,
	identity   boolean NOT NULL,
	clean_stop boolean NOT NULL,
	at         timestamptz NOT NULL DEFAULT now()
);
