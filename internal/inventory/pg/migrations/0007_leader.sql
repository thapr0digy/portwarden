-- Hot standbys: the leader's epoch (README "Running a standby"). The instance holding the
-- leader lock bumps it on taking the lead; every write checks it FOR SHARE first, so an
-- old leader can no longer commit once a new one has started.
CREATE TABLE IF NOT EXISTS inventory_leader (
	id     smallint PRIMARY KEY CHECK (id = 1),
	epoch  bigint NOT NULL,
	holder text NOT NULL DEFAULT '',
	since  timestamptz
);
INSERT INTO inventory_leader (id, epoch) VALUES (1, 0) ON CONFLICT DO NOTHING;
