-- Portwarden inventory schema v1. Levels use the proto's numbering: 0 unset, 1 local,
-- 2 bound, 3 host_firewall_open, 4 cloud_open, 5 confirmed.
CREATE TABLE IF NOT EXISTS hosts (
	host_id          text PRIMARY KEY,
	cloud            text NOT NULL DEFAULT '',
	instance_id      text NOT NULL DEFAULT '',
	region           text NOT NULL DEFAULT '',
	public_ips       jsonb NOT NULL DEFAULT '[]',
	conditions       jsonb NOT NULL DEFAULT '[]',
	run_id           text NOT NULL DEFAULT '',
	last_seq         bigint NOT NULL DEFAULT 0,
	needs_resync     boolean NOT NULL DEFAULT false,
	last_snapshot_at timestamptz,
	last_heartbeat   timestamptz,
	ringbuf_drops    bigint NOT NULL DEFAULT 0,
	queue_drops      bigint NOT NULL DEFAULT 0,
	silent_since     timestamptz,
	cloud_status     text NOT NULL DEFAULT '',
	cloud_checked_at timestamptz,
	first_seen       timestamptz NOT NULL DEFAULT now(),
	updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS listeners (
	host_id        text NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
	key            text NOT NULL,
	netns          bigint NOT NULL,
	proto          text NOT NULL,
	addr           text NOT NULL,
	port           integer NOT NULL,
	processes      jsonb NOT NULL DEFAULT '[]',
	behind_proxy   jsonb NOT NULL DEFAULT '[]',
	agent_level    smallint NOT NULL DEFAULT 0,
	agent_evidence jsonb NOT NULL DEFAULT '[]',
	cloud_level    smallint NOT NULL DEFAULT 0,
	cloud_evidence jsonb NOT NULL DEFAULT '[]',
	cloud_at       timestamptz,
	probe_result   text NOT NULL DEFAULT '',
	probe          jsonb,
	probe_at       timestamptz,
	-- Effective level: the highest of the agent's, the cloud's and 5 for a confirmed probe.
	level          smallint NOT NULL DEFAULT 0,
	opened_at      timestamptz NOT NULL,
	updated_at     timestamptz NOT NULL,
	PRIMARY KEY (host_id, key)
);
CREATE INDEX IF NOT EXISTS listeners_port ON listeners (port, proto);
CREATE INDEX IF NOT EXISTS listeners_level ON listeners (level);

CREATE TABLE IF NOT EXISTS exposure_history (
	id             bigserial PRIMARY KEY,
	host_id        text NOT NULL,
	key            text NOT NULL,
	at             timestamptz NOT NULL,
	-- agent, cloud or verifier
	origin         text NOT NULL,
	level          smallint NOT NULL,
	previous_level smallint,
	evidence       jsonb NOT NULL DEFAULT '[]',
	trigger        text NOT NULL DEFAULT '',
	detail         jsonb,
	stream_seq     bigint NOT NULL,
	UNIQUE (stream_seq, host_id, key)
);
CREATE INDEX IF NOT EXISTS exposure_history_listener ON exposure_history (host_id, key, at DESC);

CREATE TABLE IF NOT EXISTS proxies (
	host_id       text NOT NULL REFERENCES hosts (host_id) ON DELETE CASCADE,
	proxy_id      text NOT NULL,
	kind          text NOT NULL,
	proxy         jsonb NOT NULL,
	routes        jsonb NOT NULL DEFAULT '[]',
	route_count   integer NOT NULL DEFAULT 0,
	routes_digest text NOT NULL DEFAULT '',
	truncated     boolean NOT NULL DEFAULT false,
	trigger       text NOT NULL DEFAULT '',
	updated_at    timestamptz NOT NULL,
	PRIMARY KEY (host_id, proxy_id)
);
