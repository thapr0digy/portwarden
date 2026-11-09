-- M11: the agent's identity as its latest message reports it (self-reported, not
-- attestation): its version, the hex SHA-256 of its executable ('' from older agents or
-- when the agent could not read it), and the stream time of the run's clean-shutdown
-- marker (NULL while the agent runs, and before any marker).
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_version text NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_exe_sha256 text NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS agent_stopped_at timestamptz;
