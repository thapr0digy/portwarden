-- M7: the agent's firewall fingerprint (a digest of its parsed ruleset) and when it last
-- changed. Both NULL until an agent message carried one; firewall_fingerprint is '' while
-- the host's firewall cannot be read in full.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS firewall_fingerprint text;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS firewall_changed_at timestamptz;
