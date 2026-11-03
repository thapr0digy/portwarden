-- M6 fix wave: PagedKeys looks marks up by literal prefix (tamper:<host>/) with LIKE; a
-- text_pattern_ops index serves it whatever the database collation.
CREATE INDEX IF NOT EXISTS alerter_dedupe_key_prefix ON alerter_dedupe (key text_pattern_ops);
