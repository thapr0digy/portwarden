-- M10: the instance's full name in its cloud (GCP "projects/<p>/zones/<z>/instances/<id>",
-- the Azure VM's resource id), from the agent's host block. '' from agents before M10.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS cloud_resource text NOT NULL DEFAULT '';
