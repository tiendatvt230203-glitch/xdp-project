CREATE TABLE IF NOT EXISTS xdp_configs (
    id SERIAL PRIMARY KEY
);

-- Schema cleanup: legacy crypto fields moved to xdp_profile_crypto_policies
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS crypto_enabled;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS crypto_key;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS encrypt_layer;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS fake_protocol;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS crypto_mode;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS aes_bits;
ALTER TABLE xdp_configs DROP COLUMN IF EXISTS nonce_size;

CREATE TABLE IF NOT EXISTS xdp_local_configs (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    network TEXT,
    ingress_mbps INT DEFAULT 0
);

ALTER TABLE xdp_local_configs ADD COLUMN IF NOT EXISTS ingress_mbps INT DEFAULT 0;

CREATE TABLE IF NOT EXISTS xdp_wan_configs (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    dst_ip VARCHAR(32) DEFAULT ''
);


ALTER TABLE xdp_wan_configs ADD COLUMN IF NOT EXISTS dst_ip VARCHAR(32) DEFAULT '';

ALTER TABLE xdp_wan_configs DROP COLUMN IF EXISTS window_size_kb;

ALTER TABLE xdp_wan_configs DROP COLUMN IF EXISTS src_ip;
ALTER TABLE xdp_wan_configs DROP COLUMN IF EXISTS next_hop_ip;

CREATE TABLE IF NOT EXISTS xdp_redirect_rules (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    src_cidr TEXT NOT NULL,
    dst_cidr TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_redirect_config_id ON xdp_redirect_rules(config_id);
CREATE INDEX IF NOT EXISTS idx_local_config_id   ON xdp_local_configs(config_id);
CREATE INDEX IF NOT EXISTS idx_wan_config_id     ON xdp_wan_configs(config_id);

CREATE TABLE IF NOT EXISTS xdp_profiles (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    profile_name VARCHAR(64) NOT NULL,
    enabled INT DEFAULT 1,
    channel_bonding INT DEFAULT 1,
    description TEXT
);

CREATE TABLE IF NOT EXISTS xdp_profile_locals (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL
);

CREATE TABLE IF NOT EXISTS xdp_profile_wans (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL
);

ALTER TABLE xdp_profile_wans ADD COLUMN IF NOT EXISTS bandwidth_weight_percent INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS xdp_profile_traffic_rules (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    src_cidr TEXT NOT NULL,
    dst_cidr TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdp_profile_crypto_policies (
    id SERIAL PRIMARY KEY,
    profile_id INT NOT NULL REFERENCES xdp_profiles(id) ON DELETE CASCADE,
    priority INT DEFAULT 100,
    action VARCHAR(32) NOT NULL,             
    protocol VARCHAR(16) DEFAULT 'ANY',      
    src_cidr TEXT DEFAULT 'ANY',
    src_port VARCHAR(32) DEFAULT 'ANY',       
    dst_cidr TEXT DEFAULT 'ANY',
    dst_port VARCHAR(32) DEFAULT 'ANY',
    crypto_mode VARCHAR(16) DEFAULT 'gcm',    
    aes_bits INT DEFAULT 128,                 
    nonce_size INT DEFAULT 12,
    crypto_key TEXT                           
);

CREATE INDEX IF NOT EXISTS idx_profiles_config_id ON xdp_profiles(config_id);
CREATE INDEX IF NOT EXISTS idx_profile_locals_profile_id ON xdp_profile_locals(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_wans_profile_id ON xdp_profile_wans(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_rules_profile_id ON xdp_profile_traffic_rules(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_policies_profile_id ON xdp_profile_crypto_policies(profile_id);