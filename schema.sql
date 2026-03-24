CREATE TABLE IF NOT EXISTS xdp_configs (
    id SERIAL PRIMARY KEY,
    crypto_enabled INT DEFAULT 0,
    crypto_key TEXT,
    encrypt_layer INT DEFAULT 0,
    fake_protocol INT DEFAULT 0,
    crypto_mode TEXT DEFAULT 'ctr',
    aes_bits INT DEFAULT 128,
    nonce_size INT DEFAULT 12
);

CREATE TABLE IF NOT EXISTS xdp_local_configs (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    network TEXT
);

CREATE TABLE IF NOT EXISTS xdp_wan_configs (
    id SERIAL PRIMARY KEY,
    config_id INT NOT NULL REFERENCES xdp_configs(id) ON DELETE CASCADE,
    ifname VARCHAR(32) NOT NULL,
    src_mac VARCHAR(32) DEFAULT '',
    dst_mac VARCHAR(32) DEFAULT '',
    window_size_kb INT DEFAULT 8192
);

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
    action VARCHAR(32) NOT NULL,              -- bypass / encrypt_l2 / encrypt_l3 / encrypt_l4
    protocol VARCHAR(16) DEFAULT 'ANY',       -- TCP/UDP/ICMP/OSPF/ANY
    src_cidr TEXT DEFAULT 'ANY',
    src_port VARCHAR(32) DEFAULT 'ANY',       -- ANY / 443 / 1000-2000
    dst_cidr TEXT DEFAULT 'ANY',
    dst_port VARCHAR(32) DEFAULT 'ANY',
    crypto_mode VARCHAR(16) DEFAULT 'gcm',    -- gcm / ctr
    aes_bits INT DEFAULT 128,                 -- 128 / 256
    nonce_size INT DEFAULT 12,
    crypto_key TEXT                           -- hex string
);

CREATE INDEX IF NOT EXISTS idx_profiles_config_id ON xdp_profiles(config_id);
CREATE INDEX IF NOT EXISTS idx_profile_locals_profile_id ON xdp_profile_locals(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_wans_profile_id ON xdp_profile_wans(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_rules_profile_id ON xdp_profile_traffic_rules(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_policies_profile_id ON xdp_profile_crypto_policies(profile_id);
