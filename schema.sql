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
    src_mac TEXT,
    dst_mac TEXT
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
