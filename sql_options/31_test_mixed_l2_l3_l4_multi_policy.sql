DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_traffic_rules   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profiles               WHERE config_id = 31;

DELETE FROM xdp_local_configs WHERE config_id = 31;
DELETE FROM xdp_wan_configs   WHERE config_id = 31;
DELETE FROM xdp_configs       WHERE id = 31;

-- encrypt_layer: legacy global (2/3/4); forwarder still uses local L3/L4 workers + per-policy action for crypto.
INSERT INTO xdp_configs (
    id,
    crypto_enabled,
    crypto_key,
    encrypt_layer,
    fake_protocol,
    crypto_mode,
    aes_bits,
    nonce_size
) VALUES
(31, 1, '2b7e151628aed2a6abf7158809cf4f3c', 3, 99, 'ctr', 128, 16);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(31, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname,
    src_ip,
    dst_ip,
    next_hop_ip,
    window_size_kb
) VALUES
(31, 'enp4s0', '192.168.11.1/24',  '192.168.11.2/24',  '192.168.11.2',  100),
(31, 'enp5s0', '192.168.131.1/24', '192.168.131.2/24', '192.168.131.2', 100),
(31, 'enp6s0', '192.168.203.1/24', '192.168.203.2/24', '192.168.203.2', 100);

INSERT INTO xdp_profiles (
    config_id,
    profile_name,
    enabled,
    channel_bonding,
    description
) VALUES
(31, 'profile_default', 1, 1, 'mixed L3/L4: UDP=L3, TCP=L4');

INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, l.ifname
FROM xdp_profiles p
JOIN xdp_local_configs l ON l.config_id = p.config_id
WHERE p.config_id = 31;

INSERT INTO xdp_profile_wans (profile_id, ifname)
SELECT p.id, w.ifname
FROM xdp_profiles p
JOIN xdp_wan_configs w ON w.config_id = p.config_id
WHERE p.config_id = 31;

-- One rule is enough: config_select_profile_for_flow() matches the reverse direction too.
INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.9.0/24', '192.168.182.0/24'
FROM xdp_profiles p
WHERE p.config_id = 31;

-- Policy 201: UDP -> L3 GCM. Policy 202: TCP -> L4 CTR. Keep protocol column non-NULL (avoid ANY stealing TCP).
INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    201,
    p.id,
    100,
    'encrypt_l3',
    'UDP',
    'Any',
    'Any',
    'Any',
    'Any',
    'gcm',
    128,
    16,
    '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31;

INSERT INTO xdp_profile_crypto_policies (
    id,
    profile_id,
    priority,
    action,
    protocol,
    src_cidr,
    src_port,
    dst_cidr,
    dst_port,
    crypto_mode,
    aes_bits,
    nonce_size,
    crypto_key
)
SELECT
    202,
    p.id,
    100,
    'encrypt_l4',
    'TCP',
    'Any',
    'Any',
    'Any',
    'Any',
    'ctr',
    128,
    16,
    '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31;
