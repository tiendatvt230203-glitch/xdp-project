DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_traffic_rules   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 30);
DELETE FROM xdp_profiles               WHERE config_id = 30;

DELETE FROM xdp_local_configs WHERE config_id = 30;
DELETE FROM xdp_wan_configs   WHERE config_id = 30;
DELETE FROM xdp_configs       WHERE id = 30;

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
(30, 1, '2b7e151628aed2a6abf7158809cf4f3c', 3, 99, 'ctr', 128, 16);

-- ONE local + 3 WAN (tạm thời gộp 3 WAN vào 1 profile)
INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(30, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname,
    src_ip,
    dst_ip,
    next_hop_ip,
    window_size_kb
) VALUES
(30, 'enp4s0', '192.168.11.1/24',  '192.168.11.2/24',  '192.168.11.2',  100),
(30, 'enp5s0', '192.168.131.1/24', '192.168.131.2/24', '192.168.131.2', 100),
(30, 'enp6s0', '192.168.203.1/24', '192.168.203.2/24', '192.168.203.2', 100);

-- Profile traffic rules (chỉ cần khớp src/dst để chọn đúng profile)
INSERT INTO xdp_profiles (
    config_id,
    profile_name,
    enabled,
    channel_bonding,
    description
) VALUES
(30, 'profile_default', 1, 1, 'l3 multi policy test');

-- bind locals/wans into that profile
INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, l.ifname
FROM xdp_profiles p
JOIN xdp_local_configs l ON l.config_id = p.config_id
WHERE p.config_id = 30;

INSERT INTO xdp_profile_wans (profile_id, ifname)
SELECT p.id, w.ifname
FROM xdp_profiles p
JOIN xdp_wan_configs w ON w.config_id = p.config_id
WHERE p.config_id = 30;

-- src=192.168.9.0/24 dst=192.168.182.0/24 (giống redirect rule cũ)
INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.9.0/24', '192.168.182.0/24'
FROM xdp_profiles p
WHERE p.config_id = 30;

-- MULTI encryption policies within L3 instance (encrypt_layer=3)
-- TCP dst_port=8080 => Encrypt L3 (CTR) policy id=100
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
    100,
    p.id,
    100,
    'encrypt_l3',
    'TCP',
    'Any',
    'Any',
    'Any',
    '8080',
    'ctr',
    128,
    16,
    '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 30;

-- UDP dst_port=5353 => Encrypt L3 (GCM) policy id=101
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
    101,
    p.id,
    100,
    'encrypt_l3',
    'UDP',
    'Any',
    'Any',
    'Any',
    '5353',
    'gcm',
    128,
    16,
    '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 30;

