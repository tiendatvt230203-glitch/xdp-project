-- Server02 (site 192.168.182.0/24 + 192.168.180.0/24)
-- Mapping:
--   (192.168.182.2 <-> 192.168.9.2)    -> WAN1+WAN2 (enp4s0,enp5s0)
--   (192.168.180.2 <-> 192.168.10.2)   -> WAN2+WAN3 (enp5s0,enp6s0)

DELETE FROM xdp_profile_crypto_policies WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_traffic_rules   WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_locals          WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profile_wans            WHERE profile_id IN (SELECT id FROM xdp_profiles WHERE config_id = 31);
DELETE FROM xdp_profiles               WHERE config_id = 31;

DELETE FROM xdp_local_configs  WHERE config_id = 31;
DELETE FROM xdp_wan_configs    WHERE config_id = 31;
DELETE FROM xdp_redirect_rules WHERE config_id = 31;
DELETE FROM xdp_configs        WHERE id = 31;

-- encrypt_layer: legacy global (2/3/4); forwarder uses per-policy action for crypto.
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

-- Hai NIC local: 182.x trên enp7s0, 180.x trên eno2 (đổi nếu máy bạn gán port khác).
INSERT INTO xdp_local_configs (config_id, ifname, network) VALUES
(31, 'enp7s0', '192.168.182.0/24'),
(31, 'eno2', '192.168.180.0/24');

-- WAN peer (Sep device) IPs on the other end of each L2 WAN link
INSERT INTO xdp_wan_configs (config_id, ifname, dst_ip, window_size_kb) VALUES
(31, 'enp4s0', '192.168.11.1/24',  100),
(31, 'enp5s0', '192.168.131.1/24', 100),
(31, 'enp6s0', '192.168.203.1/24', 100);

-- Two profiles for two src/dst host pairs
INSERT INTO xdp_profiles (config_id, profile_name, enabled, channel_bonding, description) VALUES
(31, 'profile_182_to_9',  1, 1, '192.168.182.2 <-> 192.168.9.2 via WAN1+WAN2'),
(31, 'profile_180_to_10', 1, 1, '192.168.180.2 <-> 192.168.10.2 via WAN2+WAN3');

-- profile_182_to_9 bind enp7s0; profile_180_to_10 bind eno2.
INSERT INTO xdp_profile_locals (profile_id, ifname)
SELECT p.id, w.ifname
FROM xdp_profiles p
JOIN (VALUES
    ('profile_182_to_9',  'enp7s0'),
    ('profile_180_to_10', 'eno2')
) AS w(profile_name, ifname)
ON w.profile_name = p.profile_name
WHERE p.config_id = 31;

-- Profile-specific WAN pools
INSERT INTO xdp_profile_wans (profile_id, ifname)
SELECT p.id, w.ifname
FROM xdp_profiles p
JOIN (VALUES
    ('profile_182_to_9',  'enp4s0'),
    ('profile_182_to_9',  'enp5s0'),
    ('profile_180_to_10', 'enp5s0'),
    ('profile_180_to_10', 'enp6s0')
) AS w(profile_name, ifname)
ON w.profile_name = p.profile_name
WHERE p.config_id = 31;

-- XDP redirect rules (ensure packets reach userspace forwarder)
INSERT INTO xdp_redirect_rules (config_id, src_cidr, dst_cidr) VALUES
(31, '192.168.182.0/24', '192.168.9.0/24'),
(31, '192.168.180.0/24', '192.168.10.0/24');

-- Profile traffic rules (host-specific; profile match should also accept reverse direction)
INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.182.2/32', '192.168.9.2/32'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_182_to_9';

INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
SELECT p.id, '192.168.180.2/32', '192.168.10.2/32'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

-- Crypto policies per profile (IDs must be consistent across sites; on-wire policy_id = id & 0x7F)
-- Profile: 182<->9
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    201, p.id, 100, 'encrypt_l3', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 16, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_182_to_9';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    202, p.id, 100, 'encrypt_l4', 'TCP',
    'Any', 'Any', 'Any', 'Any',
    'ctr', 128, 16, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_182_to_9';

-- Profile: 180<->10
INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    203, p.id, 100, 'encrypt_l3', 'UDP',
    'Any', 'Any', 'Any', 'Any',
    'gcm', 128, 16, '2b7e151628aed2a6abf7158809cf4f3c'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

INSERT INTO xdp_profile_crypto_policies (
    id, profile_id, priority, action, protocol,
    src_cidr, src_port, dst_cidr, dst_port,
    crypto_mode, aes_bits, nonce_size, crypto_key
)
SELECT
    204, p.id, 100, 'encrypt_l4', 'TCP',
    'Any', 'Any', 'Any', 'Any',
    'ctr', 128, 16, '5b95b6540e1785f1797661e2413becd5'
FROM xdp_profiles p
WHERE p.config_id = 31 AND p.profile_name = 'profile_180_to_10';

