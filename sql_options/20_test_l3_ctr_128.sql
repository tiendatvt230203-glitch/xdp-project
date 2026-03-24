DELETE FROM xdp_local_configs WHERE config_id = 20;
DELETE FROM xdp_wan_configs  WHERE config_id = 20;
DELETE FROM xdp_configs      WHERE id = 20;

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
(20, 1, '2b7e151628aed2a6abf7158809cf4f3c', 3, 99, 'ctr', 128, 16);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(20, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname,
    src_mac,
    dst_mac,
    window_size_kb
) VALUES
(20, 'enp4s0', '20:7c:14:f8:0c:cf', '20:7c:14:f8:0d:4d', 100),
(20, 'enp5s0', '20:7c:14:f8:0c:d0', '20:7c:14:f8:0d:4e', 100),
(20, 'enp6s0', '20:7c:14:f8:0c:d1', '20:7c:14:f8:0d:4f', 100);

INSERT INTO xdp_redirect_rules (
    config_id,
    src_cidr,
    dst_cidr
) VALUES
(20, '192.168.9.0/24' , '192.168.182.0/24');

