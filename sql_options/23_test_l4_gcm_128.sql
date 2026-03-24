DELETE FROM xdp_local_configs WHERE config_id = 23;
DELETE FROM xdp_wan_configs  WHERE config_id = 23;
DELETE FROM xdp_configs      WHERE id = 23;

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
(23, 1, '2b7e151628aed2a6abf7158809cf4f3c', 4, 0, 'gcm', 128, 16);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(23, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname,
    src_ip,
    dst_ip,
    next_hop_ip,
    window_size_kb
) VALUES
(23, 'enp4s0', '192.168.11.1/24',  '192.168.11.2/24',  '192.168.11.2',  100),
(23, 'enp5s0', '192.168.131.1/24', '192.168.131.2/24', '192.168.131.2', 100),
(23, 'enp6s0', '192.168.203.1/24', '192.168.203.2/24', '192.168.203.2', 100);

INSERT INTO xdp_redirect_rules (
    config_id,
    src_cidr,
    dst_cidr
) VALUES
(23, '192.168.9.0/24' , '192.168.182.0/24');

