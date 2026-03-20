DELETE FROM xdp_local_configs WHERE config_id = 6;
DELETE FROM xdp_wan_configs  WHERE config_id = 6;
DELETE FROM xdp_configs      WHERE id = 6;

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
(6, 1, '2b7e151628aed2a6abf7158809cf4f3c', 3, 99, 'ctr', 128, 16);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(6, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname
) VALUES
(6, 'enp4s0'),
(6, 'enp5s0'),
(6, 'enp6s0');

INSERT INTO xdp_redirect_rules (
    config_id,
    src_cidr,
    dst_cidr
) VALUES
(6, '192.168.9.0/24' , '192.168.182.0/24');

