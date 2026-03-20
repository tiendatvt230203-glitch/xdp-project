DELETE FROM xdp_local_configs WHERE config_id = 14;
DELETE FROM xdp_wan_configs  WHERE config_id = 14;
DELETE FROM xdp_configs      WHERE id = 14;

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
(14, 0, NULL, 0, 0, 'ctr', 128, 12);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(14, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname
) VALUES
(14, 'enp4s0'),
(14, 'enp5s0'),
(14, 'enp6s0');

INSERT INTO xdp_redirect_rules (
    config_id,
    src_cidr,
    dst_cidr
) VALUES
(14, '192.168.9.0/24' , '192.168.182.0/24');

