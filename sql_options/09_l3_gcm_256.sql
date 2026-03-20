DELETE FROM xdp_local_configs WHERE config_id = 9;
DELETE FROM xdp_wan_configs  WHERE config_id = 9;
DELETE FROM xdp_configs      WHERE id = 9;

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
(9, 1, '5cb0851b5b2408bbed5dd5672cc4b04564857bfe6c518d92fcacc938a789aab6', 3, 99, 'gcm', 256, 16);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network
) VALUES
(9, 'enp7s0', '192.168.9.0/24');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname
) VALUES
(9, 'enp4s0'),
(9, 'enp5s0'),
(9, 'enp6s0');

INSERT INTO xdp_redirect_rules (
    config_id,
    src_cidr,
    dst_cidr
) VALUES
(9, '192.168.9.0/24' , '192.168.182.0/24');

