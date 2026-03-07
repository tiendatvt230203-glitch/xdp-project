DELETE FROM xdp_local_configs WHERE config_id = 4;
DELETE FROM xdp_wan_configs  WHERE config_id = 4;
DELETE FROM xdp_configs      WHERE id = 4;

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
(4, 1, '5cb0851b5b2408bbed5dd5672cc4b04564857bfe6c518d92fcacc938a789aab6', 2, 0, 'gcm', 256, 16);

INSERT INTO xdp_local_configs (
    config_id,
    ifname,
    network,
    src_mac,
    dst_mac
) VALUES
(4, 'enp7s0', '192.168.9.0/24', '20:7c:14:f8:0c:d2', '20:7c:14:f8:0d:08');

INSERT INTO xdp_wan_configs (
    config_id,
    ifname,
    src_mac,
    dst_mac
) VALUES
(4, 'enp4s0', '20:7c:14:f8:0c:cf', '20:7c:14:f8:0d:4d'),
(4, 'enp5s0', '20:7c:14:f8:0c:d0', '20:7c:14:f8:0d:4e'),
(4, 'enp6s0', '20:7c:14:f8:0c:d1', '20:7c:14:f8:0d:4f');

