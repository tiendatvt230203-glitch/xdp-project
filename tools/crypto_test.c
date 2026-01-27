/*
 * AES-128 CTR Packet Encryption Test
 *
 * Tests:
 * 1. Basic encrypt/decrypt roundtrip
 * 2. Full packet encrypt/decrypt (with Ethernet header preserved)
 * 3. Performance benchmark
 *
 * Usage: ./crypto_test [packet_count]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "../inc/packet_crypto.h"

#define TEST_PACKET_SIZE 1500
#define DEFAULT_PACKET_COUNT 1000000

/* Simulated Ethernet header */
static const uint8_t test_eth_header[ETH_HEADER_SIZE] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  /* Dest MAC */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  /* Src MAC */
    0x08, 0x00                            /* EtherType (IPv4) */
};

/* Test key and IV */
static const uint8_t test_key[AES128_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t test_iv[AES128_IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x ", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

static int test_buffer_roundtrip(void)
{
    printf("\n=== Test 1: Buffer Encrypt/Decrypt Roundtrip ===\n");

    struct packet_crypto_ctx ctx;
    if (packet_crypto_init(&ctx, test_key, test_iv) != 0) {
        printf("FAIL: Init failed\n");
        return -1;
    }

    /* Original data */
    uint8_t original[64] = "Hello, this is a test message for AES-128 CTR encryption!";
    uint8_t data[64];
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    size_t len = strlen((char *)original) + 1;

    memcpy(data, original, len);

    print_hex("Original", data, len);

    /* Encrypt */
    if (crypto_encrypt_buffer(&ctx, data, len, nonce) != 0) {
        printf("FAIL: Encrypt failed\n");
        return -1;
    }
    print_hex("Encrypted", data, len);
    print_hex("Nonce", nonce, CRYPTO_NONCE_SIZE);

    /* Decrypt */
    if (crypto_decrypt_buffer(&ctx, data, len, nonce) != 0) {
        printf("FAIL: Decrypt failed\n");
        return -1;
    }
    print_hex("Decrypted", data, len);

    /* Verify */
    if (memcmp(original, data, len) == 0) {
        printf("PASS: Data matches after roundtrip\n");
    } else {
        printf("FAIL: Data mismatch!\n");
        return -1;
    }

    packet_crypto_cleanup(&ctx);
    return 0;
}

static int test_packet_roundtrip(void)
{
    printf("\n=== Test 2: Full Packet Encrypt/Decrypt (ETH header preserved) ===\n");

    struct packet_crypto_ctx ctx;
    if (packet_crypto_init(&ctx, test_key, test_iv) != 0) {
        printf("FAIL: Init failed\n");
        return -1;
    }

    /* Create test packet: ETH header + IP-like payload */
    size_t original_len = 100;
    uint8_t original[128];
    uint8_t packet[128 + CRYPTO_NONCE_SIZE];  /* Extra space for nonce */

    /* Build packet */
    memcpy(original, test_eth_header, ETH_HEADER_SIZE);
    for (size_t i = ETH_HEADER_SIZE; i < original_len; i++) {
        original[i] = (uint8_t)(i & 0xff);  /* Simulated IP payload */
    }
    memcpy(packet, original, original_len);

    printf("Original packet size: %zu\n", original_len);
    print_hex("ETH header", packet, ETH_HEADER_SIZE);
    print_hex("Payload (L3+)", packet + ETH_HEADER_SIZE, 32);

    /* Encrypt */
    int new_len = packet_encrypt(&ctx, packet, original_len);
    if (new_len < 0) {
        printf("FAIL: Packet encrypt failed\n");
        return -1;
    }
    printf("\nAfter encryption (size: %d, added %d bytes for nonce)\n",
           new_len, (int)(new_len - original_len));
    print_hex("ETH header (unchanged)", packet, ETH_HEADER_SIZE);
    print_hex("Nonce", packet + ETH_HEADER_SIZE, CRYPTO_NONCE_SIZE);
    print_hex("Encrypted payload", packet + ETH_HEADER_SIZE + CRYPTO_NONCE_SIZE, 32);

    /* Verify ETH header unchanged */
    if (memcmp(packet, test_eth_header, ETH_HEADER_SIZE) != 0) {
        printf("FAIL: ETH header was modified!\n");
        return -1;
    }
    printf("PASS: ETH header preserved\n");

    /* Decrypt */
    int dec_len = packet_decrypt(&ctx, packet, (size_t)new_len);
    if (dec_len < 0) {
        printf("FAIL: Packet decrypt failed\n");
        return -1;
    }
    printf("\nAfter decryption (size: %d)\n", dec_len);
    print_hex("ETH header", packet, ETH_HEADER_SIZE);
    print_hex("Payload (L3+)", packet + ETH_HEADER_SIZE, 32);

    /* Verify full packet restored */
    if ((size_t)dec_len != original_len) {
        printf("FAIL: Size mismatch! Expected %zu, got %d\n", original_len, dec_len);
        return -1;
    }
    if (memcmp(packet, original, original_len) == 0) {
        printf("PASS: Packet fully restored\n");
    } else {
        printf("FAIL: Packet data mismatch!\n");
        return -1;
    }

    packet_crypto_cleanup(&ctx);
    return 0;
}

static int test_performance(int packet_count)
{
    printf("\n=== Test 3: Performance Benchmark ===\n");
    printf("Packet size: %d bytes, Count: %d\n", TEST_PACKET_SIZE, packet_count);

    struct packet_crypto_ctx ctx;
    if (packet_crypto_init(&ctx, test_key, test_iv) != 0) {
        printf("FAIL: Init failed\n");
        return -1;
    }

    /* Allocate packet buffer (with space for nonce) */
    uint8_t *packet = malloc(TEST_PACKET_SIZE + CRYPTO_NONCE_SIZE);
    if (!packet) {
        printf("FAIL: malloc failed\n");
        return -1;
    }

    /* Fill with test data */
    memcpy(packet, test_eth_header, ETH_HEADER_SIZE);
    for (int i = ETH_HEADER_SIZE; i < TEST_PACKET_SIZE; i++) {
        packet[i] = (uint8_t)(i & 0xff);
    }

    /* Benchmark encryption */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < packet_count; i++) {
        /* Reset packet for each iteration */
        int new_len = packet_encrypt(&ctx, packet, TEST_PACKET_SIZE);
        if (new_len < 0) {
            printf("FAIL: Encrypt failed at packet %d\n", i);
            free(packet);
            return -1;
        }
        /* Decrypt back */
        int dec_len = packet_decrypt(&ctx, packet, (size_t)new_len);
        if (dec_len < 0) {
            printf("FAIL: Decrypt failed at packet %d\n", i);
            free(packet);
            return -1;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double pps = packet_count / elapsed;
    double mbps = (pps * TEST_PACKET_SIZE * 8) / 1e6;
    double gbps = mbps / 1000;

    printf("\nResults (encrypt + decrypt per packet):\n");
    printf("  Time: %.3f seconds\n", elapsed);
    printf("  Packets/sec: %.0f\n", pps);
    printf("  Throughput: %.2f Mbps (%.3f Gbps)\n", mbps, gbps);
    printf("  Latency: %.3f us/packet\n", (elapsed / packet_count) * 1e6);

    /* Single operation benchmark */
    printf("\nEncrypt-only benchmark:\n");
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    for (int i = 0; i < packet_count; i++) {
        crypto_encrypt_buffer(&ctx, packet + ETH_HEADER_SIZE,
                              TEST_PACKET_SIZE - ETH_HEADER_SIZE, nonce);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    pps = packet_count / elapsed;
    mbps = (pps * (TEST_PACKET_SIZE - ETH_HEADER_SIZE) * 8) / 1e6;
    gbps = mbps / 1000;

    printf("  Packets/sec: %.0f\n", pps);
    printf("  Throughput: %.2f Mbps (%.3f Gbps)\n", mbps, gbps);

    free(packet);
    packet_crypto_cleanup(&ctx);
    return 0;
}

int main(int argc, char *argv[])
{
    int packet_count = DEFAULT_PACKET_COUNT;

    if (argc > 1) {
        packet_count = atoi(argv[1]);
        if (packet_count <= 0) packet_count = DEFAULT_PACKET_COUNT;
    }

    printf("========================================\n");
    printf("AES-128 CTR Packet Encryption Test\n");
    printf("========================================\n");

    int ret = 0;

    if (test_buffer_roundtrip() != 0) ret = -1;
    if (test_packet_roundtrip() != 0) ret = -1;
    if (test_performance(packet_count) != 0) ret = -1;

    printf("\n========================================\n");
    if (ret == 0) {
        printf("All tests PASSED\n");
    } else {
        printf("Some tests FAILED\n");
    }
    printf("========================================\n");

    return ret;
}
