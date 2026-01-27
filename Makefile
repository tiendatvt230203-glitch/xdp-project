CC = gcc
CLANG = clang
CFLAGS = -Iinc -Wall -O2
LDFLAGS = -lbpf -lxdp -lpthread

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

# Directories
BIN_DIR = bin

# Main program
SRC = main.c src/config.c src/interface.c src/forwarder.c
OBJ = $(SRC:.c=.o)
TARGET = $(BIN_DIR)/xdp_forwarder

# BPF
BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

# Test tools
TOOLS = $(BIN_DIR)/lb_test \
        $(BIN_DIR)/xdp_recv_test \
        $(BIN_DIR)/xdp_debug \
        $(BIN_DIR)/xdp_stats \
        $(BIN_DIR)/xdp_full_test \
        $(BIN_DIR)/xdp_mq_test \
        $(BIN_DIR)/local_tx_stress \
        $(BIN_DIR)/crypto_test

.PHONY: all clean run dirs

all: dirs $(BPF_OBJ) $(TARGET) $(TOOLS)

dirs:
        @mkdir -p $(BIN_DIR)

$(TARGET): $(OBJ)
        $(CC) $(OBJ) -o $@ $(LDFLAGS)

$(BIN_DIR)/lb_test: tools/lb_test.c src/config.c src/interface.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/xdp_recv_test: tools/xdp_recv_test.c src/config.c src/interface.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/xdp_debug: tools/xdp_debug.c src/config.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/xdp_stats: tools/xdp_stats.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/xdp_full_test: tools/xdp_full_test.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/xdp_mq_test: tools/xdp_multiqueue_test.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/local_tx_stress: tools/local_tx_stress.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/crypto_test: tools/crypto_test.c src/packet_crypto.c
        $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lssl -lcrypto

%.o: %.c
        $(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
        $(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
        rm -rf $(BIN_DIR) src/*.o *.o $(BPF_OBJ)

run: all
        sudo $(TARGET) config.cfg
