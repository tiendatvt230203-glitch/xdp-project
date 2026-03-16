CC = gcc
CLANG = clang
CFLAGS = -D_GNU_SOURCE -Iinc -Wall -O2 $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -lbpf -lxdp -lpthread -lssl -lcrypto -lpq

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin

SRC = main.c src/config.c src/db_config.c src/interface.c src/forwarder.c src/packet_crypto.c src/crypto_layer2.c src/crypto_layer3.c src/crypto_layer4.c src/flow_table.c src/fragment.c
OBJ = $(SRC:.c=.o)
TARGET = $(BIN_DIR)/xdp_forwarder

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c bpf/xdp_wan_redirect_l2.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o bpf/xdp_wan_redirect_l2.o

.PHONY: all clean run dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o *.o bpf/*.o $(BPF_OBJ)

run:
	sudo $(TARGET) --db-url "host=localhost user=postgres dbname=xdpdb"
