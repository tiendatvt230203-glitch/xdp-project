CC = gcc
CLANG = clang
CFLAGS = -Iinc -Wall -O2
LDFLAGS = -lbpf -lxdp -lpthread -lssl -lcrypto

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin

SRC = main.c src/config.c src/interface.c src/forwarder.c src/packet_crypto.c src/flow_table.c
OBJ = $(SRC:.c=.o)
TARGET = $(BIN_DIR)/xdp_forwarder

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

TOOLS = $(BIN_DIR)/local_encrypt_dump $(BIN_DIR)/wan_decrypt_dump

.PHONY: all clean run dirs main tools

all: dirs $(BPF_OBJ) $(TARGET) $(TOOLS)

main: dirs $(BPF_OBJ) $(TARGET)

tools: dirs $(BPF_OBJ) $(TOOLS)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

$(BIN_DIR)/local_encrypt_dump: tools/local_encrypt_dump.c src/config.c src/interface.c src/packet_crypto.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/wan_decrypt_dump: tools/wan_decrypt_dump.c src/config.c src/interface.c src/packet_crypto.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o *.o $(BPF_OBJ)

run: main
	sudo $(TARGET) config.cfg
