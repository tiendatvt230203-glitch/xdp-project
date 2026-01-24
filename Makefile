CC = gcc
CLANG = clang
CFLAGS = -Iinc -Wall -O2
LDFLAGS = -lbpf -lxdp

# BPF flags
BPF_CFLAGS = -O2 -target bpf -g

# Kernel headers
KERNEL_HEADERS = /usr/include

# Source files
SRC = main.c \
      src/config.c \
      src/interface.c \
      src/forwarder.c

OBJ = $(SRC:.c=.o)
TARGET = xdp_forwarder

BPF_SRC = bpf/xdp_redirect.c
BPF_OBJ = bpf/xdp_redirect.o

.PHONY: all clean install run

all: $(BPF_OBJ) $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -f src/*.o *.o $(TARGET) $(BPF_OBJ)

# Run with sudo
run: all
	sudo ./$(TARGET) config.cfg
