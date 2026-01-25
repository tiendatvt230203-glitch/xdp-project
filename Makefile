CC = gcc
CLANG = clang
CFLAGS = -Iinc -Wall -O2
LDFLAGS = -lbpf -lxdp

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

SRC = main.c src/config.c src/interface.c src/forwarder.c
OBJ = $(SRC:.c=.o)
TARGET = xdp_forwarder

# Test tools
LB_TEST_SRC = tools/lb_test.c src/config.c src/interface.c
LB_TEST = lb_test

BPF_SRC = bpf/xdp_redirect.c
BPF_OBJ = bpf/xdp_redirect.o

.PHONY: all clean run test

all: $(BPF_OBJ) $(TARGET) $(LB_TEST)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

$(LB_TEST): $(LB_TEST_SRC)
	$(CC) $(CFLAGS) $(LB_TEST_SRC) -o $(LB_TEST) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -f src/*.o tools/*.o *.o $(TARGET) $(LB_TEST) $(BPF_OBJ)

run: all
	sudo ./$(TARGET) config.cfg

test: $(LB_TEST)
	sudo ./$(LB_TEST) config.txt
