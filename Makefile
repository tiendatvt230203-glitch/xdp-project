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

XDP_RECV_TEST_SRC = tools/xdp_recv_test.c src/config.c src/interface.c
XDP_RECV_TEST = xdp_recv_test

XDP_DEBUG_SRC = tools/xdp_debug.c src/config.c
XDP_DEBUG = xdp_debug

XDP_STATS_SRC = tools/xdp_stats.c
XDP_STATS = xdp_stats

XDP_FULL_TEST_SRC = tools/xdp_full_test.c
XDP_FULL_TEST = xdp_full_test

XDP_MQ_TEST_SRC = tools/xdp_multiqueue_test.c
XDP_MQ_TEST = xdp_mq_test

BPF_SRC = bpf/xdp_redirect.c
BPF_OBJ = bpf/xdp_redirect.o

.PHONY: all clean run test

all: $(BPF_OBJ) $(TARGET) $(LB_TEST) $(XDP_RECV_TEST) $(XDP_DEBUG) $(XDP_STATS) $(XDP_FULL_TEST) $(XDP_MQ_TEST)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

$(LB_TEST): $(LB_TEST_SRC)
	$(CC) $(CFLAGS) $(LB_TEST_SRC) -o $(LB_TEST) $(LDFLAGS)

$(XDP_RECV_TEST): $(XDP_RECV_TEST_SRC)
	$(CC) $(CFLAGS) $(XDP_RECV_TEST_SRC) -o $(XDP_RECV_TEST) $(LDFLAGS)

$(XDP_DEBUG): $(XDP_DEBUG_SRC)
	$(CC) $(CFLAGS) $(XDP_DEBUG_SRC) -o $(XDP_DEBUG) $(LDFLAGS)

$(XDP_STATS): $(XDP_STATS_SRC)
	$(CC) $(CFLAGS) $(XDP_STATS_SRC) -o $(XDP_STATS) $(LDFLAGS)

$(XDP_FULL_TEST): $(XDP_FULL_TEST_SRC)
	$(CC) $(CFLAGS) $(XDP_FULL_TEST_SRC) -o $(XDP_FULL_TEST) $(LDFLAGS)

$(XDP_MQ_TEST): $(XDP_MQ_TEST_SRC)
	$(CC) $(CFLAGS) $(XDP_MQ_TEST_SRC) -o $(XDP_MQ_TEST) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -f src/*.o tools/*.o *.o $(TARGET) $(LB_TEST) $(XDP_RECV_TEST) $(XDP_DEBUG) $(XDP_STATS) $(XDP_FULL_TEST) $(XDP_MQ_TEST) $(BPF_OBJ)

run: all
	sudo ./$(TARGET) config.cfg

test: $(LB_TEST)
	sudo ./$(LB_TEST) config.txt
