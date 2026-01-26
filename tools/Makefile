CC = gcc
CFLAGS = -Wall -O2

all: udp_sender udp_receiver

udp_sender: udp_sender.c
	$(CC) $(CFLAGS) -o udp_sender udp_sender.c

udp_receiver: udp_receiver.c
	$(CC) $(CFLAGS) -o udp_receiver udp_receiver.c

clean:
	rm -f udp_sender udp_receiver
