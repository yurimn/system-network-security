CC = g++
CFLAGS = -Wall -g
LDLIBS += -lpcap

all: tcp-block

tcp-block: tcp_block.o
	$(CC) $(CFLAGS) -o tcp-block tcp_block.o $(LDLIBS)

tcp_block.o: tcp_block.cpp libnet.h
	$(CC) $(CFLAGS) -c tcp_block.cpp

clean:
	rm -f tcp-block tcp_block.o
