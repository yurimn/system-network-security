all: netfilter-test

netfilter-test: main.o ip.o iphdr.o tcphdr.o
	g++ -o netfilter-test main.o -lnetfilter_queue

main.o: ip.h iphdr.h tcphdr.h netfilter-test.h main.cpp

ip.o: ip.h ip.cpp

iphdr.o: iphdr.h iphdr.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

clean:
	rm -f netfilter-test
	rm -f main.o ip.o iphdr.o tcphdr.o
