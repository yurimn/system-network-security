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

void get_attacker_mac(char* dev, Mac* my_mac);
void get_attacker_ip(char* dev, Ip* my_ip);
void send_arp(pcap_t* handle, Mac destination_mac, Mac source_mac, uint16_t op, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip);
