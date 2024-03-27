#include <pcap.h>
#include "pcap-test.h"


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n\n", header->caplen);

		struct libnet_ethernet_hdr* ethernet = packet;
		struct libnet_ipv4_hdr* ipv4 = ethernet+1; 
		struct libnet_tcp_hdr* tcp = ipv4+1;
		
		if(ntohs(ethernet->ether_type)==ETHERTYPE_IP && ipv4->ip_p ==IPPROTO_TCP){
		
			// ethernet header
			printf("<1. Ethernet Header>\n");
			printf("src mac : ");
			for(int i=0;i<ETHER_ADDR_LEN;i++)
				printf("%02x",ethernet->ether_shost[i]);
			printf("\ndst mac : ");
			for(int i=0;i<ETHER_ADDR_LEN;i++)
				printf("%02x",ethernet->ether_dhost[i]);
			printf("\n\n");
			
			
			// IP header
			u_int haddr;
			printf("<2. IP Header>\n");
			haddr = ntohl(ipv4->ip_src.s_addr); //호스트 바이 정렬로 변환
    			printf("src ip : %d.%d.%d.%d\n",haddr>>24, (u_char)(haddr>>16),(u_char)(haddr>>8),(u_char)(haddr));
    			haddr = ntohl(ipv4->ip_dst.s_addr); //호스트 바이 정렬로 변환
    			printf("dst ip : %d.%d.%d.%d\n",haddr>>24, (u_char)(haddr>>16),(u_char)(haddr>>8),(u_char)(haddr));
			printf("\n");
				
				
			// TCP header
			printf("<3. TCP Header>\n");
			printf("src port :%u\n",ntohs(tcp->th_sport));
			printf("dst port :%u\n",ntohs(tcp->th_dport));
			printf("\n");
			
			
			// Data hexadecimal value
			printf("<4. Data value>\n");
			int startPoint = sizeof(struct libnet_ethernet_hdr)+ sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
			int size = header->caplen - startPoint;
			for(int i=0;i<20 &&i<size;i++){
				printf("%02x",packet[startPoint +i]);
				if((size <10 && i != size-1) || (size >=10 && i!=9))
					printf(" ");
			}
			
			printf("\n\n-------------------\n\n");
		}
	}

	pcap_close(pcap);
}
