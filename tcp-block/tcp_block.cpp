#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "libnet.h"

#define SNAP_LEN 1518

void send_rst_packet(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp);
void send_fin_packet(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp);

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct libnet_ipv4_hdr *ip;     /* The IP header */
    const struct libnet_tcp_hdr *tcp;     /* The TCP header */
    int size_ip;
    int size_tcp;
    int size_payload;

    ip = (struct libnet_ipv4_hdr*)(packet + 14);
    size_ip = ip->ip_hl * 4;
    tcp = (struct libnet_tcp_hdr*)(packet + 14 + size_ip);
    size_tcp = tcp->th_off * 4;
    auto payload = (char *)(packet + 14 + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    char *pattern = (char *)args;
    if (size_payload > 0) {
        if (strstr(payload, pattern)) {
            printf("Pattern found! Blocking...\n");
            send_rst_packet((struct libnet_ipv4_hdr *)ip, (struct libnet_tcp_hdr *)tcp);
            send_fin_packet((struct libnet_ipv4_hdr *)ip, (struct libnet_tcp_hdr *)tcp);
        }
    }
}

unsigned short checksum(void *b, int len) {    
    unsigned short *buf = (unsigned short*)b; 
    unsigned int sum=0; 
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

unsigned short tcp_checksum(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp, const char *payload, int payload_len) {
    struct pseudo_header {
        u_int32_t src_addr;
        u_int32_t dst_addr;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    } pseudo_hdr;

    int total_len = sizeof(pseudo_hdr) + sizeof(struct libnet_tcp_hdr) + payload_len;
    char *buf = (char *)malloc(total_len);
    memset(buf, 0, total_len);

    pseudo_hdr.src_addr = ip->ip_src.s_addr;
    pseudo_hdr.dst_addr = ip->ip_dst.s_addr;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_length = htons(sizeof(struct libnet_tcp_hdr) + payload_len);

    memcpy(buf, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(buf + sizeof(pseudo_hdr), tcp, sizeof(struct libnet_tcp_hdr));
    if (payload_len > 0) {
        memcpy(buf + sizeof(pseudo_hdr) + sizeof(struct libnet_tcp_hdr), payload, payload_len);
    }

    unsigned short result = checksum(buf, total_len);
    free(buf);
    return result;
}

void send_rst_packet(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp) {
    int sockfd;
    struct sockaddr_in dest_info;
    char packet[512];

    memset(packet, 0, 512);

    // IP header
    struct libnet_ipv4_hdr *iph = (struct libnet_ipv4_hdr *)packet;
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
    iph->ip_id = htons(0);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src = ip->ip_dst;
    iph->ip_dst = ip->ip_src;

    // TCP header
    struct libnet_tcp_hdr *tcph = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ipv4_hdr));
    tcph->th_sport = tcp->th_dport;
    tcph->th_dport = tcp->th_sport;
    tcph->th_seq = tcp->th_ack;
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_RST;
    tcph->th_win = htons(0);
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    // Calculate checksums
    iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct libnet_ipv4_hdr));
    tcph->th_sum = tcp_checksum(iph, tcph, NULL, 0);

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket() error");
        exit(EXIT_FAILURE);
    }

    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = iph->ip_dst;

    // Send the packet
    if (sendto(sockfd, packet, sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("sendto() error");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

void send_fin_packet(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp) {
    int sockfd;
    struct sockaddr_in dest_info;
    char packet[512];
    char *payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    int payload_size = strlen(payload);

    memset(packet, 0, 512);

    // IP header
    struct libnet_ipv4_hdr *iph = (struct libnet_ipv4_hdr *)packet;
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + payload_size);
    iph->ip_id = htons(0);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src = ip->ip_dst;
    iph->ip_dst = ip->ip_src;

    // TCP header
    struct libnet_tcp_hdr *tcph = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ipv4_hdr));
    tcph->th_sport = tcp->th_dport;
    tcph->th_dport = tcp->th_sport;
    tcph->th_seq = tcp->th_ack;
    tcph->th_ack = htonl(ntohl(tcp->th_seq) + 1);
    tcph->th_off = 5;
    tcph->th_flags = TH_FIN | TH_ACK;
    tcph->th_win = htons(0);
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    // Copy payload to packet
    memcpy(packet + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr), payload, payload_size);

    // Calculate checksums
    iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct libnet_ipv4_hdr));
    tcph->th_sum = tcp_checksum(iph, tcph, payload, payload_size);

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket() error");
        exit(EXIT_FAILURE);
    }

    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = iph->ip_dst;

    // Send the packet
    if (sendto(sockfd, packet, sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + payload_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("sendto() error");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <pattern>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *dev = argv[1];
    char *pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 0, packet_handler, (u_char *)pattern);

    pcap_close(handle);
    return 0;
}
