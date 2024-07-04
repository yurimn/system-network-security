#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <memory>

#include "libnet.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

vector<string> host_list_vector;

clock_t start_time, end_time;
double time_diff;

string getMemoryUsage(pid_t pid) {
    vector<char> buffer(128);
    string result;
    string command = "top -b -n 1 -p " + std::to_string(pid) + " | grep " + std::to_string(pid);
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	return id;
}
	
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	u_char *pkt;
	int	len = nfq_get_payload(nfa, &pkt);

	if (len >= 0) {
		struct libnet_ipv4_hdr*ip=(struct libnet_ipv4_hdr*)pkt;
		struct libnet_tcp_hdr*tcp=(struct libnet_tcp_hdr*)(pkt+ip->ip_hl * 4);	
		unsigned char *http_data = (unsigned char *)tcp + tcp->th_off * 4;

		if (ip->ip_p != IPPROTO_TCP || ntohs(tcp->th_dport) != 80) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		if (!strstr((char *)http_data, "Host: ")) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

		char *packet_host = strstr((char *)http_data, "Host: ") + 6;
		packet_host = strtok(packet_host, "\r\n");

		printf("\npacket host: %s\n", packet_host);

		start_time = clock();
		if (binary_search(host_list_vector.begin(),host_list_vector.end(),packet_host)){
			end_time = clock();
			time_diff = (double)(end_time - start_time) / CLOCKS_PER_SEC;
			printf("block in %f seconds\n", time_diff);

			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}

		end_time = clock();
		time_diff = (double)(end_time - start_time) / CLOCKS_PER_SEC;
		printf("accept in %f seconds\n", time_diff);
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	string memoryBefore, memoryAfter;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
		fprintf(stderr, "Sample: %s top-1m.txt\n", argv[0]);
		exit(1);
	}

	start_time = clock();

	pid_t pid = getpid();
    cout << "PID: " << pid << std::endl;

	memoryBefore = getMemoryUsage(pid);
    printf("Memory usage after processing the file:\n %s\n", memoryBefore.c_str());

	string host_list = argv[1];

	fstream block_list;
	block_list.open(host_list,ios::in);
	if(block_list.fail()){
		perror("Error in opening file");
		exit(1);
	}
	while(block_list.peek()!=EOF){
		string block_host;
		getline(block_list,block_host);
		host_list_vector.push_back(block_host.substr(block_host.find(',')+1));
	}
	block_list.close();

	memoryAfter = getMemoryUsage(pid);
	printf("Memory usage after processing the file:\n %s\n", memoryAfter.c_str());

	
	sort(host_list_vector.begin(),host_list_vector.end());
	end_time = clock();
	time_diff = (double)(end_time - start_time) / CLOCKS_PER_SEC;
	printf("\nupload and sorting list in %f seconds\n\n", time_diff);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
