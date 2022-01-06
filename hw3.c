#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int main(int argc, char **argv){
	int ret;
	char *file;
	char errbuffer[PCAP_ERRBUF_SIZE];
	pcap_t *handler;
	struct pcap_pkthdr *header;
	struct ether_header *ether_header;
	u_char *packet;

	if(argc < 2){
		printf("Please choose a file.\n");
		exit(0);
	}
	else{
		file = strdup(argv[1]);
	}

	handler = pcap_open_offline(file, errbuffer);

	while((ret = pcap_next_ex(handler, &header, (const u_char **)&packet)) >= 0){
		if(ret == 0) continue;
		ether_header = (struct ether_header *)packet;

		printf("time: %s", ctime((const time_t *)&header->ts.tv_sec));
		printf("source MAC address: %s\n", ether_ntoa((struct ether_addr *)ether_header->ether_shost));
		printf("destination MAC address: %s\n", ether_ntoa((struct ether_addr *)ether_header->ether_dhost));
		if(ntohs(ether_header->ether_type) == ETHERTYPE_IP){
			printf("ether type: IP\n");

			struct ip *ip;
			u_int ip_size;
			ip = (struct ip *)(packet + sizeof(struct ether_header));
			ip_size = ip->ip_hl * 4;

			printf("source IP address: %s\n", inet_ntoa(ip->ip_src));
			printf("destination IP address: %s\n", inet_ntoa(ip->ip_dst));

			if(ip->ip_p == IPPROTO_TCP){
				struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_size);
				printf("source IP port: %d\n", tcp->th_sport);
				printf("destination IP port: %d\n", tcp->th_dport);
			}
			else if(ip->ip_p == IPPROTO_UDP){
				struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_size);
				printf("source IP port: %d\n" , udp->uh_sport);
				printf("destination IP port: %d\n" , udp->uh_dport);
			}
		}
		printf("-----------------------------------------\n");
	}
}
