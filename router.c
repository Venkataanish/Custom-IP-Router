#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <unistd.h>
#include "arp.h"
char dev[5];
pcap_t* descr;
int icount = 3;
int n = 3;
typedef struct output_if_pcap {
	char iface_name[5];
	pcap_t *pcap;
	int iface;

} Output;

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

//comment added by anish

typedef struct ip_mac {
	uint32_t ip;
	uint8_t destination_mac[6];

} IpMac;

EthMacPair ethMacPair[3];
arp_t table[5];
Output output[2];
uint32_t my_ip[3] = { 16908554, 33622538, 16976394 };
/* IP header */
typedef struct sniff_ip {
	u_char ip_vhl; /* version << 4 | header length >> 2 */
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_char ip_tos; /* type of service */
	u_short ip_len; /* total length */
	u_short ip_id; /* identification */
	u_short ip_off; /* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl; /* time to live */
	u_char ip_p; /* protocol */
	u_short ip_sum; /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
} Iphdr;

void handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet);

/* looking at ethernet headers */

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {
	handle_ethernet(args, pkthdr, packet);

	/*if (type == ETHERTYPE_IP) { handle IP packet
	 } else if (type == ETHERTYPE_ARP) { handle arp packet
	 } else if (type == ETHERTYPE_REVARP) { handle reverse arp packet
	 }*/
}

unsigned short in_cksum(unsigned short *addr, int len) {
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

unsigned short checksum(Iphdr *ip, int len) {
	unsigned long sum = 0;
	const uint16_t *ip1;

	ip1 = (uint16_t *) ip;
	while (len > 1) {
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (~sum);
}

void handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {

	struct ether_header *eptr;
	eptr = (struct ether_header *) packet;
	Iphdr *ip = (Iphdr*) (packet + SIZE_ETHERNET);
	in_addr_t temp = ip->ip_src.s_addr;
	ip->ip_ttl = ip->ip_ttl - 1;
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
		printf("dst ip = %d , ttl = %d , protocol = %d\n", ip->ip_dst.s_addr,
				ip->ip_ttl, ip->ip_p);
		fprintf(stdout, "Dev: %s INCOMING: SRC MAC: %s", dev,
				ether_ntoa((const struct ether_addr *) &eptr->ether_shost));
		fprintf(stdout, " DEST MAC: %s ",
				ether_ntoa((const struct ether_addr *) &eptr->ether_dhost));
		fprintf(stdout, "(IP)\n");

		//send the modified packet

		//check if dst is my ip
		if (ip->ip_ttl == 0) {
			struct icmp *icmp_hdr;
			int ip_len, icmp_len;
			icmp_hdr =
					(struct icmp *) ((unsigned char *) ip + sizeof(struct ip));
			char buf[28];
			memcpy(buf, ip, 28);
			int len = pkthdr->len - sizeof(struct ether_header)
					- sizeof(struct ip);
			memset(icmp_hdr, 0, len);
			memcpy(icmp_hdr->icmp_data, buf, 28);

			if (((ip->ip_dst.s_addr != 33335488)
					&& ((ip->ip_dst.s_addr == my_ip[0])
							|| (ip->ip_dst.s_addr == my_ip[1])
							|| (ip->ip_dst.s_addr == my_ip[2])))) {
				//dest unreachable
				icmp_hdr->icmp_type = 3;
				icmp_hdr->icmp_code = 3;
				printf("Dest host unreachable.\n");

			} else {

				//timeout exceeded
				icmp_hdr->icmp_type = 11;
				icmp_hdr->icmp_code = 0;
				printf("timeout exceeded.\n");

			}

			icmp_hdr->icmp_cksum = 0;
			icmp_hdr->icmp_id = 0;
			icmp_hdr->icmp_seq = 0;
			ip_len = ntohs(ip->ip_len);
			icmp_len = ip_len - sizeof(struct ip);
			icmp_hdr->icmp_cksum = in_cksum((unsigned short *) icmp_hdr,
					icmp_len);

			ip->ip_tos = 0;
			ip->ip_off = 0;
			ip->ip_ttl = 255;
			ip->ip_p = IPPROTO_ICMP;
			ip->ip_sum = 0;
			ip->ip_dst.s_addr = ip->ip_src.s_addr;
			ip->ip_src.s_addr = 16908554;
			ip->ip_sum = checksum(ip, IP_HL(ip) * 4);

			// modify mac
			for (int j = 0; j < 5; j++) {
				/*printf("inside for dest ip = %d\n", ip->ip_dst.s_addr);*/
				if (table[j].destination_ip == ip->ip_dst.s_addr) {
					printf("inside if\n");

					memcpy(eptr->ether_shost, table[j].source_mac,
							sizeof(table[j].source_mac));
					memcpy(eptr->ether_dhost, table[j].destination_mac,
							sizeof(table[j].destination_mac));
					struct ether_header *sptr = (struct ether_header *) packet;

					fprintf(stdout, "icmp pkt outgoing: source: %s ",
							ether_ntoa(
									(const struct ether_addr *) &sptr->ether_shost));
					fprintf(stdout, "icmp pkt destination: %s \n",
							ether_ntoa(
									(const struct ether_addr *) &sptr->ether_dhost));
					break;

				}				//end of if
			}				// end of for

			if (pcap_inject(descr, packet, pkthdr->len) == -1) {
				pcap_perror(descr, 0);
				pcap_close(descr);
				exit(1);
			}				// end of inject if
			printf("Inject completed on %s\n", dev);

		}
	}

	if (((ip->ip_dst.s_addr != 33335488)
			&& ((ip->ip_dst.s_addr == my_ip[0])
					|| (ip->ip_dst.s_addr == my_ip[1])
					|| (ip->ip_dst.s_addr == my_ip[2])))) {

		if ((ip->ip_ttl != 0) && ip->ip_p == IPPROTO_ICMP) {

			struct icmp *icmp_hdr;
			int ip_len, icmp_len;

			icmp_hdr =
					(struct icmp *) ((unsigned char *) ip + sizeof(struct ip));

			if (icmp_hdr->icmp_type == ICMP_ECHO) {
				/* Prepare outgoing ICMP header. */
				icmp_hdr->icmp_type = 0; //11;
				icmp_hdr->icmp_code = 0;
				icmp_hdr->icmp_cksum = 0;
				ip_len = ntohs(ip->ip_len);
				icmp_len = ip_len - sizeof(struct ip);
				printf("ICMP_ECHO request.\n");
				icmp_hdr->icmp_cksum = in_cksum((unsigned short *) icmp_hdr,
						icmp_len);
			} //if echo check end

			//modify IP header

			ip->ip_sum = 0;
			ip->ip_src.s_addr = ip->ip_dst.s_addr;
			ip->ip_dst.s_addr = temp;
			ip->ip_ttl = 255;
			ip->ip_sum = checksum(ip, IP_HL(ip) * 4);

			// modify mac
			for (int j = 0; j < 5; j++) {
				printf("inside for dest ip = %d\n", ip->ip_dst.s_addr);
				if (table[j].destination_ip == ip->ip_dst.s_addr) {
					printf("inside if\n");
					memcpy(eptr->ether_shost, table[j].source_mac,
							sizeof(table[j].source_mac));
					memcpy(eptr->ether_dhost, table[j].destination_mac,
							sizeof(table[j].destination_mac));
					struct ether_header *sptr = (struct ether_header *) packet;

					fprintf(stdout, "icmp pkt outgoing: source: %s ",
							ether_ntoa(
									(const struct ether_addr *) &sptr->ether_shost));
					fprintf(stdout, "icmp pkt destination: %s \n",
							ether_ntoa(
									(const struct ether_addr *) &sptr->ether_dhost));
					break;

				}				//end of if
			}				// end of for

			if (pcap_inject(descr, packet, pkthdr->len) == -1) {
				pcap_perror(descr, 0);
				pcap_close(descr);
				exit(1);
			}				// end of inject if
			printf("Inject completed on %s\n", dev);

		} //end of my_ip if

	} else {
		int i, j;
		for (i = 0; i < 5; i++) {
			if (table[i].destination_ip == ip->ip_dst.s_addr) {

				//Decrement TTL
				//ip->ip_ttl = ip->ip_ttl - 1;
				ip->ip_sum = 0;
				ip->ip_sum = checksum(ip, IP_HL(ip) * 4);

				memcpy(eptr->ether_shost, table[i].source_mac,
						sizeof(table[i].source_mac));
				memcpy(eptr->ether_dhost, table[i].destination_mac,
						sizeof(table[i].destination_mac));
				struct ether_header *sptr = (struct ether_header *) packet;

				fprintf(stdout, "outgoing: source: %s ",
						ether_ntoa(
								(const struct ether_addr *) &sptr->ether_shost));
				fprintf(stdout, "destination: %s \n",
						ether_ntoa(
								(const struct ether_addr *) &sptr->ether_dhost));

				break;

			}
		}

		for (j = 0; j < 2; j++) {
			printf(" table iface = %d, output iface =%d \n", table[i].iface,
			 output[j].iface);
			 printf(" table iface = %s, output iface =%s \n",
			 table[i].iface_name, output[j].iface_name);
			if (output[j].iface == table[i].iface) {
				if (pcap_inject(output[j].pcap, packet, pkthdr->len) == -1) {
					pcap_perror(output[j].pcap, 0);
					pcap_close(output[j].pcap);
					exit(1);
				}
				printf("Inject completed on %s\n", output[j].iface_name);
				break;
			}
		}
	}
	// end of my_ip for

}				// end of if ETHERTYPE_IP

int main(int argc, char **argv) {
	int p = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct bpf_program fp; /* hold compiled program     */
	bpf_u_int32 netp = 0; /* ip                        */
	u_char* args = NULL;
	int fix_k = 0;

	char filter[50];

	/* Options must be passed in as a string because I am lazy */
	if (argc < 2) {
		fprintf(stdout, "Usage: %s numpackets \"options\"\n", argv[0]);
		return 0;
	}

	int i;
	get_packet(table, ethMacPair);
	printf("completed arp..\n");

	for (i = 0; i < icount; i++) {

		strcpy(dev, ethMacPair[i].iface_name);

		pid_t pid = fork();

		if (pid == 0) {

			descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
			if (descr == NULL) {
				printf("pcap_open_live(): %s\n", errbuf);
				exit(1);
			}

			sprintf(filter, "ether dst %s",
					ether_ntoa(
							(const struct ether_addr *) ethMacPair[i].source_mac));

			printf("Setting filter for interface %s .. %s\n", dev, filter);

			if (pcap_compile(descr, &fp, filter, 0, netp) == -1) {
				fprintf(stderr, "Error calling pcap_compile\n");
				exit(1);
			}

			//set the compiled program as the filter
			if (pcap_setfilter(descr, &fp) == -1) {
				fprintf(stderr, "Error setting filter\n");
				exit(1);

			}

			for (int j = 0; j < icount; j++) {
				if (j != i) {
					printf("output to be set %s\n", ethMacPair[j].iface_name);
					strcpy(output[fix_k].iface_name, ethMacPair[j].iface_name);

					output[fix_k].iface = output[fix_k].iface_name[3] - '0';

					printf("output open %s  %d input = %s j = %d\n",
							output[fix_k].iface_name, output[fix_k].iface, dev,
							j);

					output[fix_k].pcap = pcap_open_live(
							output[fix_k].iface_name,
							BUFSIZ, 1, -1, errbuf);
					if (output[fix_k].pcap == NULL) {
						printf("pcap_open_live(): %s\n", errbuf);
						exit(1);
					}
					fix_k++;
				}

			}
			// child process
			/* ... and loop */
			pcap_loop(descr, -1, my_callback, args);
			exit(0);
		} else {
			// parent process
			printf("started child %d, pid =%d\n", p++, pid);

		}
		//}
	}
	printf("--end of program--\n");

	fprintf(stdout, "\nfinished\n");
	return 0;
}
