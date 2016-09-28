#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ether.h>
#include <unistd.h>
#include "arp.h"
char *dev;
char *odev;
int icount = 2;
pcap_t *output;
EthMacPair myether[2];
arp_t myarp[3];
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

//comment added by anish

typedef struct ip_mac {
	uint32_t ip;
	uint8_t destination_mac[6];

} IpMac;

/* IP header */
typedef struct sniff_ip {
	u_char ip_vhl; /* version << 4 | header length >> 2 */
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

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr,
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

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {

	struct ether_header *eptr; /* net/ethernet.h */

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;
	Iphdr *ip = (Iphdr*) (packet + SIZE_ETHERNET);

	/* check to see if we have an ip packet */
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
		printf("dst ip = %d\n", ip->ip_dst.s_addr);
		fprintf(stdout, "Dev: %s INCOMING: SRC MAC: %s", dev,
				ether_ntoa((const struct ether_addr *) &eptr->ether_shost));
		fprintf(stdout, " DEST MAC: %s ",
				ether_ntoa((const struct ether_addr *) &eptr->ether_dhost));
		fprintf(stdout, "(IP)\n");

		//send the modified packet

		for (int i = 0; i < 3; i++) {
			if (myarp[i].destination_ip == ip->ip_dst.s_addr) {
				//uint8_t source_mac_addr[6] = { 0x00, 0x11, 0x43, 0xd4, 0x7c, 0x8d }; //connected to node4

				//Decrement TTL
				ip->ip_ttl = ip->ip_ttl - 1;
				ip->ip_sum = checksum(ip, ip->ip_len);

				memcpy(eptr->ether_shost, myarp[i].source_mac,
						sizeof(myarp[i].source_mac));
				memcpy(eptr->ether_dhost, myarp[i].destination_mac,
						sizeof(myarp[i].destination_mac));
				struct ether_header *sptr = (struct ether_header *) packet;

				fprintf(stdout, "outgoing: source: %s ",
						ether_ntoa(
								(const struct ether_addr *) &sptr->ether_shost));
				fprintf(stdout, "destination: %s \n",
						ether_ntoa(
								(const struct ether_addr *) &sptr->ether_dhost));

				printf("Inject completed on %s\n", odev);
				break;

			}
		}

		if (pcap_inject(output, packet, pkthdr->len) == -1) {
			pcap_perror(output, 0);
			pcap_close(output);
			exit(1);
		}

	}

	return eptr->ether_type;
}

int main(int argc, char **argv) {
	int p = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp; /* hold compiled program     */
	bpf_u_int32 netp = 0; /* ip                        */
	u_char* args = NULL;

	char filter[50];

	/* Options must be passed in as a string because I am lazy */
	if (argc < 2) {
		fprintf(stdout, "Usage: %s numpackets \"options\"\n", argv[0]);
		return 0;
	}

	int i;
	get_packet(myarp, myether);

	for (i = 0; i < icount; i++) {

		dev = myether[i].iface_name;

		pid_t pid = fork();

		if (pid == 0) {

			descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
			if (descr == NULL) {
				printf("pcap_open_live(): %s\n", errbuf);
				exit(1);
			}

			sprintf(filter, "ether dst %s",
					ether_ntoa(
							(const struct ether_addr *) myether[i].source_mac));

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
				if (j == i) {
					continue;
				}
				odev = myether[j].iface_name;
				output = pcap_open_live(myether[j].iface_name, BUFSIZ, 1, -1,
						errbuf);
				if (output == NULL) {
					printf("pcap_open_live(): %s\n", errbuf);
					exit(1);
				}
				break;
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
