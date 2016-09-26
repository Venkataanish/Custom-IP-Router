#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <unistd.h>
char *dev;

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

typedef struct ip_mac {
	uint32_t ip;
	uint8_t dmac[6];

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
	u_int16_t type = handle_ethernet(args, pkthdr, packet);

	if (type == ETHERTYPE_IP) {/* handle IP packet */
	} else if (type == ETHERTYPE_ARP) {/* handle arp packet */
	} else if (type == ETHERTYPE_REVARP) {/* handle reverse arp packet */
	}
}

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {
	char errbuf[PCAP_ERRBUF_SIZE];
	IpMac table[2];
	uint8_t mac0[6] = { 0x00, 0x04, 0x23, 0xbb, 0x12, 0xbc }; //node 4 mac
	uint8_t mac1[6] = { 0x00, 0x04, 0x23, 0xad, 0xd8, 0x6d }; //rtr1 mac
	table[0].ip = 67240202; // "10.1.2.4" node4
	table[1].ip = 16777482; //"10.1.0.1" node1

	for (int j = 0; j < 6; j++) {
		table[0].dmac[j] = mac0[j];
	}
	for (int j = 0; j < 6; j++) {
		table[1].dmac[j] = mac1[j];
	}

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

		if (table[0].ip == ip->ip_dst.s_addr) {
			uint8_t source_mac_addr[6] = { 0x00, 0x11, 0x43, 0xd4, 0x7c, 0x8d }; //connected to node4

			memcpy(eptr->ether_shost, source_mac_addr, sizeof(source_mac_addr));
			memcpy(eptr->ether_dhost, table[0].dmac, sizeof(table[0].dmac));
			struct ether_header *sptr = (struct ether_header *) packet;

			fprintf(stdout, "outgoing: source: %s ",
					ether_ntoa((const struct ether_addr *) &sptr->ether_shost));
			fprintf(stdout, "destination: %s \n",
					ether_ntoa((const struct ether_addr *) &sptr->ether_dhost));

			// Write the Ethernet frame to the interface.
			pcap_t *output = pcap_open_live("eth4", BUFSIZ, 1, -1, errbuf);
			if (output == NULL) {
				printf("pcap_open_live(): %s\n", errbuf);
				exit(1);
			}
			if (pcap_inject(output, packet, pkthdr->len) == -1) {
				pcap_perror(output, 0);
				pcap_close(output);
				exit(1);
			}
			printf("Inject completed on eth4\n");
			pcap_close(output);
		} else if (table[1].ip == ip->ip_dst.s_addr) {
			uint8_t source_mac_addr[6] = { 0x00, 0x04, 0x23, 0xad, 0xda, 0xf7 }; //connected to rtr1

			memcpy(eptr->ether_shost, source_mac_addr,
					sizeof(eptr->ether_shost));
			memcpy(eptr->ether_dhost, table[1].dmac, sizeof(eptr->ether_dhost));
			struct ether_header *sptr = (struct ether_header *) packet;

			fprintf(stdout, "outgoing: source: %s ",
					ether_ntoa((const struct ether_addr *) &sptr->ether_shost));
			fprintf(stdout, "destination: %s \n",
					ether_ntoa((const struct ether_addr *) &sptr->ether_dhost));

			pcap_t *output = pcap_open_live("eth2", BUFSIZ, 1, -1, errbuf);
			if (output == NULL) {
				printf("pcap_open_live(): %s\n", errbuf);
				exit(1);
			}
			// Write the Ethernet frame to the interface.
			if (pcap_inject(output, packet, pkthdr->len) == -1) {
				pcap_perror(output, 0);
				pcap_close(output);
				exit(1);
			}
			printf("Inject completed on eth2\n");
			pcap_close(output);
		}

//char if_name[] = "eth2";
// Open a PCAP packet capture descriptor for the specified interface.
		/*char pcap_errbuf[PCAP_ERRBUF_SIZE];
		 pcap_errbuf[0] = '\0';
		 pcap_t* pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
		 if (pcap_errbuf[0] != '\0') {
		 fprintf(stderr, "%s\n", pcap_errbuf);
		 }
		 if (!pcap) {
		 exit(1);
		 }*/

// Close the PCAP descriptor.
//pcap_close(pcap);
	} else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {/*
	 fprintf(stdout, "Dev: %s APR (?): SRC MAC: %s",dev,
	 ether_ntoa((const struct ether_addr *) &eptr->ether_shost));
	 fprintf(stdout, " DEST MAC: %s ",
	 ether_ntoa((const struct ether_addr *) &eptr->ether_dhost));

	 fprintf(stdout, "(ARP)\n");
	 */
	} else if (ntohs(eptr->ether_type) == ETHERTYPE_REVARP) {
		fprintf(stdout, "(RARP)\n");
	} else {
		fprintf(stdout, "(?)\n");

	}

	return eptr->ether_type;
}

int main(int argc, char **argv) {
	int p = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp; /* hold compiled program     */
	bpf_u_int32 maskp; /* subnet mask               */
	bpf_u_int32 netp; /* ip                        */
	u_char* args = NULL;

	/*variables used in for loop*/
	//struct in_addr net_addr;
	char filter[50];

	/* Options must be passed in as a string because I am lazy */
	if (argc < 2) {
		fprintf(stdout, "Usage: %s numpackets \"options\"\n", argv[0]);
		return 0;
	}

	char error[PCAP_ERRBUF_SIZE];
	char *ifnames[10] = { };
	pcap_if_t *interfaces, *temp;
	int count = 0;
	if (pcap_findalldevs(&interfaces, error) == -1) {
		printf("\nerror in pcap findall devs");
		return -1;
	}

	printf("\n the interfaces present on the system are:");
	for (temp = interfaces; temp; temp = temp->next) {

		if (strstr(temp->name, "eth") != NULL) {
			// contains eth
			ifnames[count] = temp->name;
			printf("\n%d  :  %s", count, temp->name);
			count++;
		}

	}

	int i = 0;

	printf("count %d\n", count);
	for (i = 0; i < count; i++) {
		dev = ifnames[i];

		/* ask pcap for the network address and mask of the device */
		pcap_lookupnet(dev, &netp, &maskp, errbuf);
		int first_byte = netp & 0xFF;
		if (first_byte == 10) {
			pid_t pid = fork();

			if (pid == 0) {
				/* open device for reading. NOTE: defaulting to
				 * promiscuous mode*/
				descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
				if (descr == NULL) {
					printf("pcap_open_live(): %s\n", errbuf);
					exit(1);
				}

				/* Lets try and compile the program.. non-optimized */
				//net_addr.s_addr = netp;
				//sprintf(filter, "src net %s/24", inet_ntoa(net_addr));
				if (strcmp(dev, "eth2") == 0) {
				 sprintf(filter, "ether dst %s", "00:04:23:ad:da:f7");

				 } else if (strcmp(dev, "eth4") == 0) {
				 sprintf(filter, "ether dst %s", "00:11:43:d4:7c:8d");

				 }
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

				// child process
				/* ... and loop */
				pcap_loop(descr, -1, my_callback, args);
				exit(0);
			} else {
				// parent process
				printf("started child %d, pid =%d\n", p++, pid);

			}
		}
	}
	printf("--end of program--\n");

	fprintf(stdout, "\nfinished\n");
	return 0;
}
