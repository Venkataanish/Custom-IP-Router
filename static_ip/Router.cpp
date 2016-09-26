/*
 * router.cpp
 *
 *  Created on: Sep 25, 2016
 *      Author: rakesh
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "Router.h"

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

Router::Router() {
	// TODO Auto-generated constructor stub
	this->interfaces = NULL;
	this->dev 		 = NULL;
	this->output     = NULL;
}

Router::~Router() {
	// TODO Auto-generated destructor stub
	delete(this->interfaces);
}

void Router::find_dev() {
	if (pcap_findalldevs(&this->interfaces, this->errbuf) == -1) {
		printf("\nerror in pcap findall devs");
		exit(EXIT_FAILURE);
	}
}

void router_callback_handler(unsigned char * user, const struct pcap_pkthdr *pkthdr, const unsigned char * packet) {
	((Router*) user)->handle_ethernet(user, pkthdr, packet);
}

void Router::inject_pcap(struct ether_header *eptr, IpMac table, const struct pcap_pkthdr* pkthdr,
		const u_char* packet, uint8_t *mac_addr) {
	uint8_t source_mac_addr[6];

	fprintf(stdout, "Dev: %s INCOMING: SRC MAC: %s", dev,
			ether_ntoa((const struct ether_addr *) &eptr->ether_shost));
	fprintf(stdout, " DEST MAC: %s ",
			ether_ntoa((const struct ether_addr *) &eptr->ether_dhost));
	fprintf(stdout, "(IP)\n");

	for (int j = 0; j < 6; j++) {
		source_mac_addr[j] = mac_addr[j];
	}

	memcpy(eptr->ether_shost, source_mac_addr, sizeof(source_mac_addr));
	memcpy(eptr->ether_dhost, table.dmac, sizeof(table.dmac));
	struct ether_header *sptr = (struct ether_header *) packet;

	fprintf(stdout, "outgoing: source: %s ",
			ether_ntoa((const struct ether_addr *) &sptr->ether_shost));
	fprintf(stdout, "destination: %s \n",
			ether_ntoa((const struct ether_addr *) &sptr->ether_dhost));

	if (pcap_inject(this->output, packet, pkthdr->len) == -1) {
		pcap_perror(this->output, 0);
		pcap_close(this->output);
		exit(1);
	}

}

u_int16_t Router::handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char* packet) {
	IpMac table[2];
	uint8_t mac0[6] = { 0x00, 0x04, 0x23, 0xbb, 0x12, 0xbc }; //node 4 mac
	uint8_t mac1[6] = { 0x00, 0x04, 0x23, 0xad, 0xd8, 0x6d }; //rtr1 mac
	table[0].ip = 67240202; // "10.1.2.4" node4
	table[1].ip = 16777482; //"10.1.0.1" node1

	//TODO: handle icmp request for 16908554 (10.1.2.1)

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

		//send the modified packet
		if (table[0].ip == ip->ip_dst.s_addr) {
			uint8_t source_mac_addr[6] = { 0x00, 0x11, 0x43, 0xd4, 0x7c, 0x8d }; //connected to node4

			this->inject_pcap(eptr, table[0], pkthdr, packet, source_mac_addr);
			printf("Inject completed on eth4\n");

		} else if (table[1].ip == ip->ip_dst.s_addr) {
			uint8_t source_mac_addr[6] = { 0x00, 0x04, 0x23, 0xad, 0xda, 0xf7 }; //connected to rtr1

			this->inject_pcap(eptr, table[1], pkthdr, packet, source_mac_addr);

			printf("Inject completed on eth2\n");
		}
	}

	return eptr->ether_type;
}

void Router::call_header_interact() {
	pcap_t* descr;
	struct bpf_program fp; /* hold compiled program     */
	bpf_u_int32 maskp; /* subnet mask               */
	bpf_u_int32 netp; /* ip                        */
	int p = 0;
	Router *router = this;
	/*variables used in for loop*/
	//struct in_addr net_addr;
	char filter[50];
	pcap_if_t *temp;

	for (temp = this->interfaces; temp; temp = temp->next) {

		if (strstr(temp->name, "eth") != NULL) {
			// contains eth
			this->dev = temp->name;

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
						// Write the Ethernet frame to the interface.
						output = pcap_open_live("eth4", BUFSIZ, 1, -1, errbuf);
						if (output == NULL) {
							printf("pcap_open_live(): %s\n", errbuf);
							exit(1);
						}

					} else if (strcmp(dev, "eth4") == 0) {
						sprintf(filter, "ether dst %s", "00:11:43:d4:7c:8d");
						// Write the Ethernet frame to the interface.
						output = pcap_open_live("eth2", BUFSIZ, 1, -1, errbuf);
						if (output == NULL) {
							printf("pcap_open_live(): %s\n", errbuf);
							exit(1);
						}

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
					pcap_loop(descr, -1, router_callback_handler, (u_char *)router);
					exit(0);
				} else {
					// parent process
					printf("started child %d, pid =%d\n", p++, pid);

				}
			}
		}
	}
}
