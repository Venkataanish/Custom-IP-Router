#include "arp.h"

void get_packet(struct routing_table arp_entry[], EthMacPair eth[]) {
	int i;
	struct ifaddrs *addrs, *iap;
	struct sockaddr_in *sa;
	char buf[32];
	unsigned char source_ip[4];
	unsigned char target_ip[4];
	arp_t node1_entry;
	node1_entry.destination_ip = 16777482;
	int is_node1 = 0;
	getifaddrs(&addrs);

	for (i = 0, iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if (iap->ifa_addr && (iap->ifa_flags & IFF_UP)
				&& iap->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) (iap->ifa_addr);
			inet_ntop(iap->ifa_addr->sa_family, (void *) &(sa->sin_addr), buf,
					sizeof(buf));
			if ((strcmp("10.1.2.1", buf) == 0)
					|| (strcmp("10.10.1.2", buf) == 0)) {
				if ((strcmp("10.1.2.1", buf)) == 0) {
					unsigned char s_ip[4] = { 10, 1, 2, 1 };
					unsigned char t_ip[4] = { 10, 1, 2, 4 };
					memcpy(source_ip, s_ip, 4);
					memcpy(target_ip, t_ip, 4);
				}
				if ((strcmp("10.10.1.2", buf)) == 0) {
					unsigned char s_ip[4] = { 10, 10, 1, 2 };
					unsigned char t_ip[4] = { 10, 10, 1, 1 };
					memcpy(source_ip, s_ip, 4);
					memcpy(target_ip, t_ip, 4);
					is_node1 = 1;
				}
				int sd;
				unsigned char buffer[BUF_SIZE];
				strcpy(arp_entry[i].iface_name, iap->ifa_name);
				strcpy(eth[i].iface_name, iap->ifa_name);
				struct ifreq ifr;
				struct ethhdr *send_req = (struct ethhdr *) buffer;
				struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
				struct arp_header *arp_req = (struct arp_header *) (buffer
						+ ETH_HEADER_LEN);
				struct arp_header *arp_resp = (struct arp_header *) (buffer
						+ ETH_HEADER_LEN);
				struct sockaddr_ll socket_address;
				int index, ret, length = 0, ifindex;

				memset(buffer, 0x00, 60);
				sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if (sd == -1) {
					perror("socket():");
					exit(1);
				}
				strcpy(ifr.ifr_name, iap->ifa_name);
				if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
					perror("SIOCGIFINDEX");
					exit(1);
				}
				ifindex = ifr.ifr_ifindex;
				if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
					perror("SIOCGIFINDEX");
					exit(1);
				}
				close(sd);
				for (index = 0; index < 6; index++) {
					send_req->h_dest[index] = (unsigned char) 0xff;
					arp_req->target_mac[index] = (unsigned char) 0x00;
					send_req->h_source[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
					arp_req->sender_mac[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
					socket_address.sll_addr[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
				}

				for (index = 0; index < 6; index++) {
					send_req->h_dest[index] = (unsigned char) 0xff;
					arp_req->target_mac[index] = (unsigned char) 0x00;
					send_req->h_source[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
					arp_req->sender_mac[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
					socket_address.sll_addr[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
				}

				for (index = 0; index < 6; index++) {
					eth[i].source_mac[index] =
							(uint8_t) arp_req->sender_mac[index];
					arp_entry[i].source_mac[index] =
							(uint8_t) arp_req->sender_mac[index];
				}

				/*prepare sockaddr_ll*/
				socket_address.sll_family = AF_PACKET;
				socket_address.sll_protocol = htons(ETH_P_ARP);
				socket_address.sll_ifindex = ifindex;
				socket_address.sll_hatype = htons(ARPHRD_ETHER);
				socket_address.sll_pkttype = (PACKET_BROADCAST);
				socket_address.sll_halen = MAC_LENGTH;
				socket_address.sll_addr[6] = 0x00;
				socket_address.sll_addr[7] = 0x00;

				/* Setting protocol of the packet */
				send_req->h_proto = htons(ETH_P_ARP);

				/* Creating ARP request */
				arp_req->hardware_type = htons(HW_TYPE);
				arp_req->protocol_type = htons(ETH_P_IP);
				arp_req->hardware_len = MAC_LENGTH;
				arp_req->protocol_len = IPV4_LENGTH;
				arp_req->opcode = htons(ARP_REQUEST);

				for (index = 0; index < 5; index++) {
					arp_req->sender_ip[index] =
							(unsigned char) source_ip[index];
					arp_req->target_ip[index] =
							(unsigned char) target_ip[index];
				}

				if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
					perror("socket() failed ");
					exit(EXIT_FAILURE);
				}

				buffer[32] = 0x00;
				ret = sendto(sd, buffer, 42, 0,
						(struct sockaddr*) &socket_address,
						sizeof(socket_address));
				if (ret == -1) {
					perror("sendto():");
					exit(1);
				}
				printf("\n");
				memset(buffer, 0x00, 60);
				while (1) {
					length = recvfrom(sd, buffer, BUF_SIZE, 0, NULL, NULL);
					if (length == -1) {
						perror("recvfrom():");
						exit(1);
					}
					if (htons(rcv_resp->h_proto) == PROTO_ARP) {
						arp_entry[i].destination_ip =
								(uint32_t) arp_resp->sender_ip[3] << 24
										| (uint32_t) arp_resp->sender_ip[2]
												<< 16
										| (uint32_t) arp_resp->sender_ip[1] << 8
										| (uint32_t) arp_resp->sender_ip[0];

						for (index = 0; index < 6; index++) {
							arp_entry[i].destination_mac[index] =
									(uint8_t) arp_resp->sender_mac[index];
						}

						if (is_node1) {
							memcpy(node1_entry.destination_mac,
									arp_entry[i].destination_mac,
									sizeof(arp_entry[i].destination_mac));
							memcpy(node1_entry.source_mac,
									arp_entry[i].source_mac,
									sizeof(arp_entry[i].source_mac));
							memcpy(node1_entry.iface_name,
									arp_entry[i].iface_name,
									sizeof(arp_entry[i].iface_name));
							is_node1 = 0;

						}
						i++;

						break;
					} //if
				} //while
			} //if
		}
	}

	arp_entry[i] = node1_entry;
}
