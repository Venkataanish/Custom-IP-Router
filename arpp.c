#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define PROTOCOL_TYPE 0x800
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#ifdef __linux__
#include <linux/if.h>
#else
#include <net/if.h>
#endif

typedef struct arp_table {
	uint8_t send_mac[6];
	uint32_t send_ip;

	char ethint[1];
};

typedef struct ethernet_to_mac {

	char iface_name[10];
	uint8_t mac_addr[6];

} EthMacPair;

struct arp_header {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_len;
	unsigned char protocol_len;
	unsigned short opcode;
	unsigned char sender_mac[MAC_LENGTH];
	unsigned char sender_ip[IPV4_LENGTH];
	unsigned char target_mac[MAC_LENGTH];
	unsigned char target_ip[IPV4_LENGTH];
};

int main() {
	int i;
	struct arp_table arp_entry[2];
	struct ifaddrs *addrs, *iap;
	struct sockaddr_in *sa;
	char buf[32];
	unsigned char source_ip[4];
	unsigned char target_ip[4];

	getifaddrs(&addrs);

	for (i = 0, iap = addrs; iap != NULL; i++, iap = iap->ifa_next) {
		if (iap->ifa_addr && (iap->ifa_flags & IFF_UP)
				&& iap->ifa_addr->sa_family == AF_INET) {

			sa = (struct sockaddr_in *) (iap->ifa_addr);

			inet_ntop(iap->ifa_addr->sa_family, (void *) &(sa->sin_addr), buf,
					sizeof(buf));

			if ((strcmp("10.1.2.1", buf) == 0)
					|| (strcmp("10.10.1.2", buf) == 0)) {
				if ((!strcmp("10.1.2.1", buf))) {

					printf("\n\n");
					printf("STARTING NEW ARP REQ\n");
					unsigned char s_ip[4] = { 10, 1, 2, 1 };
					unsigned char t_ip[4] = { 10, 1, 2, 4 };
					memcpy(source_ip, s_ip, 4);
					memcpy(target_ip, t_ip, 4);

				} else {
					printf("\n\n");
					printf("STARTING NEW ARP REQ\n");
					unsigned char s_ip[4] = { 10, 10, 1, 2 };
					unsigned char t_ip[4] = { 10, 10, 1, 1 };
					memcpy(source_ip, s_ip, 4);
					memcpy(target_ip, t_ip, 4);
				}

				int sd;
				unsigned char buffer[BUF_SIZE];

				strcpy(arp_entry[i].ethint, iap->ifa_name);
				printf("Destination is on interface %s", arp_entry[i].ethint);
				struct ifreq ifr;
				struct ethhdr *send_req = (struct ethhdr *) buffer;
				struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
				struct arp_header *arp_req = (struct arp_header *) (buffer
						+ ETH2_HEADER_LEN);
				struct arp_header *arp_resp = (struct arp_header *) (buffer
						+ ETH2_HEADER_LEN);
				struct sockaddr_ll socket_address;
				int index, ret, length = 0, ifindex;

				memset(buffer, 0x00, 60);
				/*open socket*/
				sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if (sd == -1) {
					perror("socket():");
					exit(1);
				}
				strcpy(ifr.ifr_name, iap->ifa_name);

				/*retrieve ethernet interface index*/
				if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
					perror("SIOCGIFINDEX");
					exit(1);
				}
				ifindex = ifr.ifr_ifindex;

				/*retrieve corresponding MAC*/
				if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
					perror("SIOCGIFINDEX");
					exit(1);
				}
				close(sd);

				for (index = 0; index < 6; index++) {

					send_req->h_dest[index] = (unsigned char) 0xff;
					arp_req->target_mac[index] = (unsigned char) 0x00;
					/* Filling the source  mac address in the header*/
					send_req->h_source[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
					arp_req->sender_mac[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
					socket_address.sll_addr[index] =
							(unsigned char) ifr.ifr_hwaddr.sa_data[index];
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
				} else {
					/*printf(" Sent the ARP REQ \n\t");
					 for(index=0;index<42;index++)
					 {
					 printf("%02X ",buffer[index]);
					 if(index % 16 ==0 && index !=0)
					 {printf("\n\t");}
					 }*/
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

						arp_entry[i].send_ip = (uint32_t) arp_resp->sender_ip[0]
								<< 24 | (uint32_t) arp_resp->sender_ip[1] << 16
								| (uint32_t) arp_resp->sender_ip[2] << 8
								| (uint32_t) arp_resp->sender_ip[3];

						printf("Sender IP in table is ");
						printf("%d\n", arp_entry[i].send_ip);

						for (index = 0; index < 6; index++) {
							arp_entry[i].send_mac[index] =
									(uint8_t) arp_resp->sender_mac[index];
						}
						//printf("\n");
						printf("\nSender MAC in table is\n");
						for (index = 0; index < 5; index++) {
							printf("%0X:", arp_entry[i].send_mac[index]);
						}
						printf("%0X", arp_entry[i].send_mac[5]);

						printf("\n");

						break;

					}

				}                                //while

			} else {
				//continue;
			}
		}
	}

//}

//}//for

	return 0;
}                                //main
