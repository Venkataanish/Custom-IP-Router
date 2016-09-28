#ifndef _ARP_H_
#define _ARP_H_

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
#include <netinet/ether.h>

#define PROTO_ARP 0x0806
#define ETH_HEADER_LEN 14
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

typedef struct routing_table {
	uint8_t destination_mac[6];
	uint32_t destination_ip;
	uint8_t source_mac[6];
	char iface_name[4];
} arp_t;

typedef struct ethernet_to_mac {

	char iface_name[4];
	uint8_t source_mac[6];

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



void get_packet(struct routing_table table[], EthMacPair eth[]);
#endif
