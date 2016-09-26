/*
 * router.h
 *
 *  Created on: Sep 25, 2016
 *      Author: rakesh
 */

#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#ifndef ROUTER_H_
#define ROUTER_H_

#define SIZE_ETHERNET 14

typedef struct ip_mac {
	uint32_t ip;
	uint8_t dmac[6];
} IpMac;

class Router {
public:
	Router();
	virtual ~Router();
	void find_dev();
	void call_header_interact();
	u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
	void inject_pcap(struct ether_header *eptr, IpMac table, const struct pcap_pkthdr* pkthdr,
			const u_char* packet, uint8_t *mac_addr);

protected:
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces;
	char *dev;
	pcap_t *output;
};

#endif /* ROUTER_H_ */
