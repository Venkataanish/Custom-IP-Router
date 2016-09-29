#include "arp.h"

int icount = 3;
EthMacPair myether[3];
int nodes = 5;
arp_t myarp[5];
int main() {

	int i;
	get_packet(myarp, myether);
	int k;

	for (i = 0; i < icount; i++) {
		printf("{ ethernet_mac struct \n");
		printf("Interface of Source : %s", myether[i].iface_name);
		printf("\nMAC of Source is :");
		for (k = 0; k < 5; k++) {
			printf("%0x:", myether[i].source_mac[k]);
		}
		printf("%0x", myether[i].source_mac[5]);
		printf("\n");
		printf("}\n");
	}
	for (i = 0; i < nodes; i++) {
		printf("{ arp_table struct \n");
		printf("IP of Destination is  :  ");
		printf("%d\n", myarp[i].destination_ip);
		printf("Destination Mac is : ");
		for (k = 0; k < 5; k++) {
			printf("%0x:", myarp[i].destination_mac[k]);
		}
		printf("%0x", myarp[i].destination_mac[5]);
		printf("\n");
		printf("Interface: %s  %d\n", myarp[i].iface_name, myarp[i].iface);
		printf("Source Macis :");
		for (k = 0; k < 5; k++) {
			printf("%0x:", myarp[i].source_mac[k]);
		}
		printf("%0x", myarp[i].source_mac[5]);

		printf("\n");
		printf("}\n");
	}

	return 0;
}               //main
