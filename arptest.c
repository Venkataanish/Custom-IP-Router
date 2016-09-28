#include "arp.h"
int main() {
	EthMacPair myether[2];
	arp_t myarp[3];
	int i;
	get_packet(myarp, myether);
	int k;

	for (i = 0; i < 2; i++) {
		printf("{ ethernet_mac struct \n");
		printf("Interface of Source : %s", myether[i].iface_name);
		printf("\nMAC of Sender is :");
		for (k = 0; k < 5; k++) {
			printf("%0x:", myether[i].source_mac[k]);
		}
		printf("%0x", myether[i].source_mac[5]);
		printf("\n");
		printf("}\n");
	}
	for (i = 0; i < 3; i++) {
		printf("{ arp_table struct \n");
		printf("IP of Destination is  :  ");
		printf("%d\n", myarp[i].destination_ip);
		printf("MAC of Destination is : ");
		for (k = 0; k < 5; k++) {
			printf("%0x:", myarp[i].destination_mac[k]);
		}
		printf("%0x", myarp[i].destination_mac[5]);
		printf("\n");
		printf("Interface of Destination : %s\n", myarp[i].iface_name);
		printf("\nMAC of Sender is :");
		for (k = 0; k < 5; k++) {
			printf("%0x:", myarp[i].source_mac[k]);
		}
		printf("%0x", myarp[i].source_mac[5]);

		printf("\n");
		printf("}\n");
	}

	return 0;
}               //main
