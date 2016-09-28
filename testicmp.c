/*
    Packet sniffer using libpcap library
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
 
#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <sys/types.h>     // checksum

 
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_icmp_packet(const u_char * , int );
unsigned int checksum(unsigned short * data, int len);

 
struct sockaddr_in source,dest;
 
int main()
{
    pcap_t *handle; //Handle of the device that shall be sniffed
 
    char errbuf[PCAP_ERRBUF_SIZE], *devname = "eth4";
    char *filter = "ether dest 00:11:43:d4:4f:48";
     
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    if (pcap_compile(descr, &fp, filter, 0, netp) == -1) {
        printf("Error calling pcap_compile\n");
        exit(1);
    }

    //set the compiled program as the filter
    if (pcap_setfilter(descr, &fp) == -1) {
        printf("Error setting filter\n");
        exit(1);
    }
     
    //Put the device in sniff loop
    pcap_loop(handle , -1 , process_packet , NULL);
     
    return 0;   
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    // Store MAC addresses
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    unsigned char src_ha[ETH_ALEN], dst_ha[ETH_ALEN]; 
    memset(&src_ha, 0, ETH_ALEN);
    memcpy(src_ha, eth->h_source, ETH_ALEN);
     
    memset(&dst_ha, 0, ETH_ALEN);
    memcpy(dst_ha, eth->h_dest, ETH_ALEN); 

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    if(iph->protocol == 1){
        process_icmp_packet(buffer, size);
    }

    // IP address exchange
    iph->saddr = dest.sin_addr.s_addr;
    iph->daddr = source.sin_addr.s_addr;

    //TODO: IP checksum
    //iph->checksum = checksum(iph, iphdrlen);

    // MAC address exchange
    memcpy(eth->h_source, dst_ha, ETH_ALEN);
    memcpy(eth->h_dest, src_ha, ETH_ALEN);

    // TODO: Send ICMP response
    /*if (pcap_inject(output, packet, pkthdr->len) == -1) {
        pcap_perror(output, 0);
        pcap_close(output);
        exit(1);
    }*/

}
 
void process_icmp_packet(const u_char * Buffer , int Size)
{
    int size = header->len; // why?

    // IP
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    printf("\n\n***********************ICMP Packet*************************\n"); 
     
    //print_ip_header(Buffer , Size);
             
    printf("\n");
         
    printf("ICMP Header\n");
    printf("Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == ICMP_ECHO)
    {

        printf("ICMP Echo request\n");
        printf("ICMP Code : %d\n",(unsigned int)(icmph->code));
        printf("ICMP Checksum : %d\n",ntohs(icmph->checksum));
        printf("\n");
        icmph->type = ICMP_ECHOREPLY; //Do an echoreply
        icmp->code = 0; 
        //icmp->seq= 0;
        icmp->cksum = 0;
        //compute checksum
        icmp->icmp_cksum = checksum((unsigned short *) icmp, sizeof(struct icmp));
    }

}

unsigned short checksum(unsigned short * data, int len){
    int i;
    unsigned int sum = 0;
    unsigned short * ptr;
    unsigned short chcksum;


    for(i=len, ptr=data; i > 1; i-=2){ //i-=2 for 2*8=16 bits at time
        sum += *ptr; //sum += 16 bit word at ptr
        ptr+=1;//move ptr to next 16 bit word
    }

    //check if we have an extra 8 bit word
    if (i == 1){
        sum += *((unsigned char*) ptr); //cast ptr to 8 bit unsigned char
    }

    //Fold the cary into the first 16 bits
    sum = (sum & 0xffff) + (sum >> 16);

    //Fold the last cary into the sum
    sum += (sum >> 16);

    // ~ compliments and return
    chcksum = ~sum;

    return chcksum;
}
 
