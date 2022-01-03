#include "parser.h"
#include "utils.h"
#include "print.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


void	parse_dns(const unsigned char *packet, t_analyzer *analyzer) {
	
}

void parse_tcp(const unsigned char *packet, uint16_t size, t_analyzer *analyzer) {
	struct              tcphdr *hdr = (struct tcphdr *)packet;
    uint16_t			data_size;
    const unsigned char	*data;

    print_tcp(packet, analyzer);
	data_size = size - hdr->doff * 4;
	data = packet + hdr->doff * 4;
    print_data(data, data_size, analyzer);
}

void	parse_udp(const unsigned char *packet, t_analyzer *analyzer) {
	struct udphdr *hdr = (struct udphdr *)packet;
	uint16_t source = ntohs(hdr->source);
	uint16_t dest = ntohs(hdr->dest);

	print_udp(packet, analyzer);

	if (dest == BOOTP_CLIENT_PORT || source == BOOTP_SERVER_PORT) {
		print_bootp(packet + sizeof(struct udphdr), analyzer);
	} else if (dest == DNS_PORT || source == DNS_PORT) {
		parse_dns(packet + sizeof(struct udphdr), analyzer);
	} else {
		//print data ?
	}

}

void 	parse_ip(const unsigned char *packet, t_analyzer *analyzer) {
	struct iphdr *hdr = (struct iphdr *)packet;
	unsigned int protocol = hdr->protocol;

    if (protocol == TCP) {
        analyzer->protocol = "TCP";
        print_ip(packet, analyzer);
	    parse_tcp(packet + hdr->ihl * 4, ntohs(hdr->tot_len) - hdr->ihl * 4, analyzer);
    } else if (protocol == UDP) {
        analyzer->protocol = "UDP";
        print_ip(packet, analyzer);
	    parse_udp(packet + hdr->ihl * 4, analyzer);
    } else {
        analyzer->protocol = "unsupported";
        print_ip(packet, analyzer);
    }
}

void	parse_ipv6(const unsigned char *packet, t_analyzer *analyzer) {
	struct ip6_hdr 	*hdr = (struct ip6_hdr *)packet;
	uint8_t 		protocol = hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	uint16_t		payload_len = ntohs(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);


	if (protocol == TCP) {
		analyzer->protocol = "TCP";
		print_ipv6(packet, analyzer);
		parse_tcp(packet + HEADER_SIZE, payload_len, analyzer);
	} else if (protocol == UDP) {
		analyzer->protocol = "UDP";
		print_ipv6(packet, analyzer);
		parse_udp(packet + HEADER_SIZE, analyzer);
	} else {
        analyzer->protocol = "unsupported";
		print_ipv6(packet, analyzer);
	}
}

void	parse_ethernet(const unsigned char *packet, t_analyzer *analyzer) {
	struct ethhdr *hdr = (struct ethhdr *)(packet);
	unsigned short proto = ntohs(hdr->h_proto);
    
    switch(proto) {
    case ETH_P_IP:
        analyzer->format = "IPv4";
        print_ethernet(packet, analyzer);
        parse_ip(packet + sizeof(struct ethhdr), analyzer);
        break;
    case ETH_P_IPV6:
        analyzer->format = "IPv6";
        print_ethernet(packet, analyzer);
        parse_ipv6(packet + sizeof(struct ethhdr), analyzer);
        break;
    case ETH_P_ARP:
        analyzer->format = "ARP";
        print_ethernet(packet, analyzer);
        print_arp(packet + sizeof(struct ethhdr), analyzer);
        break;
    case ETH_P_RARP:
        analyzer->format = "RARP";
        print_ethernet(packet, analyzer);
        print_arp(packet + sizeof(struct ethhdr), analyzer);
        break;
    default:
        analyzer->format = "Unsupported";
        print_ethernet(packet, analyzer);
        break;
    }
}
