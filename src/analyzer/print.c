#include "print.h"
#include "analyzer.h"
#include "utils.h"
#include "bootp.h"
#include "parser.h"
#include <stdio.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#define UDP_HEADER_SIZE 8

void    print_mac_addr(unsigned char *addr, bool new_line) {
	printf("%02x", addr[0]);
	for (int i = 1; i < ETH_ALEN; i++) {
		printf(":%02x", addr[i]);
	}
    if (new_line) {
        printf("\n");
    }
}

void    print_payload_addr(uint16_t len, const uint8_t *payload) {
    if (len == 6) {
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", payload[0], payload[1],
				   payload[2], payload[3], payload[4], payload[5]);
	} else if (len == 1) {
		printf("%02x (TOKEN RING)\n", payload[0]);
	}
}

void    print_addr(uint16_t len, const uint8_t *payload) {
	if (len == 4) {
        char str[INET_ADDRSTRLEN];
        printf("%s\n", inet_ntop(AF_INET, payload, str, INET_ADDRSTRLEN));
	} else if (len == 16) {
        char str[INET6_ADDRSTRLEN];
        printf("%s\n", inet_ntop(AF_INET6, payload, str, INET6_ADDRSTRLEN));
	}
}

void    print_ethernet(const unsigned char *packet, t_analyzer *analyzer) {
	struct ethhdr *hdr = (struct ethhdr *)packet;

    if (analyzer->info.verbosity == 2) {
        printf("\n%sEthernet:%s %sSRC:%s ", CSI_BLUE, CSI_RESET, CSI_BLUE, CSI_RESET);
        print_mac_addr(hdr->h_source, false);
        printf("\t%sDST:%s ", CSI_BLUE, CSI_RESET);
        print_mac_addr(hdr->h_dest, true);
    } else if (analyzer->info.verbosity == 3) { //VERBOSE COMPLETE
        printf("\n%sEthernet%s\n", CSI_BLUE, CSI_RESET);
        printf("%s%-10s%s", CSI_BLUE, "SRC: ", CSI_RESET);
        print_mac_addr(hdr->h_source, true);
        printf("%s%-10s%s", CSI_BLUE, "DST: ", CSI_RESET);
        print_mac_addr(hdr->h_dest, true);
        printf("%s%-10s%s%s\n", CSI_BLUE, "TYPE: ", CSI_RESET, analyzer->format);
    }
}

void    print_ip(const unsigned char *packet, t_analyzer *analyzer) {
    struct iphdr    *hdr = (struct iphdr *)packet;
    uint16_t        frag_off = ntohs(hdr->frag_off);
    char            str[INET_ADDRSTRLEN];

    if (analyzer->info.verbosity == 1) {
        printf(", %sIPv4: SRC:%s %s", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET, &(hdr->saddr), str, INET_ADDRSTRLEN));
        printf(", %sDST:%s %s", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET, &(hdr->daddr), str, INET_ADDRSTRLEN));
    } else if (analyzer->info.verbosity == 2) {
        printf("\t%sIPv4: SRC:%s %s", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET, &(hdr->saddr), str, INET_ADDRSTRLEN));
        printf("\t%sDST:%s %s\n", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET, &(hdr->daddr), str, INET_ADDRSTRLEN));
    } else {
        printf("\t%sIP%s\n", CSI_YELLOW, CSI_RESET);
        printf("\t%s%-10s%s%d\n", CSI_YELLOW, "VERSION: ", CSI_RESET, hdr->version);
        printf("\t%s%-10s%s%d\n", CSI_YELLOW, "IHL: ", CSI_RESET, hdr->ihl);
        printf("\t%s%-10s%s0X%04X\n", CSI_YELLOW, "TOS: ", CSI_RESET, ntohs(hdr->tos));
        printf("\t%s%-10s%s%d\n", CSI_YELLOW, "LENGTH: ", CSI_RESET, ntohs(hdr->tot_len));
        printf("\t%s%-10s%s0X%04X\n", CSI_YELLOW, "ID: ", CSI_RESET, ntohs(hdr->id));
        printf("\t%s%-10s%s%s", CSI_YELLOW, "FLAGS", CSI_RESET, "[");
        if (frag_off & 1 << 14)
            printf(" DF");
        if (frag_off & 1 << 13)
            printf(" MF");
        if (!(frag_off & 1 << 13) && !(frag_off & 1 << 14))
            printf(" NONE");
        printf(" ]\n");
        printf("\t%s%-10s%s%i\n", CSI_YELLOW, "FRAG OFF", CSI_RESET, frag_off);
        printf("\t%s%-10s%s%s\n", CSI_YELLOW, "PROTOCOL", CSI_RESET, analyzer->protocol);
        printf("\t%s%-10s%s%04X\n", CSI_YELLOW, "CHKSUM", CSI_RESET, ntohs(hdr->check));
        printf("\t%s%-10s%s%s\n", CSI_YELLOW, "SRC ADDR", CSI_RESET, inet_ntop(AF_INET, &(hdr->saddr), str, INET_ADDRSTRLEN));
        printf("\t%s%-10s%s%s\n", CSI_YELLOW, "DST ADDR", CSI_RESET, inet_ntop(AF_INET, &(hdr->daddr), str, INET_ADDRSTRLEN));
    }
}

void    print_ipv6(const unsigned char *packet, t_analyzer *analyzer) {
    struct              ip6_hdr *hdr = (struct ip6_hdr *)packet;
    uint16_t            payload_len = ntohs(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
    uint16_t            hop_limit = hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
    char                str[INET6_ADDRSTRLEN];

    if (analyzer->info.verbosity == 1) {
        printf(", %sIPv6: SRC:%s %s", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET6, &(hdr->ip6_src), str, INET6_ADDRSTRLEN));
        printf(", %sDST:%s %s", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET6, &(hdr->ip6_src), str, INET6_ADDRSTRLEN));
    } else if (analyzer->info.verbosity == 2) {
        printf("\t%sIPv6: SRC:%s %s", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET6, &(hdr->ip6_src), str, INET6_ADDRSTRLEN));
        printf("\t%sDST:%s %s\n", CSI_YELLOW, CSI_RESET, inet_ntop(AF_INET6, &(hdr->ip6_src), str, INET6_ADDRSTRLEN));
    } else {
        printf("\t%sIPv6%s\n", CSI_YELLOW, CSI_RESET);
        printf("\t%s%-15s%s%u\n", CSI_YELLOW, "PLEN: ", CSI_RESET, payload_len);
        printf("\t%s%-15s%s%s\n", CSI_YELLOW, "NEXT HEADER: ", CSI_RESET, analyzer->protocol);
        printf("\t%s%-15s%s%u\n", CSI_YELLOW, "HLIM: ", CSI_RESET, hop_limit);
        printf("\t%s%-15s%s%s\n", CSI_YELLOW, "SRC ADDR", CSI_RESET, inet_ntop(AF_INET6, &(hdr->ip6_src), str, INET6_ADDRSTRLEN));
        printf("\t%s%-15s%s%s\n", CSI_YELLOW, "DST ADDR", CSI_RESET, inet_ntop(AF_INET6, &(hdr->ip6_src), str, INET6_ADDRSTRLEN));
    }
}

void    print_arp(const unsigned char *packet, t_analyzer *analyzer) {
    struct arphdr   *hdr = (struct arphdr *)packet;
	char            *type;
    uint16_t        ar_op = ntohs(hdr->ar_op);

    type = (ar_op == ARPOP_REPLY || ar_op == ARPOP_REQUEST ? "ARP" : "RARP");

    if (analyzer->info.verbosity == 1) {
        printf("%s%s%s, [ ", CSI_YELLOW, type, CSI_RESET);
        ar_op == ARPOP_REQUEST ? printf("request ]\n") : (void)0;
        ar_op == ARPOP_REPLY ? printf("reply ]\n") : (void)0;
        ar_op == ARPOP_RREQUEST ? printf("reverse request ]\n") : (void)0;
        ar_op == ARPOP_RREPLY ? printf("reverse reply ]\n") : (void)0;
    } else if (analyzer->info.verbosity == 2) {
        printf("\t%s%s%s, [ ", CSI_YELLOW, type, CSI_RESET);
        ar_op == ARPOP_REQUEST ? printf("request ]\n") : (void)0;
        ar_op == ARPOP_REPLY ? printf("reply ]\n") : (void)0;
        ar_op == ARPOP_RREQUEST ? printf("reverse request ]\n") : (void)0;
        ar_op == ARPOP_RREPLY ? printf("reverse reply ]\n") : (void)0;
    } else {
        printf("\t%s%s%s\n", CSI_YELLOW, type, CSI_RESET);
        printf("\t%s%-15s%s%04X\n", CSI_YELLOW, "HRD", CSI_RESET, ntohs(hdr->ar_hrd));
        printf("\t%s%-15s%s%04X\n", CSI_YELLOW, "PROTOCOL", CSI_RESET, ntohs(hdr->ar_pro));
        printf("\t%s%-15s%s%u\n", CSI_YELLOW, "HLN: ", CSI_RESET, hdr->ar_hln);
        printf("\t%s%-15s%s%u\n", CSI_YELLOW, "PLN: ", CSI_RESET, hdr->ar_pln);
        printf("\t%s%-15s%s%u[ ", CSI_YELLOW, "OP: ", CSI_RESET, ar_op);
        ar_op == ARPOP_REQUEST ? printf("request ]\n") : (void)0;
        ar_op == ARPOP_REPLY ? printf("reply ]\n") : (void)0;
        ar_op == ARPOP_RREQUEST ? printf("reverse request ]\n") : (void)0;
        ar_op == ARPOP_RREPLY ? printf("reverse reply ]\n") : (void)0;
    
        packet += sizeof(struct arphdr);
        printf("\t%s%-15s%s", CSI_YELLOW, "SENDER HLN: ", CSI_RESET);
        print_payload_addr(hdr->ar_hln, packet);
        packet += hdr->ar_hln;
        printf("\t%s%-15s%s", CSI_YELLOW, "SENDER PLN: ", CSI_RESET);
        print_addr(hdr->ar_pln, packet);
        packet += hdr->ar_pln;
        printf("\t%s%-15s%s", CSI_YELLOW, "TARGET HLN: ", CSI_RESET);
        print_payload_addr(hdr->ar_hln, packet);
        packet += hdr->ar_hln;
        printf("\t%s%-15s%s", CSI_YELLOW, "TARGET PLN: ", CSI_RESET);
        print_addr(hdr->ar_pln, packet);
    }

}

void    print_tcp(const unsigned char *packet, t_analyzer *analyzer) {
    struct tcphdr *hdr = (struct tcphdr *)packet;
	// 		 doff = hdr->doff;

    if (analyzer->info.verbosity == 1) {
        printf(", %sTCP SRC:%s %hu\t%sDST:%s %hu", CSI_CYAN, CSI_RESET, ntohs(hdr->source), CSI_CYAN, CSI_RESET, ntohs(hdr->dest));
    } else if (analyzer->info.verbosity == 2) {
        printf("\t\t%sTCP SRC:%s %hu %sDST:%s %hu\n", CSI_CYAN, CSI_RESET, ntohs(hdr->source), CSI_CYAN, CSI_RESET, ntohs(hdr->dest));
    } else {
        printf("\t\t%sTCP%s\n", CSI_CYAN, CSI_RESET);
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "SRC PORT: ", CSI_RESET, ntohs(hdr->source));
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "DST PORT: ", CSI_RESET, ntohs(hdr->dest));
        printf("\t\t%s%-10s%s%u\n", CSI_CYAN, "SEQ n", CSI_RESET, ntohl(hdr->seq));
        printf("\t\t%s%-10s%s%u\n", CSI_CYAN, "ACK n", CSI_RESET, ntohl(hdr->ack_seq));
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "DOFF: ", CSI_RESET, hdr->doff);
        printf("\t\t%s%-10s%s%s", CSI_CYAN, "FLAGS", CSI_RESET, "[");
        hdr->fin ? printf(" FIN") : (void)0;
        hdr->syn ? printf(" SYN") : (void)0;
        hdr->rst ? printf(" RST") : (void)0;
        hdr->psh ? printf(" PSH") : (void)0;
        hdr->ack ? printf(" ACK") : (void)0;
        hdr->urg ? printf(" URG") : (void)0;
        printf(" ]\n");
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "WINDOW: ", CSI_RESET, ntohs(hdr->window));
        printf("\t\t%s%-10s%s0X%04X\n", CSI_CYAN, "CHECKSUM: ", CSI_RESET, ntohs(hdr->check));
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "URG PTR: ", CSI_RESET, ntohs(hdr->urg_ptr));
    }
}

void    print_udp(const unsigned char *packet, t_analyzer *analyzer) {
	struct udphdr *hdr = (struct udphdr *)packet;

    if (analyzer->info.verbosity == 1) {
        printf(", %sUDP SRC:%s %hu\t%sDST:%s %hu", CSI_CYAN, CSI_RESET, ntohs(hdr->source), CSI_CYAN, CSI_RESET, ntohs(hdr->dest));
    } else if (analyzer->info.verbosity == 2) {
        printf("\t\t%sUDP SRC:%s %hu %sDST:%s %hu\n", CSI_CYAN, CSI_RESET, ntohs(hdr->source), CSI_CYAN, CSI_RESET, ntohs(hdr->dest));
    } else {
        printf("\t\t%sUDP%s\n", CSI_CYAN, CSI_RESET);
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "SRC PORT: ", CSI_RESET, ntohs(hdr->source));
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "DST PORT: ", CSI_RESET, ntohs(hdr->dest));
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "CHECKSUM: ", CSI_RESET, ntohs(hdr->check));
        printf("\t\t%s%-10s%s%hu\n", CSI_CYAN, "LEN: ", CSI_RESET, ntohs(hdr->len) - UDP_HEADER_SIZE);
    }
}

void    print_bootp(const unsigned char *packet, t_analyzer *analyzer) {
    struct          bootp_hdr *hdr = (struct bootp_hdr *)packet;
    bool            dhcp = false;

    if (hdr->vend[0] == 99 && hdr->vend[1] == 130 && hdr->vend[2] == 83 &&
		hdr->vend[3] == 99) {
		dhcp = true;
    }
    if (analyzer->info.verbosity == 1) {
        printf(", %s%s%s", CSI_PURPLE, dhcp ? "DHCP" : "BOOTP", CSI_RESET);
    } else if (analyzer->info.verbosity == 2) {
        printf("\t\t\t%s%s%s\n", CSI_PURPLE, dhcp ? "DHCP" : "BOOTP", CSI_RESET);
    } else {
        printf("\t\t\t%sBOOTP%s\n", CSI_PURPLE, CSI_RESET);
        printf("\t\t\t%s%-10s%s%hu\n", CSI_PURPLE, "OP: ", CSI_RESET, ntohs(hdr->op));
        printf("\t\t\t%s%-10s%s%hu\n", CSI_PURPLE, "HTYPE: ", CSI_RESET, ntohs(hdr->htype));
        printf("\t\t\t%s%-10s%s%hu\n", CSI_PURPLE, "HLEN: ", CSI_RESET, ntohs(hdr->hlen));
        printf("\t\t\t%s%-10s%s%hu\n", CSI_PURPLE, "HOPS: ", CSI_RESET, ntohs(hdr->hops));
        printf("\t\t\t%s%-10s%s0X%04X\n", CSI_PURPLE, "XID: ", CSI_RESET, ntohl(hdr->xid));
        printf("\t\t\t%s%-10s%s%hu\n", CSI_PURPLE, "SECS: ", CSI_RESET, ntohs(hdr->secs));
        printf("\t\t\t%s%-10s%s%s", CSI_PURPLE, "FLAGS", CSI_RESET, "[");
        ntohs(hdr->flags) ? printf(" B ]\n") : printf(" NONE ]");
        printf("\t\t\t%s%-10s%s%s\n", CSI_PURPLE, "CIADDR: ", CSI_RESET, inet_ntoa(hdr->ciaddr));
        printf("\t\t\t%s%-10s%s%s\n", CSI_PURPLE, "YIADDR: ", CSI_RESET, inet_ntoa(hdr->yiaddr));
        printf("\t\t\t%s%-10s%s%s\n", CSI_PURPLE, "SIADDR: ", CSI_RESET, inet_ntoa(hdr->siaddr));
        printf("\t\t\t%s%-10s%s%s\n", CSI_PURPLE, "GIADDR: ", CSI_RESET, inet_ntoa(hdr->giaddr));
        printf("\t\t\t%s%-10s%s\n", CSI_PURPLE, "CHADDR: ", CSI_RESET);
        print_mac_addr(hdr->chaddr, true);
        printf("\t\t\t%s%-10s%s\n", CSI_PURPLE, "SNAME: ", CSI_RESET);
        hdr->sname[0] == 0 ? printf("UNKNOW\n") : printf("%s\n", (char *)hdr->sname);
        printf("\t\t\t%s%-10s%s\n", CSI_PURPLE, "FILE: ", CSI_RESET);
        hdr->file[0] == 0 ? printf("UNKNOW\n") : printf("%s\n",(char *)hdr->file);
    }

}

void    print_data(const unsigned char *data, uint16_t size, t_analyzer *analyzer) {
    if (analyzer->info.verbosity == 1) {

    } else if (analyzer->info.verbosity == 2) {
        printf("\t\t\t%sDATA SIZE: %s%d\n", CSI_MAGENTA, CSI_RESET, size);
    } else {
        printf("\t\t\t%sDATA SIZE: %s%d\n", CSI_MAGENTA, CSI_RESET, size);
        printf("\t\t\t%sDATA: %s", CSI_MAGENTA, CSI_RESET);
        fflush(stdout);
        write(1, data, size);
    }
}