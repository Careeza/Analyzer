#include <stdio.h>
#include "defs.h"
#include "print_info.h"

char *ARPtype(struct arphdr *arp)
{
    switch (ntohs(arp->ar_op))
    {
    case ARPOP_REQUEST:
        return "Request";
    case ARPOP_REPLY:
        return "Reply";
    case ARPOP_RREQUEST:
        return "RARP Request";
    case ARPOP_RREPLY:
        return "RARP Reply";
    }
    return "unknown ARP type";
}

char *ARPHardware(struct arphdr *arp)
{
    char *r = "";
    switch (ntohs(arp->ar_hrd))
    {
    case ARPHRD_ETHER:
        return "Ethernet 10/100 Mbps";

    default:
        snprintf(r, 3, "%d", ntohs(arp->ar_hrd));
        return r;
    }
}

char *tcptype(struct tcphdr *tcp)
{
    if (tcp->ack && tcp->syn)
        return "SYN+ACK";
    if (tcp->ack && tcp->psh)
        return "PUSH+ACK";
    if (tcp->ack)
        return "ACK";
    if (tcp->syn)
        return "SYN";
    if (tcp->fin)
        return "FIN";
    if (tcp->urg)
        return "URGENT";
    if (tcp->psh)
        return "PUSH";
    if (tcp->rst)
        return "RESET";
    if (tcp->res1)
        return "CWR";
    if (tcp->res2)
        return "ECE";
    return "unknown";
}

void printInfo_ARP(struct arphdr *arp, const u_char *packet, int mode)
{
    int i;
    switch (mode)
    {
    case V1:
        fprintf(stdout, "ARP %s\n", ARPtype(arp));
        break;
    case V2:
        printf("ARP: \t\t");
        printf("operation=%s - hardware type=%s\n", ARPtype(arp), ARPHardware(arp));
        break;
    case V3:
        printf("ARP\n");
        printf("\tHardware type: %s (%d)\n", ARPHardware(arp), ntohs(arp->ar_hrd));
        printf("\tProtocol type:");
        if (ntohs(arp->ar_pro) == 0x0800)
            printf(" IP");
        printf(" (%d)\n", ntohs(arp->ar_pro));
        printf("\tHardware Address Length: %d\n", arp->ar_hln);
        printf("\tProtocol Address Length: %d\n", arp->ar_pln);
        printf("\tOperation: %s\n", ARPtype(arp));
        packet += ETH_HEADER_SIZE + sizeof(struct arphdr);
        printf("\tSender Hardware Address: ");
        for (i = 0; i < arp->ar_hln; i++)
        {
            printf("%X:", packet[0]);
            packet++;
        }
        printf("\n\tSender Protocol Address: ");
        for (i = 0; i < arp->ar_pln; i++)
        {
            printf("%d.", packet[0]);
            packet++;
        }
        printf("\n\tTarget Hardware Address: ");
        for (i = 0; i < arp->ar_hln; i++)
        {
            printf("%X:", packet[0]);
            packet++;
        }
        printf("\n\tTarget Protocol Address: ");
        for (i = 0; i < arp->ar_pln; i++)
        {
            printf("%d.", packet[0]);
            packet++;
        }
        break;
    default:
        break;
    }
}

// print info IP
void printInfo_IP(struct iphdr *ip, int mode)
{
    char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];

    switch (mode)
    {
    case V1:
        inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
        printf("IPV4: ");
        printf("%s > %s - ", ip_src, ip_dst);
        break;
    case V2:
        inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
        printf("IPV4: \t\t");
        printf("%s > %s - ", ip_src, ip_dst);
        printf("TTL=%d - ", ip->ttl);
        printf("protocol=%d", ip->protocol);
        printf("\n");
        break;
    case V3:
        inet_ntop(AF_INET, &ip->saddr, ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->daddr, ip_dst, INET_ADDRSTRLEN);
        printf("IPV4\n");
        printf("\tsrc: %s\n\tdest: %s\n", ip_src, ip_dst);
        printf("\tIHL: %d\n", ip->ihl);
        printf("\tType of service: %d\n", ntohs(ip->tos));
        printf("\tLength: %d\n", ntohs(ip->tot_len));
        printf("\tid: %d\n", ip->id);
        printf("\tfrag. offset: %d\n", ntohs(ip->frag_off));
        printf("\tTTL: %d\n", ip->ttl);
        printf("\tprotocol: %d\n", ip->protocol);
        printf("\tchecksum: 0x%x\n", ntohs(ip->check));
        if (ip->ihl > 5)
        {
            printf("\toptions:\n");
        }
        break;

    default:
        fprintf(stderr, "%sERROR : Level of verbosity invalid%s\n", CSI_RED, CSI_RESET);
        break;
    }
}

int appliLayerContent(struct tcphdr *tcp)
{
    if (tcp == NULL)
    {
        return 0;
    }
    char *msg = tcptype(tcp);
    if (strncmp(msg, "ACK", 3) == 0)
        return -1;
    if (strncmp(msg, "SYN+ACK", 7) == 0)
        return -1;
    if (strncmp(msg, "SYN", 3) == 0)
        return -1;
    if (strncmp(msg, "FIN", 3) == 0)
        return -1;
    return 0;
}

void printInfo_Transport(struct udphdr *udp, struct tcphdr *tcp, int mode)
{
    if (udp != NULL)
    {
        switch (mode)
        {
        case V1:
            printf("UDP: ");
            printf("src: %hu ", ntohs(udp->source));
            printf("dst: %hu", ntohs(udp->dest));
            break;
        case V2:
            printf("UDP: \t\t");
            printf("src: %hu ", ntohs(udp->source));
            printf("dst: %hu\n", ntohs(udp->dest));
            break;
        case V3:
            printf("UDP\n");
            printf("\tsrc: %hu\n", ntohs(udp->source));
            printf("\tdst: %hu\n", ntohs(udp->dest));
            printf("\tlength: %d\n", ntohs(udp->len));
            printf("\tchecksum: 0x%x\n", ntohs(udp->check));
            break;

        default:
            break;
        }
    }
    else if (tcp != NULL)
    {
        switch (mode)
        {
        case V1:
            printf("TCP: ");
            printf("Source: %hu ", ntohs(tcp->source));
            printf("Destination: %hu", ntohs(tcp->dest));
            break;
        case V2:
            printf("TCP: \t\t");
            printf("src: %hu ", ntohs(tcp->source));
            printf("dst: %hu ", ntohs(tcp->dest));
            printf("type: %s", tcptype(tcp));
            printf("\n");
            break;
        case V3:
            printf("TCP\n");
            printf("\tsrc: %hu\n", ntohs(tcp->source));
            printf("\tdst: %hu\n", ntohs(tcp->dest));
            printf("\tseq number: %u\n", ntohs(tcp->seq));
            printf("\tack number: %u\n", ntohs(tcp->ack_seq));
            printf("\toffset: %d\n", ntohs(tcp->doff));
            printf("\tflags: C E U A P R S F\n");
            printf("\t       %d %d %d %d %d %d %d %d\n",
                   tcp->res1, tcp->res2, tcp->urg, tcp->ack,
                   tcp->psh, tcp->rst, tcp->syn, tcp->fin);
            printf("\twindow: %d\n", ntohs(tcp->window));
            printf("\tchecksum: 0x%x\n", ntohs(tcp->check));
            printf("\turgent pointer: 0x%x\n", tcp->urg_ptr);
            if (tcp->doff > 5)
            {
                printf("\toptions:\n");
            }
            break;

        default:
            break;
        }
    }

    else
    {
        fprintf(stderr, "%sERROR : Network transport layer not supported%s\n", CSI_RED, CSI_RESET);
    }
    return;
}

//IPV6
void printInfo_IPv6(struct ip6_hdr *ip, int mode)
{
    switch (mode)
    {
        char ip_src[INET6_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];
    case 1:
        inet_ntop(AF_INET6, &ip->ip6_src, ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip->ip6_dst, ip_dst, INET6_ADDRSTRLEN);
        printf("IPV6: ");
        printf("%s > %s - ", ip_src, ip_dst);
        break;
    case 2:
        inet_ntop(AF_INET6, &ip->ip6_src, ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip->ip6_dst, ip_dst, INET6_ADDRSTRLEN);
        printf("IPV6: ");
        printf("%s > %s - ", ip_src, ip_dst);
        printf("Hop Limit=%d - ", ntohs(ip->ip6_hops));
        printf("Next Header=%d", ntohs(ip->ip6_nxt));
        printf("\n");
        break;
    case 3:
        inet_ntop(AF_INET6, &ip->ip6_src, ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip->ip6_dst, ip_dst, INET6_ADDRSTRLEN);
        printf("IPV6: ");
        printf("%s > %s - ", ip_src, ip_dst);
        printf("Hop Limit=%d - ", ntohs(ip->ip6_hops));
        printf("Next Header=%d", ntohs(ip->ip6_nxt));
        printf("\n");
        break;

    default:
        break;
    }
}
