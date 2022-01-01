
pcap_t *initLiveAnalysis(const char *myint, char *errbuf)
{
    pcap_t *handle;
    handle = pcap_open_live(myint, MAX_SIZE_ET_FRAME, 1, 0, errbuf);
    if (handle == NULL)
        exit_failure(errbuf, NULL);
    return handle;
}

pcap_t *initOfflineAnalysis(FILE *fichier, char *errbuf)
{
    pcap_t *handle;
    handle = pcap_fopen_offline(fichier, errbuf);
    return handle;
}

int analysis(const char *myint, FILE *file, int mode, char *filtre)
{
    (void)filtre; //TODO
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr infos;
    pcap_t *handle = NULL;
    int cpt = 0;

    if (file == NULL)
    {
        // direct analysis
        if ((handle = initLiveAnalysis(myint, errbuf)) == NULL)
        {
            fprintf(stderr, "Erreur pcap_open_live: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        while (1)
        {
            printf("ICI 1\n");
            fflush(stdout);
            if ((packet = pcap_next(handle, &infos)) == NULL)
            {
                fprintf(stderr, "ERROR : Impossible to read the packet\nDescription : %s\n", errbuf);
            }
            printf("ICI 2\n");
            fflush(stdout);
            packetAnalysis(packet, infos, mode, cpt);
            printf("ICI 3\n");
            fflush(stdout);
            cpt++;
        }
        pcap_close(handle);
    }
    else
    {
        // offline analysis
        if ((handle = initOfflineAnalysis(file, errbuf)) == NULL)
        {
            fprintf(stderr, "%sERROR : pcap_fopen_offline: %s%s\n", CSI_RED, errbuf, CSI_RESET);
            return EXIT_FAILURE;
        }
        //appliquerFiltre(handle, filtre);
        while (packet != NULL)
        {
            if ((packet = pcap_next(handle, &infos)) != NULL)
            {
                packetAnalysis(packet, infos, mode, cpt);
                cpt++;
            }
        }
    }
    printf("\n%d packets captured\n", cpt);
    return 0;
}

// analysis of a packet
void packetAnalysis(const u_char *packet, struct pcap_pkthdr infos, int mode, int compteur)
{
    struct ethhdr *ethernet = NULL;
    struct iphdr *ip = NULL;
    struct ip6_hdr *ip6 = NULL;
    struct arphdr *arp = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    char *appli = NULL;
    u_int size_ip = 0;
    u_int sizeTransport = 0;
    u_int8_t protocol;
    int ethDataType;

    /**
     *  NIVEAU 2
     */
    ethernet = (struct ethhdr *)(packet);
    ethDataType = ntohs(ethernet->h_proto);

    /**
     *  NIVEAU 3
     */
    switch (ethDataType)
    {
    case ETH_P_IP: //Data type : IP
        ip = (struct iphdr *)(packet + ETH_HEADER_SIZE);
        size_ip = ip->ihl * 4;   // taille entete ip
        protocol = ip->protocol; // protocole au dessus de IP
        break;

    case ETH_P_ARP: // Data type : ARP
        arp = (struct arphdr *)(packet + ETH_HEADER_SIZE);
        break;
        // case ETH_P_RARP: // Data type : RARP
        //     //rarp = (struct )
        //     break;

    case ETH_P_IPV6:
        ip6 = (struct ip6_hdr *)(packet + ETH_HEADER_SIZE);
        protocol = ip6->ip6_nxt;
        //size_ip = analyseExtensionIp6(packet, ip6); TODO
        break;

        // case ETH_P_LOOPBACK:
        //     /**
        //      *  Ethernet Configuration Testing Protocol
        //      *  Permet de faire des tests sur le niveau 2 sur le loopback
        //      *  (similaire à echo au niveau 3)
        //      */
        //     break;

    default:
        fprintf(stderr, "%sERROR : Type 0x%x not supported%s\n", CSI_RED, ethDataType, CSI_RESET);
        // if (mode == 3)
        //     printf("\n--------------------------------------------\n\n");
        exit(EXIT_FAILURE);
    }

    /**
     *  NIVEAU 4 (analyse du numéro de protocole dans IPv4)
     */
    if ((ip != NULL) || (ip6 != NULL))
    {
        switch (protocol)
        {
        case IPPROTO_UDP:
            udp = (struct udphdr *)(packet + ETH_HEADER_SIZE + size_ip);
            sizeTransport = UDP_HEADER_SIZE;
            break;
        case IPPROTO_TCP:
            tcp = (struct tcphdr *)(packet + ETH_HEADER_SIZE + size_ip);
            sizeTransport = tcp->th_off * 4;
            break;
        // case IPPROTO_ICMP:
        //     printf("Frame %d. %d bytes\tICMP\n", compteur, infos.len);
        //     return;
        // case IPPROTO_IGMP:
        //     printf("Frame %d. %d bytes\tIGMP\n", compteur, infos.len);
        //     return;
        // case IPPROTO_ICMPV6:
        //     printf("Frame %d. %d bytes\tICMPv6\n", compteur, infos.len);
        //     return;
        default:
            printf("%sERROR : IP protocol number %d not supported%s\n", CSI_RED, protocol, CSI_RESET);
            return;
        }
    }

    /**
     * APPLICATIF
     */
    appli = (char *)packet + ETH_HEADER_SIZE + size_ip + sizeTransport;

    /**
     *  AFFICHAGE SELON LE MODE CHOISI
     */
    printf("Frame %d. %d bytes\t", compteur, infos.len);

    //print_info(mode);

    switch (ethDataType)
    {
    case ETH_P_ARP:
        printInfo_ARP(arp, packet, mode);
        return;
        break;
    case ETH_P_IP:
        printInfo_IP(ip, mode);
        break;
    case ETH_P_IPV6:
        printInfo_IPv6(ip6, mode);
        break;
    default:
        fprintf(stdout, "%sERROR : Data type from Ethernet not supported%s\n", CSI_RED, CSI_RESET);
        break;
    }

    if ((tcp != NULL) || (udp != NULL))
        printInfo_Transport(udp, tcp, mode);
    // on vérifie qu'au dessus de TCP il y a de l'applicatif
    if (appliLayerContent(tcp) == 0)
        printInfo_appliContent(udp, tcp, appli, mode);
    printf("\n");






    printf("\n");
    // afficherEthernetSynthe(ethernet);
    // if (etherType == ETH_P_ARP)
    // {
    //     afficherARPSynthe(arp);
    //     return; // plus rien après ARP
    // }
    // else if (etherType == ETH_P_IP)
    //     afficherIpSynthe(ip);
    // else if (etherType == ETH_P_IPV6)
    //     afficherIp6Synthe(ip6);
    // if ((tcp != NULL) || (udp != NULL))
    //     afficherTransportSynthe(udp, tcp);
    // if (contientCoucheApplicative(tcp) == 0)
    //     afficherApplicatifSynthe(udp, tcp, appli);
    // printf("\n\n");

    // afficherEthernetComplet(ethernet);
    // if (etherType == ETH_P_ARP)
    // {
    //     afficherARPComplet(arp, packet);
    //     printf("\n----------------------------------------\n\n");
    //     return; // plus rien après ARP
    // }
    // else if (etherType == ETH_P_IP)
    //     afficherIpComplet(ip);
    // else if (etherType == ETH_P_IPV6)
    // {
    // }
    // if ((tcp != NULL) || (udp != NULL))
    //     afficherTransportComplet(udp, tcp);
    // if (contientCoucheApplicative(tcp) == 0)
    //     afficherApplicatifComplet(udp, tcp, appli);
    // printf("\n--------------------------------------------\n\n");

    fprintf(stderr, "Erreur: mode %d inconnu.\n", mode);
    exit(EXIT_FAILURE);
}