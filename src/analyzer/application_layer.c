#include "application_layer.h"
#include "defs.h"

/**
 *  AFFICHAGE APPLICATIF
 */
// renvoie le numéro de port si type trouvé, -1 sinon
int afficherTypeApplicatif(uint16_t port, int print)
{
    switch (port)
    {
        case FTPDATA:
            if (print) 
                printf(" - %sApplication%s : FTP Data", CSI_GREEN, CSI_RESET);
            return FTPDATA;

        case FTPCMD:
            if (print) 
                printf(" - %sApplication%s :  FTP Command", CSI_GREEN, CSI_RESET);
            return FTPCMD;

        case SSH:
            if (print)
                printf(" - %sApplication%s : SSH", CSI_GREEN, CSI_RESET);
            return SSH;

        case TELNET:
            if (print)
                printf(" - %sApplication%s : TELNET", CSI_GREEN, CSI_RESET);
            return TELNET;

        case SMTP:
            if (print)
                printf(" - %sApplication%s : SMTP", CSI_GREEN, CSI_RESET);
            return SMTP;        
        
        case DNS:
            if (print)
                printf(" - %sApplication%s : DNS", CSI_GREEN, CSI_RESET);
            return DNS;        
        
        case BOOTP_C:
            if (print)
                printf(" - %sApplication%s : BOOTP or DHCP", CSI_GREEN, CSI_RESET);
            return BOOTP_C;        

        case BOOTP_S:
            if (print)
                printf(" - %sApplication%s : BOOTP or DHCP", CSI_GREEN, CSI_RESET);
            return BOOTP_S;        
        
        case HTTP:
            if (print)
                printf(" - %sApplication%s : HTTP", CSI_GREEN, CSI_RESET);
            return HTTP;        
        
        case POP3:
            if (print)
                printf(" - %sApplication%s : POP3", CSI_GREEN, CSI_RESET);
            return POP3;        
            break;

        case NTP:
            if (print)
                printf(" - %sApplication%s : NTP", CSI_GREEN, CSI_RESET);
            return NTP;

        case IMAP:
            if (print)
                printf(" - %sApplication%s : IMAP", CSI_GREEN, CSI_RESET);
            return IMAP;

        case LDAP:
            if (print)
                printf(" - %sApplication%s : LDAP", CSI_GREEN, CSI_RESET);
            return LDAP;
        
        case HTTPS:
            if (print)
                printf(" - %sApplication%s : HTTPS", CSI_GREEN, CSI_RESET);
            return HTTPS;

        case DHCP6_C:
        if (print)
                printf(" - %sApplication%s : DHCP6", CSI_GREEN, CSI_RESET);
            return DHCP6_C;
        
        case DHCP6_S:
            if (print)
                printf(" - %sApplication%s : DHCP6", CSI_GREEN, CSI_RESET);
            return DHCP6_S;
        
        default:
            break;
    }
    return -1;
}

void printInfo_appliContent(struct udphdr *udp, struct tcphdr *tcp, char *appli, int mode)
{
    uint16_t portsrc, portdst;
    (void)portdst; //TODO
    switch (mode)
    {
    case V1:

        // cas où la couche applicative est vide
        if (appli == NULL)
            return;

        if (udp != NULL)
        {
            portsrc = ntohs(udp->source);
            portdst = ntohs(udp->dest);
        }
        else if (tcp != NULL)
        {
            portsrc = ntohs(tcp->source);
            portdst = ntohs(tcp->dest);
        }

        // on regarde si le port d'un protocole applicatif connu apparait
        if (afficherTypeApplicatif(portsrc, 1) != -1)
        {
        }
        // else if (afficherTypeApplicatif(portdst, 1) != -1)
        // {
        // }
        break;

    case V2:
        break;

    case V3:
        break;

    default:
        break;
    }
}