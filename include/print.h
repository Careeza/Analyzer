#ifndef PRINT_H

# define PRINT_H

# include "analyzer.h"
# include <stdbool.h>

void    print_mac_addr(unsigned char *addr, bool new_line);
void    print_ethernet(const unsigned char *packet, t_analyzer *analyzer);
void    print_ip(const unsigned char *packet, t_analyzer *analyzer);
void    print_arp(const unsigned char *packet, t_analyzer *analyzer);
void    print_ipv6(const unsigned char *packet, t_analyzer *analyzer);
void    print_tcp(const unsigned char *packet, t_analyzer *analyzer);
void    print_data(const unsigned char *data, uint16_t size, t_analyzer *analyzer);
void    print_udp(const unsigned char *packet, t_analyzer *analyzer);
void    print_bootp(const unsigned char *packet, t_analyzer *analyzer);

#endif