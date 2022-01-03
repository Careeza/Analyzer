#ifndef PARSER_H

# define PARSER_H

# include "analyzer.h"
# include "utils.h"

#define TCP 0x06
#define UDP 0x11
#define HEADER_SIZE 40
#define BOOTP_SERVER_PORT 67
#define BOOTP_CLIENT_PORT 68
#define DNS_PORT 53


void    parse_ethernet(const unsigned char *packet, t_analyzer *analyzer);
void    parse_ip(const unsigned char *packet, t_analyzer *analyzer);
void	parse_udp(const unsigned char *packet, t_analyzer *analyzer);
void    parse_tcp(const unsigned char *packet, uint16_t size, t_analyzer *analyzer);

#endif