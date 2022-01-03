#ifndef MONITOR_BOOTP_H
#define MONITOR_BOOTP_H

#include <netinet/in.h>

/**
 * Cf RFC 1542
 */

/* @(#) $Header: /tcpdump/master/tcpdump/bootp.h,v 1.11 2001/01/09 07:39:13
 * fenner Exp $ (LBL) */
/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1048.
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 * Copyright 1988 by Carnegie Mellon.
 *
 * Permission to use, copy, modify, and distribute this program for any
 * purpose and without fee is hereby granted, provided that this copyright
 * and permission notice appear on all copies and supporting documentation,
 * the name of Carnegie Mellon not be used in advertising or publicity
 * pertaining to distribution of the program without specific prior
 * permission, and notice be given in supporting documentation that copying
 * and distribution is by permission of Carnegie Mellon and Stanford
 * University.  Carnegie Mellon makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

struct bootp_hdr {
	u_int8_t op;		   /* packet opcode type */
	u_int8_t htype;		   /* hardware addr type */
	u_int8_t hlen;		   /* hardware addr length */
	u_int8_t hops;		   /* gateway hops */
	u_int32_t xid;		   /* transaction ID */
	u_int16_t secs;		   /* seconds since boot began */
	u_int16_t flags;	   /* flags: 0x8000 is broadcast */
	struct in_addr ciaddr; /* client IP address */
	struct in_addr yiaddr; /* 'your' IP address */
	struct in_addr siaddr; /* server IP address */
	struct in_addr giaddr; /* gateway IP address */
	u_int8_t chaddr[16];   /* client hardware address */
	u_int8_t sname[64];	   /* server host name */
	u_int8_t file[128];	   /* boot file name */
	u_int8_t vend[64];	   /* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define IPPORT_BOOTPS 67
#define IPPORT_BOOTPC 68

#define BOOTREPLY 2
#define BOOTREQUEST 1

/*
 * Vendor magic cookie (v_magic) for CMU
 */
#define VM_CMU "CMU"

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048 \
	{ 99, 130, 83, 99 }

/*
 * RFC1048 tag values used to specify what information is being supplied in
 * the vendor field of the packet.
 */

#define TAG_PAD ((u_int8_t)0)
#define TAG_SUBNET_MASK ((u_int8_t)1)
#define TAG_TIME_OFFSET ((u_int8_t)2)
#define TAG_GATEWAY ((u_int8_t)3)
#define TAG_TIME_SERVER ((u_int8_t)4)
#define TAG_NAME_SERVER ((u_int8_t)5)
#define TAG_DOMAIN_SERVER ((u_int8_t)6)
#define TAG_LOG_SERVER ((u_int8_t)7)
#define TAG_COOKIE_SERVER ((u_int8_t)8)
#define TAG_LPR_SERVER ((u_int8_t)9)
#define TAG_IMPRESS_SERVER ((u_int8_t)10)
#define TAG_RLP_SERVER ((u_int8_t)11)
#define TAG_HOSTNAME ((u_int8_t)12)
#define TAG_BOOTSIZE ((u_int8_t)13)
#define TAG_END ((u_int8_t)255)
/* RFC1497 tags */
#define TAG_DUMPPATH ((u_int8_t)14)
#define TAG_DOMAINNAME ((u_int8_t)15)
#define TAG_SWAP_SERVER ((u_int8_t)16)
#define TAG_ROOTPATH ((u_int8_t)17)
#define TAG_EXTPATH ((u_int8_t)18)
/* RFC2132 */
#define TAG_IP_FORWARD ((u_int8_t)19)
#define TAG_NL_SRCRT ((u_int8_t)20)
#define TAG_PFILTERS ((u_int8_t)21)
#define TAG_REASS_SIZE ((u_int8_t)22)
#define TAG_DEF_TTL ((u_int8_t)23)
#define TAG_MTU_TIMEOUT ((u_int8_t)24)
#define TAG_MTU_TABLE ((u_int8_t)25)
#define TAG_INT_MTU ((u_int8_t)26)
#define TAG_LOCAL_SUBNETS ((u_int8_t)27)
#define TAG_BROAD_ADDR ((u_int8_t)28)
#define TAG_DO_MASK_DISC ((u_int8_t)29)
#define TAG_SUPPLY_MASK ((u_int8_t)30)
#define TAG_DO_RDISC ((u_int8_t)31)
#define TAG_RTR_SOL_ADDR ((u_int8_t)32)
#define TAG_STATIC_ROUTE ((u_int8_t)33)
#define TAG_USE_TRAILERS ((u_int8_t)34)
#define TAG_ARP_TIMEOUT ((u_int8_t)35)
#define TAG_ETH_ENCAP ((u_int8_t)36)
#define TAG_TCP_TTL ((u_int8_t)37)
#define TAG_TCP_KEEPALIVE ((u_int8_t)38)
#define TAG_KEEPALIVE_GO ((u_int8_t)39)
#define TAG_NIS_DOMAIN ((u_int8_t)40)
#define TAG_NIS_SERVERS ((u_int8_t)41)
#define TAG_NTP_SERVERS ((u_int8_t)42)
#define TAG_VENDOR_OPTS ((u_int8_t)43)
#define TAG_NETBIOS_NS ((u_int8_t)44)
#define TAG_NETBIOS_DDS ((u_int8_t)45)
#define TAG_NETBIOS_NODE ((u_int8_t)46)
#define TAG_NETBIOS_SCOPE ((u_int8_t)47)
#define TAG_XWIN_FS ((u_int8_t)48)
#define TAG_XWIN_DM ((u_int8_t)49)
#define TAG_NIS_P_DOMAIN ((u_int8_t)64)
#define TAG_NIS_P_SERVERS ((u_int8_t)65)
#define TAG_MOBILE_HOME ((u_int8_t)68)
#define TAG_SMPT_SERVER ((u_int8_t)69)
#define TAG_POP3_SERVER ((u_int8_t)70)
#define TAG_NNTP_SERVER ((u_int8_t)71)
#define TAG_WWW_SERVER ((u_int8_t)72)
#define TAG_FINGER_SERVER ((u_int8_t)73)
#define TAG_IRC_SERVER ((u_int8_t)74)
#define TAG_STREETTALK_SRVR ((u_int8_t)75)
#define TAG_STREETTALK_STDA ((u_int8_t)76)
/* DHCP options */
#define TAG_REQUESTED_IP ((u_int8_t)50)
#define TAG_IP_LEASE ((u_int8_t)51)
#define TAG_OPT_OVERLOAD ((u_int8_t)52)
#define TAG_TFTP_SERVER ((u_int8_t)66)
#define TAG_BOOTFILENAME ((u_int8_t)67)
#define TAG_DHCP_MESSAGE ((u_int8_t)53)
#define TAG_SERVER_ID ((u_int8_t)54)
#define TAG_PARM_REQUEST ((u_int8_t)55)
#define TAG_MESSAGE ((u_int8_t)56)
#define TAG_MAX_MSG_SIZE ((u_int8_t)57)
#define TAG_RENEWAL_TIME ((u_int8_t)58)
#define TAG_REBIND_TIME ((u_int8_t)59)
#define TAG_VENDOR_CLASS ((u_int8_t)60)
#define TAG_CLIENT_ID ((u_int8_t)61)
/* RFC 2241 */
#define TAG_NDS_SERVERS ((u_int8_t)85)
#define TAG_NDS_TREE_NAME ((u_int8_t)86)
#define TAG_NDS_CONTEXT ((u_int8_t)87)
/* RFC 2242 */
#define TAG_NDS_IPDOMAIN ((u_int8_t)62)
#define TAG_NDS_IPINFO ((u_int8_t)63)
/* RFC 2485 */
#define TAG_OPEN_GROUP_UAP ((u_int8_t)98)
/* RFC 2563 */
#define TAG_DISABLE_AUTOCONF ((u_int8_t)116)
/* RFC 2610 */
#define TAG_SLP_DA ((u_int8_t)78)
#define TAG_SLP_SCOPE ((u_int8_t)79)
/* RFC 2937 */
#define TAG_NS_SEARCH ((u_int8_t)117)
/* RFC 3011 */
#define TAG_IP4_SUBNET_SELECT ((u_int8_t)118)
/* ftp://ftp.isi.edu/.../assignments/bootp-dhcp-extensions */
#define TAG_USER_CLASS ((u_int8_t)77)
#define TAG_SLP_NAMING_AUTH ((u_int8_t)80)
#define TAG_CLIENT_FQDN ((u_int8_t)81)
#define TAG_AGENT_CIRCUIT ((u_int8_t)82)
#define TAG_AGENT_REMOTE ((u_int8_t)83)
#define TAG_AGENT_MASK ((u_int8_t)84)
#define TAG_TZ_STRING ((u_int8_t)88)
#define TAG_FQDN_OPTION ((u_int8_t)89)
#define TAG_AUTH ((u_int8_t)90)
#define TAG_VINES_SERVERS ((u_int8_t)91)
#define TAG_SERVER_RANK ((u_int8_t)92)
#define TAG_CLIENT_ARCH ((u_int8_t)93)
#define TAG_CLIENT_NDI ((u_int8_t)94)
#define TAG_CLIENT_GUID ((u_int8_t)97)
#define TAG_LDAP_URL ((u_int8_t)95)
#define TAG_6OVER4 ((u_int8_t)96)
#define TAG_PRINTER_NAME ((u_int8_t)100)
#define TAG_MDHCP_SERVER ((u_int8_t)101)
#define TAG_IPX_COMPAT ((u_int8_t)110)
#define TAG_NETINFO_PARENT ((u_int8_t)112)
#define TAG_NETINFO_PARENT_TAG ((u_int8_t)113)
#define TAG_URL ((u_int8_t)114)
#define TAG_FAILOVER ((u_int8_t)115)
#define TAG_SERVER_SIP ((u_int8_t) 120)
#define TAG_EXTENDED_REQUEST ((u_int8_t)126)
#define TAG_EXTENDED_OPTION ((u_int8_t)127)

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

/*
 * "vendor" data permitted for CMU bootp clients.
 */

struct cmu_vend {
	u_int8_t v_magic[4];		   /* magic number */
	u_int32_t v_flags;			   /* flags/opcodes, etc. */
	struct in_addr v_smask;		   /* Subnet mask */
	struct in_addr v_dgate;		   /* Default gateway */
	struct in_addr v_dns1, v_dns2; /* Domain name servers */
	struct in_addr v_ins1, v_ins2; /* IEN-116 name servers */
	struct in_addr v_ts1, v_ts2;   /* Time servers */
	u_int8_t v_unused[24];		   /* currently unused */
};

/* v_flags values */
#define VF_SMASK 1 /* Subnet mask field contains valid data */
/**
 * Op codes
 */
#define BOOTREQUEST 1
#define BOOTREPLY 2

/**
 * Hardware types
 */
#define ETHERNET 1
#define IEEE_802 6

/**
 * Flags
 */
#define FLAG_BROADCAST 1

#define PRINT_DEFAULT 0
#define PRINT_STR 1
#define PRINT_IP 2
#define PRINT_UINT_32 3
#define PRINT_HEX 4
struct {
	char *name;
	int displaytype;
} bootp_options_name[256] = {
	[0] = {"PAD", PRINT_DEFAULT},
	[1] = {"Subnet Mask", PRINT_IP},
	[2] = {"Time Offset", PRINT_DEFAULT},
	[3] = {"Router", PRINT_IP},
	[4] = {"Time Server", PRINT_DEFAULT},
	[5] = {"IEN-116 Name Server", PRINT_DEFAULT},
	[6] = {"DNS Name Server", PRINT_IP},
	[7] = {"Log Server", PRINT_DEFAULT},
	[8] = {"Cookie Server", PRINT_DEFAULT},
	[9] = {"LPR Server", PRINT_DEFAULT},
	[10] = {"Impress Server", PRINT_DEFAULT},
	[11] = {"Resource Location Server", PRINT_DEFAULT},
	[12] = {"Host Name", PRINT_DEFAULT},
	[13] = {"Boot File Size", PRINT_DEFAULT},
	[14] = {"Merit Dump File", PRINT_DEFAULT},
	[15] = {"Domain name", PRINT_DEFAULT},
	[16] = {"Swap Server", PRINT_DEFAULT},
	[17] = {"Root Path", PRINT_DEFAULT},
	[18] = {"Extensions Path", PRINT_DEFAULT},
	[19] = {"IP Forwaring", PRINT_DEFAULT},
	[20] = {"Non Local Source Routing", PRINT_DEFAULT},
	[21] = {"Policy Filter", PRINT_DEFAULT},
	[22] = {"Max Datagram Reassembly size", PRINT_DEFAULT},
	[23] = {"Default IP TTL", PRINT_DEFAULT},
	[24] = {"Path MTU Aging Timeout", PRINT_DEFAULT},
	[25] = {"Path MTU Plateau Table", PRINT_DEFAULT},
	[26] = {"Interface MTU", PRINT_DEFAULT},
	[27] = {"All Subnets Are Local", PRINT_DEFAULT},
	[28] = {"Broadcast Address", PRINT_DEFAULT},
	[29] = {"Perform Mask Discovery", PRINT_DEFAULT},
	[30] = {"Mask Supplier", PRINT_DEFAULT},
	[31] = {"Perform Router Discovery", PRINT_DEFAULT},
	[32] = {"Router Solicitation Address", PRINT_DEFAULT},
	[33] = {"Static Route", PRINT_DEFAULT},
	[34] = {"Trailer Encapsulation", PRINT_DEFAULT},
	[35] = {"ARP Cache Timeout", PRINT_DEFAULT},
	[36] = {"Ethernet Encapsulation", PRINT_DEFAULT},
	[37] = {"Default TTL", PRINT_DEFAULT},
	[38] = {"TCP Keepalive Interval", PRINT_DEFAULT},
	[39] = {"TCP Keepalive Garbage", PRINT_DEFAULT},
	[40] = {"Network Information Service Domain", PRINT_DEFAULT},
	[41] = {"Network Information Servers", PRINT_DEFAULT},
	[42] = {"Network Time Protocol Servers", PRINT_DEFAULT},
	[43] = {"Vendor Specific Information", PRINT_DEFAULT},
	[45] = {"NetBIOS Over TCP/IP Name Servers", PRINT_DEFAULT},
	[46] = {"NetBIOS Over TCP/IP Datagram Distribution Servers", PRINT_DEFAULT},
	[47] = {"NetBIOS Over TCP/IP Scope", PRINT_DEFAULT},
	[48] = {"X Window System Font Servers:", PRINT_DEFAULT},
	[49] = {"X Window System Display Manager", PRINT_DEFAULT},
	[50] = {"Requested IP Address", PRINT_DEFAULT}, // DHCP Options
	[51] = {"IP Address Lease Time", PRINT_UINT_32},
	[52] = {"Option Overload", PRINT_DEFAULT},
	[TAG_DHCP_MESSAGE] = {"DHCP Message Type",
						  PRINT_DEFAULT}, // See DCHP_MESSAGE const
	[54] = {"Server Identifier", PRINT_IP},
	[55] = {"Parameter Request List", PRINT_DEFAULT},
	[56] = {"Message", PRINT_DEFAULT},
	[57] = {"Maximum DHCP Message Size", PRINT_DEFAULT},
	[58] = {"Renewal (T1) Time Value", PRINT_DEFAULT},
	[59] = {"Rebinding (T2) Time Value", PRINT_DEFAULT},
	[60] = {"Vendor Class Identifier", PRINT_DEFAULT},
	[61] = {"Client Identifier", PRINT_STR}, // End DHCP Options
	[TAG_NDS_IPDOMAIN] = {"NDS Ip Domain", PRINT_DEFAULT},
	[TAG_NDS_IPINFO] = {"NDS Ip Info", PRINT_DEFAULT},
	[64] = {"Network Information Service+ Domain", PRINT_DEFAULT},
	[65] = {"Network Information Service+ Servers", PRINT_DEFAULT},
	[66] = {"TFTP Server Name", PRINT_STR}, // DHCP Option
	[67] = {"Bootfile Name", PRINT_DEFAULT},	// DHCP Option
	[68] = {"Mobile IP Home Agent", PRINT_DEFAULT},
	[69] = {"Simple Mail Transport Protocol (SMTP) Servers", PRINT_DEFAULT},
	[70] = {"Post Office Protocol (POP3) Servers", PRINT_DEFAULT},
	[71] = {"Network News Transfer Protocol (NNTP) Servers", PRINT_DEFAULT},
	[72] = {"Default World Wide Web (WWW) Servers", PRINT_DEFAULT},
	[73] = {"Default Finger Servers", PRINT_DEFAULT},
	[74] = {"Default Internet Relay Chat (IRC) Servers", PRINT_DEFAULT},
	[75] = {"StreetTalk Servers", PRINT_DEFAULT},
	[76] = {"StreetTalk Directory Assistance (STDA) Servers", PRINT_DEFAULT},

	[TAG_AGENT_CIRCUIT] = {"Agent Information Option", PRINT_HEX},

	[TAG_AUTH] = {"Auth", PRINT_HEX},
	[TAG_VINES_SERVERS] = {"Vines Servers", PRINT_DEFAULT},
	[TAG_SERVER_RANK] = {"Server Rank", PRINT_DEFAULT},
	[TAG_CLIENT_ARCH] = {"Client ARCH", PRINT_DEFAULT},
	[TAG_CLIENT_NDI] = {"Client NDI", PRINT_DEFAULT},
	[TAG_SERVER_SIP] = {"Server SIP DHCP", PRINT_DEFAULT},

	[TAG_END] = {"End", PRINT_DEFAULT}};

const char *dhcp_messages[9] = {
	[DHCPDISCOVER] = "Discover", [DHCPOFFER] = "Offer",
	[DHCPREQUEST] = "Request",	 [DHCPDECLINE] = "Decline",
	[DHCPACK] = "Ack",			 [DHCPNAK] = "Nak",
	[DHCPRELEASE] = "Release",	 [DHCPINFORM] = "Inform"};

struct bootp_option {
	uint8_t code;
	uint8_t len;
	uint8_t data[];
};

#endif