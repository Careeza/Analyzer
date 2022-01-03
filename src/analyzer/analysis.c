#include "analyzer.h"
#include "utils.h"
#include "parser.h"

void packet_call_back(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {	
	static unsigned int		pkt_nb = 1;
	static suseconds_t		start_s = 0;
	static time_t			start_ms = 0;
	t_analyzer				*analyzer;

	analyzer = (t_analyzer *)user;
	if(start_s == 0) {
		start_s = h->ts.tv_sec;
		start_ms = h->ts.tv_usec;
	}

	double time = (h->ts.tv_sec - start_s) + (h->ts.tv_usec - start_ms) / 1000000.0;
	printf("%.4lf FRAME %u (%i bytes)", time, pkt_nb, h->len);
	parse_ethernet(bytes + 2, analyzer);
	printf("\n");
	pkt_nb++;
}

void    create_filter(t_analyzer *analyzer) {
    struct bpf_program  fp;
    char                *error_message;

    if (pcap_compile(analyzer->handle, &fp, analyzer->info.filter, 0, 
        PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        error_message = pcap_geterr(analyzer->handle);
        exit_failure(analyzer, "%sError : %s%s\n", CSI_RED, error_message, CSI_RESET);
    }

	if (pcap_setfilter(analyzer->handle, &fp) == PCAP_ERROR) {
        error_message = pcap_geterr(analyzer->handle);
        exit_failure(analyzer, "%sError : %s%s\n", CSI_RED, error_message, CSI_RESET);
        pcap_freecode(&fp);
    }
    pcap_freecode(&fp);
}

void    start_analysis(t_analyzer *analyzer) {
    int     ret;
    char    *error_message;
    
    if (analyzer->info.filter != NULL) {
        create_filter(analyzer);
    }
	ret = pcap_loop(analyzer->handle, 0, packet_call_back, (u_char *)analyzer);
    pcap_close(analyzer->handle);

    if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
		error_message = pcap_geterr(analyzer->handle);
        exit_failure(analyzer, "%sError : %s%s\n", CSI_RED, error_message, CSI_RESET);
	}

}