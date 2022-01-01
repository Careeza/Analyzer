#include "analyzer.h"
#include "utils.h"
#include "string.h"

void	show_all_interfaces(t_analyzer *analyzer) {
    pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];    

    memset(errbuf, '0', PCAP_ERRBUF_SIZE);
	if (pcap_findalldevs(&alldevs, errbuf) != 0) {
		exit_failure(analyzer, "Error: findalldevs\n%s", errbuf);
	}
	while (alldevs != NULL) {
		printf("%s%s%s: %s\n", CSI_GREEN, alldevs->name, CSI_RESET, alldevs->description);
		alldevs = alldevs->next;
	}
}

int     main(int argc, char **argv) {
	t_analyzer analyzer;

	init_struct(&analyzer);
	gest_arg(&analyzer, argc, argv);

	if (analyzer.info.show_all_interfaces) {
		show_all_interfaces(&analyzer);
		return (0);
	}
	if (analyzer.info.online) {
		online_analysis(&analyzer);
	} else {
		offline_analysis(&analyzer);
	}
	return (0);
}