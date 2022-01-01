#include "analyzer.h"
#include "utils.h"
#include <stdlib.h>

void    offline_analysis(t_analyzer *analyzer) {
    char errbuf[PCAP_ERRBUF_SIZE];


    analyzer->handle = pcap_open_offline(analyzer->info.name, errbuf);
    if (analyzer->handle == NULL) {
        exit_failure(analyzer, "%sError : %s%s\n", CSI_RED, errbuf, CSI_RESET);
    }
    start_analysis(analyzer);
}