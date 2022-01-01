#include "analyzer.h"
#include "utils.h"
#include <stdlib.h>

void    online_analysis(t_analyzer *analyzer) {
    char    errbuf[PCAP_ERRBUF_SIZE];
    char    *error_message;
    int     status;

    analyzer->handle = pcap_create(analyzer->info.name, errbuf);
    if (analyzer->handle == NULL) {
        exit_failure(analyzer, "%sError : %s%s\n", CSI_RED, errbuf, CSI_RESET);
    }
    pcap_set_timeout(analyzer->handle, PCAP_TIMEOUT);
    status = pcap_activate(analyzer->handle);
    if (status < 0) {
        error_message = pcap_geterr(analyzer->handle);
        exit_failure(analyzer, "%sError : %s%s\n", CSI_RED, error_message, CSI_RESET);
    }
    start_analysis(analyzer);
}