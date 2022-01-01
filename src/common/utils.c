#include "utils.h"
#include "analyzer.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

void    exit_failure(t_analyzer *analyzer, const char *format, ...) {
    va_list params;

    va_start(params, format);
    dprintf(2, format, params);
    free(analyzer->name);
    va_end(params);
    exit (EXIT_FAILURE);
}

void    usage(char *name, char *message) {
    dprintf(2, "%s%s%s\n", CSI_RED, message, CSI_RESET);
    dprintf(2, "Usage : %s\n", name);
    dprintf(2, "-i <interface> Select an interface for the online analysis\n");
    dprintf(2, "-o <file>      Select a file for the offline analysis\n");
    dprintf(2, "-f <filter>    Select a filter for the analysis\n");
    dprintf(2, "-v <1, .., 3>  Select the level of verbosity\n");
    dprintf(2, "-l             List all the interfaces available\n");
    exit (EXIT_FAILURE);
}

void    gest_arg(t_analyzer *analyzer, int argc, char **argv) {
	int ch;

	while ((ch = getopt(argc, argv, "i:o:v:hl")) != -1)
	{
		switch (ch)
		{
		case 'i':
            if (analyzer->name != NULL) {
                usage(argv[0], "You can't select an interface and a file");
            }
			analyzer->name = optarg;
			break;
		case 'o':
            if (analyzer->name != NULL) {
                usage(argv[0], "You can't select an interface and a file");
            }
            analyzer->name = optarg;
			break;
		case 'v':
			analyzer->verbosity = atoi(optarg);
            if (analyzer->verbosity < 1 || analyzer->verbosity > 3) {
                usage(argv[0], "Wrong level of verbosity\n1) Short\n2) Synthetic\n3) Full");
            }
			break;
		case 'h':
			usage(argv[0], "");
			break;
		case 'l':
            analyzer->show_all_interfaces = true;
            break;
		default:
			usage(argv[0], "");
			break;
		}
	}
    if (analyzer->show_all_interfaces == false && analyzer->name == NULL) {
        usage(argv[0], "You need to specify either an interface or a file");
    }
    if (analyzer->name) {
        if (analyzer->online) {
            printf("Interface choosed : %s%s%s\n", CSI_GREEN, analyzer->name, CSI_RESET);
        } else {
            printf("File choosed for the offline analysis : %s%s%s\n", CSI_GREEN, analyzer->name, CSI_RESET);
        }
    }
}

void    init_struct(t_analyzer *analyzer) {
    analyzer->name = NULL;
    analyzer->verbosity = 1;
    analyzer->online = false;
    analyzer->show_all_interfaces = false;
}