#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "bootp.h"

void usage()
{
	printf("USAGE\n");
}

int gest_arg(t_info *info, int argc, char **argv)
{
	int ch;
	while ((ch = getopt(argc, argv, "i:o:v:h")) != -1)
	{
		switch (ch)
		{
		case 'i':
			info->interface = optarg;
			printf("Interface choosed : %s\n", info->interface);
			break;
		case 'o':
			info->file = optarg;
			printf("File choosed for the offline analysis : %s\n", info->file);
			break;
		case 'v':
			info->verbose = atoi(optarg); //Meilleure vérification ? compris entre 1 et 3 et que des chiffres
			printf("Verbose level choosed : %d\n", info->verbose);
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	return 0;
}

char	*find_interface(void)
{
    pcap_if_t *alldevs;
    pcap_if_t *tmp;
	char *name = "";
	char errbuf[PCAP_ERRBUF_SIZE];    

    memset(errbuf, '0', PCAP_ERRBUF_SIZE);

		if (pcap_findalldevs(&alldevs, errbuf) != 0)
	{
		fprintf(stderr, "Error: findalldevs\n%s", errbuf);
		exit(-1);
	}
	tmp = alldevs;
	while (tmp != NULL)
	{
		name = tmp->name;
		printf("%s: %s\n", name, tmp->description);
		tmp = tmp->next;
	}
    printf("Interface used %s\n", alldevs->name);
	name = strdup(alldevs->name);
	pcap_freealldevs(alldevs);
	return name;
}

int main(int argc, char **argv)
{
	printf("ANALYSER\n");
	t_analyzer analyzer;
	
	analyzer.info.interface = NULL;
	analyzer.info.file = NULL;
	analyzer.info.verbose = 0;

	gest_arg(&(analyzer.info), argc, argv);

	if (!analyzer.info.interface)
		analyzer.info.interface = find_interface();
	printf("%s\n", analyzer.info.interface);
	fflush(stdout);
	analysis(analyzer.info.interface, NULL, analyzer.info.verbose, NULL);
	return 0;
}