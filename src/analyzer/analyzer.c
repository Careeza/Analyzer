#include "analyzer.h"

int gest_arg(t_info *info, int argc, char **argv) {
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

int     main(int argc, char **argv) {
    
}