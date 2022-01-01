#ifndef ANALYZER_H

# define ANALYZER_H

# include <netinet/in.h>
# include <pcap/pcap.h>
# include <stdint.h>

typedef struct s_analyzer {
	char	*name;
	int		verbosity;
} t_analyzer;

#endif