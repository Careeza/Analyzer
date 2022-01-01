#ifndef ANALYZER_H

# define ANALYZER_H

# include <netinet/in.h>
# include <pcap/pcap.h>
# include <stdint.h>
# include <stdbool.h>

typedef struct s_analyzer {
	char	*name;
	int		verbosity;
	bool	online;
	bool	show_all_interfaces;
} t_analyzer;

#endif