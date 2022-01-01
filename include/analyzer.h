#ifndef ANALYZER_H

# define ANALYZER_H

# include <netinet/in.h>
# include <pcap/pcap.h>
# include <stdint.h>
# include <stdbool.h>

# define PCAP_TIMEOUT 128


typedef struct s_info {
	char	*name;
	char	*filter;
	int		verbosity;
	bool	online;
	bool	show_all_interfaces;
} t_info;

typedef struct s_analyzer {
	t_info	info;
	pcap_t  *handle;
} t_analyzer;

void    start_analysis(t_analyzer *analyzer);
void    online_analysis(t_analyzer *analyzer);
void    offline_analysis(t_analyzer *analyzer);

#endif