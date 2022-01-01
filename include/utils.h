#ifndef UTILS_H

# define UTILS_H

# include "analyzer.h"

# define CSI             "\033["
# define CSI_GREEN CSI   "32;01m"
# define CSI_WHITE CSI   "37;01m"
# define CSI_BLUE CSI    "34;01m"
# define CSI_YELLOW CSI  "33;01m"
# define CSI_RED CSI     "31m"
# define CSI_RESET CSI   "0m"

void    exit_failure(t_analyzer *analyzer, const char *format, ...);
void    gest_arg(t_analyzer *analyzer, int argc, char **argv);
void    init_struct(t_analyzer *analyzer);

#endif