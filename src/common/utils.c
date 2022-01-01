#include "utils.h"
#include "analyzer.h"

void    exit_failure(t_analyzer analyzer, const char *format, ...) {
    free(analyzer.name);
}