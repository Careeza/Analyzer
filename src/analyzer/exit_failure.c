#include "bootp.h"
#include "defs.h"
#include <stdio.h>
#include <stdlib.h>
#include "bootp.h"

void exit_failure(const char *error_message, t_analyzer *analyzer)
{
    (void)analyzer;
    fprintf(stderr, "%sERROR :%s%s\n", CSI_RED, error_message, CSI_RESET);
    exit(EXIT_FAILURE);
}