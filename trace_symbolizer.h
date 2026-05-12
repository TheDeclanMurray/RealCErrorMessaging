#ifndef TRACE_SYMBOLIZER_H
#define TRACE_SYMBOLIZER_H

#include <stdint.h>
#include <stdbool.h>

int get_location(void *addr, char func[64], char file[128], int *line);
int print_location(void *addr);
bool print_stack(void);
uintptr_t exe_base_from_maps(void);


#endif