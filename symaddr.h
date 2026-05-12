// symaddr.h
#ifndef SYMADDR_H
#define SYMADDR_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

uintptr_t get_tracee_lib_base(pid_t pid, const char *libname);
uintptr_t get_symbol_offset(const char *elf_path, const char *symname);
uintptr_t get_tracee_symbol_addr(pid_t pid, const char *libname,
                                 const char *elf_path, const char *symname);

#ifdef __cplusplus
}
#endif

#endif