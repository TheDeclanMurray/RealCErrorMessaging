// symaddr.c
#define _GNU_SOURCE
#include "symaddr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

uintptr_t get_tracee_lib_base(pid_t pid, const char *libname) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[512];
    uintptr_t base = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname)) {
            unsigned long start = 0;
            if (sscanf(line, "%lx-%*lx", &start) == 1) {
                base = (uintptr_t)start;
                break;
            }
        }
    }

    fclose(f);
    return base;
}

uintptr_t get_symbol_offset(const char *elf_path, const char *symname) {
    FILE *f = fopen(elf_path, "rb");
    if (!f) return 0;

    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        fclose(f);
        return 0;
    }

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(f);
        return 0;
    }

    if (fseek(f, eh.e_shoff, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    Elf64_Shdr *shdrs = calloc(eh.e_shnum, sizeof(Elf64_Shdr));
    if (!shdrs) {
        fclose(f);
        return 0;
    }

    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    if (eh.e_shstrndx == SHN_UNDEF) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    Elf64_Shdr shstr = shdrs[eh.e_shstrndx];
    char *shstrtab = malloc(shstr.sh_size);
    if (!shstrtab) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    if (fseek(f, shstr.sh_offset, SEEK_SET) != 0 ||
        fread(shstrtab, 1, shstr.sh_size, f) != shstr.sh_size) {
        free(shstrtab);
        free(shdrs);
        fclose(f);
        return 0;
    }

    uintptr_t off = 0;

    for (int i = 0; i < eh.e_shnum; i++) {
        const char *secname = shstrtab + shdrs[i].sh_name;
        if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM)
            continue;

        Elf64_Shdr strsec = shdrs[shdrs[i].sh_link];
        char *strtab = malloc(strsec.sh_size);
        if (!strtab) continue;

        if (fseek(f, strsec.sh_offset, SEEK_SET) != 0 ||
            fread(strtab, 1, strsec.sh_size, f) != strsec.sh_size) {
            free(strtab);
            continue;
        }

        size_t nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);
        Elf64_Sym *syms = malloc(shdrs[i].sh_size);
        if (!syms) {
            free(strtab);
            continue;
        }

        if (fseek(f, shdrs[i].sh_offset, SEEK_SET) != 0 ||
            fread(syms, sizeof(Elf64_Sym), nsyms, f) != nsyms) {
            free(syms);
            free(strtab);
            continue;
        }

        for (size_t j = 0; j < nsyms; j++) {
            const char *name = strtab + syms[j].st_name;
            if (strcmp(name, symname) == 0) {
                off = (uintptr_t)syms[j].st_value;
                break;
            }
        }

        free(syms);
        free(strtab);
        if (off) break;
    }

    free(shstrtab);
    free(shdrs);
    fclose(f);
    return off;
}

uintptr_t get_tracee_symbol_addr(pid_t pid, const char *libname,
                                 const char *elf_path, const char *symname) {
    uintptr_t base = get_tracee_lib_base(pid, libname);
    uintptr_t off = get_symbol_offset(elf_path, symname);
    if (!base || !off) return 0;
    return base + off;
}