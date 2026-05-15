#include "symaddr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

// get start of address space
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

// Returns the virtual address of a symbol inside a ELF binary
// On failure returns 0
uintptr_t get_symbol_offset(const char *elf_path, const char *symname) {

    // Open ELF file in binary read mode
    FILE *f = fopen(elf_path, "rb");
    if (!f)
        return 0;

    // Read ELF header
    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        fclose(f);
        return 0;
    }

    // Verify this is a valid 64-bit ELF file
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(f);
        return 0;
    }

    // Seek to section header table
    if (fseek(f, eh.e_shoff, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    // Allocate memory for all section headers
    Elf64_Shdr *shdrs = calloc(eh.e_shnum, sizeof(Elf64_Shdr));
    if (!shdrs) {
        fclose(f);
        return 0;
    }

    // Read all section headers
    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    // Ensure section header string table exists
    if (eh.e_shstrndx == SHN_UNDEF) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    // Get section-header string table descriptor
    Elf64_Shdr shstr = shdrs[eh.e_shstrndx];

    // Allocate memory for section-header string table
    char *shstrtab = malloc(shstr.sh_size);
    if (!shstrtab) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    // Read section-header string table
    if (fseek(f, shstr.sh_offset, SEEK_SET) != 0 ||
        fread(shstrtab, 1, shstr.sh_size, f) != shstr.sh_size) {
        free(shstrtab);
        free(shdrs);
        fclose(f);
        return 0;
    }

    // Final symbol address/result
    uintptr_t off = 0;

    // Iterate through all sections looking for symbol tables
    for (int i = 0; i < eh.e_shnum; i++) {

        // Skip sections that are not symbol tables
        if (shdrs[i].sh_type != SHT_SYMTAB &&
            shdrs[i].sh_type != SHT_DYNSYM)
            continue;

        // The linked section contains the string table for this symbol table
        Elf64_Shdr strsec = shdrs[shdrs[i].sh_link];

        // Allocate memory for symbol names
        char *strtab = malloc(strsec.sh_size);
        if (!strtab)
            continue;

        // Read symbol string table
        if (fseek(f, strsec.sh_offset, SEEK_SET) != 0 ||
            fread(strtab, 1, strsec.sh_size, f) != strsec.sh_size) {
            free(strtab);
            continue;
        }

        // Calculate number of symbols in this table
        size_t nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);

        // Allocate memory for symbol entries
        Elf64_Sym *syms = malloc(shdrs[i].sh_size);
        if (!syms) {
            free(strtab);
            continue;
        }

        // Read symbol table entries
        if (fseek(f, shdrs[i].sh_offset, SEEK_SET) != 0 ||
            fread(syms, sizeof(Elf64_Sym), nsyms, f) != nsyms) {
            free(syms);
            free(strtab);
            continue;
        }

        // Search for requested symbol by name
        for (size_t j = 0; j < nsyms; j++) {

            // Symbol name is stored as an offset into the string table
            const char *name = strtab + syms[j].st_name;

            // Compare symbol name with requested name
            if (strcmp(name, symname) == 0) {

                // Store symbol value/address
                off = (uintptr_t)syms[j].st_value;
                break;
            }
        }

        // Cleanup symbol table resources
        free(syms);
        free(strtab);

        // Stop searching once symbol is found
        if (off)
            break;
    }

    // Cleanup global resources
    free(shstrtab);
    free(shdrs);
    fclose(f);

    // Return symbol offset/address
    return off;
}

// gets th exact address of a var in the tracee code
uintptr_t get_tracee_symbol_addr(pid_t pid, const char *libname,
                                 const char *elf_path, const char *symname) {
    uintptr_t base = get_tracee_lib_base(pid, libname);
    uintptr_t off = get_symbol_offset(elf_path, symname);
    if (!base || !off) return 0;
    return base + off;
}