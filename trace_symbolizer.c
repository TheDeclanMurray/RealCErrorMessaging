#include "trace_symbolizer.h"

#include <execinfo.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <ctype.h>

// i think this is needed
#ifdef _WIN32
  #include <direct.h>
  #define getcwd _getcwd
#else
  #include <unistd.h>
#endif

#define NORMALIZE_ADDR true

uintptr_t exe_base_from_maps(void) {
    // get path
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) return 0;
    exe_path[len] = '\0';

    // open file
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    // get start of address range
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, off = 0;
        char perms[8] = {0};
        char path[PATH_MAX] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %s", &start, &end, perms, &off, path);
        if (n == 5 && strcmp(path, exe_path) == 0 && strchr(perms, 'x')) {
            fclose(fp);
            return (uintptr_t)start - (uintptr_t)off;
        }
    }
    fclose(fp);
    return 0;
}

// use Dwarf functions to walk the tables
static int lookup_function_name(Dwarf_Debug dbg, Dwarf_Die cu_die, uintptr_t addr,
                                char *func_out, size_t func_out_sz){
    Dwarf_Die child = 0;
    Dwarf_Die cur = 0;
    Dwarf_Half tag = 0;
    Dwarf_Error err = 0;

    if (dwarf_child(cu_die, &child, &err) != DW_DLV_OK) {
        return -1;
    }

    cur = child;
    while (cur) {
        if (dwarf_tag(cur, &tag, &err) == DW_DLV_OK && tag == DW_TAG_subprogram) {
            Dwarf_Addr low_pc = 0;
            Dwarf_Addr high_pc = 0;
            Dwarf_Half high_form = 0;
            enum Dwarf_Form_Class high_class = DW_FORM_CLASS_UNKNOWN;
            Dwarf_Attribute attr = 0;

            if (dwarf_attr(cur, DW_AT_low_pc, &attr, &err) == DW_DLV_OK &&
                dwarf_formaddr(attr, &low_pc, &err) == DW_DLV_OK &&
                dwarf_highpc_b(cur, &high_pc, &high_form, &high_class, &err) == DW_DLV_OK) {

                Dwarf_Addr end = (high_form == DW_FORM_addr) ? high_pc : (low_pc + high_pc);

                if ((Dwarf_Addr)addr >= low_pc && (Dwarf_Addr)addr < end) {
                    char *name = 0;
                    if (dwarf_diename(cur, &name, &err) == DW_DLV_OK && name) {
                        // printf("Function: %s\n", name);
                        snprintf(func_out, func_out_sz, "%s", name);
                        return 0;
                    }
                }
            }
        }

        Dwarf_Die sib = 0;
        if (dwarf_siblingof_b(dbg, cur, 1, &sib, &err) != DW_DLV_OK) {
            break;
        }
        cur = sib;
    }

    return -1;
}

static int lookup_line_libdwarf(const char *path, uintptr_t addr,
                                char *func_out, size_t func_out_sz,
                                char *line_out, size_t line_out_sz)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Error err = 0;
    int res = dwarf_init_path(path, NULL, 0, 0, NULL, NULL, &dbg, &err);
    if (res != DW_DLV_OK) {
        return -1;
    }

    Dwarf_Die cu_die = 0;
    int found = 0;

    Dwarf_Bool is_info = 1;
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Off abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half offset_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 signature;
    memset(&signature, 0, sizeof(signature));
    Dwarf_Off typeoffset = 0;
    Dwarf_Off next_cu_header = 0;
    Dwarf_Half header_cu_type = 0;

    while ((res = dwarf_next_cu_header_d(dbg, is_info,
                                        &cu_header_length, &version_stamp, &abbrev_offset,
                                        &address_size, &offset_size, &extension_size,
                                        &signature, &typeoffset, &next_cu_header,
                                        &header_cu_type, &err)) == DW_DLV_OK) {
        if (dwarf_siblingof_b(dbg, NULL, 1, &cu_die, &err) != DW_DLV_OK) continue;

        if (lookup_function_name(dbg, cu_die, addr, func_out, func_out_sz) != 0) {
            func_out[0] = '\0';
        }

        Dwarf_Unsigned version_out = 0;
        Dwarf_Small table_count = 0;
        Dwarf_Line_Context line_context = 0;
        if (dwarf_srclines_b(cu_die,
                            &version_out,
                            &table_count,
                            &line_context,
                            &err) != DW_DLV_OK) {
            dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
            continue;
        }

        Dwarf_Line *linebuf = 0;
        Dwarf_Signed line_count = 0;
        if (dwarf_srclines_from_linecontext(line_context,
                                            &linebuf,
                                            &line_count,
                                            &err) != DW_DLV_OK) {
            dwarf_srclines_dealloc_b(line_context);
            dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
            continue;
        }

        for (Dwarf_Signed i = 0; i < line_count; i++) {
            Dwarf_Addr line_addr = 0;
            Dwarf_Unsigned line_no = 0;
            char *fname = 0;
            if (dwarf_lineaddr(linebuf[i], &line_addr, &err) != DW_DLV_OK) continue;
            if (dwarf_lineno(linebuf[i], &line_no, &err) != DW_DLV_OK) continue;
            if (dwarf_linesrc(linebuf[i], &fname, &err) != DW_DLV_OK) continue;
            if ((uintptr_t)line_addr <= addr) {
                Dwarf_Addr next_addr = 0;
                if (i + 1 < line_count && dwarf_lineaddr(linebuf[i + 1], &next_addr, &err) == DW_DLV_OK) {
                    if (addr < (uintptr_t)next_addr) {
                        snprintf(line_out, line_out_sz, "%s:%llu\n", fname, (unsigned long long)line_no);
                        found = 1;
                        break;
                    }
                }
            }
        }

        dwarf_srclines_dealloc_b(line_context);
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
        if (found) break;
    }

    dwarf_finish(dbg);
    return found ? 0 : -1;
}

int get_location(void *addr, char func[64], char file[128], int *line)
{
    char exe[PATH_MAX];

    // TODO: this is repeating a lot sometimes
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) return -1;
    exe[n] = '\0';

    // get the start of the address range
    uintptr_t rel = (uintptr_t) addr;
    if (NORMALIZE_ADDR){
        uintptr_t base = exe_base_from_maps();
        if (!base) return -1;

        rel = (uintptr_t)addr - base;
    }

    char line_out[512];
    if (lookup_line_libdwarf(exe, rel, func, sizeof(char)*64, line_out, sizeof(line_out)) == 0) {
        // Split file path and line number
        const char* colon = strrchr(line_out, ':');
        char full_path[512];

        if (colon && isdigit((unsigned char)colon[1])) {
            *line = atoi(colon + 1);
            size_t path_len = colon - line_out;
            if (path_len >= sizeof(full_path)) path_len = sizeof(full_path) - 1;
            strncpy(full_path, line_out, path_len);
            full_path[path_len] = '\0';
        } else {
            // No colon/line found, copy entire string
            strncpy(full_path, line_out, sizeof(full_path) - 1);
            full_path[sizeof(full_path) - 1] = '\0';
        }

        // Make path relative to cwd if possible
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd))) {
            size_t cwd_len = strlen(cwd);
            if (strncmp(full_path, cwd, cwd_len) == 0 && full_path[cwd_len] == '/') {
                // skip cwd + '/'
                const char* relative = full_path + cwd_len + 1;
                strncpy(file, relative, 127);
                file[127] = '\0';
            } else {
                strncpy(file, full_path, 127);
                file[127] = '\0';
            }
        } else {
            // fallback: copy full path
            strncpy(file, full_path, 127);
            file[127] = '\0';
        }
        // copy function name and line number
        if (func) func[63] = '\0'; // ensure null-termination (func is already filled by lookup_line_libdwarf)

        return 0;
    }
    
    return -1;
}

int print_location(void *addr){
    char func[64];
    char file[128];
    int line = -1;
    char buffer[256]; 

    int status = get_location(addr, func, file, &line);
    if (status == 0){
        int n = snprintf(buffer, sizeof(buffer), "%s:%d\t\t%s\n", file, line, func);
        
        // write the string 
        if (n > 0) {
            if (n > (int)sizeof(buffer) - 1) n = sizeof(buffer) - 1; // truncate if too long
            write(STDERR_FILENO, buffer, n);
        }
    }
    return status;
}

bool print_stack(void)
{
    // get the backtrace
    void *buf[64];
    int n = backtrace(buf, 64);

    // walk backtrace 
    bool status = false;
    for (int i = n-1; i >= 2; i--) {
        status = (print_location(buf[i]) == 0) || status;    
    }

    return status;
}