#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <inttypes.h>

#include "memHelper.h"
#include "trace_symbolizer.h"

#define OVERRIDE_MEM true

typedef void* (*malloc_fn_t)(size_t);
typedef void  (*free_fn_t)(void*);
typedef void* (*realloc_fn_t)(void*, size_t);

static hashTable_t* mem_table = NULL;

static int in_hook = 0;
static int disable_tracking = 0;

void* real_malloc(size_t size) {
    static malloc_fn_t real_malloc = NULL;
    if (!real_malloc) {
        in_hook = 1;
        real_malloc = (malloc_fn_t) dlsym(RTLD_NEXT, "malloc");
        in_hook = 0;
        if (!real_malloc) {
            fprintf(stderr, "Failed to find real malloc: %s\n", dlerror());
            return NULL;
        }
    }

    void* ptr = real_malloc(size);
    return ptr;
}

void real_free(void* ptr) {
    static free_fn_t real_free = NULL;
    if (!real_free) {
        in_hook = 1;
        real_free = (free_fn_t)dlsym(RTLD_NEXT, "free");
        in_hook = 0;
        if (!real_free) {
            fprintf(stderr, "Failed to find real free: %s\n", dlerror());
            return;
        }
    }

    real_free(ptr);
}

void* real_realloc(void* ptr, size_t size) {
    static realloc_fn_t real_realloc = NULL;
    if (!real_realloc) {
        in_hook = 1;
        real_realloc = (realloc_fn_t)dlsym(RTLD_NEXT, "realloc");
        in_hook = 0;
        if (!real_realloc) {
            fprintf(stderr, "Failed to find real realloc: %s\n", dlerror());
            return NULL;
        }
    }

    void* new_ptr = real_realloc(ptr, size);
    return new_ptr;
}


// TODO: add mutexes so this works on multi thread programs

static size_t ptr_hash(void* ptr) {
    return ((uintptr_t)ptr) % TABLE_SIZE;
}

void hashtable_insert(hashTable_t* table, void* key, memStruct_t value) {
    size_t idx = ptr_hash(key);
    hashNode_t* node = table->buckets[idx];

    // Check if key already exists, update if so
    while (node) {
        if (node->key == key) {
            node->value = value;
            return;
        }
        node = node->next;
    }

    // Key not found, insert new node at the head
    hashNode_t* new_node = real_malloc(sizeof(hashNode_t));
    new_node->key = key;
    new_node->value = value;
    new_node->next = table->buckets[idx];
    table->buckets[idx] = new_node;
}

memStruct_t* hashtable_lookup(hashTable_t* table, void* key) {
    size_t idx = ptr_hash(key);
    hashNode_t* node = table->buckets[idx];

    // check if key in table
    while (node) {
        if (node->key == key) return &node->value;
        node = node->next;
    }
    return NULL; // Not found
}

void hashtable_remove(hashTable_t* table, void* key) {
    size_t idx = ptr_hash(key);
    hashNode_t* node = table->buckets[idx];
    hashNode_t* prev = NULL;

    // find key and remove it
    while (node) {
        if (node->key == key) {
            if (prev) prev->next = node->next;
            else table->buckets[idx] = node->next;
            real_free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

hashTable_t* hashtable_create() {
    // initialize table
    hashTable_t* table = real_malloc(sizeof(hashTable_t));
    for (int i = 0; i < TABLE_SIZE; i++) table->buckets[i] = NULL;
    return table;
}


void check_memory_leaks(void) {
    if (!mem_table) return; // no allocations done

    int leaks = 0;

    // count active mem
    for (int i = 0; i < TABLE_SIZE; i++) {
        hashNode_t* node = mem_table->buckets[i];
        while (node) {
            if (node->value.status) {
                leaks++;
                fprintf(stderr,
                        "[MEM LEAK] Pointer %p, size %zu bytes still allocated\nAt: \n",
                        node->key,
                        node->value.size);
                // TODO: see if we can get these pritns to work better
                print_location(node->key);
            }
            node = node->next;
        }
    }

    // print results
    if (leaks == 0) {
        fprintf(stderr, "[MEM CHECK] All memory freed correctly.\n");
    } else {
        fprintf(stderr, "[MEM CHECK] Total leaks detected: %d\n", leaks);
    }
}

// helper function
void set_disable_tracking(int t){
    disable_tracking = t;
}

void* malloc(size_t size) {
    if (in_hook) return real_malloc(size);
    if (disable_tracking) return real_malloc(size);
    if (!OVERRIDE_MEM) return real_malloc(size); 
    in_hook = 1;

    if (!mem_table) mem_table = hashtable_create();

    // Allocate extra byte for canary
    void* ptr_real = real_malloc(size + 1);
    if (!ptr_real) return NULL;

    // Set canary at the end
    ((unsigned char*)ptr_real)[size] = CANARY;

    uintptr_t caller_addr = (uintptr_t) __builtin_return_address(0);

    // Store metadata
    memStruct_t info = {.size = size, 
                        .status = true,
                        .caller = caller_addr};
    
    hashtable_insert(mem_table, ptr_real, info);

    in_hook = 0;
    return ptr_real; // Return pointer to user (before canary)
}

void free(void* ptr) {
    if (in_hook) return real_free(ptr);
    if (disable_tracking) return real_free(ptr);
    if (!OVERRIDE_MEM) return real_free(ptr);
    in_hook = 1;

    memStruct_t* info = hashtable_lookup(mem_table, ptr);
    if (info) {
        // check if inactive
        if (!info->status){
            printf("Double Free Detected: %p\n", (void*) info->caller);
            print_location((void*) info->caller);
            // exit(EXIT_FAILURE);
            return;
        }

        // Check canary
        unsigned char* end = (unsigned char*)ptr + info->size;
        if (*end != CANARY) {
            printf("Memory corruption detected.\nLikely an out of bounds error related to a variable allocated here:\n");
            print_location((void*) info->caller);
            exit(EXIT_FAILURE);
        }
        info->status = false;
    }

    in_hook = 0;
    real_free(ptr);
}


void* realloc(void* ptr, size_t size) {
    if (in_hook) return real_realloc(ptr, size);
    if (disable_tracking) return real_realloc(ptr, size);
    if (!OVERRIDE_MEM) return real_realloc(ptr, size);
    in_hook = 1;

    if (!mem_table) mem_table = hashtable_create();

    memStruct_t* info = hashtable_lookup(mem_table, ptr);
    if (info) {
        // check old canary before realloc
        unsigned char* old_end = (unsigned char*)ptr + info->size;
        if (*old_end != CANARY) fprintf(stderr, "Memory corruption before realloc at %p!\n", ptr);

        // Remove old entry
        hashtable_remove(mem_table, ptr);
    }

    void* ptr_new = real_realloc(ptr, size + 1);
    if (!ptr_new) return NULL;

    // Set new canary
    ((unsigned char*)ptr_new)[size] = CANARY;

    uintptr_t caller_addr = (uintptr_t) __builtin_return_address(0);

    // Update hash table
    memStruct_t new_info = {.size = size, 
                            .status = true,
                            .caller = caller_addr };
    hashtable_insert(mem_table, ptr_new, new_info);

    in_hook = 0;
    return ptr_new;
}