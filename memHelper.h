
#include <stdio.h>
#include <stdbool.h>


#define TABLE_SIZE 1024
#define CANARY 0xAD

typedef struct memStruct {
    size_t size;
    bool status; // 0 = freed   1 = active 
    uintptr_t caller;
} memStruct_t;

typedef struct hashNode {
    void* key;
    memStruct_t value;
    struct hashNode* next;
} hashNode_t;

typedef struct hashTable {
    hashNode_t* buckets[TABLE_SIZE];
} hashTable_t;

void check_memory_leaks(void);
void set_disable_tracking(int t);
void *malloc(size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);
