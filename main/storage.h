#ifndef KEYMGR_STORAGE_H
#define KEYMGR_STORAGE_H

#include "memory.h"
#include <stddef.h>
void km_store_init();
void *km_store_read(km_memory_pool_t *pool, const char *key, size_t *len);
bool km_store_write(const char *key, const void *value, size_t len);

#endif // KEYMGR_STORAGE_H
