#ifndef KEYMGR_STORAGE_H
#define KEYMGR_STORAGE_H

#include "esp_err.h"
#include "memory.h"
#include <stdbool.h>
#include <stddef.h>

void km_store_init();
esp_err_t km_store_read_alloc(km_memory_pool_t *pool, const char *key,
                              void **value, size_t *len);
void *km_store_read(km_memory_pool_t *pool, const char *key, size_t *len);
bool km_store_write(const char *key, const void *value, size_t len);

#endif // KEYMGR_STORAGE_H
