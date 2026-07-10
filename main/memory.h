#ifndef KEYMGR_MEMORY_H
#define KEYMGR_MEMORY_H

#define KEYMGR_MEMORY_DEFAULT_BYTES 1024 * 4 // 4 KB

#include <stdbool.h>
#include <stddef.h>

typedef struct _memory_pool {
  void *memory;
  size_t pointer;
  size_t allocated;
  struct _memory_pool *next;
} km_memory_pool_t;

km_memory_pool_t *km_memory_init(size_t bytes);
void km_memory_free(km_memory_pool_t *pool);
void *km_memory_alloc(km_memory_pool_t *pool, size_t bytes);
void *km_memory_realloc(km_memory_pool_t *pool, void *original, size_t obytes,
                        size_t nbytes);

#endif // KEYMGR_MEMORY_H
