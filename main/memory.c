#include "memory.h"
#include "esp_log.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "keymgr_mem";

km_memory_pool_t *km_memory_init(size_t bytes) {
  km_memory_pool_t *pool = malloc(sizeof(km_memory_pool_t));
  if (pool == NULL)
    return NULL;

  pool->memory = malloc(bytes);
  if (pool->memory == NULL) {
    free(pool);
    return NULL;
  }

  pool->pointer = 0;
  pool->allocated = bytes;
  pool->next = NULL;

  ESP_LOGI(TAG, "Pool created (%x)", pool);

  return pool;
}

void km_memory_free(km_memory_pool_t *pool) {
  km_memory_pool_t *current = pool;
  while (current != NULL) {
    km_memory_pool_t *next = current->next;
    free(current->memory);
    free(current);
    current = next;
  }
  ESP_LOGI(TAG, "Pool freed (%x)", pool);
}

void *km_memory_alloc(km_memory_pool_t *pool, size_t bytes) {
  // We may allocate memory in layers where we don't have an allocator.
  // For instance, km_store_read may or may not have caller up the chain
  // with a km_memory_pool_t.
  if (pool == NULL) {
    return malloc(bytes);
  }

  // We have to be a little clever here; doing `realloc` would invalidate
  // all previous pointers we gave out. Here, we need to basically walk a
  // linked list, where `next` is another pool. If there is no `next`, we
  // need to create it. The root pool can continue to be used. For free,
  // we get the ability to create a new pool for a larger allocation, while
  // still allowing the free space at the end of the current pool to be used
  // later for a smaller allocation.
  km_memory_pool_t *current = pool;
  size_t alignment = _Alignof(max_align_t);

  for (;;) {
    // We also need to include padding for pointer alignment
    size_t remainder = current->pointer % alignment;
    size_t padding = remainder ? alignment - remainder : 0;
    size_t remaining = current->allocated - current->pointer;

    if (padding <= remaining && bytes <= remaining - padding) {
      size_t start = current->pointer + padding;
      void *ptr = (unsigned char *)current->memory + start;

      current->pointer = start + bytes;
      ESP_LOGI(TAG, "Pool allocated %zu bytes (%p)", bytes, (void *)pool);
      return ptr;
    }

    if (current->next == NULL) {
      // If we request more bytes than a page allocates (determined by the top
      // level init), we need this page to allocate the number of bytes we are
      // requesting, else we would enter an endless memory allocation loop and
      // crash.
      size_t capacity = bytes > pool->allocated ? bytes : pool->allocated;
      current->next = km_memory_init(capacity);
      if (current->next == NULL)
        return NULL;
      ESP_LOGI(TAG, "Pool allocated a new page of %zu bytes (%p)", capacity,
               (void *)pool);
    }

    current = current->next;
  }
}

void *km_memory_realloc(km_memory_pool_t *pool, void *original, size_t obytes,
                        size_t nbytes) {
  if (pool == NULL) {
    return realloc(original, nbytes);
  }

  void *copy = original;
  void *new = km_memory_alloc(pool, nbytes);
  if (new == NULL) {
    return NULL;
  }
  memcpy(new, copy, obytes);
  return new;
}
