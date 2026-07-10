#ifndef KEYMGR_KEYS_H
#define KEYMGR_KEYS_H

#include "memory.h"
#include <stdint.h>

typedef uint32_t km_slot_t;

typedef struct _key_metadata {
  km_slot_t slot;
  char *label;
  uint8_t type;
  uint16_t size;
  uint32_t created_at;
} km_key_metadata_t;

typedef struct _key_store {
  uint32_t count;
  km_slot_t *slots;
} km_key_store_t;

void km_keys_init_storage();
bool km_keys_add_key(km_memory_pool_t *pool, km_key_metadata_t *metadata);
bool km_keys_find_label(km_memory_pool_t *pool, const char *label,
                        km_key_metadata_t *out);
bool km_keys_get_meta(km_memory_pool_t *pool, km_slot_t slot,
                      km_key_metadata_t *out);

#endif // KEYMGR_KEYS_H
