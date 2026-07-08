#ifndef KEYMGR_KEYS_H
#define KEYMGR_KEYS_H

#include <stdint.h>

typedef uint32_t km_slot_t;

typedef struct _km_key_metadata {
  km_slot_t slot;
  char *label;
  uint8_t type;
  uint16_t size;
  uint32_t created_at;
} km_key_metadata_t;

bool km_keys_add_key(km_key_metadata_t *metadata);
bool km_keys_find_label(const char *label, km_slot_t *out);
bool km_keys_get_meta(km_slot_t slot, km_key_metadata_t *out);

#endif // KEYMGR_KEYS_H
