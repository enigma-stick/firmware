#ifndef KEYMGR_KEY_H
#define KEYMGR_KEY_H

#include <stdint.h>

typedef enum { km_key_type_aes = 0x01 } km_key_type_t;

typedef struct {
  uint32_t id;
  km_key_type_t type;
  uint16_t size;
  char *label;
} km_key_metadata_t;

#endif // KEYMGR_KEY_H
