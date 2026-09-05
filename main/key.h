#ifndef KEYMGR_KEY_H
#define KEYMGR_KEY_H

#include <stdint.h>

typedef enum { km_key_type_aes = 0x01, km_key_type_rsa = 0x02 } km_key_type_t;

typedef enum {
  km_key_usage_encrypt = 0x01,
  km_key_usage_sign = 0x02
} km_key_usage_t;

typedef struct {
  uint32_t id;
  km_key_type_t type;
  km_key_usage_t usage;
  uint16_t size;
  char *label;
} km_key_metadata_t;

#endif // KEYMGR_KEY_H
