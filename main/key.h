#ifndef KEYMGR_KEY_H
#define KEYMGR_KEY_H

#include <stdint.h>

#define KEYMGR_LIST_FILTER_LABEL (1 << 0)
#define KEYMGR_LIST_FILTER_TYPE (1 << 1)
#define KEYMGR_LIST_FILTER_USAGE (1 << 2)
#define KEYMGR_LIST_FILTER_ID (1 << 3)

#define KEYMGR_KEY_META_CURRENT_VERSION 1

typedef enum {
  km_key_type_aes = 0x01,
  km_key_type_rsa = 0x02,
  km_key_type_ec = 0x03,
  km_key_type_hmac = 0x04,
} km_key_type_t;

typedef enum {
  km_key_usage_encrypt = 0x01,
  km_key_usage_sign = 0x02,
  km_key_usage_derive = 0x03,
} km_key_usage_t;

typedef enum {
  km_public_key_encoding_der_spki = 0x01
} km_public_key_encoding_t;

typedef struct {
  uint32_t id;
  km_key_type_t type;
  km_key_usage_t usage;
  uint16_t size;
  char *label;
  uint32_t created_at;
} km_key_metadata_t;

#endif // KEYMGR_KEY_H
