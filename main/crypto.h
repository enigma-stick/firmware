#ifndef KEYMGR_CRYPTO_H
#define KEYMGR_CRYPTO_H

#include "psa/crypto_types.h"

enum km_key_type { km_key_type_ecc = 0x01 };

typedef struct _key_generate_params {
  enum km_key_type type;
  uint16_t size;
} km_key_generate_params_t;

void km_crypto_init();
bool km_crypto_handle_generate(km_key_generate_params_t params,
                               psa_key_id_t *out);

#endif // KEYMGR_CRYPTO_H
