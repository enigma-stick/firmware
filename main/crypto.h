#ifndef KEYMGR_CRYPTO_H
#define KEYMGR_CRYPTO_H

#include "keys.h"
#include "memory.h"
#include "psa/crypto_types.h"

enum km_key_type { km_key_type_ecc = 0x01, km_key_type_aes = 0x02 };

typedef struct _key_generate_params {
  enum km_key_type type;
  uint16_t size;
} km_key_generate_params_t;

typedef struct _key_encrypt_params {
  km_memory_pool_t *pool;
  km_key_metadata_t *key;
  uint8_t *plaintext;
  size_t plaintext_length;
  uint8_t nonce[12];
} km_key_encrypt_params_t;

typedef struct _key_decrypt_params {
  km_memory_pool_t *pool;
  km_key_metadata_t *key;
  uint8_t *ciphertext;
  size_t ciphertext_length;
  uint8_t nonce[12];
} km_key_decrypt_params_t;

void km_crypto_init();
bool km_crypto_handle_generate(km_key_generate_params_t params,
                               psa_key_id_t *out);
bool km_crypto_export_public_key(km_memory_pool_t *pool,
                                 km_key_metadata_t metadata, uint8_t **out,
                                 size_t *len);
bool km_crypto_sign(km_memory_pool_t *pool, km_key_metadata_t metadata,
                    uint8_t *digest, uint8_t **out);
size_t km_crypto_encrypt(km_memory_pool_t *pool,
                         km_key_encrypt_params_t *params, uint8_t **out);
size_t km_crypto_decrypt(km_memory_pool_t *pool,
                         km_key_decrypt_params_t *params, uint8_t **out);

#endif // KEYMGR_CRYPTO_H
