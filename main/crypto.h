#ifndef KEYMGR_CRYPTO_H
#define KEYMGR_CRYPTO_H

#include "psa/crypto_types.h"

void km_crypto_init();
bool km_crypto_rand(uint8_t *buffer, size_t bytes);
bool km_crypto_generate_hmac(psa_key_id_t key_id);
bool km_crypto_pbkdf2(uint32_t rounds, const uint8_t *salt, size_t salt_len,
                      const uint8_t *pin, size_t pin_len, uint8_t *output,
                      size_t output_len);
bool km_crypto_kdf_hmac(psa_key_id_t key_id, const char *label,
                        const uint8_t *uid, size_t uid_len,
                        const uint8_t *material, size_t material_len,
                        uint8_t *output, size_t output_len);
void km_crypto_zero(void *buffer, size_t len);

#endif // KEYMGR_CRYPTO_H
