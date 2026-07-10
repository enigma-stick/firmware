#include "crypto.h"
#include "esp_log.h"
#include "keys.h"
#include "mbedtls/psa_util.h"
#include "memory.h"
#include "psa/crypto.h"
#include "psa/crypto_sizes.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

static const char *TAG = "keymgr_crypto";

void km_crypto_init() {
  psa_status_t err = psa_crypto_init();
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not initialize crypto stack");
    // TODO: panic
  }
}

bool km_crypto_generate_ecc(size_t bits, psa_key_id_t *out) {
  if (out == NULL) {
    ESP_LOGE(TAG, "Attempted to pass NULL as km_key_metadata_t");
    return false;
  }

  // Set key attributes
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_bits(&attr, bits);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
  psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

  // TODO: REMOVE AFTER TESTING
  psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

  // Generate the key
  psa_key_id_t key;
  psa_status_t err = psa_generate_key(&attr, &key);
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not generate key");
    return false;
  }
  *out = key;

  // Success!
  psa_reset_key_attributes(&attr);
  return true;
}

bool km_crypto_generate_aes(size_t bits, psa_key_id_t *out) {
  if (out == NULL) {
    ESP_LOGE(TAG, "Attempted to pass NULL as km_key_metadata_t");
    return false;
  }

  // Set key attributes
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, bits);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, PSA_ALG_GCM);

  // TODO: REMOVE AFTER TESTING
  psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

  psa_key_id_t key;
  psa_status_t err = psa_generate_key(&attr, &key);
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not generate key");
    return false;
  }
  *out = key;

  psa_reset_key_attributes(&attr);
  return true;
}

bool km_crypto_handle_generate(km_key_generate_params_t params,
                               psa_key_id_t *out) {
  psa_key_id_t key;

  switch (params.type) {
  case km_key_type_ecc:
    if (!km_crypto_generate_ecc(params.size, &key)) {
      ESP_LOGE(TAG, "Error generating ECC key");
      return false;
    }
    break;
  case km_key_type_aes:
    if (!km_crypto_generate_aes(params.size, &key)) {
      ESP_LOGE(TAG, "Error generating AES key");
      return false;
    }
    break;
  default:
    return false;
  }

  *out = key;
  return true;
}

bool km_crypto_export_public_key(km_memory_pool_t *pool,
                                 km_key_metadata_t metadata, uint8_t **out,
                                 size_t *len) {
  size_t to_alloc = 0;
  switch (metadata.type) {
  case km_key_type_ecc:
    to_alloc = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), metadata.size);
    break;
  default:
    ESP_LOGE(TAG, "Key type not supported");
    return false;
  }

  uint8_t *buffer = km_memory_alloc(pool, sizeof(uint8_t) * to_alloc);
  if (!buffer) {
    ESP_LOGE(TAG, "Unable to allocate enough memory to export public key");
    return false;
  }

  size_t actual_size;
  psa_status_t err =
      psa_export_public_key(metadata.slot, buffer, to_alloc, &actual_size);
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Error exporting public key");
    return false;
  }

  *out = buffer;
  *len = actual_size;

  return true;
}

bool km_crypto_sign(km_memory_pool_t *pool, km_key_metadata_t metadata,
                    uint8_t *digest, uint8_t **out) {

  psa_algorithm_t alg;
  switch (metadata.type) {
  case km_key_type_ecc:
    alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    break;
  default:
    ESP_LOGE(TAG, "Unsupported key type");
    return false;
  }

  // TODO: this needs to be more generalized, but fine for a first pass.
  uint8_t *signature = km_memory_alloc(pool, sizeof(uint8_t) * 64);
  size_t signature_length = 0;
  psa_status_t err = psa_sign_hash(metadata.slot, alg, digest, 32, signature,
                                   64, &signature_length);
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not sign hash");
    return false;
  }

  *out = signature;
  return true;
}

size_t km_crypto_encrypt(km_memory_pool_t *pool,
                         km_key_encrypt_params_t *params, uint8_t **out) {
  psa_algorithm_t alg;
  switch (params->key->type) {
  case km_key_type_aes:
    alg = PSA_ALG_GCM;
    break;
  default:
    ESP_LOGE(TAG, "Unsupported key type");
    return false;
  }

  size_t ciphertext_size =
      PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(params->plaintext_length);
  uint8_t *ciphertext = km_memory_alloc(pool, ciphertext_size);
  size_t ciphertext_length = 0;

  psa_status_t err =
      psa_aead_encrypt(params->key->slot, alg, params->nonce, 12, NULL, 0,
                       params->plaintext, params->plaintext_length, ciphertext,
                       ciphertext_size, &ciphertext_length);
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not encrypt plaintext");
    return false;
  }

  *out = ciphertext;
  return ciphertext_length;
}

size_t km_crypto_decrypt(km_memory_pool_t *pool,
                         km_key_decrypt_params_t *params, uint8_t **out) {
  psa_algorithm_t alg;
  switch (params->key->type) {
  case km_key_type_aes:
    alg = PSA_ALG_GCM;
    break;
  default:
    ESP_LOGE(TAG, "Unsupported key type");
    return false;
  }

  size_t plaintext_size =
      PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(params->ciphertext_length);
  uint8_t *plaintext = km_memory_alloc(pool, plaintext_size);
  size_t plaintext_length = 0;

  psa_status_t err = psa_aead_decrypt(
      params->key->slot, alg, params->nonce, 12, NULL, 0, params->ciphertext,
      params->ciphertext_length, plaintext, plaintext_size, &plaintext_length);
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not encrypt plaintext");
    return false;
  }

  *out = plaintext;
  return plaintext_length;
}
