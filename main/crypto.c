#include "crypto.h"
#include "esp_log.h"
#include "mbedtls/psa_util.h"
#include "psa/crypto.h"
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

bool km_crypto_handle_generate(km_key_generate_params_t params,
                               psa_key_id_t *out) {
  psa_key_id_t key;

  switch (params.type) {
  case km_key_type_ecc:
    if (!km_crypto_generate_ecc(params.size, &key)) {
      return false;
    }
    break;
  default:
    return false;
  }

  *out = key;
  return true;
}
