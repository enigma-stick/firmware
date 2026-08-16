#include "crypto.h"
#include "esp_log.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/psa_util.h"
#include "memory.h"
#include "psa/crypto.h"
#include "psa/crypto_sizes.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include <string.h>

static const char *TAG = "keymgr_crypto";

void km_crypto_init() {
  psa_status_t err = psa_crypto_init();
  if (err != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not initialize crypto stack: PSA status=%d",
             (int)err);
    // TODO: panic
  }
}

bool km_crypto_rand(uint8_t *buffer, size_t bytes) {
  if (buffer == NULL || bytes <= 0) {
    return false;
  }

  psa_status_t err = psa_generate_random(buffer, bytes);
  if (err != PSA_SUCCESS) {
    return false;
  }

  return true;
}

static bool key_exists(psa_key_id_t key_id) {
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_status_t status = psa_get_key_attributes(key_id, &attr);
  psa_reset_key_attributes(&attr);

  if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE &&
      status != PSA_ERROR_DOES_NOT_EXIST) {
    ESP_LOGW(TAG,
             "Could not check whether PSA key 0x%08x exists: status=%d",
             (unsigned)key_id, (int)status);
  }

  return status == PSA_SUCCESS;
}

bool km_crypto_generate_hmac(psa_key_id_t key_id) {
  if (key_exists(key_id)) {
    ESP_LOGI(TAG, "Key already exists; will re-use");
    return true;
  }

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_id(&attr, key_id);
  psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&attr, 256);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
  psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);

  psa_key_id_t generated_id = 0;
  psa_status_t status = psa_generate_key(&attr, &generated_id);

  psa_reset_key_attributes(&attr);

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG,
             "Could not generate persistent HMAC key 0x%08x: PSA status=%d",
             (unsigned)key_id, (int)status);
    return false;
  }

  if (generated_id != key_id) {
    ESP_LOGE(TAG,
             "PSA generated HMAC key 0x%08x instead of requested 0x%08x",
             (unsigned)generated_id, (unsigned)key_id);
    return false;
  }

  return true;
}

bool km_crypto_pbkdf2(uint32_t rounds, const uint8_t *salt, size_t salt_len,
                      const uint8_t *pin, size_t pin_len, uint8_t *output,
                      size_t output_len) {
  psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
  psa_status_t status = psa_key_derivation_setup(
      &operation, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not set up KDF");
    goto cleanup;
  }

  status = psa_key_derivation_input_integer(
      &operation, PSA_KEY_DERIVATION_INPUT_COST, rounds);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not set KDF cost");
    goto cleanup;
  }

  status = psa_key_derivation_input_bytes(
      &operation, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not set KDF salt");
    goto cleanup;
  }

  status = psa_key_derivation_input_bytes(
      &operation, PSA_KEY_DERIVATION_INPUT_PASSWORD, pin, pin_len);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not set KDF password");
    goto cleanup;
  }

  status = psa_key_derivation_output_bytes(&operation, output, output_len);

cleanup:
  psa_key_derivation_abort(&operation);

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not compute KDF");
    return false;
  }
  return true;
}

bool km_crypto_kdf_hmac(psa_key_id_t key_id, const char *label,
                        const uint8_t *uid, size_t uid_len,
                        const uint8_t *material, size_t material_len,
                        uint8_t *output, size_t output_len) {
  uint8_t D[PSA_MAC_MAX_SIZE] = {0};
  psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

  psa_status_t status =
      psa_mac_sign_setup(&operation, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not set up MAC operation");
    goto cleanup;
  }

  status = psa_mac_update(&operation, (uint8_t *)label, strlen(label));
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not add label to MAC payload");
    goto cleanup;
  }

  status = psa_mac_update(&operation, uid, uid_len);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not add UID to MAC payload");
    goto cleanup;
  }

  status = psa_mac_update(&operation, material, material_len);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not add KDF material to MAC payload");
    goto cleanup;
  }

  size_t mac_length = 0;
  status = psa_mac_sign_finish(&operation, D, sizeof(D), &mac_length);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not compute MAC");
    goto cleanup;
  }

  if (mac_length != 32) {
    goto cleanup;
  }

  size_t final_length = output_len < mac_length ? output_len : mac_length;

  if (output == NULL || output_len == 0 || output_len > 32) {
    goto cleanup;
  }

  memcpy(output, D, final_length);
  memset(D, 0, sizeof(D));

cleanup:
  km_crypto_zero(D, sizeof(D));
  psa_mac_abort(&operation);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not HMAC the KDF");
    return false;
  }
  return true;
}

void km_crypto_zero(void *buffer, size_t len) {
  mbedtls_platform_zeroize(buffer, len);
}
