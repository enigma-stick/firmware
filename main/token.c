#include "token.h"

#include "crypto.h"
#include "esp_log.h"
#include "nvs.h"
#include "se_worker.h"
#include "serial.h"
#include "storage.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define KEYMGR_TOKEN_STORE_KEY "keymgr:se:token"
#define KEYMGR_TOKEN_DEFAULT_PBKDF2_ROUNDS 256u
#define KEYMGR_TOKEN_LABEL "keymgr/se051-auth/v1"

static const char *TAG = "keymgr_token";
static km_token_metadata_t token_metadata;
static bool token_metadata_loaded;

static esp_err_t token_metadata_deserialize(const uint8_t *data, size_t length,
                                            km_token_metadata_t *out) {
  if (data == NULL || out == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  km_deserializer_t dz = {
      .data = (uint8_t *)data,
      .len = length,
      .cursor = 0,
      .owned = false,
      .failed = false,
  };
  km_token_metadata_t decoded = {0};

  if (!km_dz_u8(&dz, &decoded.version)) {
    return ESP_ERR_INVALID_SIZE;
  }
  if (decoded.version != KEYMGR_TOKEN_METADATA_VERSION) {
    return ESP_ERR_INVALID_VERSION;
  }

  uint8_t state = 0;
  if (!km_dz_u8(&dz, &state) || state > KM_TOKEN_READY) {
    return ESP_ERR_INVALID_STATE;
  }
  decoded.state = (km_token_state_t)state;

  uint32_t uid_length = 0;
  if (!km_dz_u32(&dz, &uid_length) || uid_length != sizeof(decoded.uid)) {
    return ESP_ERR_INVALID_SIZE;
  }
  for (size_t index = 0; index < sizeof(decoded.uid); ++index) {
    if (!km_dz_u8(&dz, &decoded.uid[index])) {
      return ESP_ERR_INVALID_SIZE;
    }
  }

  uint32_t salt_length = 0;
  if (!km_dz_u32(&dz, &salt_length) || salt_length != sizeof(decoded.salt)) {
    return ESP_ERR_INVALID_SIZE;
  }
  for (size_t index = 0; index < sizeof(decoded.salt); ++index) {
    if (!km_dz_u8(&dz, &decoded.salt[index])) {
      return ESP_ERR_INVALID_SIZE;
    }
  }

  if (!km_dz_u32(&dz, &decoded.pbkdf2_rounds) ||
      !km_dz_u32(&dz, &decoded.esp_key_id) ||
      !km_dz_u32(&dz, &decoded.se_auth_object_id) ||
      !km_dz_u32(&dz, &decoded.se_hmac_id) || dz.failed ||
      dz.cursor != dz.len) {
    return ESP_ERR_INVALID_SIZE;
  }

  *out = decoded;
  return ESP_OK;
}

static esp_err_t token_metadata_write(const km_token_metadata_t *metadata) {
  if (metadata == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  km_serializer_t *sz = km_sz_init(sizeof(*metadata) + 32u);
  if (sz == NULL) {
    return ESP_ERR_NO_MEM;
  }

  km_sz_u8(sz, metadata->version);
  km_sz_u8(sz, (uint8_t)metadata->state);
  km_sz_array(km_sz_u8, sz, metadata->uid, sizeof(metadata->uid));
  km_sz_array(km_sz_u8, sz, metadata->salt, sizeof(metadata->salt));
  km_sz_u32(sz, metadata->pbkdf2_rounds);
  km_sz_u32(sz, metadata->esp_key_id);
  km_sz_u32(sz, metadata->se_auth_object_id);
  km_sz_u32(sz, metadata->se_hmac_id);

  bool written = km_store_write(KEYMGR_TOKEN_STORE_KEY, sz->data, sz->len);
  km_sz_free(sz);
  return written ? ESP_OK : ESP_FAIL;
}

static esp_err_t token_metadata_commit(const km_token_metadata_t *candidate) {
  esp_err_t err = token_metadata_write(candidate);
  if (err != ESP_OK) {
    return err;
  }

  token_metadata = *candidate;
  token_metadata_loaded = true;
  return ESP_OK;
}

static void token_metadata_set_defaults(km_token_metadata_t *metadata) {
  memset(metadata, 0, sizeof(*metadata));
  metadata->version = KEYMGR_TOKEN_METADATA_VERSION;
  metadata->state = KM_TOKEN_UNINITIALIZED;
  metadata->pbkdf2_rounds = KEYMGR_TOKEN_DEFAULT_PBKDF2_ROUNDS;
  metadata->se_auth_object_id = TEST_AUTH_OBJECT_ID; // TODO: change to prod
  metadata->se_hmac_id = TEST_HMAC_MASTER_ID;        // TODO: change to prod
  metadata->esp_key_id = KEYMGR_ESP_HMAC_KEY_ID;
}

esp_err_t km_token_init(void) {
  token_metadata_loaded = false;

  void *stored = NULL;
  size_t stored_length = 0;
  esp_err_t err = km_store_read_alloc(NULL, KEYMGR_TOKEN_STORE_KEY, &stored,
                                      &stored_length);

  if (err == ESP_ERR_NVS_NOT_FOUND) {
    km_token_metadata_t defaults;
    token_metadata_set_defaults(&defaults);

    err = token_metadata_write(&defaults);
    if (err != ESP_OK) {
      return err;
    }

    token_metadata = defaults;
    token_metadata_loaded = true;
    ESP_LOGI(TAG, "Created uninitialized token metadata (version=%u)",
             defaults.version);
    return ESP_OK;
  }

  if (err != ESP_OK) {
    return err;
  }

  km_token_metadata_t decoded;
  err = token_metadata_deserialize(stored, stored_length, &decoded);
  free(stored);
  if (err != ESP_OK) {
    return err;
  }

  token_metadata = decoded;
  token_metadata_loaded = true;
  ESP_LOGI(TAG, "Loaded token metadata (version=%u state=%u)", decoded.version,
           (unsigned)decoded.state);
  return ESP_OK;
}

const km_token_metadata_t *km_token_get_metadata(void) {
  return token_metadata_loaded ? &token_metadata : NULL;
}

static esp_err_t token_derive_auth_key(char *pin, size_t pin_length,
                                       uint8_t key[16]) {
  uint8_t derived_material[32] = {0};
  uint8_t K[16] = {0};
  esp_err_t result = ESP_FAIL;

  if (!km_crypto_pbkdf2(token_metadata.pbkdf2_rounds, token_metadata.salt,
                        sizeof(token_metadata.salt), (uint8_t *)pin, pin_length,
                        derived_material, sizeof(derived_material))) {
    ESP_LOGE(TAG, "Could not derive auth key material from PIN");
    goto cleanup;
  }

  if (!km_crypto_kdf_hmac(token_metadata.esp_key_id, KEYMGR_TOKEN_LABEL,
                          token_metadata.uid, sizeof(token_metadata.uid),
                          derived_material, sizeof(derived_material), K,
                          sizeof(K))) {
    ESP_LOGE(TAG, "Could not HMAC the PIN material");
    goto cleanup;
  }

  memcpy(key, K, sizeof(K));
  result = ESP_OK;

cleanup:
  km_crypto_zero(derived_material, sizeof(derived_material));
  km_crypto_zero(K, sizeof(K));
  return result;
}

static esp_err_t km_token_provision_generate_keys(char *pin,
                                                  size_t pin_length) {
  uint8_t K[16] = {0};
  esp_err_t result = ESP_FAIL;

  if (!km_crypto_generate_hmac(token_metadata.esp_key_id)) {
    ESP_LOGE(TAG, "Could not generate auth HMAC");
    goto cleanup;
  }

  if (token_derive_auth_key(pin, pin_length, K) != ESP_OK) {
    ESP_LOGE(TAG, "Could not derive auth key");
    goto cleanup;
  }

  if (km_se_worker_provision_auth_object(token_metadata.se_auth_object_id, K) !=
      ESP_OK) {
    ESP_LOGE(TAG, "Could not provision auth object on SE05X");
    goto cleanup;
  }
  km_crypto_zero(K, sizeof(K));

  if (km_se_worker_provision_hmac_master(token_metadata.se_hmac_id) != ESP_OK) {
    ESP_LOGE(TAG, "Could not provision HMAC master on SE05X");
    goto cleanup;
  }

  result = ESP_OK;

cleanup:
  km_crypto_zero(K, sizeof(K));
  return result;
}

esp_err_t km_token_provision(char *pin, size_t pin_length) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot provision before token metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  if (pin == NULL || pin_length == 0) {
    ESP_LOGE(TAG, "Cannot provision with an empty PIN");
    return ESP_ERR_INVALID_ARG;
  }

  if (token_metadata.state == KM_TOKEN_READY) {
    ESP_LOGE(TAG, "Token is already provisioned");
    return ESP_ERR_INVALID_STATE;
  }

  km_token_metadata_t candidate = token_metadata;

  // Get UID
  uint8_t uid[SE05X_ESP_UID_SIZE];
  size_t uid_len = sizeof(uid);
  esp_err_t err = km_se_worker_get_uid(uid, &uid_len);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not get secure element UID: %s", esp_err_to_name(err));
    return err;
  }

  if (candidate.state == KM_TOKEN_PROVISIONING) {
    if (memcmp(uid, candidate.uid, sizeof(candidate.uid)) != 0) {
      ESP_LOGE(TAG, "SE051 UID changed while provisioning");
      return ESP_ERR_INVALID_STATE;
    }
  } else if (candidate.state == KM_TOKEN_UNINITIALIZED) {
    memcpy(candidate.uid, uid, uid_len);

    uint8_t salt[KEYMGR_TOKEN_SALT_SIZE];
    uint8_t salt_len = sizeof(salt);
    if (!km_crypto_rand(salt, salt_len)) {
      ESP_LOGE(TAG, "Could not generate token salt");
      return ESP_FAIL;
    }

    memcpy(candidate.salt, salt, salt_len);

    candidate.state = KM_TOKEN_PROVISIONING;
    err = token_metadata_commit(&candidate);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Could not commit PROVISIONING metadata: %s",
               esp_err_to_name(err));
      return err;
    }
    ESP_LOGI(TAG, "Token metadata committed in PROVISIONING state");
  }

  err = km_token_provision_generate_keys(pin, pin_length);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not generate provisional keys: %s",
             esp_err_to_name(err));
    return err;
  }

  candidate.state = KM_TOKEN_READY;
  err = token_metadata_commit(&candidate);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not commit READY metadata: %s", esp_err_to_name(err));
    return err;
  }

  ESP_LOGI(TAG, "Token provisioning completed; state is READY");

  return ESP_OK;
}

esp_err_t km_token_authenticate(char *pin, size_t pin_length) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot provision before token metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  if (pin == NULL || pin_length == 0) {
    ESP_LOGE(TAG, "Cannot provision with an empty PIN");
    return ESP_ERR_INVALID_ARG;
  }

  if (token_metadata.state != KM_TOKEN_READY) {
    ESP_LOGE(TAG, "Token is not provisioned");
    return ESP_ERR_INVALID_STATE;
  }

  uint8_t K[16];
  esp_err_t err = token_derive_auth_key(pin, pin_length, K);
  if (err == ESP_OK) {
    err = km_se_worker_open_session(token_metadata.se_auth_object_id, K);
  }

  km_crypto_zero(K, sizeof(K));
  return err;
}

esp_err_t km_token_get_status(km_token_status_t *token_status) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot provide token status before metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  token_status->token_state = token_metadata.state;
  if (km_se_worker_get_session_state(&token_status->session_state) != ESP_OK) {
    ESP_LOGE(TAG, "Could not retrieve SE05X session state");
    return ESP_FAIL;
  }

  return ESP_OK;
}

esp_err_t km_token_get_key_metadata(km_memory_pool_t *pool, uint32_t key_id,
                                    km_key_metadata_t *out) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Token metadata is not loaded");
    return ESP_ERR_INVALID_STATE;
  }

  if (out == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  char name[15] = {0};
  snprintf(name, sizeof(name), "km:%08" PRIx32, key_id);
  uint8_t *data;
  size_t len;
  esp_err_t status = km_store_read_alloc(pool, name, (void *)&data, &len);

  if (status != ESP_OK) {
    ESP_LOGE(TAG, "Could not read metadata for key %08" PRIx32 ": %s", key_id,
             esp_err_to_name(status));
    return status;
  }

  km_deserializer_t *dz = km_dz_init_move(pool, data, len);

  uint32_t type;
  uint32_t usage;
  if (!km_dz_u32(dz, &type) || !km_dz_u32(dz, &usage) ||
      !km_dz_u16(dz, &out->size) || !km_dz_str(pool, dz, &out->label)) {
    ESP_LOGE(TAG, "Could not deserialize key metadata from NVS");
    return ESP_FAIL;
  }
  out->type = (km_key_type_t)type;
  out->usage = (km_key_usage_t)usage;
  out->id = key_id;

  return ESP_OK;
}

esp_err_t km_token_generate_aes(uint16_t bits, km_key_usage_t usage,
                                const char *label, uint32_t *key_id) {

  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot generate keys before token metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  if (usage != km_key_usage_encrypt) {
    ESP_LOGE(TAG, "Invalid key usage for AES key");
    return ESP_ERR_INVALID_ARG;
  }

  esp_err_t status =
      km_se_worker_generate_aes(token_metadata.se_hmac_id, bits, key_id);
  if (status != ESP_OK) {
    ESP_LOGE(TAG, "Could not generate AES key");
    return status;
  }

  char name[15] = {0};
  snprintf(name, sizeof(name), "km:%08" PRIx32, *key_id);

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_u32(sz, km_key_type_aes);
  km_sz_u32(sz, usage);
  km_sz_u16(sz, bits);
  km_sz_str(sz, label);

  if (!km_store_write(name, sz->data, sz->len)) {
    ESP_LOGE(TAG, "Could not save key metadata to NVS");
    status = ESP_FAIL;
  }

  km_sz_free(sz);
  return status;
}

esp_err_t km_token_generate_rsa(uint16_t bits, km_key_usage_t usage,
                                const char *label, uint32_t *key_id) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot generate keys before token metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  if (usage != km_key_usage_encrypt && usage != km_key_usage_sign) {
    return ESP_ERR_INVALID_ARG;
  }

  esp_err_t status = km_se_worker_generate_rsa(bits, usage, key_id);
  if (status != ESP_OK) {
    ESP_LOGE(TAG, "Could not generate RSA key");
    return status;
  }

  char name[15] = {0};
  snprintf(name, sizeof(name), "km:%08" PRIx32, *key_id);

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_u32(sz, km_key_type_rsa);
  km_sz_u32(sz, usage);
  km_sz_u16(sz, bits);
  km_sz_str(sz, label);

  if (!km_store_write(name, sz->data, sz->len)) {
    ESP_LOGE(TAG, "Could not save key metadata to NVS");
    status = ESP_FAIL;
  }

  km_sz_free(sz);
  return status;
}

esp_err_t km_token_encrypt_aes_gcm(km_memory_pool_t *pool,
                                   km_key_metadata_t *key, uint8_t *plaintext,
                                   size_t plaintext_len, uint8_t **ciphertext,
                                   size_t *ciphertext_len) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot perform encryption before token metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  esp_err_t status = km_se_worker_encrypt_aes_gcm(
      pool, key, plaintext, plaintext_len, ciphertext, ciphertext_len);

  return status;
}

esp_err_t km_token_decrypt_aes_gcm(km_memory_pool_t *pool,
                                   km_key_metadata_t *key, uint8_t *ciphertext,
                                   size_t ciphertext_len, uint8_t **plaintext,
                                   size_t *plaintext_len) {
  if (!token_metadata_loaded) {
    ESP_LOGE(TAG, "Cannot perform decryption before token metadata is loaded");
    return ESP_ERR_INVALID_STATE;
  }

  esp_err_t status = km_se_worker_decrypt_aes_gcm(
      pool, key, ciphertext, ciphertext_len, plaintext, plaintext_len);

  return status;
}
