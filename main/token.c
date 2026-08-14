#include "token.h"

#include "esp_log.h"
#include "nvs.h"
#include "serial.h"
#include "storage.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define KEYMGR_TOKEN_STORE_KEY "keymgr:se:token"
#define KEYMGR_TOKEN_DEFAULT_PBKDF2_ROUNDS 256u

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

static void token_metadata_set_defaults(km_token_metadata_t *metadata) {
  memset(metadata, 0, sizeof(*metadata));
  metadata->version = KEYMGR_TOKEN_METADATA_VERSION;
  metadata->state = KM_TOKEN_UNINITIALIZED;
  metadata->pbkdf2_rounds = KEYMGR_TOKEN_DEFAULT_PBKDF2_ROUNDS;
  metadata->se_auth_object_id = KEYMGR_SE_AUTH_OBJECT_ID;
  metadata->se_hmac_id = KEYMGR_SE_HMAC_MASTER_ID;
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
