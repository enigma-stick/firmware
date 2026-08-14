#ifndef KEYMGR_TOKEN_H
#define KEYMGR_TOKEN_H

#include "esp_err.h"
#include "se05x_esp.h"
#include <stdint.h>

#define KEYMGR_TOKEN_METADATA_VERSION 0x01u
#define KEYMGR_TOKEN_SALT_SIZE 16u

#define KEYMGR_SE_AUTH_OBJECT_ID 0x4B4D0001u
#define KEYMGR_SE_HMAC_MASTER_ID 0x4B4D0002u
#define KEYMGR_SE_APP_KEY_BASE 0x4B4D1000u

typedef enum {
  KM_TOKEN_UNINITIALIZED,
  KM_TOKEN_PROVISIONING,
  KM_TOKEN_READY
} km_token_state_t;

typedef struct {
  uint8_t version;
  km_token_state_t state;
  uint8_t uid[SE05X_ESP_UID_SIZE];
  uint8_t salt[KEYMGR_TOKEN_SALT_SIZE];
  uint32_t pbkdf2_rounds;
  uint32_t esp_key_id;
  uint32_t se_auth_object_id;
  uint32_t se_hmac_id;
} km_token_metadata_t;

/** Load the token record, creating an uninitialized record when it is absent. */
esp_err_t km_token_init(void);

/** Return the loaded metadata, or NULL if km_token_init has not succeeded. */
const km_token_metadata_t *km_token_get_metadata(void);

#endif // KEYMGR_TOKEN_H
