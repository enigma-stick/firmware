#ifndef KEYMGR_SE05X_ESP_H
#define KEYMGR_SE05X_ESP_H

#include "fsl_sss_se05x_apis.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SE05X_ESP_UID_SIZE 18
#define SE05X_ESP_VERSION_SIZE 7
#define SE05X_ESP_RANDOM_SAMPLE_SIZE 16
#define SE05X_ESP_AES_AUTH_KEY_SIZE 16

typedef struct {
  sss_se05x_session_t sss;
  SE05x_Connect_Ctx_t connection;
  /** Private host-crypto state used by an authenticated session. */
  void *authentication_state;
  bool is_open;
} se05x_esp_session_t;

typedef struct {
  uint8_t uid[SE05X_ESP_UID_SIZE];
  size_t uid_length;
  uint8_t applet_version[SE05X_ESP_VERSION_SIZE];
  size_t applet_version_length;
  uint8_t random_sample[SE05X_ESP_RANDOM_SAMPLE_SIZE];
} se05x_esp_info_t;

/** Open a plain/default SSS session for initial board bring-up. */
sss_status_t se05x_esp_session_open(se05x_esp_session_t *session);

/**
 * Open an encrypted applet session authenticated by a 128-bit AES object.
 *
 * The authentication key is copied into temporary host-crypto objects and is
 * released when the session closes. The caller should clear its own key copy.
 */
sss_status_t se05x_esp_session_open_aes_key(se05x_esp_session_t *session,
                                            uint32_t authentication_object_id,
                                            const uint8_t *authentication_key,
                                            size_t authentication_key_length);

/**
 * Create a persistent 128-bit AES applet authentication object.
 *
 * This fills a gap in the generic SSS symmetric-key API, which creates a
 * normal AES object rather than an authentication object. An explicit policy
 * is required because an authentication object's policy cannot be changed
 * after creation.
 *
 * The function is create-only. If authentication_object_id already exists it
 * returns kStatus_SSS_ResourceBusy without modifying the object.
 */
sss_status_t se05x_esp_create_aes_auth_object(
    se05x_esp_session_t *session, uint32_t authentication_object_id,
    const uint8_t authentication_key[SE05X_ESP_AES_AUTH_KEY_SIZE],
    uint16_t maximum_attempts, sss_policy_t *policies);

/** Close a session opened by se05x_esp_session_open. */
void se05x_esp_session_close(se05x_esp_session_t *session);

/** Read non-destructive identity/version data and exercise the hardware RNG. */
sss_status_t se05x_esp_get_info(se05x_esp_session_t *session,
                                se05x_esp_info_t *info);

#endif
