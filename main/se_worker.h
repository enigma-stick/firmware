#ifndef KEYMGR_SE_WORKER_H
#define KEYMGR_SE_WORKER_H

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "portmacro.h"
#include "se05x_esp.h"

#define KEYMGR_SE_ECDH_KEY_A_ID 0x4B4DFF33u
#define KEYMGR_SE_ECDH_KEY_B_ID 0x4B4DFF34u

typedef enum {
  SE_WORKER_SESSION_CLOSED,
  SE_WORKER_SESSION_AUTHENTICATED,
  SE_WORKER_SESSION_FAULT
} se_worker_session_state_t;

typedef enum {
  SE_REQUEST_GET_UID,
  SE_REQUEST_PROVISION_AUTH_OBJECT,
  SE_REQUEST_PROVISION_HMAC_MASTER,
} se_request_type_t;

typedef struct _request_t {
  se_request_type_t type;

  StaticSemaphore_t completion_storage;
  SemaphoreHandle_t completion;

  esp_err_t result;

  union {
    struct {
      uint8_t *buffer;
      size_t *length;
    } get_uid;

    struct {
      uint32_t object_id;
      uint8_t key[16];
    } provision_auth_object;

    struct {
      uint32_t object_id;
    } provision_hmac_master;
  } args;
} se_request_t;

typedef struct {
  QueueHandle_t queue;

  se05x_esp_session_t session;
  se_worker_session_state_t session_state;
  sss_key_store_t key_store;
  bool key_store_initialized;

  uint32_t auth_object_id;
  uint8_t auth_key[16];

  TickType_t last_activity;
} se_worker_context_t;

esp_err_t km_se_worker_start(void);
esp_err_t km_se_worker_get_uid(uint8_t *uid, size_t *length);
esp_err_t km_se_worker_provision_auth_object(uint32_t object_id,
                                             const uint8_t key[16]);
esp_err_t km_se_worker_provision_hmac_master(uint32_t object_id);

#endif // KEYMGR_SE_WORKER_H
