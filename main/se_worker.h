#ifndef KEYMGR_SE_WORKER_H
#define KEYMGR_SE_WORKER_H

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "portmacro.h"
#include "se05x_esp.h"

typedef enum {
  SE_WORKER_SESSION_CLOSED,
  SE_WORKER_SESSION_AUTHENTICATED,
  SE_WORKER_SESSION_FAULT
} se_worker_session_state_t;

typedef enum { SE_REQUEST_GET_UID } se_request_type_t;

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
  } args;
} se_request_t;

typedef struct {
  QueueHandle_t queue;

  se05x_esp_session_t session;
  se_worker_session_state_t session_state;

  uint32_t auth_object_id;
  uint8_t auth_key[16];

  TickType_t last_activity;
} se_worker_context_t;

esp_err_t km_se_worker_start(void);
esp_err_t km_se_worker_get_uid(uint8_t *uid, size_t *length);

#endif // KEYMGR_SE_WORKER_H
