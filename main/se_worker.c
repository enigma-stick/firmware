#include "se_worker.h"
#include "freertos/idf_additions.h"
#include "fsl_sss_api.h"
#include "se05x_esp.h"
#include <stdlib.h>
#include <string.h>

#define KEYMGR_SE_WORKER_STACK_SIZE (16 * 1024) // 16 KB

static se_worker_context_t *ctx;

static esp_err_t se_worker_get_uid_impl(se_worker_context_t *ctx, uint8_t *uid,
                                        size_t *length) {
  bool opened_here = false;

  if (!ctx->session.is_open) {
    if (se05x_esp_session_open(&ctx->session) != kStatus_SSS_Success) {
      return ESP_FAIL;
    }
    opened_here = true;
  }

  se05x_esp_info_t info;
  sss_status_t status = se05x_esp_get_info(&ctx->session, &info);

  if (status == kStatus_SSS_Success) {
    if (*length < info.uid_length) {
      status = kStatus_SSS_InvalidArgument;
    } else {
      memcpy(uid, info.uid, info.uid_length);
      *length = info.uid_length;
    }
  }

  if (opened_here) {
    se05x_esp_session_close(&ctx->session);
  }

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t handle_request(se_worker_context_t *ctx,
                                se_request_t *request) {
  switch (request->type) {
  case SE_REQUEST_GET_UID:
    return se_worker_get_uid_impl(ctx, request->args.get_uid.buffer,
                                  request->args.get_uid.length);
  default:
    return ESP_ERR_NOT_SUPPORTED;
  }
}

void se_worker_start_task(void *_ctx) {
  for (;;) {
    se_request_t *request;

    if (xQueueReceive(ctx->queue, &request, portMAX_DELAY) == pdTRUE) {
      request->result = handle_request(ctx, request);
      xSemaphoreGive(request->completion);
    } else {
      // TODO: close_session
    }
  }
}

esp_err_t km_se_worker_start(void) {
  ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    return ESP_ERR_NO_MEM;
  }

  ctx->queue = xQueueCreate(32, sizeof(se_request_t *));
  if (ctx->queue == NULL) {
    free(ctx);
    return ESP_ERR_NO_MEM;
  }

  ctx->session_state = SE_WORKER_SESSION_CLOSED;

  if (xTaskCreate(se_worker_start_task, "se_worker_task",
                  KEYMGR_SE_WORKER_STACK_SIZE, NULL, 1, NULL) != pdPASS) {
    vQueueDelete(ctx->queue);
    free(ctx);
    ctx = NULL;
    return ESP_ERR_NO_MEM;
  }

  return ESP_OK;
}

esp_err_t km_se_worker_get_uid(uint8_t *uid, size_t *uid_len) {
  se_request_t request = {.type = SE_REQUEST_GET_UID,
                          .args.get_uid = {.buffer = uid, .length = uid_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}
