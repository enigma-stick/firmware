#include "se_worker.h"
#include "crypto.h"
#include "esp_log.h"
#include "freertos/idf_additions.h"
#include "fsl_sss_api.h"
#include "fsl_sss_se05x_apis.h"
#include "se05x_esp.h"
#include "se05x_esp_admin.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define KEYMGR_SE_WORKER_STACK_SIZE (16 * 1024) // 16 KB

static const char *TAG = "keymgr_se_worker";
static se_worker_context_t *ctx;

static esp_err_t se_worker_get_uid_impl(se_worker_context_t *ctx, uint8_t *uid,
                                        size_t *length) {
  bool opened_here = false;

  if (!ctx->session.is_open) {
    if (se05x_esp_session_open(&ctx->session) != kStatus_SSS_Success) {
      ESP_LOGE(TAG, "Could not open plain SE051 session for UID read");
      return ESP_FAIL;
    }
    opened_here = true;
  }

  se05x_esp_info_t info;
  sss_status_t status = se05x_esp_get_info(&ctx->session, &info);

  if (status == kStatus_SSS_Success) {
    if (*length < info.uid_length) {
      ESP_LOGE(TAG, "UID buffer too small: have=%u need=%u", (unsigned)*length,
               (unsigned)info.uid_length);
      status = kStatus_SSS_InvalidArgument;
    } else {
      memcpy(uid, info.uid, info.uid_length);
      *length = info.uid_length;
    }
  } else {
    ESP_LOGE(TAG, "Could not read SE051 identity: status=0x%08x",
             (unsigned)status);
  }

  if (opened_here) {
    se05x_esp_session_close(&ctx->session);
  }

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_provision_auth_object_impl(se_worker_context_t *ctx,
                                                      uint32_t object_id,
                                                      const uint8_t key[16]) {
  bool opened_here = false;

  if (!ctx->session.is_open) {
    if (se05x_esp_session_open(&ctx->session) != kStatus_SSS_Success) {
      ESP_LOGE(
          TAG,
          "Could not open plain session to provision auth object %08" PRIx32,
          object_id);
      return ESP_FAIL;
    }
    opened_here = true;
  }

  sss_policy_u delete_policy = {.type = KPolicy_Common,
                                .auth_obj_id = 0,
                                .policy.common = {.can_Delete = 1}};

  sss_policy_u self_write_policy = {.type = KPolicy_Common,
                                    .auth_obj_id = object_id,
                                    .policy.common = {.can_Write = 1}};

  sss_policy_t policies = {.policies = {&delete_policy, &self_write_policy},
                           .nPolicies = 2};

  sss_status_t status = se05x_esp_create_aes_auth_object(
      &ctx->session, object_id, key, 0, &policies);

  if (status == kStatus_SSS_Success) {
    ESP_LOGI(TAG, "Created AES auth object %08" PRIx32, object_id);
  } else if (status == kStatus_SSS_ResourceBusy) {
    ESP_LOGI(TAG,
             "AES auth object %08" PRIx32
             " already exists; verifying credential",
             object_id);
  }

  if (opened_here) {
    se05x_esp_session_close(&ctx->session);
  }

  if (status != kStatus_SSS_Success && status != kStatus_SSS_ResourceBusy) {
    ESP_LOGE(TAG,
             "Could not create AES auth object %08" PRIx32 ": status=0x%08x",
             object_id, (unsigned)status);
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Opening authenticated session with object %08" PRIx32,
           object_id);
  status = se05x_esp_session_open_aes_key(&ctx->session, object_id, key,
                                          SE05X_ESP_AES_AUTH_KEY_SIZE);

  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG,
             "Authentication with object %08" PRIx32 " failed: status=0x%08x",
             object_id, (unsigned)status);
    return ESP_FAIL;
  }

  ctx->session_state = SE_WORKER_SESSION_AUTHENTICATED;
  ctx->auth_object_id = object_id;
  ESP_LOGI(TAG, "Authenticated SE051 session opened");

  return ESP_OK;
}

static esp_err_t se_worker_provision_hmac_master_impl(se_worker_context_t *ctx,
                                                      uint32_t object_id) {
  sss_object_t hmac_master = {0};
  sss_object_t ec_key_a = {0};
  sss_object_t ec_key_b = {0};
  sss_derive_key_t derive_ctx = {0};

  bool ec_key_a_generated = false;
  bool ec_key_b_generated = false;
  bool derive_ctx_init = false;

  if (ctx->session_state != SE_WORKER_SESSION_AUTHENTICATED) {
    ESP_LOGE(TAG,
             "Cannot provision HMAC master without an authenticated session");
    return ESP_ERR_INVALID_STATE;
  }

  ESP_LOGI(TAG, "Provisioning HMAC master %08" PRIx32, object_id);

  // Initialize key store
  sss_status_t status = sss_key_store_context_init(
      &ctx->key_store, (sss_session_t *)&ctx->session.sss);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize SE051 key store: status=0x%08x",
             (unsigned)status);
    return ESP_FAIL;
  }

  status = sss_key_store_allocate(&ctx->key_store, 0);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not allocate SE051 key store: status=0x%08x",
             (unsigned)status);
    sss_key_store_context_free(&ctx->key_store);
    return ESP_FAIL;
  }

  ctx->key_store_initialized = true;

  // Allocate HMAC master handle

  status = sss_key_object_init(&hmac_master, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize HMAC master handle: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }

  // Check if the HMAC already exists; if it does we need to just return instead
  // of regenerating it.
  status = sss_key_object_get_handle(&hmac_master, object_id);
  if (status == kStatus_SSS_Success) {
    if (hmac_master.cipherType != kSSS_CipherType_HMAC) {
      ESP_LOGE(TAG,
               "Existing object %08" PRIx32
               " is not HMAC: cipher-type=0x%08" PRIx32,
               object_id, hmac_master.cipherType);
      sss_key_object_free(&hmac_master);
      return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "HMAC master %08" PRIx32 " already exists", object_id);
  } else {
    ESP_LOGI(TAG,
             "HMAC master %08" PRIx32 " not found; generating it internally",
             object_id);

    status = sss_key_object_allocate_handle(
        &hmac_master, object_id, kSSS_KeyPart_Default, kSSS_CipherType_HMAC, 32,
        kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
      ESP_LOGE(TAG,
               "Could not allocate HMAC master handle %08" PRIx32
               ": status=0x%08x",
               object_id, (unsigned)status);
      goto cleanup;
    }

    uint8_t placeholder[32] = {0};
    if (!km_crypto_rand(placeholder, sizeof(placeholder))) {
      ESP_LOGE(TAG, "Could not generate HMAC destination placeholder");
      status = kStatus_SSS_Fail;
      goto cleanup;
    }

    sss_policy_u rw_policy = {
        .type = KPolicy_Common,
        .auth_obj_id = ctx->auth_object_id,
        .policy.common = {.can_Write = 1, .can_Delete = 1}};

    sss_policy_u sym_policy = {
        .type = KPolicy_Sym_Key,
        .auth_obj_id = ctx->auth_object_id,
        .policy.symmkey = {.can_HKDF = 1, .forbid_Derived_Output = 1}};

    sss_policy_t policies = {.policies = {&rw_policy, &sym_policy},
                             .nPolicies = 2};
    status = sss_key_store_set_key(&ctx->key_store, &hmac_master, placeholder,
                                   sizeof(placeholder), 256, &policies,
                                   sizeof(policies));
    km_crypto_zero(placeholder, sizeof(placeholder));

    if (status != kStatus_SSS_Success) {
      ESP_LOGE(TAG,
               "Could not create HMAC master destination %08" PRIx32
               ": status=0x%08x",
               object_id, (unsigned)status);
      goto cleanup;
    }
  }

  // Generate EC part A

  status = sss_key_object_init(&ec_key_a, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG,
             "Could not initialize transient EC key A handle: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }

  status = sss_key_object_allocate_handle(
      &ec_key_a, KEYMGR_SE_ECDH_KEY_A_ID, kSSS_KeyPart_Pair,
      kSSS_CipherType_EC_NIST_P, 32, kKeyObject_Mode_Transient);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG,
             "Could not allocate transient EC key A %08" PRIx32
             ": status=0x%08x",
             KEYMGR_SE_ECDH_KEY_A_ID, (unsigned)status);
    goto cleanup;
  }

  ESP_LOGI(TAG, "Generating transient P-256 key A at %08" PRIx32,
           KEYMGR_SE_ECDH_KEY_A_ID);
  status = sss_key_store_generate_key(&ctx->key_store, &ec_key_a, 256, NULL);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not generate transient EC key A: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }

  ec_key_a_generated = true;

  // Generate EC part B

  status = sss_key_object_init(&ec_key_b, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG,
             "Could not initialize transient EC key B handle: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }

  status = sss_key_object_allocate_handle(
      &ec_key_b, KEYMGR_SE_ECDH_KEY_B_ID, kSSS_KeyPart_Pair,
      kSSS_CipherType_EC_NIST_P, 32, kKeyObject_Mode_Transient);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG,
             "Could not allocate transient EC key B %08" PRIx32
             ": status=0x%08x",
             KEYMGR_SE_ECDH_KEY_B_ID, (unsigned)status);
    goto cleanup;
  }

  ESP_LOGI(TAG, "Generating transient P-256 key B at %08" PRIx32,
           KEYMGR_SE_ECDH_KEY_B_ID);
  status = sss_key_store_generate_key(&ctx->key_store, &ec_key_b, 256, NULL);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not generate transient EC key B: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }

  ec_key_b_generated = true;

  // ECDH time!

  status = sss_derive_key_context_init(
      &derive_ctx, (sss_session_t *)&ctx->session.sss, &ec_key_a,
      kAlgorithm_SSS_ECDH, kMode_SSS_ComputeSharedSecret);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize ECDH context: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }
  derive_ctx_init = true;

  ESP_LOGI(TAG, "Deriving persistent HMAC master with internal ECDH");
  status = sss_derive_key_dh(&derive_ctx, &ec_key_b, &hmac_master);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Internal ECDH derivation failed: status=0x%08x",
             (unsigned)status);
    goto cleanup;
  }

  ESP_LOGI(TAG, "Persistent HMAC master %08" PRIx32 " created", object_id);

cleanup:
  if (derive_ctx_init) {
    sss_derive_key_context_free(&derive_ctx);
  }

  if (ec_key_a_generated) {
    // best effort erasure
    sss_status_t erase_status =
        sss_key_store_erase_key(&ctx->key_store, &ec_key_a);
    if (erase_status != kStatus_SSS_Success) {
      ESP_LOGW(TAG,
               "Could not erase transient EC key A %08" PRIx32
               ": status=0x%08x",
               KEYMGR_SE_ECDH_KEY_A_ID, (unsigned)erase_status);
    }
  }

  if (ec_key_b_generated) {
    // best effort erasure
    sss_status_t erase_status =
        sss_key_store_erase_key(&ctx->key_store, &ec_key_b);
    if (erase_status != kStatus_SSS_Success) {
      ESP_LOGW(TAG,
               "Could not erase transient EC key B %08" PRIx32
               ": status=0x%08x",
               KEYMGR_SE_ECDH_KEY_B_ID, (unsigned)erase_status);
    }
  }

  sss_key_object_free(&hmac_master);
  sss_key_object_free(&ec_key_a);
  sss_key_object_free(&ec_key_b);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_open_session_impl(se_worker_context_t *ctx,
                                             uint32_t auth_object_id,
                                             const uint8_t key[16]) {
  if (ctx->session_state != SE_WORKER_SESSION_CLOSED) {
    return ESP_ERR_INVALID_STATE;
  }

  ESP_LOGI(TAG, "Opening authenticated session with object %08" PRIx32,
           auth_object_id);
  sss_status_t status = se05x_esp_session_open_aes_key(
      &ctx->session, auth_object_id, key, SE05X_ESP_AES_AUTH_KEY_SIZE);

  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG,
             "Authentication with object %08" PRIx32 " failed: status=0x%08x",
             auth_object_id, (unsigned)status);
    return ESP_FAIL;
  }

  ctx->session_state = SE_WORKER_SESSION_AUTHENTICATED;
  ctx->auth_object_id = auth_object_id;
  ESP_LOGI(TAG, "Authenticated SE051 session opened");

  return ESP_OK;
}

static esp_err_t
se_worker_get_session_state_impl(se_worker_context_t *ctx,
                                 se_worker_session_state_t *state) {
  if (state == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *state = ctx->session_state;
  return ESP_OK;
}

static esp_err_t handle_request(se_worker_context_t *ctx,
                                se_request_t *request) {
  switch (request->type) {
  case SE_REQUEST_GET_UID:
    return se_worker_get_uid_impl(ctx, request->args.get_uid.buffer,
                                  request->args.get_uid.length);
  case SE_REQUEST_PROVISION_AUTH_OBJECT:
    return se_worker_provision_auth_object_impl(
        ctx, request->args.provision_auth_object.object_id,
        request->args.provision_auth_object.key);
  case SE_REQUEST_PROVISION_HMAC_MASTER:
    return se_worker_provision_hmac_master_impl(
        ctx, request->args.provision_hmac_master.object_id);
  case SE_REQUEST_OPEN_SESSION:
    return se_worker_open_session_impl(ctx,
                                       request->args.open_session.object_id,
                                       request->args.open_session.auth_key);
  case SE_REQUEST_GET_SESSION_STATE:
    return se_worker_get_session_state_impl(
        ctx, request->args.get_session_state.state);
  default:
    ESP_LOGE(TAG, "Unsupported SE worker request: %u", (unsigned)request->type);
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
    ESP_LOGE(TAG, "Could not allocate SE worker context");
    return ESP_ERR_NO_MEM;
  }

  ctx->queue = xQueueCreate(32, sizeof(se_request_t *));
  if (ctx->queue == NULL) {
    ESP_LOGE(TAG, "Could not allocate SE worker queue");
    free(ctx);
    return ESP_ERR_NO_MEM;
  }

  ctx->session_state = SE_WORKER_SESSION_CLOSED;

  if (xTaskCreate(se_worker_start_task, "se_worker_task",
                  KEYMGR_SE_WORKER_STACK_SIZE, NULL, 1, NULL) != pdPASS) {
    ESP_LOGE(TAG, "Could not start SE worker task");
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
    ESP_LOGE(TAG, "Could not enqueue UID request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_provision_auth_object(uint32_t object_id,
                                             const uint8_t key[16]) {
  se_request_t request = {
      .type = SE_REQUEST_PROVISION_AUTH_OBJECT,
      .args.provision_auth_object = {.object_id = object_id}};
  memcpy(request.args.provision_auth_object.key, key, 16);

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue auth-object provisioning request");
    km_crypto_zero(request.args.provision_auth_object.key, 16);
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);

  km_crypto_zero(request.args.provision_auth_object.key, 16);
  return request.result;
}

esp_err_t km_se_worker_provision_hmac_master(uint32_t object_id) {
  se_request_t request = {
      .type = SE_REQUEST_PROVISION_HMAC_MASTER,
      .args.provision_hmac_master = {.object_id = object_id}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue HMAC-master provisioning request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_open_session(uint32_t object_id, const uint8_t key[16]) {
  se_request_t request = {.type = SE_REQUEST_OPEN_SESSION,
                          .args.open_session = {.object_id = object_id}};
  memcpy(request.args.open_session.auth_key, key, 16);

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue open session request");
    km_crypto_zero(request.args.open_session.auth_key, 16);
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);

  km_crypto_zero(request.args.open_session.auth_key, 16);
  return request.result;
}

esp_err_t km_se_worker_get_session_state(se_worker_session_state_t *state) {
  se_request_t request = {.type = SE_REQUEST_GET_SESSION_STATE,
                          .args.get_session_state = {.state = state}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue get session state request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);

  return request.result;
}
