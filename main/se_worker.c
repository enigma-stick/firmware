#include "se_worker.h"
#include "crypto.h"
#include "esp_log.h"
#include "freertos/idf_additions.h"
#include "fsl_sss_api.h"
#include "fsl_sss_user_apis.h"
#include "key.h"
#include "memory.h"
#include "psa/crypto_types.h"
#include "se05x_esp.h"
#include "se05x_esp_admin.h"
#include "token.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define KEYMGR_SE_WORKER_STACK_SIZE (16 * 1024) // 16 KB
#define KEYMGR_SE_WORKER_TIMEOUT pdMS_TO_TICKS(10 * 60 * 1000)

#define KEYMGR_SE_APP_KEY_FIRST 0x4B4D1000u
#define KEYMGR_SE_APP_KEY_LAST 0x4B4DEFFFu

#define KM_AES_GCM_NONCE_LEN 12
#define KM_AES_GCM_TAG_LEN 16
#define KM_AES_GCM_OVERHEAD (KM_AES_GCM_NONCE_LEN + KM_AES_GCM_TAG_LEN)

static const char *TAG = "keymgr_se_worker";
static se_worker_context_t *ctx;

static esp_err_t se_worker_init_keystore(se_worker_context_t *ctx) {
  if (ctx->key_store_initialized == true) {
    return ESP_OK;
  }

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
  return ESP_OK;
}

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
  ctx->last_activity = xTaskGetTickCount();
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
  ctx->last_activity = xTaskGetTickCount();
  ESP_LOGI(TAG, "Authenticated SE051 session opened");

  return ESP_OK;
}

static esp_err_t se_worker_close_session_impl(se_worker_context_t *ctx) {
  if (ctx->key_store_initialized) {
    sss_key_store_context_free(&ctx->key_store);
    memset(&ctx->key_store, 0, sizeof(ctx->key_store));
    ctx->key_store_initialized = false;
  }

  if (ctx->session.is_open) {
    se05x_esp_session_close(&ctx->session);
  }

  ctx->session_state = SE_WORKER_SESSION_CLOSED;
  ctx->auth_object_id = 0;
  ctx->last_activity = 0;

  // I think this is unused and should probably stay that way. To be safe, we
  // clear it. Later on, we can remove this.
  km_crypto_zero(ctx->auth_key, sizeof(ctx->auth_key));

  ESP_LOGI(TAG, "SE051 session closed");
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

static esp_err_t se_worker_generate_aes_impl(se_worker_context_t *ctx,
                                             uint32_t hmac_id, uint16_t bits,
                                             uint32_t *key_id) {
  if (hmac_id == 0 || key_id == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *key_id = 0;
  sss_object_t master = {0};
  sss_object_t destination = {0};
  sss_derive_key_t derive = {0};
  size_t key_bytes = bits / 8;
  bool placeholder_created = false;
  bool master_initialized = false;
  bool destination_initialized = false;
  bool derive_initialized = false;

  if (bits != 128 && bits != 192 && bits != 256) {
    ESP_LOGE(TAG, "Invalid provided bits for AES key generation");
    return ESP_ERR_INVALID_ARG;
  }

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  // TODO: we need to move and improve this LOL
  uint32_t obj_id = KEYMGR_SE_APP_KEY_FIRST;
  bool exists = false;
  for (; obj_id <= KEYMGR_SE_APP_KEY_LAST; obj_id++) {
    se05x_esp_admin_status_t result =
        se05x_esp_admin_object_exists(&ctx->session, obj_id, &exists);

    if (result != SE05X_ESP_ADMIN_OK) {
      ESP_LOGE(TAG, "Could not determine if object exists during object scan");
      return ESP_FAIL;
    }

    if (!exists) {
      break;
    }
  }
  if (exists) {
    ESP_LOGE(TAG, "Could not find free object");
    return ESP_ERR_INVALID_STATE;
  }

  ESP_LOGI(TAG, "Destination key ID = %08" PRIx32, obj_id);

  sss_status_t status;

  status = sss_key_object_init(&master, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not init handle to HMAC master key");
    goto cleanup;
  }
  master_initialized = true;

  bool master_exists = false;
  se05x_esp_admin_status_t admin_status =
      se05x_esp_admin_object_exists(&ctx->session, hmac_id, &master_exists);

  if (admin_status != SE05X_ESP_ADMIN_OK || !master_exists) {
    ESP_LOGE(TAG, "HMAC master %08" PRIx32 " does not exist", hmac_id);
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_key_object_allocate_handle(
      &master, hmac_id, kSSS_KeyPart_Default, kSSS_CipherType_HMAC, 32,
      kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not configure HMAC master handle");
    goto cleanup;
  }

  status = sss_key_object_init(&destination, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not init handle to destination AES key");
    goto cleanup;
  }
  destination_initialized = true;

  status = sss_key_object_allocate_handle(
      &destination, obj_id, kSSS_KeyPart_Default, kSSS_CipherType_AES,
      key_bytes, kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not allocate handle to destination AES key");
    goto cleanup;
  }

  sss_policy_u common_policy = {
      .type = KPolicy_Common,
      .auth_obj_id = ctx->auth_object_id,
      .policy.common = {.can_Write = 1, .can_Delete = 1, .req_Sm = 1}};

  sss_policy_u aes_policy = {
      .type = KPolicy_Sym_Key,
      .auth_obj_id = ctx->auth_object_id,
      .policy.symmkey = {.can_Encrypt = 1, .can_Decrypt = 1}};

  sss_policy_t policies = {.policies = {&common_policy, &aes_policy},
                           .nPolicies = 2};

  uint8_t placeholder[32] = {0};
  if (!km_crypto_rand(placeholder, sizeof(placeholder))) {
    ESP_LOGE(TAG, "Could not generate HMAC destination placeholder");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_key_store_set_key(&ctx->key_store, &destination, placeholder,
                                 key_bytes, bits, &policies, sizeof(policies));
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not set destination key policies");
    goto cleanup;
  }
  placeholder_created = true;
  km_crypto_zero(placeholder, sizeof(placeholder));

  status = sss_derive_key_context_init(
      &derive, (sss_session_t *)&ctx->session.sss, &master,
      kAlgorithm_SSS_SHA256, kMode_SSS_HKDF_ExtractExpand);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize derivation context");
    goto cleanup;
  }
  derive_initialized = true;

  uint8_t salt[32] = {0};
  const char *info = "keymgr/aes/v1";
  if (!km_crypto_rand(salt, sizeof(salt))) {
    ESP_LOGE(TAG, "Could not generate HMAC destination placeholder");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_derive_key_one_go(&derive, salt, sizeof(salt), (uint8_t *)info,
                                 strlen(info), &destination, key_bytes);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not derive AES key from HMAC master");
    goto cleanup;
  }

cleanup:
  km_crypto_zero(placeholder, sizeof(placeholder));

  esp_err_t esp_status;
  if (status != kStatus_SSS_Success) {
    if (placeholder_created) {
      sss_key_store_erase_key(&ctx->key_store, &destination);
    }
    esp_status = ESP_FAIL;
  } else {
    *key_id = obj_id;
    esp_status = ESP_OK;
    ctx->last_activity = xTaskGetTickCount();
  }

  if (derive_initialized)
    sss_derive_key_context_free(&derive);
  if (destination_initialized)
    sss_key_object_free(&destination);
  if (master_initialized)
    sss_key_object_free(&master);

  return esp_status;
}

static esp_err_t se_worker_generate_rsa_impl(se_worker_context_t *ctx,
                                             uint16_t bits,
                                             km_key_usage_t usage,
                                             uint32_t *key_id) {
  if ((bits != 1024 && bits != 2048 && bits != 4096) || key_id == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *key_id = 0;

  sss_object_t rsa_key = {0};
  bool rsa_init = false;

  if (!ctx->key_store_initialized) {
    esp_err_t err = se_worker_init_keystore(ctx);
    if (err != ESP_OK) {
      return err;
    }
  }

  uint32_t obj_id = KEYMGR_SE_APP_KEY_FIRST;
  bool exists = false;
  for (; obj_id <= KEYMGR_SE_APP_KEY_LAST; obj_id++) {
    se05x_esp_admin_status_t result =
        se05x_esp_admin_object_exists(&ctx->session, obj_id, &exists);

    if (result != SE05X_ESP_ADMIN_OK) {
      ESP_LOGE(TAG, "Could not determine if object exists during object scan");
      return ESP_FAIL;
    }

    if (!exists) {
      break;
    }
  }
  if (exists) {
    ESP_LOGE(TAG, "Could not find free object");
    return ESP_ERR_INVALID_STATE;
  }

  ESP_LOGI(TAG, "Destination key ID = %08" PRIx32, obj_id);

  sss_status_t status = sss_key_object_init(&rsa_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize RSA key handle");
    goto cleanup;
  }
  rsa_init = true;

  status = sss_key_object_allocate_handle(&rsa_key, obj_id, kSSS_KeyPart_Pair,
                                          kSSS_CipherType_RSA, bits / 8,
                                          kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not allocate RSA key handle on secure element");
    goto cleanup;
  }

  sss_policy_u common_policy = {
      .type = KPolicy_Common,
      .auth_obj_id = ctx->auth_object_id,
      .policy.common = {
          .can_Write = 1, .can_Read = 1, .can_Delete = 1, .req_Sm = 1}};

  sss_policy_u rsa_policy = {
      .type = KPolicy_Asym_Key,
      .auth_obj_id = ctx->auth_object_id,
      .policy.asymmkey = {.can_Encrypt = usage == km_key_usage_encrypt ? 1 : 0,
                          .can_Decrypt = usage == km_key_usage_encrypt ? 1 : 0,
                          .can_Sign = usage == km_key_usage_sign ? 1 : 0,
                          .can_Verify = usage == km_key_usage_sign ? 1 : 0}};

  sss_policy_t policies = {.policies = {&common_policy, &rsa_policy},
                           .nPolicies = 2};

  status =
      sss_key_store_generate_key(&ctx->key_store, &rsa_key, bits, &policies);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not generate RSA keypair on secure element");
    goto cleanup;
  }

  *key_id = obj_id;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (rsa_init)
    sss_key_object_free(&rsa_key);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_generate_ec_impl(se_worker_context_t *ctx,
                                            uint16_t size, km_key_usage_t usage,
                                            uint32_t *key_id) {
  if ((size != 256 && size != 384 && size != 521) || key_id == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  sss_object_t ec_key = {0};
  bool ec_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize key store");
    return err;
  }

  uint32_t obj_id = KEYMGR_SE_APP_KEY_FIRST;
  bool exists = false;
  for (; obj_id <= KEYMGR_SE_APP_KEY_LAST; obj_id++) {
    se05x_esp_admin_status_t result =
        se05x_esp_admin_object_exists(&ctx->session, obj_id, &exists);

    if (result != SE05X_ESP_ADMIN_OK) {
      ESP_LOGE(TAG, "Could not determine if object exists during object scan");
      return ESP_FAIL;
    }

    if (!exists) {
      break;
    }
  }
  if (exists) {
    ESP_LOGE(TAG, "Could not find free object");
    return ESP_ERR_INVALID_STATE;
  }

  ESP_LOGI(TAG, "Destination key ID = %08" PRIx32, obj_id);

  sss_status_t status = sss_key_object_init(&ec_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize key handle");
    goto cleanup;
  }
  ec_init = true;

  status = sss_key_object_allocate_handle(
      &ec_key, obj_id, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P,
      (size + 7) / 8, kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to allocate key handle");
    goto cleanup;
  }

  sss_policy_u common_policy = {
      .type = KPolicy_Common,
      .auth_obj_id = ctx->auth_object_id,
      .policy.common = {
          .can_Write = 1, .can_Read = 1, .can_Delete = 1, .req_Sm = 1}};

  sss_policy_u ec_policy = {
      .type = KPolicy_Asym_Key,
      .auth_obj_id = ctx->auth_object_id,
      .policy.asymmkey = {.can_KA = usage == km_key_usage_derive ? 1 : 0,
                          .can_Sign = usage == km_key_usage_sign ? 1 : 0,
                          .can_Verify = usage == km_key_usage_sign ? 1 : 0}};

  sss_policy_t policies = {.policies = {&common_policy, &ec_policy},
                           .nPolicies = 2};

  status =
      sss_key_store_generate_key(&ctx->key_store, &ec_key, size, &policies);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to generate EC key");
    goto cleanup;
  }

  *key_id = obj_id;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (ec_init)
    sss_key_object_free(&ec_key);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_generate_hmac_impl(se_worker_context_t *ctx,
                                              uint32_t hmac_id, uint16_t size,
                                              km_key_usage_t usage,
                                              uint32_t *key_id) {
  if (hmac_id == 0 || (size != 256 && size != 512) || key_id == NULL ||
      usage != km_key_usage_sign) {
    return ESP_ERR_INVALID_ARG;
  }
  *key_id = 0;

  sss_object_t hmac_key = {0};
  sss_object_t master = {0};
  sss_derive_key_t derive = {0};
  bool hmac_init = false;
  bool master_init = false;
  bool derive_init = false;
  bool placeholder_created = false;
  size_t key_bytes = size / 8;
  uint8_t placeholder[64] = {0};
  uint8_t salt[32] = {0};
  const char *info = "keymgr/hmac/v1";

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize key store");
    return err;
  }

  uint32_t obj_id = KEYMGR_SE_APP_KEY_FIRST;
  bool exists = false;
  for (; obj_id <= KEYMGR_SE_APP_KEY_LAST; obj_id++) {
    se05x_esp_admin_status_t result =
        se05x_esp_admin_object_exists(&ctx->session, obj_id, &exists);

    if (result != SE05X_ESP_ADMIN_OK) {
      ESP_LOGE(TAG, "Could not determine if object exists during object scan");
      return ESP_FAIL;
    }

    if (!exists) {
      break;
    }
  }
  if (exists) {
    ESP_LOGE(TAG, "Could not find free object");
    return ESP_ERR_INVALID_STATE;
  }

  ESP_LOGI(TAG, "Destination key ID = %08" PRIx32, obj_id);

  sss_status_t status = sss_key_object_init(&master, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize HMAC master handle");
    goto cleanup;
  }
  master_init = true;

  bool master_exists = false;
  se05x_esp_admin_status_t admin_status =
      se05x_esp_admin_object_exists(&ctx->session, hmac_id, &master_exists);
  if (admin_status != SE05X_ESP_ADMIN_OK || !master_exists) {
    ESP_LOGE(TAG, "Could not find HMAC master %08" PRIx32, hmac_id);
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_key_object_allocate_handle(
      &master, hmac_id, kSSS_KeyPart_Default, kSSS_CipherType_HMAC, 32,
      kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not configure HMAC master handle");
    goto cleanup;
  }

  status = sss_key_object_init(&hmac_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize key handle");
    goto cleanup;
  }
  hmac_init = true;

  status = sss_key_object_allocate_handle(
      &hmac_key, obj_id, kSSS_KeyPart_Default, kSSS_CipherType_HMAC, size / 8,
      kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not allocate handle");
    goto cleanup;
  }

  sss_policy_u common_policy = {
      .type = KPolicy_Common,
      .auth_obj_id = ctx->auth_object_id,
      .policy.common = {.can_Write = 1, .can_Delete = 1, .req_Sm = 1}};

  sss_policy_u hmac_policy = {
      .type = KPolicy_Sym_Key,
      .auth_obj_id = ctx->auth_object_id,
      .policy.symmkey = {.can_Sign = usage == km_key_usage_sign ? 1 : 0,
                         .can_Verify = usage == km_key_usage_sign ? 1 : 0}};

  sss_policy_t policies = {.policies = {&common_policy, &hmac_policy},
                           .nPolicies = 2};

  if (!km_crypto_rand(placeholder, key_bytes)) {
    ESP_LOGE(TAG, "Could not generate HMAC destination placeholder");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_key_store_set_key(&ctx->key_store, &hmac_key, placeholder,
                                 key_bytes, size, &policies, sizeof(policies));
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not create HMAC destination");
    goto cleanup;
  }
  placeholder_created = true;
  km_crypto_zero(placeholder, sizeof(placeholder));

  status = sss_derive_key_context_init(
      &derive, (sss_session_t *)&ctx->session.sss, &master,
      kAlgorithm_SSS_SHA256, kMode_SSS_HKDF_ExtractExpand);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize HMAC derivation context");
    goto cleanup;
  }
  derive_init = true;

  if (!km_crypto_rand(salt, sizeof(salt))) {
    ESP_LOGE(TAG, "Could not generate HMAC derivation salt");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_derive_key_one_go(&derive, salt, sizeof(salt), (uint8_t *)info,
                                 strlen(info), &hmac_key, key_bytes);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not derive HMAC key from HMAC master");
    goto cleanup;
  }

  *key_id = obj_id;
  ctx->last_activity = xTaskGetTickCount();
  ESP_LOGI(TAG, "Derived HMAC key %08" PRIx32 " (%u bits)", obj_id,
           (unsigned)size);

cleanup:
  km_crypto_zero(placeholder, sizeof(placeholder));
  if (status != kStatus_SSS_Success && placeholder_created) {
    if (sss_key_store_erase_key(&ctx->key_store, &hmac_key) !=
        kStatus_SSS_Success)
      ESP_LOGE(TAG, "Could not clean up HMAC destination %08" PRIx32, obj_id);
  }
  if (derive_init)
    sss_derive_key_context_free(&derive);
  if (hmac_init)
    sss_key_object_free(&hmac_key);
  if (master_init)
    sss_key_object_free(&master);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t
se_worker_encrypt_aes_gcm_impl(se_worker_context_t *ctx, km_memory_pool_t *pool,
                               km_key_metadata_t *key, uint8_t *plaintext,
                               size_t plaintext_len, uint8_t **ciphertext,
                               size_t *ciphertext_len) {
  if (pool == NULL || key == NULL || key->id == 0 || plaintext == NULL ||
      plaintext_len == 0 || ciphertext == NULL || ciphertext_len == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *ciphertext = NULL;
  *ciphertext_len = 0;

  sss_object_t encryption_key = {0};
  sss_aead_t aead_ctx = {0};
  bool encryption_key_init = false;
  bool symmetric_init = false;

  size_t blob_len = KM_AES_GCM_NONCE_LEN + plaintext_len + KM_AES_GCM_TAG_LEN;
  uint8_t *blob = km_memory_alloc(pool, blob_len);
  uint8_t *nonce = blob;
  uint8_t *encrypted = blob + KM_AES_GCM_NONCE_LEN;
  uint8_t *tag = encrypted + plaintext_len;
  size_t tag_len = KM_AES_GCM_TAG_LEN;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&encryption_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize encryption key handle");
    goto cleanup;
  }
  encryption_key_init = true;

  bool encryption_key_exists = false;
  se05x_esp_admin_status_t admin_status = se05x_esp_admin_object_exists(
      &ctx->session, key->id, &encryption_key_exists);

  if (admin_status != SE05X_ESP_ADMIN_OK || !encryption_key_exists) {
    ESP_LOGE(TAG, "Encryption key %08" PRIx32 " does not exist", key->id);
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_key_object_allocate_handle(
      &encryption_key, key->id, kSSS_KeyPart_Default, kSSS_CipherType_AES,
      key->size / 8, kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to allocate encryption key handle");
    goto cleanup;
  }

  status = sss_aead_context_init(&aead_ctx, (sss_session_t *)&ctx->session.sss,
                                 &encryption_key, kAlgorithm_SSS_AES_GCM_INT_IV,
                                 kMode_SSS_Encrypt);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize AEAD context");
    goto cleanup;
  }
  symmetric_init = true;

  memset(nonce, 0, KM_AES_GCM_NONCE_LEN);

  status = sss_aead_one_go(&aead_ctx, plaintext, encrypted, plaintext_len,
                           nonce, KM_AES_GCM_NONCE_LEN, NULL, 0, tag, &tag_len);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not perform AES-GCM encryption");
    goto cleanup;
  }

  if (tag_len != KM_AES_GCM_TAG_LEN) {
    ESP_LOGE(TAG, "Unexpected AES-GCM tag length: %zu", tag_len);
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  *ciphertext = blob;
  *ciphertext_len = blob_len;

  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (symmetric_init)
    sss_aead_context_free(&aead_ctx);
  if (encryption_key_init)
    sss_key_object_free(&encryption_key);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t
se_worker_decrypt_aes_gcm_impl(se_worker_context_t *ctx, km_memory_pool_t *pool,
                               km_key_metadata_t *key, uint8_t *ciphertext,
                               size_t ciphertext_len, uint8_t **plaintext,
                               size_t *plaintext_len) {
  if (pool == NULL || key == NULL || key->id == 0 || plaintext == NULL ||
      plaintext_len == NULL || ciphertext == NULL || ciphertext_len == 0 ||
      ciphertext_len <= KM_AES_GCM_OVERHEAD) {
    return ESP_ERR_INVALID_ARG;
  }

  *plaintext = NULL;
  *plaintext_len = 0;

  sss_object_t decryption_key = {0};
  sss_aead_t aead_ctx = {0};
  bool decryption_key_init = false;
  bool symmetric_init = false;

  size_t encrypted_len = ciphertext_len - KM_AES_GCM_OVERHEAD;
  uint8_t *nonce = ciphertext;
  uint8_t *encrypted = ciphertext + KM_AES_GCM_NONCE_LEN;
  uint8_t *tag = ciphertext + ciphertext_len - KM_AES_GCM_TAG_LEN;
  uint8_t *out = km_memory_alloc(pool, encrypted_len);
  size_t tag_len = KM_AES_GCM_TAG_LEN;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&decryption_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize decryption key handle");
    goto cleanup;
  }
  decryption_key_init = true;

  bool decryption_key_exists = false;
  se05x_esp_admin_status_t admin_status = se05x_esp_admin_object_exists(
      &ctx->session, key->id, &decryption_key_exists);

  if (admin_status != SE05X_ESP_ADMIN_OK || !decryption_key_exists) {
    ESP_LOGE(TAG, "Decryption key %08" PRIx32 " does not exist", key->id);
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_key_object_allocate_handle(
      &decryption_key, key->id, kSSS_KeyPart_Default, kSSS_CipherType_AES,
      key->size / 8, kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to allocate decryption key handle");
    goto cleanup;
  }

  status = sss_aead_context_init(&aead_ctx, (sss_session_t *)&ctx->session.sss,
                                 &decryption_key, kAlgorithm_SSS_AES_GCM,
                                 kMode_SSS_Decrypt);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize AEAD context");
    goto cleanup;
  }
  symmetric_init = true;

  status = sss_aead_one_go(&aead_ctx, encrypted, out, encrypted_len, nonce,
                           KM_AES_GCM_NONCE_LEN, NULL, 0, tag, &tag_len);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not perform AES-GCM decryption");
    goto cleanup;
  }

  if (tag_len != KM_AES_GCM_TAG_LEN) {
    ESP_LOGE(TAG, "Unexpected AES-GCM tag length: %zu", tag_len);
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  *plaintext = out;
  *plaintext_len = encrypted_len;

  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (symmetric_init)
    sss_aead_context_free(&aead_ctx);
  if (decryption_key_init)
    sss_key_object_free(&decryption_key);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t
se_worker_decrypt_rsa_oaep_impl(se_worker_context_t *ctx,
                                km_memory_pool_t *pool, km_key_metadata_t *key,
                                uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t **plaintext, size_t *plaintext_len) {
  if (pool == NULL || key == NULL || key->id == 0 || plaintext == NULL ||
      plaintext_len == NULL || ciphertext == NULL || ciphertext_len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  *plaintext = NULL;
  *plaintext_len = 0;

  sss_object_t decryption_key = {0};
  sss_asymmetric_t asym_ctx = {0};
  bool decryption_key_init = false;
  bool asymmetric_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&decryption_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize key handle");
    goto cleanup;
  }
  decryption_key_init = true;

  status = sss_key_object_get_handle(&decryption_key, key->id);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not get key handle from secure element");
    goto cleanup;
  }

  status = sss_asymmetric_context_init(
      &asym_ctx, (sss_session_t *)&ctx->session.sss, &decryption_key,
      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA1, kMode_SSS_Decrypt);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize asymmetric context");
    goto cleanup;
  }
  asymmetric_init = true;

  size_t alloc = (key->size / 8);
  uint8_t *out = km_memory_alloc(pool, alloc);
  if (out == NULL) {
    status = kStatus_SSS_Fail;
    ESP_LOGE(TAG, "Could not allocate plaintext output");
    goto cleanup;
  }
  size_t out_len = alloc;
  status = sss_asymmetric_decrypt(&asym_ctx, ciphertext, ciphertext_len, out,
                                  &out_len);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not perform RSA OAEP decryption");
    goto cleanup;
  }

  *plaintext = out;
  *plaintext_len = out_len;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (decryption_key_init)
    sss_key_object_free(&decryption_key);
  if (asymmetric_init)
    sss_asymmetric_context_free(&asym_ctx);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t
se_worker_sign_rsa_pss_impl(se_worker_context_t *ctx, km_memory_pool_t *pool,
                            km_key_metadata_t *key, uint8_t *message,
                            size_t message_len, uint8_t **signature,
                            size_t *signature_len) {
  if (key == NULL || signature == NULL || signature_len == NULL ||
      message == NULL || message_len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  *signature = NULL;
  *signature_len = 0;

  sss_object_t rsa_key = {0};
  sss_asymmetric_t sign_ctx = {0};
  bool rsa_init = false;
  bool ctx_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&rsa_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize signing key handle");
    goto cleanup;
  }
  rsa_init = true;

  status = sss_key_object_allocate_handle(&rsa_key, key->id, kSSS_KeyPart_Pair,
                                          kSSS_CipherType_RSA, key->size / 8,
                                          kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to allocate signing key handle");
    goto cleanup;
  }

  status = sss_asymmetric_context_init(
      &sign_ctx, (sss_session_t *)&ctx->session.sss, &rsa_key,
      kAlgorithm_SSS_RSASSA_PKCS1_PSS_MGF1_SHA256, kMode_SSS_Sign);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize signing context");
    goto cleanup;
  }
  ctx_init = true;

  size_t capacity = key->size / 8;
  uint8_t *out = km_memory_alloc(pool, capacity);
  if (out == NULL) {
    ESP_LOGE(TAG, "Could not allocate RSA signature buffer");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  size_t written = capacity;
  status =
      se05x_esp_asymmetric_sign(&sign_ctx, message, message_len, out, &written);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to create RSA-PSS signature");
    goto cleanup;
  }

  *signature = out;
  *signature_len = written;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (ctx_init)
    sss_asymmetric_context_free(&sign_ctx);
  if (rsa_init)
    sss_key_object_free(&rsa_key);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t
se_worker_sign_ec_ecdsa_impl(se_worker_context_t *ctx, km_memory_pool_t *pool,
                             km_key_metadata_t *key, uint8_t *message,
                             size_t message_len, uint8_t **signature,
                             size_t *signature_len) {
  if (key == NULL || signature == NULL || signature_len == NULL ||
      message == NULL || message_len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  *signature = NULL;
  *signature_len = 0;

  sss_object_t ec_key = {0};
  sss_asymmetric_t sign_ctx = {0};
  bool ec_init = false;
  bool ctx_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&ec_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize signing key handle");
    goto cleanup;
  }
  ec_init = true;

  status = sss_key_object_get_handle(&ec_key, key->id);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to get signing key handle");
    goto cleanup;
  }

  sss_algorithm_t se_alg;
  psa_algorithm_t psa_alg;

  switch (key->size) {
  case 256:
    se_alg = kAlgorithm_SSS_ECDSA_SHA256;
    psa_alg = PSA_ALG_SHA_256;
    break;
  case 384:
    se_alg = kAlgorithm_SSS_ECDSA_SHA384;
    psa_alg = PSA_ALG_SHA_384;
    break;
  case 521:
    se_alg = kAlgorithm_SSS_ECDSA_SHA512;
    psa_alg = PSA_ALG_SHA_512;
    break;
  default:
    status = kStatus_SSS_Fail;
    ESP_LOGE(TAG, "Invalid key size");
    goto cleanup;
  }

  uint8_t digest[64];
  size_t digest_len = 0;

  psa_status_t psa_status = psa_hash_compute(
      psa_alg, message, message_len, digest, sizeof(digest), &digest_len);
  if (psa_status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "Could not perform hash on host");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status =
      sss_asymmetric_context_init(&sign_ctx, (sss_session_t *)&ctx->session.sss,
                                  &ec_key, se_alg, kMode_SSS_Sign);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to initialize signing context");
    goto cleanup;
  }
  ctx_init = true;

  size_t capacity = 144;
  uint8_t *out = km_memory_alloc(pool, capacity);
  if (out == NULL) {
    ESP_LOGE(TAG, "Could not allocate EC signature buffer");
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  size_t written = capacity;
  status =
      sss_asymmetric_sign_digest(&sign_ctx, digest, digest_len, out, &written);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Failed to create ECDSA signature");
    goto cleanup;
  }

  *signature = out;
  *signature_len = written;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (ctx_init)
    sss_asymmetric_context_free(&sign_ctx);
  if (ec_init)
    sss_key_object_free(&ec_key);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_sign_hmac_impl(se_worker_context_t *ctx,
                                          km_memory_pool_t *pool,
                                          km_key_metadata_t *key,
                                          uint8_t *message, size_t message_len,
                                          uint8_t **mac, size_t *mac_len) {
  if (pool == NULL || key == NULL || message == NULL || mac == NULL ||
      mac_len == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *mac = NULL;
  *mac_len = 0;

  sss_object_t hmac_key = {0};
  sss_mac_t mac_ctx = {0};
  bool hmac_init = false;
  bool mac_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&hmac_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize key handle");
    goto cleanup;
  }
  hmac_init = true;

  status = sss_key_object_get_handle(&hmac_key, key->id);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not retrieve key handle");
    goto cleanup;
  }

  sss_algorithm_t alg;
  switch (key->size) {
  case 256:
    alg = kAlgorithm_SSS_HMAC_SHA256;
    break;
  case 512:
    alg = kAlgorithm_SSS_HMAC_SHA512;
    break;
  default:
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_mac_context_init(&mac_ctx, (sss_session_t *)&ctx->session.sss,
                                &hmac_key, alg, kMode_SSS_Mac);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize MAC context");
    goto cleanup;
  }
  mac_init = true;

  size_t capacity = key->size / 8;
  uint8_t *out = km_memory_alloc(pool, capacity);
  if (out == NULL) {
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  size_t out_len = capacity;
  status = sss_mac_one_go(&mac_ctx, message, message_len, out, &out_len);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not perform HMAC signature");
    goto cleanup;
  }

  *mac = out;
  *mac_len = out_len;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (hmac_init)
    sss_key_object_free(&hmac_key);
  if (mac_init)
    sss_mac_context_free(&mac_ctx);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_verify_hmac_impl(se_worker_context_t *ctx,
                                            km_memory_pool_t *pool,
                                            km_key_metadata_t *key,
                                            uint8_t *message,
                                            size_t message_len, uint8_t *mac,
                                            size_t mac_len, bool *verified) {
  if (pool == NULL || key == NULL || message == NULL || mac == NULL ||
      verified == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *verified = false;

  sss_object_t hmac_key = {0};
  sss_mac_t mac_ctx = {0};
  bool hmac_init = false;
  bool mac_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    return err;
  }

  sss_status_t status = sss_key_object_init(&hmac_key, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize key handle");
    goto cleanup;
  }
  hmac_init = true;

  status = sss_key_object_get_handle(&hmac_key, key->id);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not retrieve key handle");
    goto cleanup;
  }

  sss_algorithm_t alg;
  switch (key->size) {
  case 256:
    alg = kAlgorithm_SSS_HMAC_SHA256;
    break;
  case 512:
    alg = kAlgorithm_SSS_HMAC_SHA512;
    break;
  default:
    status = kStatus_SSS_Fail;
    goto cleanup;
  }

  status = sss_mac_context_init(&mac_ctx, (sss_session_t *)&ctx->session.sss,
                                &hmac_key, alg, kMode_SSS_Mac_Validate);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize MAC context");
    goto cleanup;
  }
  mac_init = true;

  status = sss_mac_one_go(&mac_ctx, message, message_len, mac, &mac_len);

  *verified = status == kStatus_SSS_Success;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (hmac_init)
    sss_key_object_free(&hmac_key);
  if (mac_init)
    sss_mac_context_free(&mac_ctx);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_get_public_key_rsa_impl(se_worker_context_t *ctx,
                                                   km_memory_pool_t *pool,
                                                   km_key_metadata_t *key,
                                                   uint8_t **public_key,
                                                   size_t *public_key_len) {
  if (key == NULL || public_key == NULL || public_key_len == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *public_key = NULL;
  *public_key_len = 0;

  sss_object_t keypair = {0};
  bool keypair_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize key store");
    return err;
  }

  sss_status_t status = sss_key_object_init(&keypair, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize keypair handle");
    goto cleanup;
  }
  keypair_init = true;

  status = sss_key_object_allocate_handle(&keypair, key->id, kSSS_KeyPart_Pair,
                                          kSSS_CipherType_RSA, key->size / 8,
                                          kKeyObject_Mode_Persistent);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not allocate keypair handle");
    goto cleanup;
  }

  size_t capacity = (key->size / 8) + 64;
  uint8_t *der = km_memory_alloc(pool, capacity);
  size_t der_len = capacity;
  size_t ignored_key_bits = 0;

  status = sss_key_store_get_key(&ctx->key_store, &keypair, der, &der_len,
                                 &ignored_key_bits);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not retrieve public key material");
    goto cleanup;
  }

  *public_key = der;
  *public_key_len = der_len;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (keypair_init)
    sss_key_object_free(&keypair);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_get_public_key_ec_impl(se_worker_context_t *ctx,
                                                  km_memory_pool_t *pool,
                                                  km_key_metadata_t *key,
                                                  uint8_t **public_key,
                                                  size_t *public_key_len) {
  if (key == NULL || public_key == NULL || public_key_len == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *public_key = NULL;
  *public_key_len = 0;

  sss_object_t keypair = {0};
  bool keypair_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize key store");
    return err;
  }

  sss_status_t status = sss_key_object_init(&keypair, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize keypair handle");
    goto cleanup;
  }
  keypair_init = true;

  status = sss_key_object_get_handle(&keypair, key->id);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not get keypair handle");
    goto cleanup;
  }

  size_t capacity = 256;
  uint8_t *der = km_memory_alloc(pool, capacity);
  size_t der_len = capacity;
  size_t ignored_key_bits = 0;

  status = sss_key_store_get_key(&ctx->key_store, &keypair, der, &der_len,
                                 &ignored_key_bits);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not retrieve public key material");
    goto cleanup;
  }

  *public_key = der;
  *public_key_len = der_len;
  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (keypair_init)
    sss_key_object_free(&keypair);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static esp_err_t se_worker_destroy_key_impl(se_worker_context_t *ctx,
                                            uint32_t key_id) {
  if (key_id < KEYMGR_SE_APP_KEY_FIRST || key_id > KEYMGR_SE_APP_KEY_LAST) {
    return ESP_ERR_INVALID_ARG;
  }

  sss_object_t object = {0};
  bool object_init = false;

  esp_err_t err = se_worker_init_keystore(ctx);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize key store");
    return err;
  }

  bool exists = false;
  se05x_esp_admin_status_t result =
      se05x_esp_admin_object_exists(&ctx->session, key_id, &exists);
  if (result != SE05X_ESP_ADMIN_OK) {
    ESP_LOGE(TAG, "Could not determine if key exists in SE");
    return ESP_FAIL;
  }
  if (!exists) {
    ESP_LOGI(TAG, "Key does not exist in SE");
    return ESP_OK;
  }

  sss_status_t status = sss_key_object_init(&object, &ctx->key_store);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not initialize key handle");
    goto cleanup;
  }
  object_init = true;

  status = sss_key_object_get_handle(&object, key_id);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not get key handle");
    goto cleanup;
  }

  status = sss_key_store_erase_key(&ctx->key_store, &object);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "Could not erase key handle");
    goto cleanup;
  }

  ctx->last_activity = xTaskGetTickCount();

cleanup:
  if (object_init)
    sss_key_object_free(&object);

  return status == kStatus_SSS_Success ? ESP_OK : ESP_FAIL;
}

static bool se_request_requires_auth(se_request_type_t type) {
  switch (type) {
  case SE_REQUEST_PROVISION_HMAC_MASTER:
  case SE_REQUEST_GENERATE_AES:
  case SE_REQUEST_GENERATE_RSA:
  case SE_REQUEST_GENERATE_EC:
  case SE_REQUEST_GENERATE_HMAC:
  case SE_REQUEST_ENCRYPT_AES_GCM:
  case SE_REQUEST_DECRYPT_AES_GCM:
  case SE_REQUEST_DECRYPT_RSA_OAEP:
  case SE_REQUEST_SIGN_RSA_PSS:
  case SE_REQUEST_SIGN_EC_ECDSA:
  case SE_REQUEST_SIGN_HMAC:
  case SE_REQUEST_VERIFY_HMAC:
  case SE_REQUEST_GET_PUBLIC_KEY_RSA:
  case SE_REQUEST_GET_PUBLIC_KEY_EC:
  case SE_REQUEST_DESTROY_KEY:
    return true;
  default:
    return false;
  }
}

static esp_err_t handle_request(se_worker_context_t *ctx,
                                se_request_t *request) {
  if (se_request_requires_auth(request->type) &&
      ctx->session_state != SE_WORKER_SESSION_AUTHENTICATED) {
    return KM_ERR_AUTH_REQUIRED;
  }

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
  case SE_REQUEST_CLOSE_SESSION:
    return se_worker_close_session_impl(ctx);
  case SE_REQUEST_GET_SESSION_STATE:
    return se_worker_get_session_state_impl(
        ctx, request->args.get_session_state.state);
  case SE_REQUEST_GENERATE_AES:
    return se_worker_generate_aes_impl(ctx, request->args.generate_aes.hmac_id,
                                       request->args.generate_aes.bits,
                                       request->args.generate_aes.key_id);
  case SE_REQUEST_GENERATE_RSA:
    return se_worker_generate_rsa_impl(ctx, request->args.generate_rsa.bits,
                                       request->args.generate_rsa.usage,
                                       request->args.generate_rsa.key_id);
  case SE_REQUEST_GENERATE_EC:
    return se_worker_generate_ec_impl(ctx, request->args.generate_ec.size,
                                      request->args.generate_ec.usage,
                                      request->args.generate_ec.key_id);
  case SE_REQUEST_GENERATE_HMAC:
    return se_worker_generate_hmac_impl(
        ctx, request->args.generate_hmac.hmac_id,
        request->args.generate_hmac.size, request->args.generate_hmac.usage,
        request->args.generate_hmac.key_id);
  case SE_REQUEST_ENCRYPT_AES_GCM:
    return se_worker_encrypt_aes_gcm_impl(
        ctx, request->args.encrypt_aes_gcm.pool,
        request->args.encrypt_aes_gcm.key,
        request->args.encrypt_aes_gcm.plaintext,
        request->args.encrypt_aes_gcm.plaintext_len,
        request->args.encrypt_aes_gcm.ciphertext,
        request->args.encrypt_aes_gcm.ciphertext_len);
  case SE_REQUEST_DECRYPT_AES_GCM:
    return se_worker_decrypt_aes_gcm_impl(
        ctx, request->args.decrypt.pool, request->args.decrypt.key,
        request->args.decrypt.ciphertext, request->args.decrypt.ciphertext_len,
        request->args.decrypt.plaintext, request->args.decrypt.plaintext_len);
  case SE_REQUEST_DECRYPT_RSA_OAEP:
    return se_worker_decrypt_rsa_oaep_impl(
        ctx, request->args.decrypt.pool, request->args.decrypt.key,
        request->args.decrypt.ciphertext, request->args.decrypt.ciphertext_len,
        request->args.decrypt.plaintext, request->args.decrypt.plaintext_len);
  case SE_REQUEST_SIGN_RSA_PSS:
    return se_worker_sign_rsa_pss_impl(
        ctx, request->args.sign.pool, request->args.sign.key,
        request->args.sign.message, request->args.sign.message_len,
        request->args.sign.signature, request->args.sign.signature_len);
  case SE_REQUEST_SIGN_EC_ECDSA:
    return se_worker_sign_ec_ecdsa_impl(
        ctx, request->args.sign.pool, request->args.sign.key,
        request->args.sign.message, request->args.sign.message_len,
        request->args.sign.signature, request->args.sign.signature_len);
  case SE_REQUEST_SIGN_HMAC:
    return se_worker_sign_hmac_impl(
        ctx, request->args.sign.pool, request->args.sign.key,
        request->args.sign.message, request->args.sign.message_len,
        request->args.sign.signature, request->args.sign.signature_len);
  case SE_REQUEST_VERIFY_HMAC:
    return se_worker_verify_hmac_impl(
        ctx, request->args.verify.pool, request->args.verify.key,
        request->args.verify.message, request->args.verify.message_len,
        request->args.verify.signature, request->args.verify.signature_len,
        request->args.verify.verified);
  case SE_REQUEST_GET_PUBLIC_KEY_RSA:
    return se_worker_get_public_key_rsa_impl(
        ctx, request->args.get_public_key.pool,
        request->args.get_public_key.key,
        request->args.get_public_key.public_key,
        request->args.get_public_key.public_key_len);
  case SE_REQUEST_GET_PUBLIC_KEY_EC:
    return se_worker_get_public_key_ec_impl(
        ctx, request->args.get_public_key.pool,
        request->args.get_public_key.key,
        request->args.get_public_key.public_key,
        request->args.get_public_key.public_key_len);
  case SE_REQUEST_DESTROY_KEY:
    return se_worker_destroy_key_impl(ctx, request->args.destroy_key.key_id);
  default:
    ESP_LOGE(TAG, "Unsupported SE worker request: %u", (unsigned)request->type);
    return ESP_ERR_NOT_SUPPORTED;
  }
}

void se_worker_start_task(void *_ctx) {
  for (;;) {
    se_request_t *request;
    TickType_t wait = portMAX_DELAY;

    if (ctx->session_state == SE_WORKER_SESSION_AUTHENTICATED) {
      TickType_t elapsed = xTaskGetTickCount() - ctx->last_activity;

      if (elapsed >= KEYMGR_SE_WORKER_TIMEOUT) {
        se_worker_close_session_impl(ctx);
      } else {
        wait = KEYMGR_SE_WORKER_TIMEOUT - elapsed;
      }
    }

    if (xQueueReceive(ctx->queue, &request, wait) == pdTRUE) {

      if (ctx->session_state == SE_WORKER_SESSION_AUTHENTICATED) {
        TickType_t elapsed = xTaskGetTickCount() - ctx->last_activity;

        if (elapsed >= KEYMGR_SE_WORKER_TIMEOUT) {
          se_worker_close_session_impl(ctx);
        }
      }

      request->result = handle_request(ctx, request);
      xSemaphoreGive(request->completion);
    } else {
      if (ctx->session_state == SE_WORKER_SESSION_AUTHENTICATED) {
        se_worker_close_session_impl(ctx);
      }
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

esp_err_t km_se_worker_close_session(void) {
  se_request_t request = {.type = SE_REQUEST_CLOSE_SESSION};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue close session request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
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

esp_err_t km_se_worker_generate_aes(uint32_t hmac_id, uint16_t bits,
                                    uint32_t *key_id) {
  se_request_t request = {.type = SE_REQUEST_GENERATE_AES,
                          .args.generate_aes = {.hmac_id = hmac_id,
                                                .bits = bits,
                                                .key_id = key_id}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue generate aes request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_generate_rsa(uint16_t bits, km_key_usage_t usage,
                                    uint32_t *key_id) {
  se_request_t request = {
      .type = SE_REQUEST_GENERATE_RSA,
      .args.generate_rsa = {.bits = bits, .usage = usage, .key_id = key_id}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue generate rsa request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_generate_ec(uint16_t size, km_key_usage_t usage,
                                   uint32_t *key_id) {
  se_request_t request = {
      .type = SE_REQUEST_GENERATE_EC,
      .args.generate_ec = {.size = size, .usage = usage, .key_id = key_id}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue generate ec request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_generate_hmac(uint32_t hmac_id, uint16_t size,
                                     km_key_usage_t usage, uint32_t *key_id) {
  se_request_t request = {
      .type = SE_REQUEST_GENERATE_HMAC,
      .args.generate_hmac = {
          .hmac_id = hmac_id, .size = size, .usage = usage, .key_id = key_id}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue generate hmac request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_encrypt_aes_gcm(km_memory_pool_t *pool,
                                       km_key_metadata_t *key,
                                       uint8_t *plaintext, size_t plaintext_len,
                                       uint8_t **ciphertext,
                                       size_t *ciphertext_len) {
  se_request_t request = {
      .type = SE_REQUEST_ENCRYPT_AES_GCM,
      .args.encrypt_aes_gcm = {.pool = pool,
                               .key = key,
                               .plaintext = plaintext,
                               .plaintext_len = plaintext_len,
                               .ciphertext = ciphertext,
                               .ciphertext_len = ciphertext_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue encrypt aes request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t
km_se_worker_decrypt_aes_gcm(km_memory_pool_t *pool, km_key_metadata_t *key,
                             uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t **plaintext, size_t *plaintext_len) {
  se_request_t request = {.type = SE_REQUEST_DECRYPT_AES_GCM,
                          .args.decrypt = {.pool = pool,
                                           .key = key,
                                           .ciphertext = ciphertext,
                                           .ciphertext_len = ciphertext_len,
                                           .plaintext = plaintext,
                                           .plaintext_len = plaintext_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue decrypt aes request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t
km_se_worker_decrypt_rsa_oaep(km_memory_pool_t *pool, km_key_metadata_t *key,
                              uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t **plaintext, size_t *plaintext_len) {
  se_request_t request = {.type = SE_REQUEST_DECRYPT_RSA_OAEP,
                          .args.decrypt = {.pool = pool,
                                           .key = key,
                                           .ciphertext = ciphertext,
                                           .ciphertext_len = ciphertext_len,
                                           .plaintext = plaintext,
                                           .plaintext_len = plaintext_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue decrypt rsa request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_sign_rsa_pss(km_memory_pool_t *pool,
                                    km_key_metadata_t *key, uint8_t *message,
                                    size_t message_len, uint8_t **signature,
                                    size_t *signature_len) {
  se_request_t request = {.type = SE_REQUEST_SIGN_RSA_PSS,
                          .args.sign = {.pool = pool,
                                        .key = key,
                                        .message = message,
                                        .message_len = message_len,
                                        .signature = signature,
                                        .signature_len = signature_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue sign rsa request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_sign_ec_ecdsa(km_memory_pool_t *pool,
                                     km_key_metadata_t *key, uint8_t *message,
                                     size_t message_len, uint8_t **signature,
                                     size_t *signature_len) {
  se_request_t request = {.type = SE_REQUEST_SIGN_EC_ECDSA,
                          .args.sign = {.pool = pool,
                                        .key = key,
                                        .message = message,
                                        .message_len = message_len,
                                        .signature = signature,
                                        .signature_len = signature_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue sign ec request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_sign_hmac(km_memory_pool_t *pool, km_key_metadata_t *key,
                                 uint8_t *message, size_t message_len,
                                 uint8_t **mac, size_t *mac_len) {
  se_request_t request = {.type = SE_REQUEST_SIGN_HMAC,
                          .args.sign = {.pool = pool,
                                        .key = key,
                                        .message = message,
                                        .message_len = message_len,
                                        .signature = mac,
                                        .signature_len = mac_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue sign hmac request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_verify_hmac(km_memory_pool_t *pool,
                                   km_key_metadata_t *key, uint8_t *message,
                                   size_t message_len, uint8_t *mac,
                                   size_t mac_len, bool *verified) {
  se_request_t request = {.type = SE_REQUEST_VERIFY_HMAC,
                          .args.verify = {.pool = pool,
                                          .key = key,
                                          .message = message,
                                          .message_len = message_len,
                                          .signature = mac,
                                          .signature_len = mac_len,
                                          .verified = verified}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue verify hmac request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_get_public_key_rsa(km_memory_pool_t *pool,
                                          km_key_metadata_t *key,
                                          uint8_t **public_key,
                                          size_t *public_key_len) {
  se_request_t request = {
      .type = SE_REQUEST_GET_PUBLIC_KEY_RSA,
      .args.get_public_key = {.pool = pool,
                              .key = key,
                              .public_key = public_key,
                              .public_key_len = public_key_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue get public key request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_get_public_key_ec(km_memory_pool_t *pool,
                                         km_key_metadata_t *key,
                                         uint8_t **public_key,
                                         size_t *public_key_len) {
  se_request_t request = {
      .type = SE_REQUEST_GET_PUBLIC_KEY_EC,
      .args.get_public_key = {.pool = pool,
                              .key = key,
                              .public_key = public_key,
                              .public_key_len = public_key_len}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue get public key request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}

esp_err_t km_se_worker_destroy_key(uint32_t key_id) {
  se_request_t request = {.type = SE_REQUEST_DESTROY_KEY,
                          .args.destroy_key = {.key_id = key_id}};

  request.completion =
      xSemaphoreCreateBinaryStatic(&request.completion_storage);

  se_request_t *request_ptr = &request;
  if (xQueueSend(ctx->queue, &request_ptr, portMAX_DELAY) != pdTRUE) {
    ESP_LOGE(TAG, "Could not enqueue destroy key request");
    return ESP_FAIL;
  }

  xSemaphoreTake(request.completion, portMAX_DELAY);
  return request.result;
}
