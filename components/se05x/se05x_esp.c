#include "se05x_esp.h"

#include "fsl_sss_se05x_policy.h"
#include "fsl_sss_user_apis.h"
#include "mbedtls/platform_util.h"
#include "sdkconfig.h"
#include "se05x_APDU.h"
#include "sm_types.h"

#include <stdlib.h>
#include <string.h>

/*
 * Present in NXP's fsl_sss_se05x_apis.c, but omitted from the corresponding
 * public header in this middleware release.
 */
sss_status_t sss_se05x_asymmetric_sign(
    sss_se05x_asymmetric_t *context, const uint8_t *src_data,
    size_t src_length, uint8_t *signature, size_t *signature_length);

typedef struct {
  sss_session_t host_session;
  sss_key_store_t host_key_store;
  NXSCP03_StaticCtx_t static_context;
  NXSCP03_DynCtx_t dynamic_context;
  bool host_session_open;
  bool host_key_store_initialized;
} se05x_esp_authentication_state_t;

static void se05x_esp_free_host_object(sss_object_t *object) {
  sss_key_object_free(object);
}

static void se05x_esp_authentication_state_free(
    se05x_esp_authentication_state_t *state) {
  if (state == NULL) {
    return;
  }

  se05x_esp_free_host_object(&state->dynamic_context.Rmac);
  se05x_esp_free_host_object(&state->dynamic_context.Mac);
  se05x_esp_free_host_object(&state->dynamic_context.Enc);
  se05x_esp_free_host_object(&state->static_context.Dek);
  se05x_esp_free_host_object(&state->static_context.Mac);
  se05x_esp_free_host_object(&state->static_context.Enc);

  if (state->host_key_store_initialized) {
    sss_key_store_context_free(&state->host_key_store);
  }
  if (state->host_session_open) {
    sss_session_close(&state->host_session);
  }
  mbedtls_platform_zeroize(state, sizeof(*state));
  free(state);
}

static sss_status_t se05x_esp_allocate_host_key(
    se05x_esp_authentication_state_t *state, sss_object_t *object,
    uint32_t object_id, const uint8_t *key) {
  sss_status_t status =
      sss_key_object_init(object, &state->host_key_store);
  if (status != kStatus_SSS_Success) {
    return status;
  }

  status = sss_key_object_allocate_handle(
      object, object_id, kSSS_KeyPart_Default, kSSS_CipherType_AES,
      SE05X_ESP_AES_AUTH_KEY_SIZE, kKeyObject_Mode_Transient);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  if (key == NULL) {
    return kStatus_SSS_Success;
  }

  return sss_key_store_set_key(
      &state->host_key_store, object, key, SE05X_ESP_AES_AUTH_KEY_SIZE,
      SE05X_ESP_AES_AUTH_KEY_SIZE * 8u, NULL, 0);
}

static sss_status_t se05x_esp_prepare_aes_authentication(
    se05x_esp_session_t *session, const uint8_t *authentication_key) {
  static const uint32_t host_object_ids[] = {
      0x4B4D0101u, 0x4B4D0102u, 0x4B4D0103u,
      0x4B4D0104u, 0x4B4D0105u, 0x4B4D0106u,
  };

  se05x_esp_authentication_state_t *state = calloc(1, sizeof(*state));
  if (state == NULL) {
    return kStatus_SSS_Fail;
  }
  session->authentication_state = state;

  sss_status_t status = sss_session_open(
      &state->host_session, kType_SSS_Software, 0,
      kSSS_ConnectionType_Plain, NULL);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  state->host_session_open = true;

  status = sss_key_store_context_init(&state->host_key_store,
                                      &state->host_session);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  state->host_key_store_initialized = true;

  status =
      sss_key_store_allocate(&state->host_key_store, 0x4B4D0100u);
  if (status != kStatus_SSS_Success) {
    return status;
  }

  state->static_context.key_len = SE05X_ESP_AES_AUTH_KEY_SIZE;
  status = se05x_esp_allocate_host_key(state, &state->static_context.Enc,
                                       host_object_ids[0], authentication_key);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  status = se05x_esp_allocate_host_key(state, &state->static_context.Mac,
                                       host_object_ids[1], authentication_key);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  status = se05x_esp_allocate_host_key(state, &state->static_context.Dek,
                                       host_object_ids[2], authentication_key);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  status = se05x_esp_allocate_host_key(state, &state->dynamic_context.Enc,
                                       host_object_ids[3], NULL);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  status = se05x_esp_allocate_host_key(state, &state->dynamic_context.Mac,
                                       host_object_ids[4], NULL);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  status = se05x_esp_allocate_host_key(state, &state->dynamic_context.Rmac,
                                       host_object_ids[5], NULL);
  if (status != kStatus_SSS_Success) {
    return status;
  }

  session->connection.auth.ctx.scp03.pStatic_ctx = &state->static_context;
  session->connection.auth.ctx.scp03.pDyn_ctx = &state->dynamic_context;
  return kStatus_SSS_Success;
}

sss_status_t se05x_esp_session_open(se05x_esp_session_t *session) {
  if (session == NULL) {
    return kStatus_SSS_InvalidArgument;
  }

  memset(session, 0, sizeof(*session));
  session->connection.sizeOfStucture = sizeof(session->connection);
  session->connection.auth.authType = kSSS_AuthType_None;
  session->connection.connType = kType_SE_Conn_Type_T1oI2C;
  session->connection.i2cAddress = CONFIG_SE05X_I2C_ADDRESS;

  sss_status_t status = sss_se05x_session_open(
      &session->sss, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain,
      &session->connection);
  if (status == kStatus_SSS_Success) {
    session->is_open = true;
  }
  return status;
}

sss_status_t se05x_esp_session_open_aes_key(
    se05x_esp_session_t *session, uint32_t authentication_object_id,
    const uint8_t *authentication_key, size_t authentication_key_length) {
  if (session == NULL || authentication_object_id == 0 ||
      authentication_key == NULL ||
      authentication_key_length != SE05X_ESP_AES_AUTH_KEY_SIZE) {
    return kStatus_SSS_InvalidArgument;
  }

  memset(session, 0, sizeof(*session));
  session->connection.sizeOfStucture = sizeof(session->connection);
  session->connection.auth.authType = kSSS_AuthType_AESKey;
  session->connection.connType = kType_SE_Conn_Type_T1oI2C;
  session->connection.i2cAddress = CONFIG_SE05X_I2C_ADDRESS;

  sss_status_t status =
      se05x_esp_prepare_aes_authentication(session, authentication_key);
  if (status != kStatus_SSS_Success) {
    se05x_esp_authentication_state_free(session->authentication_state);
    session->authentication_state = NULL;
    return status;
  }

  status = sss_se05x_session_open(
      &session->sss, kType_SSS_SE_SE05x, authentication_object_id,
      kSSS_ConnectionType_Encrypted, &session->connection);
  if (status != kStatus_SSS_Success) {
    se05x_esp_authentication_state_free(session->authentication_state);
    session->authentication_state = NULL;
    return status;
  }

  session->is_open = true;
  return kStatus_SSS_Success;
}

sss_status_t se05x_esp_create_aes_auth_object(
    se05x_esp_session_t *session, uint32_t authentication_object_id,
    const uint8_t authentication_key[SE05X_ESP_AES_AUTH_KEY_SIZE],
    uint16_t maximum_attempts, sss_policy_t *policies) {
  if (session == NULL || !session->is_open ||
      authentication_object_id == 0 || authentication_key == NULL ||
      policies == NULL || policies->nPolicies == 0 ||
      policies->nPolicies > SSS_POLICY_COUNT_MAX) {
    return kStatus_SSS_InvalidArgument;
  }

  for (size_t i = 0; i < policies->nPolicies; ++i) {
    if (policies->policies[i] == NULL) {
      return kStatus_SSS_InvalidArgument;
    }
  }

  SE05x_Result_t exists = kSE05x_Result_NA;
  smStatus_t sm_status = Se05x_API_CheckObjectExists(
      &session->sss.s_ctx, authentication_object_id, &exists);
  if (sm_status != SM_OK) {
    return kStatus_SSS_Fail;
  }
  if (exists == kSE05x_Result_SUCCESS) {
    return kStatus_SSS_ResourceBusy;
  }
  if (exists != kSE05x_Result_FAILURE) {
    return kStatus_SSS_Fail;
  }

  uint8_t policy_buffer[MAX_POLICY_BUFFER_SIZE] = {0};
  size_t policy_length = 0;
  sss_status_t status = sss_se05x_create_object_policy_buffer(
      policies, policy_buffer, &policy_length);
  if (status != kStatus_SSS_Success || policy_length == 0) {
    return status == kStatus_SSS_Success ? kStatus_SSS_Fail : status;
  }

  Se05xPolicy_t policy = {
      .value = policy_buffer,
      .value_len = policy_length,
  };
  sm_status = Se05x_API_WriteSymmKey_Ver(
      &session->sss.s_ctx, &policy, maximum_attempts,
      authentication_object_id, SE05x_KeyID_KEK_NONE, authentication_key,
      SE05X_ESP_AES_AUTH_KEY_SIZE, kSE05x_INS_AUTH_OBJECT,
      kSE05x_SymmKeyType_AES, 0);
  return sm_status == SM_OK ? kStatus_SSS_Success : kStatus_SSS_Fail;
}

sss_status_t se05x_esp_asymmetric_sign(sss_asymmetric_t *context,
                                       const uint8_t *message,
                                       size_t message_length,
                                       uint8_t *signature,
                                       size_t *signature_length) {
  if (context == NULL || message == NULL || message_length == 0 ||
      signature == NULL || signature_length == NULL ||
      *signature_length == 0) {
    return kStatus_SSS_InvalidArgument;
  }

  return sss_se05x_asymmetric_sign((sss_se05x_asymmetric_t *)context, message,
                                   message_length, signature,
                                   signature_length);
}

void se05x_esp_session_close(se05x_esp_session_t *session) {
  if (session == NULL || !session->is_open) {
    return;
  }

  sss_se05x_session_close(&session->sss);
  session->is_open = false;
  se05x_esp_authentication_state_free(session->authentication_state);
  session->authentication_state = NULL;
}

sss_status_t se05x_esp_get_info(se05x_esp_session_t *session,
                                se05x_esp_info_t *info) {
  if (session == NULL || info == NULL || !session->is_open) {
    return kStatus_SSS_InvalidArgument;
  }

  memset(info, 0, sizeof(*info));

  info->applet_version_length = sizeof(info->applet_version);
  smStatus_t sm_status = Se05x_API_GetVersion(
      &session->sss.s_ctx, info->applet_version,
      &info->applet_version_length);
  if (sm_status != SM_OK) {
    return kStatus_SSS_Fail;
  }

  info->uid_length = sizeof(info->uid);
  sss_status_t status = sss_se05x_session_prop_get_au8(
      &session->sss, kSSS_SessionProp_UID, info->uid, &info->uid_length);
  if (status != kStatus_SSS_Success) {
    return status;
  }

  sss_se05x_rng_context_t rng = {0};
  status = sss_se05x_rng_context_init(&rng, &session->sss);
  if (status != kStatus_SSS_Success) {
    return status;
  }

  status = sss_se05x_rng_get_random(&rng, info->random_sample,
                                    sizeof(info->random_sample));
  sss_status_t free_status = sss_se05x_rng_context_free(&rng);
  if (status != kStatus_SSS_Success) {
    return status;
  }
  return free_status;
}
