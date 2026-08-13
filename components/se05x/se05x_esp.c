#include "se05x_esp.h"

#include "se05x_APDU.h"
#include "sdkconfig.h"
#include "sm_types.h"

#include <string.h>

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

void se05x_esp_session_close(se05x_esp_session_t *session) {
  if (session == NULL || !session->is_open) {
    return;
  }

  sss_se05x_session_close(&session->sss);
  session->is_open = false;
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
