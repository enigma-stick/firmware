#include "se05x_esp_admin.h"

#include "esp_log.h"
#include "se05x_APDU.h"
#include "sm_apdu.h"
#include "sm_types.h"

#include <limits.h>
#include <string.h>

#define SE05X_ADMIN_MEMORY_LOWER_BOUND 0x7FFFu
/* SE051 applet 7.2 returns a four-byte big-endian object version. */
#define SE05X_ADMIN_ATTRIBUTE_FIXED_SIZE 19u
#define SE05X_ADMIN_ID_SIZE 4u

static const char *TAG = "se05x_admin";

static uint16_t se05x_admin_read_be16(const uint8_t *input) {
  return ((uint16_t)input[0] << 8) | input[1];
}

static uint32_t se05x_admin_read_be32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | input[3];
}

static se05x_esp_admin_status_t se05x_admin_map_sm_status(smStatus_t status) {
  // NXP's APIs use smStatus_t, but that enum is also used as a carrier for
  // ISO7816 and transport-layer 16-bit status values outside the enum members.
  switch ((uint16_t)status) {
  case SM_OK:
    return SE05X_ESP_ADMIN_OK;
  case ERR_API_ERROR:
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  case SW_SECURITY_STATUS_NOT_SATISFIED:
  case SW_CONDITIONS_NOT_SATISFIED:
  case SW_COMMAND_NOT_ALLOWED:
    return SE05X_ESP_ADMIN_ACCESS_DENIED;
  case SW_FILE_NOT_FOUND:
    return SE05X_ESP_ADMIN_NOT_FOUND;
  case ERR_BUF_TOO_SMALL:
    return SE05X_ESP_ADMIN_BUFFER_TOO_SMALL;
  case SW_INS_NOT_SUPPORTED:
  case SW_CLA_NOT_SUPPORTED:
    return SE05X_ESP_ADMIN_UNSUPPORTED;
  case ERR_WRONG_RESPONSE:
  case ERR_TLV_MISSING:
    return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
  case ERR_CONNECT_LINK_FAILED:
  case ERR_CONNECT_SELECT_FAILED:
  case ERR_COMM_ERROR:
  case ERR_APDU_THROUGHPUT:
    return SE05X_ESP_ADMIN_TRANSPORT_ERROR;
  default:
    return SE05X_ESP_ADMIN_DEVICE_ERROR;
  }
}

static se05x_esp_admin_status_t
se05x_admin_checked_status(const char *operation, smStatus_t status) {
  se05x_esp_admin_status_t mapped = se05x_admin_map_sm_status(status);
  if (mapped != SE05X_ESP_ADMIN_OK) {
    ESP_LOGD(TAG, "%s failed with SE051 status 0x%04X", operation, status);
  }
  return mapped;
}

static se05x_esp_admin_status_t
se05x_admin_validate_session(se05x_esp_session_t *session) {
  if (session == NULL) {
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  }
  if (!session->is_open) {
    return SE05X_ESP_ADMIN_SESSION_CLOSED;
  }
  return SE05X_ESP_ADMIN_OK;
}

static se05x_esp_admin_status_t
se05x_admin_read_memory_region(se05x_esp_session_t *session,
                               SE05x_MemoryType_t type,
                               se05x_esp_admin_memory_region_t *region) {
  uint32_t bytes = 0;
  smStatus_t status =
      Se05x_API_GetFreeMemory(&session->sss.s_ctx, type, &bytes);
  se05x_esp_admin_status_t result =
      se05x_admin_checked_status("GetFreeMemory", status);
  if (result != SE05X_ESP_ADMIN_OK) {
    return result;
  }

  region->bytes = bytes;
  region->is_lower_bound = bytes == SE05X_ADMIN_MEMORY_LOWER_BOUND;
  return SE05X_ESP_ADMIN_OK;
}

static se05x_esp_admin_status_t
se05x_admin_object_exists(se05x_esp_session_t *session, uint32_t object_id,
                          bool *exists) {
  SE05x_Result_t result = kSE05x_Result_NA;
  smStatus_t status =
      Se05x_API_CheckObjectExists(&session->sss.s_ctx, object_id, &result);
  se05x_esp_admin_status_t mapped =
      se05x_admin_checked_status("CheckObjectExists", status);
  if (mapped != SE05X_ESP_ADMIN_OK) {
    return mapped;
  }

  if (result == kSE05x_Result_SUCCESS) {
    *exists = true;
    return SE05X_ESP_ADMIN_OK;
  }
  if (result == kSE05x_Result_FAILURE) {
    *exists = false;
    return SE05X_ESP_ADMIN_OK;
  }
  return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
}

se05x_esp_admin_status_t
se05x_esp_admin_object_exists(se05x_esp_session_t *session, uint32_t object_id,
                              bool *exists) {
  if (exists == NULL) {
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  }

  *exists = false;

  se05x_esp_admin_status_t status = se05x_admin_validate_session(session);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }

  return se05x_admin_object_exists(session, object_id, exists);
}

const char *se05x_esp_admin_status_name(se05x_esp_admin_status_t status) {
  switch (status) {
  case SE05X_ESP_ADMIN_OK:
    return "ok";
  case SE05X_ESP_ADMIN_INVALID_ARGUMENT:
    return "invalid argument";
  case SE05X_ESP_ADMIN_SESSION_CLOSED:
    return "session closed";
  case SE05X_ESP_ADMIN_NOT_FOUND:
    return "not found";
  case SE05X_ESP_ADMIN_ACCESS_DENIED:
    return "access denied";
  case SE05X_ESP_ADMIN_BUFFER_TOO_SMALL:
    return "buffer too small";
  case SE05X_ESP_ADMIN_UNSUPPORTED:
    return "unsupported";
  case SE05X_ESP_ADMIN_PROTOCOL_ERROR:
    return "malformed protocol response";
  case SE05X_ESP_ADMIN_TRANSPORT_ERROR:
    return "transport error";
  case SE05X_ESP_ADMIN_DEVICE_ERROR:
    return "device error";
  default:
    return "unknown";
  }
}

se05x_esp_admin_status_t
se05x_esp_admin_get_memory_info(se05x_esp_session_t *session,
                                se05x_esp_admin_memory_info_t *info) {
  if (info == NULL) {
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  }
  se05x_esp_admin_status_t status = se05x_admin_validate_session(session);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }

  memset(info, 0, sizeof(*info));
  status = se05x_admin_read_memory_region(session, kSE05x_MemoryType_PERSISTENT,
                                          &info->persistent);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  status = se05x_admin_read_memory_region(
      session, kSE05x_MemoryType_TRANSIENT_RESET, &info->transient_reset);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  return se05x_admin_read_memory_region(
      session, kSE05x_MemoryType_TRANSIENT_DESELECT, &info->transient_deselect);
}

se05x_esp_admin_status_t
se05x_esp_admin_list_objects(se05x_esp_session_t *session, uint8_t type_filter,
                             uint32_t *ids, size_t capacity, size_t *count) {
  if (count == NULL || (ids == NULL && capacity != 0)) {
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  }
  se05x_esp_admin_status_t status = se05x_admin_validate_session(session);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }

  *count = 0;
  size_t total = 0;
  uint16_t offset = 0;
  uint8_t more = kSE05x_MoreIndicator_NA;

  do {
    uint8_t raw_ids[SE05X_MAX_BUF_SIZE_RSP];
    size_t raw_ids_length = sizeof(raw_ids);
    smStatus_t sm_status =
        Se05x_API_ReadIDList(&session->sss.s_ctx, offset, type_filter, &more,
                             raw_ids, &raw_ids_length);
    status = se05x_admin_checked_status("ReadIDList", sm_status);
    if (status != SE05X_ESP_ADMIN_OK) {
      return status;
    }
    if ((raw_ids_length % SE05X_ADMIN_ID_SIZE) != 0) {
      return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
    }

    size_t page_count = raw_ids_length / SE05X_ADMIN_ID_SIZE;
    if (page_count == 0 && more == kSE05x_MoreIndicator_MORE) {
      return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
    }
    for (size_t index = 0; index < page_count; ++index) {
      if (ids != NULL && total < capacity) {
        ids[total] =
            se05x_admin_read_be32(&raw_ids[index * SE05X_ADMIN_ID_SIZE]);
      }
      ++total;
    }

    if (more != kSE05x_MoreIndicator_MORE &&
        more != kSE05x_MoreIndicator_NO_MORE) {
      return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
    }
    if (more == kSE05x_MoreIndicator_MORE) {
      if (total > UINT16_MAX) {
        return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
      }
      offset = (uint16_t)total;
    }
  } while (more == kSE05x_MoreIndicator_MORE);

  *count = total;
  if (ids != NULL && total > capacity) {
    return SE05X_ESP_ADMIN_BUFFER_TOO_SMALL;
  }
  return SE05X_ESP_ADMIN_OK;
}

se05x_esp_admin_status_t
se05x_esp_admin_get_object_info(se05x_esp_session_t *session,
                                uint32_t object_id,
                                se05x_esp_admin_object_info_t *info) {
  if (info == NULL) {
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  }
  se05x_esp_admin_status_t status = se05x_admin_validate_session(session);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }

  memset(info, 0, sizeof(*info));
  bool exists = false;
  status = se05x_admin_object_exists(session, object_id, &exists);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  if (!exists) {
    return SE05X_ESP_ADMIN_NOT_FOUND;
  }

  SE05x_SecureObjectType_t object_type = kSE05x_SecObjTyp_NA;
  uint8_t transient = kSE05x_TransientIndicator_NA;
  smStatus_t sm_status =
      Se05x_API_ReadType(&session->sss.s_ctx, object_id, &object_type,
                         &transient, kSE05x_AttestationType_None);
  status = se05x_admin_checked_status("ReadType", sm_status);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  if (transient != kSE05x_TransientIndicator_PERSISTENT &&
      transient != kSE05x_TransientIndicator_TRANSIENT) {
    return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
  }

  info->object_id = object_id;
  info->object_type = (uint8_t)object_type;
  info->storage = transient == kSE05x_TransientIndicator_TRANSIENT
                      ? SE05X_ESP_ADMIN_STORAGE_TRANSIENT
                      : SE05X_ESP_ADMIN_STORAGE_PERSISTENT;

  if (object_type == kSE05x_SecObjTyp_UserID) {
    return SE05X_ESP_ADMIN_OK;
  }

  uint16_t size = 0;
  sm_status = Se05x_API_ReadSize(&session->sss.s_ctx, object_id, &size);
  status = se05x_admin_checked_status("ReadSize", sm_status);
  if (status == SE05X_ESP_ADMIN_ACCESS_DENIED ||
      status == SE05X_ESP_ADMIN_UNSUPPORTED) {
    return SE05X_ESP_ADMIN_OK;
  }
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  info->size_available = true;
  info->size_bytes = size;
  return SE05X_ESP_ADMIN_OK;
}

se05x_esp_admin_status_t se05x_esp_admin_get_object_attributes(
    se05x_esp_session_t *session, uint32_t object_id,
    se05x_esp_admin_object_attributes_t *attributes) {
  if (attributes == NULL) {
    return SE05X_ESP_ADMIN_INVALID_ARGUMENT;
  }
  se05x_esp_admin_status_t status = se05x_admin_validate_session(session);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }

  memset(attributes, 0, sizeof(*attributes));
  bool exists = false;
  status = se05x_admin_object_exists(session, object_id, &exists);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  if (!exists) {
    return SE05X_ESP_ADMIN_NOT_FOUND;
  }

  uint8_t raw_attributes[SE05X_MAX_BUF_SIZE_RSP];
  size_t raw_attributes_length = sizeof(raw_attributes);
  smStatus_t sm_status = Se05x_API_ReadObjectAttributes(
      &session->sss.s_ctx, object_id, raw_attributes, &raw_attributes_length);
  status = se05x_admin_checked_status("ReadObjectAttributes", sm_status);
  if (status != SE05X_ESP_ADMIN_OK) {
    return status;
  }
  if (raw_attributes_length < SE05X_ADMIN_ATTRIBUTE_FIXED_SIZE) {
    return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
  }

  size_t policy_length =
      raw_attributes_length - SE05X_ADMIN_ATTRIBUTE_FIXED_SIZE;
  if (policy_length > sizeof(attributes->policy)) {
    return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
  }

  attributes->object_id = se05x_admin_read_be32(&raw_attributes[0]);
  attributes->object_type = raw_attributes[4];
  attributes->authentication_attribute = raw_attributes[5];
  attributes->is_authentication_object =
      raw_attributes[5] == kSE05x_SetIndicator_SET;
  if (attributes->object_id != object_id) {
    return SE05X_ESP_ADMIN_PROTOCOL_ERROR;
  }

  uint16_t counter_or_tag = se05x_admin_read_be16(&raw_attributes[6]);
  attributes->owner_auth_object_id = se05x_admin_read_be32(&raw_attributes[8]);
  if (attributes->is_authentication_object) {
    attributes->failed_authentication_attempts = counter_or_tag;
    attributes->maximum_authentication_attempts =
        se05x_admin_read_be16(&raw_attributes[12]);
  } else {
    attributes->aead_tag_length = counter_or_tag;
  }

  attributes->origin = raw_attributes[raw_attributes_length - 5];
  attributes->version =
      se05x_admin_read_be32(&raw_attributes[raw_attributes_length - 4]);
  attributes->policy_length = policy_length;
  if (policy_length > 0) {
    memcpy(attributes->policy, &raw_attributes[14], policy_length);
  }
  return SE05X_ESP_ADMIN_OK;
}
