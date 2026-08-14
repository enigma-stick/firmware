#ifndef KEYMGR_SE05X_ESP_ADMIN_H
#define KEYMGR_SE05X_ESP_ADMIN_H

#include "se05x_esp.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SE05X_ESP_ADMIN_OBJECT_TYPE_ANY 0xFFu
#define SE05X_ESP_ADMIN_MAX_POLICY_SIZE 256u

/** Result codes for SE051-specific administrative operations. */
typedef enum {
  SE05X_ESP_ADMIN_OK = 0,
  SE05X_ESP_ADMIN_INVALID_ARGUMENT,
  SE05X_ESP_ADMIN_SESSION_CLOSED,
  SE05X_ESP_ADMIN_NOT_FOUND,
  SE05X_ESP_ADMIN_ACCESS_DENIED,
  SE05X_ESP_ADMIN_BUFFER_TOO_SMALL,
  SE05X_ESP_ADMIN_UNSUPPORTED,
  SE05X_ESP_ADMIN_PROTOCOL_ERROR,
  SE05X_ESP_ADMIN_TRANSPORT_ERROR,
  SE05X_ESP_ADMIN_DEVICE_ERROR,
} se05x_esp_admin_status_t;

/** Free space reported for one SE051 memory region. */
typedef struct {
  uint32_t bytes;
  /**
   * The applet reports 0x7FFF when at least 32768 bytes are available. In that
   * case bytes is a lower bound rather than an exact measurement.
   */
  bool is_lower_bound;
} se05x_esp_admin_memory_region_t;

typedef struct {
  se05x_esp_admin_memory_region_t persistent;
  se05x_esp_admin_memory_region_t transient_reset;
  se05x_esp_admin_memory_region_t transient_deselect;
} se05x_esp_admin_memory_info_t;

typedef enum {
  SE05X_ESP_ADMIN_STORAGE_PERSISTENT = 0,
  SE05X_ESP_ADMIN_STORAGE_TRANSIENT,
} se05x_esp_admin_storage_t;

/** Basic information available through the applet's type and size commands. */
typedef struct {
  uint32_t object_id;
  uint8_t object_type;
  se05x_esp_admin_storage_t storage;
  /** False when ReadSize is unsupported or disallowed for this object. */
  bool size_available;
  uint16_t size_bytes;
} se05x_esp_admin_object_info_t;

/** Parsed SE051 object attributes. The policy remains in its applet encoding.
 */
typedef struct {
  uint32_t object_id;
  uint8_t object_type;
  uint8_t authentication_attribute;
  bool is_authentication_object;
  /** Valid for authentication objects. */
  uint16_t failed_authentication_attempts;
  /** Valid for authentication objects; zero means unlimited. */
  uint16_t maximum_authentication_attempts;
  /**
   * Valid for non-authentication AES objects, in bytes. Zero selects the
   * applet's 16-byte default.
   */
  uint16_t aead_tag_length;
  /** Authentication object that owned the session when this object was made. */
  uint32_t owner_auth_object_id;
  uint8_t origin;
  /** Four-byte object version returned by the SE051 7.2 applet. */
  uint32_t version;
  uint8_t policy[SE05X_ESP_ADMIN_MAX_POLICY_SIZE];
  size_t policy_length;
} se05x_esp_admin_object_attributes_t;

const char *se05x_esp_admin_status_name(se05x_esp_admin_status_t status);

/** Read free persistent and transient memory. This operation is read-only. */
se05x_esp_admin_status_t
se05x_esp_admin_get_memory_info(se05x_esp_session_t *session,
                                se05x_esp_admin_memory_info_t *info);

/**
 * Enumerate object IDs, handling the applet's pagination internally.
 *
 * Pass ids=NULL and capacity=0 to measure the required element count. When ids
 * is non-NULL, *count receives the total number of matching IDs. If capacity is
 * insufficient, the prefix that fits is written and BUFFER_TOO_SMALL is
 * returned. type_filter accepts an SE05x secure-object type value or
 * SE05X_ESP_ADMIN_OBJECT_TYPE_ANY.
 */
se05x_esp_admin_status_t
se05x_esp_admin_list_objects(se05x_esp_session_t *session, uint8_t type_filter,
                             uint32_t *ids, size_t capacity, size_t *count);

/** Read an object's type, persistence, and size when supported. */
se05x_esp_admin_status_t
se05x_esp_admin_get_object_info(se05x_esp_session_t *session,
                                uint32_t object_id,
                                se05x_esp_admin_object_info_t *info);

/** Read and parse an object's policy-bearing attribute record. */
se05x_esp_admin_status_t se05x_esp_admin_get_object_attributes(
    se05x_esp_session_t *session, uint32_t object_id,
    se05x_esp_admin_object_attributes_t *attributes);

#endif
