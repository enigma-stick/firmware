/*
 * Minimal SSS user-host types for the ESP-IDF PSA SCP03 port.
 *
 * NXP's generic SSS structures reserve enough storage for these concrete
 * structures and cast to them through fsl_sss_user_apis.h.
 */
#ifndef KEYMGR_FSL_SSS_USER_TYPES_H
#define KEYMGR_FSL_SSS_USER_TYPES_H

#include "fsl_sss_api.h"
#include "psa/crypto.h"

#include <stddef.h>
#include <stdint.h>

#define SSS_SUBSYSTEM_TYPE_IS_HOST(subsystem) \
  ((subsystem) == kType_SSS_Software)
#define SSS_SESSION_TYPE_IS_HOST(session) \
  ((session) != NULL && SSS_SUBSYSTEM_TYPE_IS_HOST((session)->subsystem))
#define SSS_KEY_STORE_TYPE_IS_HOST(key_store) \
  ((key_store) != NULL && SSS_SESSION_TYPE_IS_HOST((key_store)->session))
#define SSS_OBJECT_TYPE_IS_HOST(object) \
  ((object) != NULL && SSS_KEY_STORE_TYPE_IS_HOST((object)->keyStore))

typedef struct {
  sss_type_t subsystem;
} sss_user_impl_session_t;

typedef struct {
  sss_user_impl_session_t *session;
} sss_user_impl_key_store_t;

typedef struct {
  sss_user_impl_key_store_t *keyStore;
  uint32_t objectType;
  uint32_t cipherType;
  uint32_t keyId;
  uint8_t key[16];
  size_t key_length;
} sss_user_impl_object_t;

typedef struct {
  sss_user_impl_session_t *session;
  sss_user_impl_object_t *keyObject;
  sss_algorithm_t algorithm;
  sss_mode_t mode;
} sss_user_impl_derive_key_t;

typedef struct {
  sss_user_impl_session_t *session;
  sss_user_impl_object_t *keyObject;
  sss_algorithm_t algorithm;
  sss_mode_t mode;
} sss_user_impl_asymmetric_t;

typedef struct {
  sss_user_impl_session_t *session;
  sss_user_impl_object_t *keyObject;
  sss_algorithm_t algorithm;
  sss_mode_t mode;
  psa_key_id_t psa_key;
} sss_user_impl_symmetric_t;

typedef struct {
  sss_user_impl_session_t *session;
  sss_user_impl_object_t *keyObject;
  sss_algorithm_t algorithm;
  sss_mode_t mode;
  psa_key_id_t psa_key;
  psa_mac_operation_t *operation;
} sss_user_impl_mac_t;

typedef struct {
  sss_user_impl_session_t *session;
  sss_algorithm_t algorithm;
  sss_mode_t mode;
  size_t digestFullLen;
} sss_user_impl_digest_t;

typedef struct {
  sss_user_impl_session_t *session;
} sss_user_impl_rng_context_t;

#endif
