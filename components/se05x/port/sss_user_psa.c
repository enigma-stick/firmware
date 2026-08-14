#include "fsl_sss_user_apis.h"

#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

#include <stdlib.h>
#include <string.h>

#define SE05X_HOST_AES_KEY_SIZE 16u

_Static_assert(sizeof(sss_user_impl_session_t) <= sizeof(sss_session_t),
               "SSS user session exceeds generic storage");
_Static_assert(sizeof(sss_user_impl_key_store_t) <= sizeof(sss_key_store_t),
               "SSS user key store exceeds generic storage");
_Static_assert(sizeof(sss_user_impl_object_t) <= sizeof(sss_object_t),
               "SSS user object exceeds generic storage");
_Static_assert(sizeof(sss_user_impl_symmetric_t) <= sizeof(sss_symmetric_t),
               "SSS user symmetric context exceeds generic storage");
_Static_assert(sizeof(sss_user_impl_mac_t) <= sizeof(sss_mac_t),
               "SSS user MAC context exceeds generic storage");
_Static_assert(sizeof(sss_user_impl_rng_context_t) <= sizeof(sss_rng_context_t),
               "SSS user RNG context exceeds generic storage");

static sss_status_t se05x_host_psa_status(psa_status_t status) {
  return status == PSA_SUCCESS ? kStatus_SSS_Success : kStatus_SSS_Fail;
}

static sss_status_t se05x_host_import_key(const sss_user_impl_object_t *object,
                                          psa_key_usage_t usage,
                                          psa_algorithm_t algorithm,
                                          psa_key_id_t *key_id) {
  if (object == NULL || key_id == NULL ||
      object->cipherType != kSSS_CipherType_AES ||
      object->key_length != SE05X_HOST_AES_KEY_SIZE) {
    return kStatus_SSS_InvalidArgument;
  }

  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, SE05X_HOST_AES_KEY_SIZE * 8u);
  psa_set_key_usage_flags(&attributes, usage);
  psa_set_key_algorithm(&attributes, algorithm);
  psa_status_t status = psa_import_key(&attributes, object->key,
                                       object->key_length, key_id);
  psa_reset_key_attributes(&attributes);
  return se05x_host_psa_status(status);
}

sss_status_t sss_user_impl_session_create(
    sss_user_impl_session_t *session, sss_type_t subsystem,
    uint32_t application_id, sss_connection_type_t connection_type,
    void *connection_data) {
  return sss_user_impl_session_open(session, subsystem, application_id,
                                    connection_type, connection_data);
}

sss_status_t sss_user_impl_session_open(
    sss_user_impl_session_t *session, sss_type_t subsystem,
    uint32_t application_id, sss_connection_type_t connection_type,
    void *connection_data) {
  (void)application_id;
  (void)connection_data;
  if (session == NULL || subsystem != kType_SSS_Software ||
      connection_type != kSSS_ConnectionType_Plain) {
    return kStatus_SSS_InvalidArgument;
  }

  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    return kStatus_SSS_Fail;
  }
  memset(session, 0, sizeof(*session));
  session->subsystem = subsystem;
  return kStatus_SSS_Success;
}

void sss_user_impl_session_close(sss_user_impl_session_t *session) {
  if (session != NULL) {
    memset(session, 0, sizeof(*session));
  }
}

void sss_user_impl_session_delete(sss_user_impl_session_t *session) {
  sss_user_impl_session_close(session);
}

sss_status_t sss_user_impl_key_store_context_init(
    sss_user_impl_key_store_t *key_store,
    sss_user_impl_session_t *session) {
  if (key_store == NULL || session == NULL ||
      session->subsystem != kType_SSS_Software) {
    return kStatus_SSS_InvalidArgument;
  }
  memset(key_store, 0, sizeof(*key_store));
  key_store->session = session;
  return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_key_store_allocate(
    sss_user_impl_key_store_t *key_store, uint32_t key_store_id) {
  (void)key_store_id;
  return key_store != NULL && key_store->session != NULL
             ? kStatus_SSS_Success
             : kStatus_SSS_InvalidArgument;
}

void sss_user_impl_key_store_context_free(
    sss_user_impl_key_store_t *key_store) {
  if (key_store != NULL) {
    memset(key_store, 0, sizeof(*key_store));
  }
}

sss_status_t sss_user_impl_key_object_init(
    sss_user_impl_object_t *object, sss_user_impl_key_store_t *key_store) {
  if (object == NULL || key_store == NULL || key_store->session == NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  memset(object, 0, sizeof(*object));
  object->keyStore = key_store;
  return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_key_object_allocate_handle(
    sss_user_impl_object_t *object, uint32_t key_id,
    sss_key_part_t key_part, sss_cipher_type_t cipher_type,
    size_t key_byte_length_max, uint32_t options) {
  (void)options;
  if (object == NULL || object->keyStore == NULL || key_id == 0 ||
      key_part != kSSS_KeyPart_Default ||
      cipher_type != kSSS_CipherType_AES ||
      key_byte_length_max != SE05X_HOST_AES_KEY_SIZE) {
    return kStatus_SSS_InvalidArgument;
  }
  object->keyId = key_id;
  object->objectType = key_part;
  object->cipherType = cipher_type;
  return kStatus_SSS_Success;
}

void sss_user_impl_key_object_free(sss_user_impl_object_t *object) {
  if (object != NULL) {
    mbedtls_platform_zeroize(object, sizeof(*object));
  }
}

sss_status_t sss_user_impl_key_store_set_key(
    sss_user_impl_key_store_t *key_store, sss_user_impl_object_t *object,
    const uint8_t *data, size_t data_length, size_t key_bit_length,
    void *options, size_t options_length) {
  (void)options;
  (void)options_length;
  if (key_store == NULL || object == NULL || data == NULL ||
      object->keyStore != key_store ||
      data_length != SE05X_HOST_AES_KEY_SIZE ||
      key_bit_length != SE05X_HOST_AES_KEY_SIZE * 8u) {
    return kStatus_SSS_InvalidArgument;
  }
  memcpy(object->key, data, data_length);
  object->key_length = data_length;
  return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_key_store_get_key(
    sss_user_impl_key_store_t *key_store, sss_user_impl_object_t *object,
    uint8_t *data, size_t *data_length, size_t *key_bit_length) {
  if (key_store == NULL || object == NULL || data == NULL ||
      data_length == NULL || key_bit_length == NULL ||
      object->keyStore != key_store || *data_length < object->key_length) {
    return kStatus_SSS_InvalidArgument;
  }

  memcpy(data, object->key, object->key_length);
  *data_length = object->key_length;
  *key_bit_length = object->key_length * 8u;
  return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_symmetric_context_init(
    sss_user_impl_symmetric_t *context,
    sss_user_impl_session_t *session, sss_user_impl_object_t *object,
    sss_algorithm_t algorithm, sss_mode_t mode) {
  if (context == NULL || session == NULL || object == NULL ||
      algorithm != kAlgorithm_SSS_AES_CBC ||
      (mode != kMode_SSS_Encrypt && mode != kMode_SSS_Decrypt)) {
    return kStatus_SSS_InvalidArgument;
  }

  memset(context, 0, sizeof(*context));
  context->session = session;
  context->keyObject = object;
  context->algorithm = algorithm;
  context->mode = mode;
  psa_key_usage_t usage = mode == kMode_SSS_Encrypt
                              ? PSA_KEY_USAGE_ENCRYPT
                              : PSA_KEY_USAGE_DECRYPT;
  return se05x_host_import_key(object, usage, PSA_ALG_CBC_NO_PADDING,
                               &context->psa_key);
}

sss_status_t sss_user_impl_cipher_one_go(
    sss_user_impl_symmetric_t *context, uint8_t *iv, size_t iv_length,
    const uint8_t *source, uint8_t *destination, size_t data_length) {
  if (context == NULL || context->psa_key == PSA_KEY_ID_NULL || iv == NULL ||
      iv_length != 16u || source == NULL || destination == NULL ||
      (data_length % 16u) != 0) {
    return kStatus_SSS_InvalidArgument;
  }

  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
  psa_status_t status = context->mode == kMode_SSS_Encrypt
                            ? psa_cipher_encrypt_setup(
                                  &operation, context->psa_key,
                                  PSA_ALG_CBC_NO_PADDING)
                            : psa_cipher_decrypt_setup(
                                  &operation, context->psa_key,
                                  PSA_ALG_CBC_NO_PADDING);
  if (status == PSA_SUCCESS) {
    status = psa_cipher_set_iv(&operation, iv, iv_length);
  }

  size_t output_length = 0;
  if (status == PSA_SUCCESS) {
    status = psa_cipher_update(&operation, source, data_length, destination,
                               data_length, &output_length);
  }

  uint8_t final_block[16] = {0};
  size_t final_length = 0;
  if (status == PSA_SUCCESS) {
    status = psa_cipher_finish(&operation, final_block, sizeof(final_block),
                               &final_length);
  }
  psa_cipher_abort(&operation);
  mbedtls_platform_zeroize(final_block, sizeof(final_block));
  if (status != PSA_SUCCESS || output_length != data_length ||
      final_length != 0) {
    return kStatus_SSS_Fail;
  }
  return kStatus_SSS_Success;
}

void sss_user_impl_symmetric_context_free(
    sss_user_impl_symmetric_t *context) {
  if (context == NULL) {
    return;
  }
  if (context->psa_key != PSA_KEY_ID_NULL) {
    psa_destroy_key(context->psa_key);
  }
  memset(context, 0, sizeof(*context));
}

sss_status_t sss_user_impl_mac_context_init(
    sss_user_impl_mac_t *context, sss_user_impl_session_t *session,
    sss_user_impl_object_t *object, sss_algorithm_t algorithm,
    sss_mode_t mode) {
  if (context == NULL || session == NULL || object == NULL ||
      algorithm != kAlgorithm_SSS_CMAC_AES || mode != kMode_SSS_Mac) {
    return kStatus_SSS_InvalidArgument;
  }

  memset(context, 0, sizeof(*context));
  context->session = session;
  context->keyObject = object;
  context->algorithm = algorithm;
  context->mode = mode;
  return se05x_host_import_key(object, PSA_KEY_USAGE_SIGN_MESSAGE,
                               PSA_ALG_CMAC, &context->psa_key);
}

sss_status_t sss_user_impl_mac_one_go(
    sss_user_impl_mac_t *context, const uint8_t *message,
    size_t message_length, uint8_t *mac, size_t *mac_length) {
  if (context == NULL || context->psa_key == PSA_KEY_ID_NULL ||
      message == NULL || mac == NULL || mac_length == NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  return se05x_host_psa_status(psa_mac_compute(
      context->psa_key, PSA_ALG_CMAC, message, message_length, mac, *mac_length,
      mac_length));
}

sss_status_t sss_user_impl_mac_init(sss_user_impl_mac_t *context) {
  if (context == NULL || context->psa_key == PSA_KEY_ID_NULL ||
      context->operation != NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  context->operation = calloc(1, sizeof(*context->operation));
  if (context->operation == NULL) {
    return kStatus_SSS_Fail;
  }
  *context->operation = psa_mac_operation_init();
  return se05x_host_psa_status(psa_mac_sign_setup(
      context->operation, context->psa_key, PSA_ALG_CMAC));
}

sss_status_t sss_user_impl_mac_update(sss_user_impl_mac_t *context,
                                      const uint8_t *message,
                                      size_t message_length) {
  if (context == NULL || context->operation == NULL || message == NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  return se05x_host_psa_status(
      psa_mac_update(context->operation, message, message_length));
}

sss_status_t sss_user_impl_mac_finish(sss_user_impl_mac_t *context,
                                      uint8_t *mac, size_t *mac_length) {
  if (context == NULL || context->operation == NULL || mac == NULL ||
      mac_length == NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  return se05x_host_psa_status(psa_mac_sign_finish(
      context->operation, mac, *mac_length, mac_length));
}

void sss_user_impl_mac_context_free(sss_user_impl_mac_t *context) {
  if (context == NULL) {
    return;
  }
  if (context->operation != NULL) {
    psa_mac_abort(context->operation);
    mbedtls_platform_zeroize(context->operation,
                             sizeof(*context->operation));
    free(context->operation);
  }
  if (context->psa_key != PSA_KEY_ID_NULL) {
    psa_destroy_key(context->psa_key);
  }
  memset(context, 0, sizeof(*context));
}

sss_status_t sss_user_impl_rng_context_init(
    sss_user_impl_rng_context_t *context,
    sss_user_impl_session_t *session) {
  if (context == NULL || session == NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  memset(context, 0, sizeof(*context));
  context->session = session;
  return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_rng_get_random(
    sss_user_impl_rng_context_t *context, uint8_t *random_data,
    size_t data_length) {
  if (context == NULL || context->session == NULL || random_data == NULL) {
    return kStatus_SSS_InvalidArgument;
  }
  return se05x_host_psa_status(psa_generate_random(random_data, data_length));
}

sss_status_t sss_user_impl_rng_context_free(
    sss_user_impl_rng_context_t *context) {
  if (context != NULL) {
    memset(context, 0, sizeof(*context));
  }
  return kStatus_SSS_Success;
}
