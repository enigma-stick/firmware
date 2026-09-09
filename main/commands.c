#include "commands.h"
#include "app.h"
#include "crypto.h"
#include "esp_log.h"
#include "key.h"
#include "led_status.h"
#include "memory.h"
#include "protocol.h"
#include "se_worker.h"
#include "serial.h"
#include "token.h"
#include "usb_transport.h"
#include <string.h>

static const char *TAG = "keymgr_cmd";

bool km_command_init_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_init_t *out) {
  if (!out) {
    return false;
  }

  km_command_init_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_str(pool, dz, &command.pin)) {
    return false;
  }

  *out = command;
  return true;
}

bool km_command_authenticate_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_authenticate_t *out) {
  if (!out) {
    return false;
  }
  km_command_authenticate_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_str(pool, dz, &command.pin)) {
    return false;
  }

  *out = command;
  return true;
}

size_t km_command_response_status_serialize(
    km_memory_pool_t *pool, const km_command_response_status_t *response,
    uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);

  km_sz_u32(sz, response->token_state);
  km_sz_u32(sz, response->session_state);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_generate_key_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_generate_key_t *out) {
  if (!out) {
    return false;
  }

  km_command_generate_key_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  uint32_t type;
  uint32_t usage;
  if (!km_dz_u32(dz, &type) || !km_dz_u32(dz, &usage) ||
      !km_dz_u16(dz, &command.bits) || !km_dz_str(pool, dz, &command.label) ||
      !km_dz_u32(dz, &command.timestamp)) {
    return false;
  }

  command.type = (km_key_type_t)type;
  command.usage = (km_key_usage_t)usage;

  *out = command;
  return true;
}

size_t km_command_response_generate_key_serialize(
    km_memory_pool_t *pool, const km_command_response_generate_key_t *response,
    uint8_t **out) {

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);

  km_sz_u32(sz, response->key_id);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_encrypt_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_encrypt_t *out) {
  if (!out) {
    return false;
  }

  km_command_encrypt_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_u32(dz, &command.key_id) ||
      !km_dz_u32(dz, (uint32_t *)&command.plaintext_len)) {
    return false;
  }

  command.plaintext = km_memory_alloc(pool, command.plaintext_len);
  km_dz_array(km_dz_u8, dz, command.plaintext, command.plaintext_len);

  *out = command;
  return true;
}

size_t km_command_response_encrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_encrypt_t *response,
    uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_array(km_sz_u8, sz, response->ciphertext, response->ciphertext_len);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_decrypt_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_decrypt_t *out) {
  if (!out) {
    return false;
  }

  km_command_decrypt_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_u32(dz, &command.key_id) ||
      !km_dz_u32(dz, (uint32_t *)&command.ciphertext_len)) {
    return false;
  }

  command.ciphertext = km_memory_alloc(pool, command.ciphertext_len);
  km_dz_array(km_dz_u8, dz, command.ciphertext, command.ciphertext_len);

  *out = command;
  return true;
}

size_t km_command_response_decrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_decrypt_t *response,
    uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_array(km_sz_u8, sz, response->plaintext, response->plaintext_len);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_sign_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_sign_t *out) {
  if (!out) {
    return false;
  }

  km_command_sign_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_u32(dz, &command.key_id) ||
      !km_dz_u32(dz, (uint32_t *)&command.message_len)) {
    return false;
  }

  command.message = km_memory_alloc(pool, command.message_len);
  km_dz_array(km_dz_u8, dz, command.message, command.message_len);

  *out = command;
  return true;
}

size_t
km_command_response_sign_serialize(km_memory_pool_t *pool,
                                   const km_command_response_sign_t *response,
                                   uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_array(km_sz_u8, sz, response->signature, response->signature_len);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_get_key_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_get_key_t *out) {
  if (!out) {
    return false;
  }

  km_command_get_key_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_u32(dz, &command.key_id)) {
    return false;
  }

  *out = command;
  return true;
}

size_t km_command_response_get_key_serialize(
    km_memory_pool_t *pool, const km_command_response_get_key_t *response,
    uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_u32(sz, response->encoding);
  km_sz_array(km_sz_u8, sz, response->public_key, response->public_key_len);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_list_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_list_t *out) {
  if (!out) {
    return false;
  }

  km_command_list_t command = {0};
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  uint32_t type;
  uint32_t usage;
  if (!km_dz_u32(dz, &command.filter_flags) || !km_dz_u32(dz, &type) ||
      !km_dz_u32(dz, &usage) || !km_dz_str(pool, dz, &command.key_label) ||
      !km_dz_u32(dz, &command.key_id)) {
    return false;
  }

  command.key_type = (km_key_type_t)type;
  command.key_usage = (km_key_usage_t)usage;

  *out = command;

  return true;
}

size_t
km_command_response_list_serialize(km_memory_pool_t *pool,
                                   const km_command_response_list_t *response,
                                   uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);

  km_sz_u32(sz, response->count);
  for (size_t i = 0; i < response->count; i++) {
    km_key_metadata_t *key = &response->keys[i];
    km_sz_u32(sz, key->id);
    km_sz_u32(sz, key->type);
    km_sz_u32(sz, key->usage);
    km_sz_u16(sz, key->size);
    km_sz_str(sz, key->label);
    km_sz_u32(sz, key->created_at);
  }

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

bool km_command_destroy_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_destroy_t *out) {
  if (!out) {
    return false;
  }

  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);
  km_command_destroy_t command;

  if (!km_dz_u32(dz, &command.key_id)) {
    return false;
  }

  *out = command;
  return true;
}

static void km_command_handle_init(const km_frame_header_t *frame_header,
                                   const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_init_t command;
  if (!km_command_init_deserialize(pool, payload, frame_header->length,
                                   &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  size_t pin_length = strlen(command.pin);
  esp_err_t err = km_token_provision(command.pin, pin_length);

  km_crypto_zero(command.pin, pin_length);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize token: %s", esp_err_to_name(err));
    km_usb_write_error("Failed to initialize token");
    goto cleanup;
  }

  km_usb_write_success();

cleanup:
  km_memory_free(pool);
}

static void
km_command_handle_authenticate(const km_frame_header_t *frame_header,
                               const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_authenticate_t command;
  if (!km_command_authenticate_deserialize(pool, payload, frame_header->length,
                                           &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  size_t pin_length = strlen(command.pin);
  esp_err_t err = km_token_authenticate(command.pin, pin_length);
  km_crypto_zero(command.pin, pin_length);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not authenticate token: %s", esp_err_to_name(err));
    km_usb_write_error("Failed to authenticate token");
    goto cleanup;
  }

  km_usb_write_success();

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_status(void) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_token_status_t token_status;
  if (km_token_get_status(&token_status) != ESP_OK) {
    km_usb_write_error("Could not get token status");
    goto cleanup;
  }

  km_command_response_status_t response = {
      .token_state = token_status.token_state,
      .session_state = token_status.session_state};
  uint8_t *payload;
  size_t len = km_command_response_status_serialize(pool, &response, &payload);
  if (len == 0) {
    km_usb_write_error("Could not serialize response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_status, payload, len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_lock(void) {
  km_se_worker_close_session();
  km_usb_write_success();
}

static void
km_command_handle_generate_key(const km_frame_header_t *frame_header,
                               const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_generate_key_t command;
  if (!km_command_generate_key_deserialize(pool, payload, frame_header->length,
                                           &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  uint32_t key_id = 0;
  esp_err_t result =
      km_token_generate_key(command.type, command.bits, command.usage,
                            command.label, command.timestamp, &key_id);
  if (result == KM_ERR_AUTH_REQUIRED) {
    km_usb_write_response(km_command_response_auth_required, NULL, 0);
    goto cleanup;
  }

  if (result != ESP_OK) {
    km_usb_write_error("Could not generate key");
    goto cleanup;
  }

  km_command_response_generate_key_t response = {.key_id = key_id};
  uint8_t *out;
  size_t len =
      km_command_response_generate_key_serialize(pool, &response, &out);
  if (len == 0) {
    ESP_LOGE(TAG, "Could not serialize response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_generate_key, out, len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_encrypt(const km_frame_header_t *frame_header,
                                      const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_encrypt_t command;
  if (!km_command_encrypt_deserialize(pool, payload, frame_header->length,
                                      &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  km_key_metadata_t key_meta;
  esp_err_t status = km_token_get_key_metadata(pool, command.key_id, &key_meta);
  if (status != ESP_OK) {
    km_usb_write_error("Could not retrieve key metadata");
    goto cleanup;
  }

  uint8_t *ciphertext;
  size_t ciphertext_len;

  switch (key_meta.type) {
  case km_key_type_aes:
    status = km_token_encrypt_aes_gcm(pool, &key_meta, command.plaintext,
                                      command.plaintext_len, &ciphertext,
                                      &ciphertext_len);
    break;
  default:
    km_usb_write_error("Unsupported key type for requsted operation");
    goto cleanup;
  }

  if (status == KM_ERR_AUTH_REQUIRED) {
    km_usb_write_response(km_command_response_auth_required, NULL, 0);
    goto cleanup;
  }

  if (status != ESP_OK) {
    ESP_LOGE(TAG, "encryption failed: %s", esp_err_to_name(status));
    km_usb_write_error("Encryption failed");
    goto cleanup;
  }

  km_command_response_encrypt_t response;
  response.ciphertext = ciphertext;
  response.ciphertext_len = ciphertext_len;
  uint8_t *out;
  size_t out_len = km_command_response_encrypt_serialize(pool, &response, &out);

  if (out_len == 0) {
    km_usb_write_error("Could not serialize command response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_encrypt, out, out_len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_decrypt(const km_frame_header_t *frame_header,
                                      const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_decrypt_t command;
  if (!km_command_decrypt_deserialize(pool, payload, frame_header->length,
                                      &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  km_key_metadata_t key_meta;
  esp_err_t status = km_token_get_key_metadata(pool, command.key_id, &key_meta);
  if (status != ESP_OK) {
    km_usb_write_error("Could not retrieve key metadata");
    goto cleanup;
  }

  uint8_t *plaintext;
  size_t plaintext_len;

  switch (key_meta.type) {
  case km_key_type_aes:
    status = km_token_decrypt_aes_gcm(pool, &key_meta, command.ciphertext,
                                      command.ciphertext_len, &plaintext,
                                      &plaintext_len);
    break;
  case km_key_type_rsa:
    status = km_token_decrypt_rsa_oaep(pool, &key_meta, command.ciphertext,
                                       command.ciphertext_len, &plaintext,
                                       &plaintext_len);
    break;
  default:
    km_usb_write_error("Unsupported key type for requsted operation");
    goto cleanup;
  }

  if (status == KM_ERR_AUTH_REQUIRED) {
    km_usb_write_response(km_command_response_auth_required, NULL, 0);
    goto cleanup;
  }

  if (status != ESP_OK) {
    ESP_LOGE(TAG, "decryption failed: %s", esp_err_to_name(status));
    km_usb_write_error("Decryption failed");
    goto cleanup;
  }

  km_command_response_decrypt_t response;
  response.plaintext = plaintext;
  response.plaintext_len = plaintext_len;
  uint8_t *out;
  size_t out_len = km_command_response_decrypt_serialize(pool, &response, &out);

  if (out_len == 0) {
    km_usb_write_error("Could not serialize command response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_decrypt, out, out_len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_sign(const km_frame_header_t *frame_header,
                                   const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_sign_t command;
  if (!km_command_sign_deserialize(pool, payload, frame_header->length,
                                   &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  km_key_metadata_t key_meta;
  esp_err_t status = km_token_get_key_metadata(pool, command.key_id, &key_meta);
  if (status != ESP_OK) {
    km_usb_write_error("Could not retrieve key metadata");
    goto cleanup;
  }

  uint8_t *signature;
  size_t signature_len;

  switch (key_meta.type) {
  case km_key_type_rsa:
    status =
        km_token_sign_rsa_pss(pool, &key_meta, command.message,
                              command.message_len, &signature, &signature_len);
    break;
  case km_key_type_ec:
    status =
        km_token_sign_ec_ecdsa(pool, &key_meta, command.message,
                               command.message_len, &signature, &signature_len);
    break;
  default:
    km_usb_write_error("Unsupported key type for requsted operation");
    goto cleanup;
  }

  if (status == KM_ERR_AUTH_REQUIRED) {
    km_usb_write_response(km_command_response_auth_required, NULL, 0);
    goto cleanup;
  }

  if (status != ESP_OK) {
    ESP_LOGE(TAG, "sign failed: %s", esp_err_to_name(status));
    km_usb_write_error("Sign failed");
    goto cleanup;
  }

  km_command_response_sign_t response;
  response.signature = signature;
  response.signature_len = signature_len;
  uint8_t *out;
  size_t out_len = km_command_response_sign_serialize(pool, &response, &out);

  if (out_len == 0) {
    km_usb_write_error("Could not serialize command response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_sign, out, out_len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_get_key(const km_frame_header_t *frame_header,
                                      const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_get_key_t command;
  if (!km_command_get_key_deserialize(pool, payload, frame_header->length,
                                      &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  km_key_metadata_t key_meta;
  esp_err_t status = km_token_get_key_metadata(pool, command.key_id, &key_meta);
  if (status != ESP_OK) {
    km_usb_write_error("Could not retrieve key metadata");
    goto cleanup;
  }

  switch (key_meta.type) {
  case km_key_type_aes:
    km_usb_write_error("Cannot get symmetric key material");
    goto cleanup;
  default:
    break;
  }

  uint8_t *public_key;
  size_t public_key_len;
  status =
      km_token_get_public_key(pool, &key_meta, &public_key, &public_key_len);

  if (status == KM_ERR_AUTH_REQUIRED) {
    km_usb_write_response(km_command_response_auth_required, NULL, 0);
    goto cleanup;
  }

  if (status != ESP_OK) {
    ESP_LOGE(TAG, "get public key failed: %s", esp_err_to_name(status));
    km_usb_write_error("Get public key failed");
    goto cleanup;
  }

  km_command_response_get_key_t response;
  response.encoding = km_public_key_encoding_der_spki;
  response.public_key = public_key;
  response.public_key_len = public_key_len;
  uint8_t *out;
  size_t out_len = km_command_response_get_key_serialize(pool, &response, &out);

  if (out_len == 0) {
    km_usb_write_error("Could not serialize command response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_get_key, out, out_len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_list(const km_frame_header_t *frame_header,
                                   const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_list_t command;
  if (!km_command_list_deserialize(pool, payload, frame_header->length,
                                   &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  km_key_type_t *key_type = NULL;
  km_key_usage_t *key_usage = NULL;
  uint32_t *key_id = NULL;
  char *key_label = NULL;

  if (command.filter_flags & KEYMGR_LIST_FILTER_TYPE)
    key_type = &command.key_type;
  if (command.filter_flags & KEYMGR_LIST_FILTER_USAGE)
    key_usage = &command.key_usage;
  if (command.filter_flags & KEYMGR_LIST_FILTER_LABEL)
    key_label = command.key_label;
  if (command.filter_flags & KEYMGR_LIST_FILTER_ID)
    key_id = &command.key_id;

  km_key_metadata_t *keys = NULL;
  size_t count = 0;

  esp_err_t err = km_token_list_keys(pool, &keys, &count, key_type, key_usage,
                                     key_label, key_id);
  if (err != ESP_OK) {
    km_usb_write_error("Error getting key list");
    goto cleanup;
  }

  km_command_response_list_t response;
  response.count = count;
  response.keys = keys;

  uint8_t *out;
  size_t out_len = km_command_response_list_serialize(pool, &response, &out);
  if (out_len == 0) {
    km_usb_write_error("Could not serialize response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_list, out, out_len);

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_destroy(const km_frame_header_t *frame_header,
                                      const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_destroy_t command;
  if (!km_command_destroy_deserialize(pool, payload, frame_header->length,
                                      &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  esp_err_t err = km_token_destroy_key(command.key_id);
  if (err == KM_ERR_AUTH_REQUIRED) {
    km_usb_write_response(km_command_response_auth_required, NULL, 0);
    goto cleanup;
  }
  if (err != ESP_OK) {
    km_usb_write_error("Could not destroy key");
    goto cleanup;
  }

  km_usb_write_success();

cleanup:
  km_memory_free(pool);
}

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload) {
  if (frame_header->version != KM_PROTOCOL_VERSION) {
    km_usb_write_error("Invalid command version");
    return;
  }

  km_led_busy_on(ctx);
  switch (frame_header->command) {
  case km_command_ping:
    km_usb_write_success();
    break;
  case km_command_init:
    km_command_handle_init(frame_header, payload);
    break;
  case km_command_authenticate:
    km_command_handle_authenticate(frame_header, payload);
    break;
  case km_command_status:
    km_command_handle_status();
    break;
  case km_command_lock:
    km_command_handle_lock();
    break;
  case km_command_generate_key:
    km_command_handle_generate_key(frame_header, payload);
    break;
  case km_command_encrypt:
    km_command_handle_encrypt(frame_header, payload);
    break;
  case km_command_decrypt:
    km_command_handle_decrypt(frame_header, payload);
    break;
  case km_command_sign:
    km_command_handle_sign(frame_header, payload);
    break;
  case km_command_get_key:
    km_command_handle_get_key(frame_header, payload);
    break;
  case km_command_list:
    km_command_handle_list(frame_header, payload);
    break;
  case km_command_destroy:
    km_command_handle_destroy(frame_header, payload);
    break;
  default:
    km_usb_write_error("Invalid command");
  }
  km_led_busy_off(ctx);
}
