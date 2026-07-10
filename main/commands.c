#include "commands.h"
#include "app.h"
#include "crypto.h"
#include "esp_log.h"
#include "keys.h"
#include "led_status.h"
#include "memory.h"
#include "protocol.h"
#include "serial.h"
#include "usb_transport.h"
#include <string.h>

static const char *TAG = "keymgr_cmd";

bool km_command_generate_key_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_generate_key_t *out) {
  if (!out) {
    return false;
  }

  km_command_generate_key_t command;

  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_u8(dz, &command.type)) {
    ESP_LOGE(TAG, "Failed to deserialize command type");
    return false;
  }

  if (!km_dz_u16(dz, &command.size)) {
    ESP_LOGE(TAG, "Failed to deserialize command size");
    return false;
  }

  if (!km_dz_str(pool, dz, &command.label)) {
    ESP_LOGE(TAG, "Failed to deserialize command label");
    return false;
  }

  *out = command;
  return true;
}

bool km_command_public_key_deserialize(km_memory_pool_t *pool,
                                       const uint8_t *payload, size_t len,
                                       km_command_public_key_t *out) {
  if (!out) {
    return false;
  }

  km_command_public_key_t command;

  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);
  if (!km_dz_u32(dz, &command.slot) || !km_dz_str(pool, dz, &command.label)) {
    return false;
  }
  // km_dz_free(dz);

  *out = command;
  return true;
}

size_t km_command_response_public_key_serialize(
    km_memory_pool_t *pool, const km_command_response_public_key_t *command,
    uint8_t **out) {
  if (!out) {
    return 0;
  }

  km_serializer_t *sz = km_sz_init(command->public_key_length + 4);
  km_sz_array(km_sz_u8, sz, command->public_key, command->public_key_length);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);
  km_sz_free(sz);

  return len;
}

bool km_command_sign_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_sign_t *out) {
  if (!out) {
    return false;
  }

  km_command_sign_t command;

  km_deserializer_t *dz = km_dz_init_copy(pool, (uint8_t *)payload, len);
  if (!km_dz_u32(dz, &command.slot) || !km_dz_str(pool, dz, &command.label)) {
    return false;
  }

  for (int i = 0; i < 32; i++) {
    uint8_t out;
    if (!km_dz_u8(dz, &out)) {
      return false;
    }
    command.digest[i] = out;
  }

  *out = command;
  return true;
}

size_t
km_command_response_sign_serialize(km_memory_pool_t *pool,
                                   const km_command_response_sign_t *command,
                                   uint8_t **out) {
  if (!out) {
    return 0;
  }

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  for (int i = 0; i < 64; i++) {
    km_sz_u8(sz, command->signature[i]);
  }

  size_t len = sz->len;
  *out = km_memory_alloc(pool, sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);
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

  if (!km_dz_u32(dz, &command.slot) || !km_dz_str(pool, dz, &command.label)) {
    return false;
  }

  km_dz_u32(dz, &command.plaintext_length);
  command.plaintext =
      km_memory_alloc(pool, sizeof(uint8_t) * command.plaintext_length);
  km_dz_array(km_dz_u8, dz, command.plaintext, command.plaintext_length);
  km_dz_array(km_dz_u8, dz, command.nonce, 12);

  *out = command;
  return true;
}

size_t km_command_response_encrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_encrypt_t *command,
    uint8_t **out) {
  if (!out) {
    return 0;
  }

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_array(km_sz_u8, sz, command->ciphertext, command->ciphertext_length);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);
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

  if (!km_dz_u32(dz, &command.slot) || !km_dz_str(pool, dz, &command.label)) {
    return false;
  }

  km_dz_u32(dz, &command.ciphertext_length);
  command.ciphertext =
      km_memory_alloc(pool, sizeof(uint8_t) * command.ciphertext_length);
  km_dz_array(km_dz_u8, dz, command.ciphertext, command.ciphertext_length);
  km_dz_array(km_dz_u8, dz, command.nonce, 12);

  *out = command;
  return true;
}

size_t km_command_response_decrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_decrypt_t *command,
    uint8_t **out) {
  if (!out) {
    return 0;
  }

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_array(km_sz_u8, sz, command->plaintext, command->plaintext_length);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);
  km_sz_free(sz);

  return len;
}

static bool km_command_load_key_metadata(km_memory_pool_t *pool, km_slot_t slot,
                                         const char *label,
                                         km_key_metadata_t *metadata) {
  if (slot != 0) {
    return km_keys_get_meta(pool, slot, metadata);
  }

  km_key_metadata_t key;
  if (!km_keys_find_label(pool, label, &key)) {
    return false;
  }

  return km_keys_get_meta(pool, key.slot, metadata);
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

  km_key_generate_params_t params;
  params.type = command.type;
  params.size = command.size;

  uint32_t key;
  if (!km_crypto_handle_generate(params, &key)) {
    km_usb_write_error("Could not generate key");
    goto cleanup;
  }

  km_key_metadata_t metadata = {
      .slot = key,
      .type = command.type,
      .size = command.size,
      .label = command.label,
      .created_at = 0x0 // TODO: set how?
  };

  if (!km_keys_add_key(pool, &metadata)) {
    km_usb_write_error("Could not persist key metadata");
    goto cleanup;
  }

  km_usb_write_success();

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_public_key(const km_frame_header_t *frame_header,
                                         const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_public_key_t command;
  if (!km_command_public_key_deserialize(pool, payload, frame_header->length,
                                         &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  ESP_LOGI(TAG, "Deserialized command");

  km_key_metadata_t metadata;
  if (!km_command_load_key_metadata(pool, command.slot, command.label,
                                    &metadata)) {
    km_usb_write_error(command.slot == 0 ? "Could not find key by given label"
                                         : "Could not find key metadata");
    goto cleanup;
  }

  ESP_LOGI(TAG, "Loaded key metadata");

  uint8_t *buffer;
  size_t buffer_len;
  if (!km_crypto_export_public_key(pool, metadata, &buffer, &buffer_len)) {
    km_usb_write_error("Could not export public key");
    goto cleanup;
  }

  ESP_LOGI(TAG, "Exported public key");

  km_command_response_public_key_t response;
  response.public_key = buffer;
  response.public_key_length = buffer_len;

  uint8_t *response_buffer;
  size_t response_length = km_command_response_public_key_serialize(
      pool, &response, &response_buffer);
  if (response_length == 0) {
    km_usb_write_error("Could not serialize response");
    goto cleanup;
  }

  ESP_LOGI(TAG, "Serialized command response");
  km_usb_write_response(km_command_response_public_key, response_buffer,
                        response_length);
  ESP_LOGI(TAG, "Done");

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

  km_key_metadata_t metadata;
  if (!km_command_load_key_metadata(pool, command.slot, command.label,
                                    &metadata)) {
    km_usb_write_error(command.slot == 0 ? "Could not find key by given label"
                                         : "Could not find key metadata");
    goto cleanup;
  }

  uint8_t *signature;
  if (!km_crypto_sign(pool, metadata, (uint8_t *)command.digest, &signature)) {
    km_usb_write_error("Could not sign payload");
    goto cleanup;
  }

  km_command_response_sign_t response;
  memcpy(response.signature, signature, 64);

  uint8_t *response_buffer;
  size_t response_length =
      km_command_response_sign_serialize(pool, &response, &response_buffer);

  km_usb_write_response(km_command_response_sign, response_buffer,
                        response_length);

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

  km_key_metadata_t metadata;
  if (!km_command_load_key_metadata(pool, command.slot, command.label,
                                    &metadata)) {
    km_usb_write_error(command.slot == 0 ? "Could not find key with label"
                                         : "Could not find key by slot");
    goto cleanup;
  }

  km_key_encrypt_params_t params;
  params.pool = pool;
  params.key = &metadata;
  params.plaintext = command.plaintext;
  params.plaintext_length = command.plaintext_length;
  memcpy(params.nonce, command.nonce, 12);

  uint8_t *ciphertext;
  size_t ciphertext_len = km_crypto_encrypt(pool, &params, &ciphertext);
  if (ciphertext_len == 0) {
    km_usb_write_error("Could not encrypt given plaintext");
    goto cleanup;
  }

  km_command_response_encrypt_t response;
  response.ciphertext = ciphertext;
  response.ciphertext_length = ciphertext_len;

  uint8_t *response_buffer;
  size_t response_length =
      km_command_response_encrypt_serialize(pool, &response, &response_buffer);

  km_usb_write_response(km_command_response_encrypt, response_buffer,
                        response_length);

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

  km_key_metadata_t metadata;
  if (!km_command_load_key_metadata(pool, command.slot, command.label,
                                    &metadata)) {
    km_usb_write_error(command.slot == 0 ? "Could not find key with label"
                                         : "Could not find key by slot");
    goto cleanup;
  }

  km_key_decrypt_params_t params;
  params.pool = pool;
  params.key = &metadata;
  params.ciphertext = command.ciphertext;
  params.ciphertext_length = command.ciphertext_length;
  memcpy(params.nonce, command.nonce, 12);

  uint8_t *plaintext;
  size_t plaintext_len = km_crypto_decrypt(pool, &params, &plaintext);
  if (plaintext_len == 0) {
    km_usb_write_error("Could not decrypt given ciphertext");
    goto cleanup;
  }

  km_command_response_decrypt_t response;
  response.plaintext = plaintext;
  response.plaintext_length = plaintext_len;

  uint8_t *response_buffer;
  size_t response_length =
      km_command_response_decrypt_serialize(pool, &response, &response_buffer);

  km_usb_write_response(km_command_response_decrypt, response_buffer,
                        response_length);

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
  case km_command_generate_key:
    km_command_handle_generate_key(frame_header, payload);
    break;
  case km_command_public_key:
    km_command_handle_public_key(frame_header, payload);
    break;
  case km_command_sign:
    km_command_handle_sign(frame_header, payload);
    break;
  case km_command_encrypt:
    km_command_handle_encrypt(frame_header, payload);
    break;
  case km_command_decrypt:
    km_command_handle_decrypt(frame_header, payload);
    break;
  default:
    km_usb_write_error("Invalid command");
  }
  km_led_busy_off(ctx);
}
