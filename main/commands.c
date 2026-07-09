#include "commands.h"
#include "crypto.h"
#include "keys.h"
#include "protocol.h"
#include "serial.h"
#include "usb_transport.h"
#include <string.h>

bool km_command_generate_key_deserialize(const uint8_t *payload, size_t len,
                                         km_command_generate_key_t *out) {
  if (!out) {
    return false;
  }

  km_command_generate_key_t command;

  km_deserializer_t *dz = km_dz_init_copy(payload, len);
  if (!km_dz_u8(dz, (uint8_t *)&command.type) ||
      !km_dz_u16(dz, &command.size) || !km_dz_str(dz, &command.label)) {
    return false;
  }
  km_dz_free(dz);

  *out = command;
  return true;
}

bool km_command_public_key_deserialize(const uint8_t *payload, size_t len,
                                       km_command_public_key_t *out) {
  if (!out) {
    return false;
  }

  km_command_public_key_t command;

  km_deserializer_t *dz = km_dz_init_copy(payload, len);
  if (!km_dz_u32(dz, &command.slot) || !km_dz_str(dz, &command.label)) {
    return false;
  }
  km_dz_free(dz);

  *out = command;
  return true;
}

size_t km_command_response_public_key_serialize(
    const km_command_response_public_key_t *command, uint8_t **out) {
  if (!out) {
    return 0;
  }

  km_serializer_t *sz = km_sz_init(command->public_key_length + 4);
  km_sz_array(km_sz_u8, sz, command->public_key, command->public_key_length);

  size_t len = sz->len;
  *out = malloc(sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);
  km_sz_free(sz);

  return len;
}

bool km_command_sign_deserialize(const uint8_t *payload, size_t len,
                                 km_command_sign_t *out) {
  if (!out) {
    return false;
  }

  km_command_sign_t command;

  km_deserializer_t *dz = km_dz_init_copy(payload, len);
  if (!km_dz_u32(dz, &command.slot) || !km_dz_str(dz, &command.label)) {
    return false;
  }

  for (int i = 0; i < 32; i++) {
    uint8_t out;
    if (!km_dz_u8(dz, &out)) {
      return false;
    }
    command.digest[i] = out;
  }
  km_dz_free(dz);

  *out = command;
  return true;
}

size_t
km_command_response_sign_serialize(const km_command_response_sign_t *command,
                                   uint8_t **out) {
  if (!out) {
    return 0;
  }

  km_serializer_t *sz = km_sz_init(64);
  for (int i = 0; i < 64; i++) {
    km_sz_u8(sz, command->signature[i]);
  }

  size_t len = sz->len;
  *out = malloc(sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);
  km_sz_free(sz);

  return len;
}

void km_commands_handle(const km_frame_header_t *frame_header,
                        const uint8_t *payload) {
  if (frame_header->version != KM_PROTOCOL_VERSION) {
    km_usb_write_error("Invalid command version");
    return;
  }

  switch (frame_header->command) {
  case km_command_ping:
    km_usb_write_success();
    break;
  case km_command_generate_key: {
    // Deserialize command
    km_command_generate_key_t command;
    if (!km_command_generate_key_deserialize(payload, frame_header->length,
                                             &command)) {
      km_usb_write_error("Could not deserialize command");
      break;
    }

    // Key gen params
    km_key_generate_params_t params;
    params.type = command.type;
    params.size = command.size;

    // Generate key
    uint32_t key;
    if (!km_crypto_handle_generate(params, &key)) {
      km_usb_write_error("Could not generate key");
      break;
    }

    // Persist metadata
    km_key_metadata_t metadata = {
        .slot = key,
        .type = command.type,
        .size = command.size,
        .label = command.label,
        .created_at = 0x0 // TODO: set how?
    };
    km_keys_add_key(&metadata);

    // Send back success
    km_usb_write_success();

    // Cleanup
    free(command.label);
    break;
  }
  case km_command_public_key: {
    km_command_public_key_t command;
    if (!km_command_public_key_deserialize(payload, frame_header->length,
                                           &command)) {
      km_usb_write_error("Could not deserialize command");
      break;
    }

    km_slot_t slot;
    if (command.slot != 0) {
      slot = command.slot;
    } else {
      km_key_metadata_t key;
      if (!km_keys_find_label(command.label, &key)) {
        free(command.label);
        km_usb_write_error("Could not find key by given label");
        break;
      }
      slot = key.slot;
      free(key.label);
    }

    km_key_metadata_t metadata;
    if (!km_keys_get_meta(slot, &metadata)) {
      free(command.label);
      km_usb_write_error("Could not find key metadata");
      break;
    }

    uint8_t *buffer;
    size_t buffer_len;
    if (!km_crypto_export_public_key(metadata, &buffer, &buffer_len)) {
      free(command.label);
      free(metadata.label);
      km_usb_write_error("Could not export public key");
      break;
    }

    km_command_response_public_key_t response;
    response.public_key = buffer;
    response.public_key_length = buffer_len;

    uint8_t *response_buffer;
    size_t response_length =
        km_command_response_public_key_serialize(&response, &response_buffer);

    if (response_length == 0) {
      free(command.label);
      free(metadata.label);
      free(buffer);
      km_usb_write_error("Could not serialize response");
      break;
    }

    km_usb_write_response(km_command_response_public_key, response_buffer,
                          response_length);

    free(metadata.label);
    free(command.label);
    free(buffer);
    free(response_buffer);

    break;
  }
  case km_command_sign: {
    km_command_sign_t command;
    if (!km_command_sign_deserialize(payload, frame_header->length, &command)) {
      km_usb_write_error("Could not deserialize command");
      break;
    }

    km_slot_t slot;
    if (command.slot != 0) {
      slot = command.slot;
    } else {
      km_key_metadata_t key;
      if (!km_keys_find_label(command.label, &key)) {
        free(command.label);
        km_usb_write_error("Could not find key by given label");
        break;
      }
      slot = key.slot;
      free(key.label);
    }

    km_key_metadata_t metadata;
    if (!km_keys_get_meta(slot, &metadata)) {
      free(command.label);
      km_usb_write_error("Could not find key metadata");
      break;
    }

    uint8_t *signature;
    if (!km_crypto_sign(metadata, (uint8_t *)command.digest, &signature)) {
      km_usb_write_error("Could not sign payload");
      break;
    }

    km_command_response_sign_t response;
    memcpy(response.signature, signature, 64);
    free(signature);

    uint8_t *response_buffer;
    size_t response_length =
        km_command_response_sign_serialize(&response, &response_buffer);

    km_usb_write_response(km_command_response_sign, response_buffer,
                          response_length);

    free(response_buffer);
  } break;
  default:
    km_usb_write_error("Invalid command");
  }
}
