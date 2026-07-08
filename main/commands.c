#include "commands.h"
#include "crypto.h"
#include "keys.h"
#include "usb_transport.h"

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
  default:
    km_usb_write_error("Invalid command");
  }
}
