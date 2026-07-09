#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "protocol.h"
#include "serial.h"
#include <stdint.h>

typedef struct _command_generate_key {
  uint8_t type;
  uint16_t size;
  char *label;
} km_command_generate_key_t;

bool km_command_generate_key_deserialize(const uint8_t *payload, size_t len,
                                         km_command_generate_key_t *out);

typedef struct _command_public_key {
  uint32_t slot;
  char *label;
} km_command_public_key_t;

bool km_command_public_key_deserialize(const uint8_t *payload, size_t len,
                                       km_command_public_key_t *out);

// NOTE: as a consequence of serializing a variable length buffer, the length
// gets encoded by default. We do not read in the public_key_length separately;
// that would be redundant.
typedef struct _command_response_public_key {
  uint32_t public_key_length;
  uint8_t *public_key;
} km_command_response_public_key_t;

size_t km_command_response_public_key_serialize(
    const km_command_response_public_key_t *command, uint8_t **out);

typedef struct _command_sign {
  uint32_t slot;
  char *label;
  uint8_t digest[32];
} km_command_sign_t;

bool km_command_sign_deserialize(const uint8_t *payload, size_t len,
                                 km_command_sign_t *out);

typedef struct _command_response_sign {
  uint8_t signature[64];
} km_command_response_sign_t;

size_t
km_command_response_sign_serialize(const km_command_response_sign_t *command,
                                   uint8_t **out);

void km_commands_handle(const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
