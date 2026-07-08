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

void km_commands_handle(const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
