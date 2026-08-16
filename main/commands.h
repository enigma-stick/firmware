#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "app.h"
#include "memory.h"
#include "protocol.h"
#include "serial.h"
#include <stdint.h>

typedef struct _command_init {
  char *pin;
} km_command_init_t;

bool km_command_init_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_init_t *out);

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
