#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "app.h"
#include "memory.h"
#include "protocol.h"
#include "se_worker.h"
#include "serial.h"
#include "token.h"
#include <stdint.h>

typedef struct {
  char *pin;
} km_command_init_t;

bool km_command_init_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_init_t *out);

typedef struct {
  char *pin;
} km_command_authenticate_t;

bool km_command_authenticate_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_authenticate_t *out);

typedef struct {
  km_token_state_t token_state;
  se_worker_session_state_t session_state;
} km_command_response_status_t;

size_t km_command_response_status_serialize(
    km_memory_pool_t *pool, const km_command_response_status_t *response,
    uint8_t **out);

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
