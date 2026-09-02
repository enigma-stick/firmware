#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "app.h"
#include "memory.h"
#include "protocol.h"
#include "se_worker.h"
#include "serial.h"
#include "token.h"
#include <stdint.h>

// km_command_init

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
// km_command_generate_key

typedef enum { km_generate_key_aes = 0x01 } km_generate_key_type_t;

typedef struct {
  km_generate_key_type_t type;
  uint16_t bits;
  char *label;
} km_command_generate_key_t;

bool km_command_generate_key_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_generate_key_t *out);

// command generate key response

typedef struct {
  uint32_t key_id;
} km_command_response_generate_key_t;

size_t km_command_response_generate_key_serialize(
    km_memory_pool_t *pool, const km_command_response_generate_key_t *response,
    uint8_t **out);

// km_command_encrypt

typedef struct {
  uint32_t key_id;
  uint8_t *plaintext;
  size_t plaintext_len;
} km_command_encrypt_t;

bool km_command_encrypt_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_encrypt_t *out);

// encrypt response

typedef struct {
  uint8_t *ciphertext;
  size_t ciphertext_len;
} km_command_response_encrypt_t;

size_t km_command_response_encrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_encrypt_t *response,
    uint8_t **out);

// km_command_decrypt

typedef struct {
  uint32_t key_id;
  uint8_t *ciphertext;
  size_t ciphertext_len;
} km_command_decrypt_t;

bool km_command_decrypt_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_decrypt_t *out);

// decrypt response

typedef struct {
  uint8_t *plaintext;
  size_t plaintext_len;
} km_command_response_decrypt_t;

size_t km_command_response_decrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_decrypt_t *response,
    uint8_t **out);

// status response

typedef struct {
  km_token_state_t token_state;
  se_worker_session_state_t session_state;
} km_command_response_status_t;

size_t km_command_response_status_serialize(
    km_memory_pool_t *pool, const km_command_response_status_t *response,
    uint8_t **out);

// command hanlder

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
