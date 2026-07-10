#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "app.h"
#include "memory.h"
#include "protocol.h"
#include "serial.h"
#include <stdint.h>

typedef struct _command_generate_key {
  uint8_t type;
  uint16_t size;
  char *label;
} km_command_generate_key_t;

bool km_command_generate_key_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_generate_key_t *out);

typedef struct _command_public_key {
  uint32_t slot;
  char *label;
} km_command_public_key_t;

bool km_command_public_key_deserialize(km_memory_pool_t *pool,
                                       const uint8_t *payload, size_t len,
                                       km_command_public_key_t *out);

// NOTE: as a consequence of serializing a variable length buffer, the length
// gets encoded by default. We do not read in the public_key_length separately;
// that would be redundant.
typedef struct _command_response_public_key {
  uint32_t public_key_length;
  uint8_t *public_key;
} km_command_response_public_key_t;

size_t km_command_response_public_key_serialize(
    km_memory_pool_t *pool, const km_command_response_public_key_t *command,
    uint8_t **out);

typedef struct _command_sign {
  uint32_t slot;
  char *label;
  uint8_t digest[32];
} km_command_sign_t;

bool km_command_sign_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_sign_t *out);

typedef struct _command_response_sign {
  uint8_t signature[64];
} km_command_response_sign_t;

size_t
km_command_response_sign_serialize(km_memory_pool_t *pool,
                                   const km_command_response_sign_t *command,
                                   uint8_t **out);

typedef struct _command_encrypt {
  uint32_t slot;
  char *label;
  uint32_t plaintext_length;
  uint8_t *plaintext;
  uint8_t nonce[12];
} km_command_encrypt_t;

bool km_command_encrypt_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_encrypt_t *out);

typedef struct _command_response_encrypt {
  uint32_t ciphertext_length;
  uint8_t *ciphertext;
} km_command_response_encrypt_t;

size_t km_command_response_encrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_encrypt_t *command,
    uint8_t **out);

typedef struct _command_decrypt {
  uint32_t slot;
  char *label;
  uint32_t ciphertext_length;
  uint8_t *ciphertext;
  uint8_t nonce[12];
} km_command_decrypt_t;

bool km_command_decrypt_deserialize(km_memory_pool_t *pool,
                                    const uint8_t *payload, size_t len,
                                    km_command_decrypt_t *out);

typedef struct _command_response_decrypt {
  uint32_t plaintext_length;
  uint8_t *plaintext;
} km_command_response_decrypt_t;

size_t km_command_response_decrypt_serialize(
    km_memory_pool_t *pool, const km_command_response_decrypt_t *command,
    uint8_t **out);

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
