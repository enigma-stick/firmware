#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "app.h"
#include "key.h"
#include "protocol.h"
#include "token.h"
#include <stdint.h>

typedef struct {
  char *pin;
} km_command_init_t;

typedef struct {
  char *pin;
} km_command_authenticate_t;

typedef struct {
  km_key_type_t type;
  km_key_usage_t usage;
  uint16_t bits;
  char *label;
  uint32_t timestamp;
} km_command_generate_key_t;

typedef struct {
  uint32_t key_id;
} km_command_response_generate_key_t;

typedef struct {
  uint32_t key_id;
  uint8_t *plaintext;
  size_t plaintext_len;
} km_command_encrypt_t;

typedef struct {
  uint8_t *ciphertext;
  size_t ciphertext_len;
} km_command_response_encrypt_t;

typedef struct {
  uint32_t key_id;
  uint8_t *ciphertext;
  size_t ciphertext_len;
} km_command_decrypt_t;

typedef struct {
  uint8_t *plaintext;
  size_t plaintext_len;
} km_command_response_decrypt_t;

typedef struct {
  uint32_t key_id;
  uint8_t *message;
  size_t message_len;
} km_command_sign_t;

typedef struct {
  uint8_t *signature;
  size_t signature_len;
} km_command_response_sign_t;

typedef struct {
  uint32_t key_id;
  uint8_t *message;
  size_t message_len;
  uint8_t *signature;
  size_t signature_len;
} km_command_verify_t;

typedef struct {
  uint8_t verified;
} km_command_response_verify_t;

typedef struct {
  uint32_t key_id;
} km_command_get_key_t;

typedef struct {
  uint32_t encoding;
  uint8_t *public_key;
  uint32_t public_key_len;
} km_command_response_get_key_t;

typedef struct {
  uint32_t filter_flags;
  km_key_type_t key_type;
  km_key_usage_t key_usage;
  char *key_label;
  uint32_t key_id;
} km_command_list_t;

typedef struct {
  uint32_t count;
  km_key_metadata_t *keys;
} km_command_response_list_t;

typedef struct {
  uint32_t key_id;
} km_command_destroy_t;

typedef struct {
  km_token_state_t token_state;
  se_worker_session_state_t session_state;
} km_command_response_status_t;

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
