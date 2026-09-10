#ifndef KEYMGR_PROTOCOL_H
#define KEYMGR_PROTOCOL_H

#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>

#define KM_FRAME_HEADER_SIZE 8
#define KM_FRAME_PAYLOAD_MAX 1024
#define KM_FRAME_MAGIC 0x4B4D4752U
#define KM_PROTOCOL_VERSION 0x01

enum km_command_type {
  km_command_ping = 0x01,
  km_command_status = 0x02,
  km_command_init = 0x10,
  km_command_authenticate = 0x11,
  km_command_lock = 0x12,
  km_command_generate_key = 0x20,
  km_command_encrypt = 0x21,
  km_command_decrypt = 0x22,
  km_command_sign = 0x23,
  km_command_verify = 0x24,
  km_command_derive_ecdh = 0x25,
  km_command_get_key = 0x30,
  km_command_list = 0x40,
  km_command_destroy = 0x41,
};

enum km_command_response_type {
  km_command_response_ok = 0x00,
  km_command_response_auth_required = 0x01,
  km_command_response_status = 0x02,
  km_command_response_generate_key = 0x20,
  km_command_response_encrypt = 0x21,
  km_command_response_decrypt = 0x22,
  km_command_response_sign = 0x23,
  km_command_response_verify = 0x24,
  km_command_response_derive_ecdh = 0x25,
  km_command_response_get_key = 0x30,
  km_command_response_list = 0x40,
  km_command_response_error = 0xFF,
};

typedef enum {
  km_error_ok = 0x00,
  km_error_auth_required = 0x01,
  km_error_auth_failed = 0x02,
  km_error_invalid_input = 0x03,
  km_error_unsupported_operation = 0x04,
  km_error_missing_key = 0x05,
  km_error_policy_reject = 0x06,
  km_error_storage = 0x07,
  km_error_bad_command = 0x08,
  km_error_serialize = 0x09,
  km_error_init_failed = 0x0A,
  km_error_invalid_state = 0x0B,
  km_error_fail = 0xFF
} km_error_t;

km_error_t km_err_from_esp(esp_err_t err, km_error_t def);
km_error_t km_err_key_lookup(esp_err_t err, km_error_t def);

typedef struct _frame_header {
  uint8_t magic[4];
  uint8_t version;
  uint8_t command;
  uint16_t length;
} km_frame_header_t;

typedef enum {
  km_frame_parse_ok,
  km_frame_parse_too_long,
} km_frame_parse_result_t;

typedef enum {
  km_frame_find_magic,
  km_frame_read_header,
  km_frame_read_payload,
} km_frame_parser_state_t;

typedef struct _frame_parser {
  km_frame_parser_state_t state;
  uint32_t magic_window;
  uint8_t header_buffer[4];
  uint8_t payload_buffer[KM_FRAME_PAYLOAD_MAX];
  size_t cursor;
  km_frame_header_t header;
} km_frame_parser_t;

typedef void (*km_frame_handler_t)(const km_frame_header_t *frame_header,
                                   const uint8_t *payload, void *ctx);

km_frame_header_t km_frame_response_header(enum km_command_response_type type,
                                           uint16_t length);
uint8_t *km_frame_build_buffer(const km_frame_header_t *frame_header,
                               const uint8_t *payload, size_t *out_len);
void km_frame_parser_init(km_frame_parser_t *parser);
km_frame_parse_result_t km_frame_parser_feed(km_frame_parser_t *parser,
                                             uint8_t byte,
                                             km_frame_handler_t handler,
                                             void *ctx);

#endif // KEYMGR_PROTOCOL_H
