#ifndef KEYMGR_PROTOCOL_H
#define KEYMGR_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define KM_FRAME_HEADER_SIZE 8
#define KM_FRAME_PAYLOAD_MAX 512
#define KM_FRAME_MAGIC 0x4B4D4752U
#define KM_PROTOCOL_VERSION 0x01

enum km_command_type {
  km_command_ping = 0x01,
  km_command_generate_key = 0x20,
  km_command_public_key = 0x21,
  km_command_sign = 0x22
};

enum km_command_response_type {
  km_command_response_error = 0xFF,
  km_command_response_ok = 0x00,
};

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
