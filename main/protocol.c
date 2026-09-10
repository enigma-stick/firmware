#include "protocol.h"
#include "nvs.h"
#include "se_worker.h"
#include <stdlib.h>
#include <string.h>

static const km_frame_header_t km_frame_header_empty;

static void km_frame_header_set_magic(km_frame_header_t *frame_header) {
  frame_header->magic[0] = 'K';
  frame_header->magic[1] = 'M';
  frame_header->magic[2] = 'G';
  frame_header->magic[3] = 'R';
}

km_frame_header_t km_frame_response_header(enum km_command_response_type type,
                                           uint16_t length) {
  km_frame_header_t frame_header = km_frame_header_empty;
  km_frame_header_set_magic(&frame_header);
  frame_header.version = KM_PROTOCOL_VERSION;
  frame_header.command = type;
  frame_header.length = length;
  return frame_header;
}

uint8_t *km_frame_build_buffer(const km_frame_header_t *frame_header,
                               const uint8_t *payload, size_t *out_len) {
  size_t len = frame_header->length + KM_FRAME_HEADER_SIZE;
  uint8_t *buffer = (uint8_t *)malloc(sizeof(uint8_t) * len);
  if (buffer == NULL) {
    return NULL;
  }

  buffer[0] = frame_header->magic[0];
  buffer[1] = frame_header->magic[1];
  buffer[2] = frame_header->magic[2];
  buffer[3] = frame_header->magic[3];
  buffer[4] = frame_header->version;
  buffer[5] = frame_header->command;
  buffer[6] = (frame_header->length >> 8) & 0xFF;
  buffer[7] = frame_header->length & 0xFF;

  if (payload != NULL && frame_header->length > 0) {
    memcpy(buffer + KM_FRAME_HEADER_SIZE, payload, frame_header->length);
  }

  if (out_len != NULL) {
    *out_len = len;
  }
  return buffer;
}

void km_frame_parser_init(km_frame_parser_t *parser) {
  parser->state = km_frame_find_magic;
  parser->magic_window = 0;
  parser->cursor = 0;
  parser->header = km_frame_header_empty;
}

static void km_frame_parser_reset(km_frame_parser_t *parser) {
  km_frame_parser_init(parser);
}

km_frame_parse_result_t km_frame_parser_feed(km_frame_parser_t *parser,
                                             uint8_t byte,
                                             km_frame_handler_t handler,
                                             void *ctx) {
  switch (parser->state) {
  case km_frame_find_magic:
    parser->magic_window = (parser->magic_window << 8) | byte;
    if (parser->magic_window == KM_FRAME_MAGIC) {
      parser->magic_window = 0;
      parser->state = km_frame_read_header;
      parser->cursor = 0;
      km_frame_header_set_magic(&parser->header);
    }
    return km_frame_parse_ok;

  case km_frame_read_header:
    parser->header_buffer[parser->cursor++] = byte;
    if (parser->cursor == sizeof(parser->header_buffer)) {
      parser->header.version = parser->header_buffer[0];
      parser->header.command = parser->header_buffer[1];
      parser->header.length =
          ((uint16_t)parser->header_buffer[2] << 8) | parser->header_buffer[3];

      if (parser->header.length > KM_FRAME_PAYLOAD_MAX) {
        km_frame_parser_reset(parser);
        return km_frame_parse_too_long;
      }

      if (parser->header.length == 0) {
        if (handler != NULL) {
          handler(&parser->header, NULL, ctx);
        }
        km_frame_parser_reset(parser);
        return km_frame_parse_ok;
      }

      parser->state = km_frame_read_payload;
      parser->cursor = 0;
    }
    return km_frame_parse_ok;

  case km_frame_read_payload:
    parser->payload_buffer[parser->cursor++] = byte;
    if (parser->cursor == parser->header.length) {
      if (handler != NULL) {
        handler(&parser->header, parser->payload_buffer, ctx);
      }
      km_frame_parser_reset(parser);
    }
    return km_frame_parse_ok;
  }

  km_frame_parser_reset(parser);
  return km_frame_parse_ok;
}

km_error_t km_err_from_esp(esp_err_t err, km_error_t def) {
  switch (err) {
  case ESP_ERR_INVALID_ARG:
    return km_error_invalid_input;
  case ESP_ERR_NVS_INVALID_HANDLE:
  case ESP_ERR_NVS_INVALID_LENGTH:
  case ESP_ERR_NVS_INVALID_NAME:
  case ESP_ERR_NVS_INVALID_STATE:
    return km_error_storage;
  case ESP_ERR_INVALID_STATE:
    return km_error_invalid_state;
  case ESP_ERR_NOT_SUPPORTED:
    return km_error_unsupported_operation;
  case KM_ERR_AUTH_REQUIRED:
    return km_error_auth_required;
  default:
    return def;
  }
}

km_error_t km_err_key_lookup(esp_err_t err, km_error_t def) {
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    return km_error_missing_key;
  }
  return km_err_from_esp(err, def);
}
