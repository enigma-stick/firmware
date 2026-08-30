#include "commands.h"
#include "app.h"
#include "crypto.h"
#include "esp_err.h"
#include "esp_log.h"
#include "led_status.h"
#include "memory.h"
#include "protocol.h"
#include "se_worker.h"
#include "serial.h"
#include "token.h"
#include "usb_transport.h"
#include <string.h>

static const char *TAG = "keymgr_cmd";

bool km_command_init_deserialize(km_memory_pool_t *pool, const uint8_t *payload,
                                 size_t len, km_command_init_t *out) {
  if (!out) {
    return false;
  }

  km_command_init_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_str(pool, dz, &command.pin)) {
    return false;
  }

  *out = command;
  return true;
}

bool km_command_authenticate_deserialize(km_memory_pool_t *pool,
                                         const uint8_t *payload, size_t len,
                                         km_command_authenticate_t *out) {
  if (!out) {
    return false;
  }
  km_command_authenticate_t command;
  km_deserializer_t *dz = km_dz_init_copy(pool, payload, len);

  if (!km_dz_str(pool, dz, &command.pin)) {
    return false;
  }

  *out = command;
  return true;
}

size_t km_command_response_status_serialize(
    km_memory_pool_t *pool, const km_command_response_status_t *response,
    uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);

  km_sz_u32(sz, response->token_state);
  km_sz_u32(sz, response->session_state);

  size_t len = sz->len;
  *out = km_memory_alloc(pool, len);
  memcpy(*out, sz->data, len);
  km_sz_free(sz);

  return len;
}

static void km_command_handle_init(const km_frame_header_t *frame_header,
                                   const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_init_t command;
  if (!km_command_init_deserialize(pool, payload, frame_header->length,
                                   &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  size_t pin_length = strlen(command.pin);
  esp_err_t err = km_token_provision(command.pin, pin_length);

  km_crypto_zero(command.pin, pin_length);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not initialize token: %s", esp_err_to_name(err));
    km_usb_write_error("Failed to initialize token");
    goto cleanup;
  }

  km_usb_write_success();

cleanup:
  km_memory_free(pool);
}

static void
km_command_handle_authenticate(const km_frame_header_t *frame_header,
                               const uint8_t *payload) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_command_authenticate_t command;
  if (!km_command_authenticate_deserialize(pool, payload, frame_header->length,
                                           &command)) {
    km_usb_write_error("Could not deserialize command");
    goto cleanup;
  }

  size_t pin_length = strlen(command.pin);
  esp_err_t err = km_token_authenticate(command.pin, pin_length);
  km_crypto_zero(command.pin, pin_length);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not authenticate token: %s", esp_err_to_name(err));
    km_usb_write_error("Failed to authenticate token");
    goto cleanup;
  }

  km_usb_write_success();

cleanup:
  km_memory_free(pool);
}

static void km_command_handle_status(void) {
  km_memory_pool_t *pool = km_memory_init(KEYMGR_MEMORY_DEFAULT_BYTES);

  km_token_status_t token_status;
  if (km_token_get_status(&token_status) != ESP_OK) {
    km_usb_write_error("Could not get token status");
    goto cleanup;
  }

  km_command_response_status_t response = {
      .token_state = token_status.token_state,
      .session_state = token_status.session_state};
  uint8_t *payload;
  size_t len = km_command_response_status_serialize(pool, &response, &payload);
  if (len == 0) {
    km_usb_write_error("Could not serialize response");
    goto cleanup;
  }

  km_usb_write_response(km_command_response_status, payload, len);

cleanup:
  km_memory_free(pool);
}

void km_commands_handle(km_app_context_t *ctx,
                        const km_frame_header_t *frame_header,
                        const uint8_t *payload) {
  if (frame_header->version != KM_PROTOCOL_VERSION) {
    km_usb_write_error("Invalid command version");
    return;
  }

  km_led_busy_on(ctx);
  switch (frame_header->command) {
  case km_command_ping:
    km_usb_write_success();
    break;
  case km_command_init:
    km_command_handle_init(frame_header, payload);
    break;
  case km_command_authenticate:
    km_command_handle_authenticate(frame_header, payload);
    break;
  case km_command_status:
    km_command_handle_status();
    break;
  default:
    km_usb_write_error("Invalid command");
  }
  km_led_busy_off(ctx);
}
