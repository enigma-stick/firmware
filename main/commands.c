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
  default:
    km_usb_write_error("Invalid command");
  }
  km_led_busy_off(ctx);
}
