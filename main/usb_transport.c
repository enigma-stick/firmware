#include "usb_transport.h"
#include "app.h"
#include "commands.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "serial.h"
#include <stdlib.h>
#include <string.h>

#define USB_BUFFER_SIZE 1024

static const char *TAG = "keymgr_usb";

static void km_usb_frame_handler(const km_frame_header_t *frame_header,
                                 const uint8_t *payload, void *ctx) {
  km_commands_handle(ctx, frame_header, payload);
}

void km_usb_write_response(enum km_command_response_type type,
                           const uint8_t *payload, uint16_t len) {
  km_frame_header_t frame_header = km_frame_response_header(type, len);
  size_t frame_len = 0;
  uint8_t *buffer = km_frame_build_buffer(&frame_header, payload, &frame_len);
  if (buffer == NULL) {
    return;
  }

  int written =
      usb_serial_jtag_write_bytes(buffer, frame_len, 20 / portTICK_PERIOD_MS);

  if (written != frame_len) {
    ESP_LOGE(TAG, "USB response truncated: wrote %d of %zu bytes", written,
             frame_len);
  }
  free(buffer);
}

void km_usb_write_error(km_error_t code, const char *err) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_u8(sz, code);
  km_sz_str(sz, err);
  km_usb_write_response(km_command_response_error, sz->data, sz->len);
  km_sz_free(sz);
}

void km_usb_write_success(void) {
  km_usb_write_response(km_command_response_ok, NULL, 0);
}

static void km_usb_task_handler(void *ctx) {
  usb_serial_jtag_driver_config_t usb_config = {
      .rx_buffer_size = USB_BUFFER_SIZE,
      .tx_buffer_size = USB_BUFFER_SIZE,
  };

  ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb_config));
  ESP_LOGI(TAG, "USB initialization done");

  uint8_t rx_buffer[USB_BUFFER_SIZE];
  km_frame_parser_t parser;
  km_frame_parser_init(&parser);

  while (1) {
    int len = usb_serial_jtag_read_bytes(rx_buffer, USB_BUFFER_SIZE - 1,
                                         20 / portTICK_PERIOD_MS);
    for (int i = 0; i < len; i++) {
      km_frame_parse_result_t result = km_frame_parser_feed(
          &parser, rx_buffer[i], km_usb_frame_handler, ctx);
      if (result == km_frame_parse_too_long) {
        km_usb_write_error(km_error_bad_command, "Command too long");
      }
    }
  }
}

void km_usb_start(km_app_context_t *ctx) {
  xTaskCreate(km_usb_task_handler, "km_usb_task_handler", 8 * 1024, ctx, 10,
              NULL);
}
