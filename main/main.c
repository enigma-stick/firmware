#include "app.h"
#include "crypto.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "keys.h"
#include "led.h"
#include "led_status.h"
#include "storage.h"
#include "usb_transport.h"

static const char *TAG = "keymgr";

void app_main(void) {
  ESP_LOGI(TAG, "Starting keymgr...");

  // Set up context
  km_app_context_t ctx;
  ctx.led_queue = xQueueCreate(8, sizeof(km_led_event_t));

  // Set up storage
  km_store_init();
  km_keys_init_storage();

  // Set up crypto
  km_crypto_init();

  // Set up lights
  km_led_event_listener_start(&ctx);

  // Set up USB handler
  km_usb_start(&ctx);

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
