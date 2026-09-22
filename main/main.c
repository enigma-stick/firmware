#include "app.h"
#include "btn.h"
#include "crypto.h"
#include "esp_log.h"
#include "esp_log_buffer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_status.h"
#include "se05x_impl.h"
#include "se_worker.h"
#include "storage.h"
#include "token.h"
#include "usb_transport.h"

static const char *TAG = "keymgr";

void app_main(void) {
  ESP_LOGI(TAG, "Starting keymgr...");

  // Set up context
  km_app_context_t ctx;
  ctx.led_queue = xQueueCreate(8, sizeof(km_led_event_t));

  // Set up storage
  km_store_init();
  ESP_ERROR_CHECK(km_token_init());

  // Set up crypto
  km_crypto_init();

  // Start SE05X worker
  ESP_ERROR_CHECK(km_se_worker_start());

  // Set up lights and buttons
  km_led_event_listener_start(&ctx);
  km_btn_task_start(&ctx);

  // Set up USB handler
  km_usb_start(&ctx);

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
