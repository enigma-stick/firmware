#include "crypto.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "keys.h"
#include "led.h"
#include "storage.h"
#include "usb_transport.h"

static const char *TAG = "keymgr";

static km_led_t led_red;
static km_led_t led_blue;

void app_main(void) {
  ESP_LOGI(TAG, "Starting keymgr...");

  // Set up storage
  km_store_init();
  km_keys_init_storage();

  // Set up crypto
  km_crypto_init();

  // Set up lights
  km_led_init(&led_red, 1);
  km_led_init(&led_blue, 2);

  // Set blue LED to always on
  km_led_set(&led_blue, true);

  // Set up USB handler
  km_usb_start();

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
