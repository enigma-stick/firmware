#include "led_status.h"
#include "app.h"
#include "esp_log.h"
#include "freertos/idf_additions.h"
#include "led.h"

static km_led_t led_red;
static km_led_t led_blue;

static const char *TAG = "keymgr_led_status";

static void km_led_event_handler(void *ctx) {
  ESP_LOGI(TAG, "LED event handler initialization done");
  km_app_context_t *app = (km_app_context_t *)ctx;

  while (1) {
    km_led_event_t event;
    if (xQueueReceive(app->led_queue, &event, portMAX_DELAY)) {
      switch (event.type) {
      case km_led_event_busy_on:
        km_led_set(&led_red, true);
        break;
      case km_led_event_busy_off:
        km_led_set(&led_red, false);
        break;
      }
    }
  }
}

void km_led_event_listener_start(km_app_context_t *ctx) {
  // Initialize lights
  km_led_init(&led_red, 1);
  km_led_init(&led_blue, 2);

  km_led_set(&led_blue, true);
  km_led_set(&led_red, false);

  // Start listening
  xTaskCreate(km_led_event_handler, "km_led_event_handler", 4096, ctx, 11,
              NULL);
}

void km_led_busy_on(km_app_context_t *ctx) {
  km_led_event_t event;
  event.type = km_led_event_busy_on;

  xQueueSend(ctx->led_queue, &event, 0);
}

void km_led_busy_off(km_app_context_t *ctx) {
  km_led_event_t event;
  event.type = km_led_event_busy_off;

  xQueueSend(ctx->led_queue, &event, 0);
}
