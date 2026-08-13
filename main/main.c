#include "app.h"
#include "crypto.h"
#include "esp_log.h"
#include "esp_log_buffer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "keys.h"
#include "led.h"
#include "led_status.h"
#include "se05x_esp.h"
#include "storage.h"
#include "usb_transport.h"

#include <stdlib.h>

static const char *TAG = "keymgr";

static void se05x_diagnostic_task(void *context) {
  (void)context;

  se05x_esp_session_t *session = calloc(1, sizeof(*session));
  if (session == NULL) {
    ESP_LOGE(TAG, "Unable to allocate SE051 diagnostic session");
    vTaskDelete(NULL);
    return;
  }

  sss_status_t status = se05x_esp_session_open(session);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "SE051 SSS session open failed: 0x%08lX",
             (unsigned long)status);
    free(session);
    vTaskDelete(NULL);
    return;
  }

  se05x_esp_info_t info;
  status = se05x_esp_get_info(session, &info);
  if (status != kStatus_SSS_Success) {
    ESP_LOGE(TAG, "SE051 Get Info failed: 0x%08lX", (unsigned long)status);
    se05x_esp_session_close(session);
    free(session);
    vTaskDelete(NULL);
    return;
  }

  ESP_LOGI(TAG, "SE051 communication and SSS session confirmed");
  ESP_LOGI(TAG, "SE051 applet version response [%u]",
           (unsigned)info.applet_version_length);
  ESP_LOG_BUFFER_HEX(TAG, info.applet_version, info.applet_version_length);
  ESP_LOGI(TAG, "SE051 unique ID [%u]", (unsigned)info.uid_length);
  ESP_LOG_BUFFER_HEX(TAG, info.uid, info.uid_length);
  ESP_LOGI(TAG, "SE051 random sample [%u]",
           (unsigned)sizeof(info.random_sample));
  ESP_LOG_BUFFER_HEX(TAG, info.random_sample, sizeof(info.random_sample));

  se05x_esp_session_close(session);
  free(session);
  ESP_LOGI(TAG, "SE051 diagnostic session closed cleanly");
  vTaskDelete(NULL);
}

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

  // Temporary, non-destructive SE051 board bring-up. This task opens a plain
  // SSS session, reads identity/version information, samples the hardware RNG,
  // and closes the session. It does not create or modify secure objects.
  BaseType_t se05x_task_created =
      xTaskCreate(se05x_diagnostic_task, "se05x_diag", 12288, NULL, 12, NULL);
  if (se05x_task_created != pdPASS) {
    ESP_LOGE(TAG, "Unable to start SE051 diagnostic task");
  }

  // Set up lights
  km_led_event_listener_start(&ctx);

  // Set up USB handler
  km_usb_start(&ctx);

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
