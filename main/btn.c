#include "btn.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_log.h"
#include "led_status.h"
#include "portmacro.h"
#include "se_worker.h"

#define HOLD_TOKEN_RESET_MS 10000
#define HOLD_DEBOUNCE_MS 30
#define HOLD_MAX_SAMPLE_GAP_MS 100

static const char *TAG = "keymgr_btn";
static km_btn_t btn_reset;

void km_btn_init(km_btn_t *btn, gpio_num_t pin) {
  // Set up struct
  btn->pin = pin;

  // Set up GPIO configuration
  gpio_config_t io_conf = {};
  io_conf.intr_type = GPIO_INTR_DISABLE;
  io_conf.mode = GPIO_MODE_INPUT;
  io_conf.pin_bit_mask = (1ULL << btn->pin);
  io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
  io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
  ESP_ERROR_CHECK(gpio_config(&io_conf));
}

bool km_btn_pressed(km_btn_t *btn) { return gpio_get_level(btn->pin) == 0; }

static void km_btn_task_handler(void *ctx) {
  ESP_LOGI(TAG, "Button task initialization done");
  km_app_context_t *app = (km_app_context_t *)ctx;

  bool holding = false;
  bool reported = false;
  bool last_raw = km_btn_pressed(&btn_reset);
  bool pressed = false;
  bool warning_on = false;
  bool armed = false;
  TickType_t pressed_at = 0;
  TickType_t raw_changed_at = xTaskGetTickCount();
  TickType_t last_sample_at = raw_changed_at;

  while (1) {
    se_worker_session_state_t session_state = SE_WORKER_SESSION_CLOSED;
    bool authenticated =
        km_se_worker_get_session_state(&session_state) == ESP_OK &&
        session_state == SE_WORKER_SESSION_AUTHENTICATED;
    TickType_t now = xTaskGetTickCount();
    bool raw_pressed = km_btn_pressed(&btn_reset);

    // A busy worker can delay the status read. Do not count unobserved time
    // toward a continuous hold; require a fresh stable release instead.
    if ((TickType_t)(now - last_sample_at) >=
        pdMS_TO_TICKS(HOLD_MAX_SAMPLE_GAP_MS)) {
      armed = false;
      holding = false;
      reported = false;
      raw_changed_at = now;
    }
    last_sample_at = now;

    if (raw_pressed != last_raw) {
      last_raw = raw_pressed;
      raw_changed_at = now;
    }

    bool stable = (TickType_t)(now - raw_changed_at) >=
                  pdMS_TO_TICKS(HOLD_DEBOUNCE_MS);
    if (stable) {
      pressed = last_raw;
    }

    if (!authenticated) {
      armed = false;
      holding = false;
      reported = false;
    } else if (!armed) {
      // The initial value of pressed is not evidence of a physical release.
      if (stable && !raw_pressed && !pressed) {
        armed = true;
      }
    } else if (!pressed) {
      holding = false;
      reported = false;
    } else if (!holding) {
      holding = true;
      pressed_at = now;
      ESP_LOGI(TAG, "Button pressed");
    } else if (!reported && (TickType_t)(now - pressed_at) >=
                                pdMS_TO_TICKS(HOLD_TOKEN_RESET_MS)) {
      reported = true;
      // Log only: a future reset request must enforce auth in the worker.
      ESP_LOGI(TAG, "Authenticated button hold completed (reset not implemented)");
    }

    bool next_warning_on = false;
    if (holding && !reported) {
      TickType_t elapsed = (TickType_t)(now - pressed_at);
      TickType_t warning_start = pdMS_TO_TICKS(1000);
      TickType_t blink_interval = pdMS_TO_TICKS(250);

      if (elapsed >= warning_start) {
        TickType_t phase = (elapsed - warning_start) / blink_interval;
        next_warning_on = (phase % 2) == 0;
      }
    }

    if (next_warning_on != warning_on) {
      km_led_reset_warning_set(app, next_warning_on);
      warning_on = next_warning_on;
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

void km_btn_task_start(km_app_context_t *ctx) {
  km_btn_init(&btn_reset, 4);
  xTaskCreate(km_btn_task_handler, "km_btn_task_handler", 2048, ctx, 20, NULL);
}
