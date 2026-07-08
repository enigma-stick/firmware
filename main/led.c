#include "led.h"
#include "driver/gpio.h"
#include "soc/gpio_num.h"

void km_led_init(km_led_t *led, gpio_num_t pin) {
  // Set up struct
  led->pin = pin;
  led->enabled = false;

  // Set up GPIO configuration
  gpio_config_t io_conf = {};
  io_conf.intr_type = GPIO_INTR_DISABLE;
  io_conf.mode = GPIO_MODE_OUTPUT;
  io_conf.pin_bit_mask = (1ULL << led->pin);
  io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
  io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
  gpio_config(&io_conf);
  gpio_set_level(led->pin, 0);
}

void km_led_set(km_led_t *led, bool enabled) {
  if (!led) {
    return;
  }

  led->enabled = enabled;
  gpio_set_level(led->pin, led->enabled);
}
