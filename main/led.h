#ifndef KEYMGR_LIGHT_H
#define KEYMGR_LIGHT_H

#include "soc/gpio_num.h"
#include <stdbool.h>

typedef struct _led_t {
  gpio_num_t pin;
  bool enabled;
} km_led_t;

void km_led_init(km_led_t *led, gpio_num_t pin);
void km_led_set(km_led_t *led, bool enabled);

#endif // KEYMGR_LIGHT_H
