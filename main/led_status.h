#ifndef KEYMGR_LED_STATUS_H
#define KEYMGR_LED_STATUS_H

#include "app.h"

typedef enum {
  km_led_event_busy_on,
  km_led_event_busy_off,
  km_led_event_reset_warning_on,
  km_led_event_reset_warning_off,
} km_led_event_type_t;

typedef struct _led_event {
  km_led_event_type_t type;
} km_led_event_t;

void km_led_event_listener_start(km_app_context_t *ctx);
void km_led_busy_on(km_app_context_t *ctx);
void km_led_busy_off(km_app_context_t *ctx);
void km_led_reset_warning_set(km_app_context_t *ctx, bool on);

#endif // KEYMGR_LED_STATUS_H
