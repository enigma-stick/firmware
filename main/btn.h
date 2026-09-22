#ifndef KEYMGR_BTN_H
#define KEYMGR_BTN_H

#include "app.h"
#include "soc/gpio_num.h"

typedef struct {
  gpio_num_t pin;
} km_btn_t;

void km_btn_init(km_btn_t *btn, gpio_num_t pin);
bool km_btn_pressed(km_btn_t *btn);

void km_btn_task_start(km_app_context_t *ctx);

#endif // KEYMGR_BTN_H
