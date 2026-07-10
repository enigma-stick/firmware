#ifndef KEYMGR_APP_H
#define KEYMGR_APP_H

#include "freertos/idf_additions.h"

typedef struct _app_context {
  QueueHandle_t led_queue;
} km_app_context_t;

#endif // KEYMGR_APP_H
