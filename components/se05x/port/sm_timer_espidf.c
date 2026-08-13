#include "sm_timer.h"

#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdint.h>

uint32_t sm_initSleep(void) { return 0; }

void sm_sleep(uint32_t milliseconds) {
  if (milliseconds == 0) {
    taskYIELD();
    return;
  }
  vTaskDelay(pdMS_TO_TICKS(milliseconds) > 0 ? pdMS_TO_TICKS(milliseconds) : 1);
}

void sm_usleep(uint32_t microseconds) {
  uint32_t milliseconds = microseconds / 1000;
  uint32_t remainder = microseconds % 1000;

  if (milliseconds > 0) {
    vTaskDelay(pdMS_TO_TICKS(milliseconds) > 0 ? pdMS_TO_TICKS(milliseconds)
                                              : 1);
  }
  if (remainder > 0) {
    esp_rom_delay_us(remainder);
  }
}
