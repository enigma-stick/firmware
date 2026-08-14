#include "se05x_impl.h"
#include "se_worker.h"

esp_err_t km_se05x_get_uid(uint8_t *uid, size_t *length) {
  esp_err_t result = km_se_worker_get_uid(uid, length);
  return result;
}
