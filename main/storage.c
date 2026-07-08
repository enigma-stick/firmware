#include "storage.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *NAMESPACE = "keymgr";
static const char *TAG = "keymgr_store";

void km_store_init() {
  esp_err_t err = nvs_flash_init();
  ESP_ERROR_CHECK(err);
}

void *km_store_read(const char *key, size_t *len) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "read: Could not open NVS handle");
    return NULL;
  }

  size_t required_size = 0;
  err = nvs_get_blob(handle, key, NULL, &required_size);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGE(TAG, "read: Could not get blob size");
    nvs_close(handle);
    return NULL;
  }

  void *raw_data = malloc(required_size);
  err = nvs_get_blob(handle, key, raw_data, &required_size);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGE(TAG, "read: Could not get blob data");
    nvs_close(handle);
    return NULL;
  }

  nvs_close(handle);
  if (len) {
    *len = required_size;
  }
  return raw_data;
}

void km_store_write(const char *key, const void *value, size_t len) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "write: Could not open NVS handle");
    return;
  }

  err = nvs_set_blob(handle, key, value, len);
  if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGE(TAG, "write: Could not write NVS blob");
    nvs_close(handle);
    return;
  }

  err = nvs_commit(handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "write: Could not commit to NVS store");
    return;
  }

  nvs_close(handle);
}
