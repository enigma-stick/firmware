#include "storage.h"
#include "esp_err.h"
#include "esp_log.h"
#include "memory.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdlib.h>

static const char *NAMESPACE = "keymgr";
static const char *TAG = "keymgr_store";

void km_store_init() {
  esp_err_t err = nvs_flash_init();
  ESP_ERROR_CHECK(err);
}

esp_err_t km_store_read_alloc(km_memory_pool_t *pool, const char *key,
                              void **value, size_t *len) {
  if (key == NULL || value == NULL || len == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  *value = NULL;
  *len = 0;

  nvs_handle_t handle;
  esp_err_t err = nvs_open(NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) {
    if (err != ESP_ERR_NVS_NOT_FOUND) {
      ESP_LOGE(TAG, "read: Could not open NVS handle: %s",
               esp_err_to_name(err));
    }
    return err;
  }

  size_t required_size = 0;
  err = nvs_get_blob(handle, key, NULL, &required_size);
  if (err != ESP_OK) {
    if (err != ESP_ERR_NVS_NOT_FOUND) {
      ESP_LOGE(TAG, "read: Could not get blob size: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
    return err;
  }

  if (required_size == 0) {
    nvs_close(handle);
    return ESP_OK;
  }

  void *raw_data = km_memory_alloc(pool, required_size);
  if (raw_data == NULL) {
    nvs_close(handle);
    return ESP_ERR_NO_MEM;
  }

  err = nvs_get_blob(handle, key, raw_data, &required_size);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "read: Could not get blob data: %s", esp_err_to_name(err));
    nvs_close(handle);
    if (pool == NULL) {
      free(raw_data);
    }
    return err;
  }

  nvs_close(handle);
  *value = raw_data;
  *len = required_size;
  return ESP_OK;
}

void *km_store_read(km_memory_pool_t *pool, const char *key, size_t *len) {
  void *value = NULL;
  size_t value_len = 0;
  esp_err_t err = km_store_read_alloc(pool, key, &value, &value_len);
  if (err != ESP_OK) {
    return NULL;
  }

  if (len != NULL) {
    *len = value_len;
  }
  return value;
}

bool km_store_write(const char *key, const void *value, size_t len) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "write: Could not open NVS handle");
    return false;
  }

  err = nvs_set_blob(handle, key, value, len);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "write: Could not write NVS blob: %s", esp_err_to_name(err));
    nvs_close(handle);
    return false;
  }

  err = nvs_commit(handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "write: Could not commit to NVS store: %s",
             esp_err_to_name(err));
    nvs_close(handle);
    return false;
  }

  nvs_close(handle);
  return true;
}
