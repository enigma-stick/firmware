#include "storage.h"
#include "esp_err.h"
#include "esp_log.h"
#include "memory.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdlib.h>
#include <strings.h>

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

esp_err_t km_store_get_entries(km_memory_pool_t *pool, char ***labels,
                               size_t *count) {
  if (pool == NULL || labels == NULL || count == NULL) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t handle = {0};
  nvs_iterator_t iter = {0};
  bool iter_open = false;
  bool label_alloc = false;

  *labels = NULL;
  *count = 0;

  esp_err_t err = nvs_open(NAMESPACE, NVS_READONLY, &handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "entries: could not open nvs handle");
    return err;
  }

  err = nvs_entry_find_in_handle(handle, NVS_TYPE_BLOB, &iter);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    err = ESP_OK;
    goto cleanup;
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "entries: could not find in handle");
    goto cleanup;
  }
  iter_open = true;

  nvs_entry_info_t info = {0};
  size_t label_capacity = 1;
  size_t label_count = 0;
  char **found_labels = malloc(sizeof(char *) * label_capacity);
  if (found_labels == NULL) {
    err = ESP_ERR_NO_MEM;
    ESP_LOGE(TAG, "malloc failed");
    goto cleanup;
  }
  label_alloc = true;

  while (err == ESP_OK) {
    err = nvs_entry_info(iter, &info);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "entries: error getting entry info");
      goto cleanup;
    }

    size_t this_label_len = strlen(info.key);
    char *this_label = km_memory_alloc(pool, sizeof(char) * this_label_len + 1);
    memcpy(this_label, info.key, this_label_len);
    this_label[this_label_len] = '\0';

    if (label_count == label_capacity) {
      size_t new_capacity = label_capacity * 2;
      char **grown = realloc(found_labels, sizeof(char *) * new_capacity);
      if (grown == NULL) {
        err = ESP_ERR_NO_MEM;
        ESP_LOGE(TAG, "realloc failed");
        goto cleanup;
      }
      found_labels = grown;
      label_capacity = new_capacity;
    }

    found_labels[label_count] = this_label;
    label_count++;

    err = nvs_entry_next(&iter);
  }

  if (err == ESP_ERR_NVS_NOT_FOUND) {
    err = ESP_OK;
  } else {
    ESP_LOGE(TAG, "Invalid error code from NVS entry loop");
    goto cleanup;
  }

  char **result = km_memory_alloc(pool, label_count * sizeof(*result));
  memcpy(result, found_labels, label_count * sizeof(*result));

  *labels = result;
  *count = label_count;

cleanup:
  nvs_close(handle);
  if (iter_open)
    nvs_release_iterator(iter);
  if (label_alloc)
    free(found_labels);

  return err;
}

esp_err_t km_store_delete(const char *key) {
  nvs_handle_t handle;
  esp_err_t err = nvs_open(NAMESPACE, NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "delete: Could not open NVS handle");
    return err;
  }

  err = nvs_erase_key(handle, key);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGI(TAG, "delete: Key meta does not exist; returning early");
    err = ESP_OK;
    goto cleanup;
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "delete: Could not erase key");
    goto cleanup;
  }

  err = nvs_commit(handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "delete: Could not commit key erasure");
    goto cleanup;
  }

cleanup:
  nvs_close(handle);
  return err;
}
