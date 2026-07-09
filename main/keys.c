#include "keys.h"
#include "esp_log.h"
#include "serial.h"
#include "storage.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEYMGR_KEYS_MAIN_INDEX "key:index"
#define KEYMGR_KEYS_SLOT_INDEX "key:%lu"

static const char *TAG = "keymgr_keys";

bool key_metadata_deserialize(km_deserializer_t *dz, km_key_metadata_t *out) {
  km_key_metadata_t meta;

  if (!km_dz_u32(dz, &meta.slot) || !km_dz_str(dz, &meta.label) ||
      !km_dz_u8(dz, &meta.type) || !km_dz_u16(dz, &meta.size) ||
      !km_dz_u32(dz, &meta.created_at)) {
    return false;
  }

  *out = meta;
  return true;
}

void key_metadata_serialize(km_serializer_t *sz, km_key_metadata_t *in) {
  km_sz_u32(sz, in->slot);
  km_sz_str(sz, in->label);
  km_sz_u8(sz, in->type);
  km_sz_u16(sz, in->size);
  km_sz_u32(sz, in->created_at);
}

bool key_store_deserialize(km_deserializer_t *dz, km_key_store_t *out) {
  uint32_t size = 0;
  if (!km_dz_u32(dz, &size)) {
    return false;
  }

  out->count = size;
  out->slots = malloc(sizeof(km_slot_t) * size == 0 ? 1 : size);
  km_dz_array(km_dz_u32, dz, out->slots, size);

  return true;
}

void key_store_serialize(km_serializer_t *sz, km_key_store_t *in) {
  km_sz_array(km_sz_u32, sz, in->slots, in->count);
}

bool km_keys_get_meta(km_slot_t slot, km_key_metadata_t *out) {
  char lookup[32];
  size_t n = snprintf(lookup, 32, KEYMGR_KEYS_SLOT_INDEX, slot);
  lookup[n] = '\0';

  size_t index_size = 0;
  uint8_t *index = km_store_read(lookup, &index_size);
  if (index == NULL) {
    ESP_LOGE(TAG, "Key does not exist with that slot ID");
    return false;
  }

  km_deserializer_t *dz = km_dz_init_copy(index, index_size);
  km_key_metadata_t metadata;
  if (!key_metadata_deserialize(dz, &metadata)) {
    ESP_LOGE(TAG, "Could not deserialize key metadata");
    km_dz_free(dz);
    return false;
  }

  *out = metadata;
  km_dz_free(dz);
  return true;
}

bool km_keys_find_label(const char *label, km_key_metadata_t *out) {
  // Read index from NVS
  // TODO: put this in a function
  size_t index_size = 0;
  uint8_t *index_buffer = km_store_read(KEYMGR_KEYS_MAIN_INDEX, &index_size);

  // Deserialize the index
  km_key_store_t index;
  km_deserializer_t *dz = km_dz_init_copy(index_buffer, index_size);
  if (!key_store_deserialize(dz, &index)) {
    ESP_LOGE(TAG, "Could not deserialize key index");
    return false;
  }

  for (int i = 0; i < index.count; i++) {
    km_key_metadata_t key;
    km_keys_get_meta(index.slots[i], &key);

    if (!strcmp(key.label, label)) {
      *out = key;
      return true;
    }

    free(key.label);
  }

  return false;
}

void write_to_key_slot_store(km_key_metadata_t *metadata) {
  char key_buffer[32];
  size_t n = snprintf(key_buffer, 32, KEYMGR_KEYS_SLOT_INDEX, metadata->slot);
  key_buffer[n] = '\0';

  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  key_metadata_serialize(sz, metadata);
  if (!km_store_write(key_buffer, sz->data, sz->len)) {
    ESP_LOGE(TAG, "Could not persist key metadata");
  }
  km_sz_free(sz);
}

void km_keys_init_storage() {
  size_t len;
  if (km_store_read(KEYMGR_KEYS_MAIN_INDEX, &len) != NULL) {
    ESP_LOGI(TAG, "Key index already initialized.");
    return;
  }
  ESP_LOGI(TAG, "Key index not initialized... initializing now...");

  km_key_store_t index;
  index.count = 0;

  km_serializer_t *sz = km_sz_init(4);
  key_store_serialize(sz, &index);

  if (!km_store_write(KEYMGR_KEYS_MAIN_INDEX, sz->data, sz->len)) {
    ESP_LOGE(TAG, "Could not initialize key index in NVS");
    return;
  }

  ESP_LOGI(TAG, "Key index initialized.");
  return;
}

bool km_keys_add_key(km_key_metadata_t *metadata) {
  // Read index from NVS
  size_t index_size = 0;
  uint8_t *index_buffer = km_store_read(KEYMGR_KEYS_MAIN_INDEX, &index_size);

  // Deserialize the index
  km_key_store_t index;
  km_deserializer_t *dz = km_dz_init_copy(index_buffer, index_size);
  if (!key_store_deserialize(dz, &index)) {
    ESP_LOGE(TAG, "Could not deserialize key index");
    return false;
  }

  // Increment the key count and add slot to the list
  index.count++;
  index.slots = realloc(index.slots, sizeof(km_slot_t) * index.count);
  index.slots[index.count - 1] = metadata->slot;

  // Serialize the index and write back to NVS
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  key_store_serialize(sz, &index);
  if (!km_store_write(KEYMGR_KEYS_MAIN_INDEX, sz->data, sz->len)) {
    ESP_LOGE(TAG, "Could not persist key index");
    return false;
  }

  write_to_key_slot_store(metadata);

  // All done
  free(index.slots);
  return true;
}
