#include "keys.h"
#include "serial.h"
#include "storage.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool key_metadata_dz_single(km_deserializer_t *dz, km_key_metadata_t **out) {
  km_key_metadata_t *meta = malloc(sizeof(km_key_metadata_t));

  if (!km_dz_u32(dz, &meta->slot) || !km_dz_str(dz, &meta->label) ||
      !km_dz_u8(dz, &meta->type) || !km_dz_u16(dz, &meta->size) ||
      !km_dz_u32(dz, &meta->created_at)) {
    free(meta);
    return false;
  }

  *out = meta;
  return true;
}

void key_metadata_sz_single(km_serializer_t *sz, km_key_metadata_t *in) {
  km_sz_u32(sz, in->slot);
  km_sz_str(sz, in->label);
  km_sz_u8(sz, in->type);
  km_sz_u16(sz, in->size);
  km_sz_u32(sz, in->created_at);
}

km_key_metadata_t **key_metadata_deserialize(uint8_t *payload, size_t len,
                                             size_t *array_length) {
  km_deserializer_t *dz = km_dz_init_copy(payload, len);

  uint32_t array_size;
  km_dz_u32(dz, &array_size);

  km_key_metadata_t **array = malloc(sizeof(km_key_metadata_t *) * array_size);
  km_dz_array(key_metadata_dz_single, dz, array, array_size);

  *array_length = array_size;

  km_dz_free(dz);
  return array;
}

size_t key_metadata_serialize(km_key_metadata_t **metadata, size_t len,
                              uint8_t **out) {
  km_serializer_t *sz = km_sz_init(KEYMGR_SZ_DEFAULT_ALLOC);
  km_sz_array(key_metadata_sz_single, sz, metadata, len);
  // TODO: capture errors

  *out = malloc(sizeof(uint8_t) * sz->len);
  memcpy(*out, sz->data, sz->len);

  size_t out_len = sz->len;
  km_sz_free(sz);

  return out_len;
}

void key_metadata_array_free(km_key_metadata_t **array, size_t len) {
  for (int i = 0; i < len; i++) {
    free(array[i]->label);
    free(array[i]);
  }
  free(array);
}

km_key_metadata_t **load_key_metadata(size_t *len) {
  size_t blob_size = 0;
  uint8_t *blob = (uint8_t *)km_store_read("key_index", &blob_size);

  if (blob_size == 0) {
    *len = 0;
    return malloc(sizeof(km_key_metadata_t *));
  }

  size_t key_length;
  km_key_metadata_t **keys =
      key_metadata_deserialize(blob, blob_size, &key_length);

  *len = key_length;
  return keys;
}

bool km_keys_find_label(const char *label, km_slot_t *out) {
  size_t key_length;
  km_key_metadata_t **keys = load_key_metadata(&key_length);

  for (int i = 0; i < key_length; i++) {
    if (!strcmp(keys[i]->label, label)) {
      *out = keys[i]->slot;
      key_metadata_array_free(keys, key_length);
      return true;
    }
  }

  key_metadata_array_free(keys, key_length);
  return false;
}

// NOTE: currently very redundant vs km_keys_find_label but when the
// secure element is actually on board, this becomes an I2C operation.
bool km_keys_get_meta(km_slot_t slot, km_key_metadata_t *out) {
  size_t key_length;
  km_key_metadata_t **keys = load_key_metadata(&key_length);

  for (int i = 0; i < key_length; i++) {
    if (keys[i]->slot == slot) {
      *out = *keys[i];
      size_t label_len = strlen(keys[i]->label);
      out->label = malloc(sizeof(char) * (label_len + 1));
      strncpy(out->label, keys[i]->label, label_len);
      out->label[label_len] = '\0';
      key_metadata_array_free(keys, key_length);
      return true;
    }
  }

  key_metadata_array_free(keys, key_length);
  return false;
}

bool km_keys_add_key(km_key_metadata_t *metadata) {
  size_t key_length;
  km_key_metadata_t **keys = load_key_metadata(&key_length);

  // More memory!
  key_length++;
  keys = (km_key_metadata_t **)realloc(keys, sizeof(km_key_metadata_t *) *
                                                 key_length);

  // Copy metadata
  km_key_metadata_t *target_key = malloc(sizeof(km_key_metadata_t));
  keys[key_length - 1] = target_key;
  target_key->slot = metadata->slot;
  target_key->type = metadata->type;
  target_key->size = metadata->size;
  target_key->created_at = metadata->created_at;

  // Deep copy the label since we free it later
  size_t label_len = strlen(metadata->label);
  target_key->label = malloc(sizeof(char) * label_len + 1);
  strncpy(target_key->label, metadata->label, label_len);
  target_key->label[label_len] = '\0';

  // The serializer malloc's for us
  uint8_t *payload;
  size_t payload_length = key_metadata_serialize(keys, key_length, &payload);

  // Write
  km_store_write("key_index", payload, payload_length);

  // Clean up
  free(payload);
  key_metadata_array_free(keys, key_length);

  // Done
  return true;
}
