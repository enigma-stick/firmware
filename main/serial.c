#include "serial.h"
#include "esp_log.h"
#include "memory.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "keymgr_serial";

km_serializer_t *km_sz_init(size_t alloc) {
  km_serializer_t *inst = (km_serializer_t *)malloc(sizeof(km_serializer_t));
  inst->len = 0;
  inst->allocated =
      alloc == KEYMGR_SZ_DEFAULT_ALLOC ? KEYMGR_SZ_DEFAULT_ALLOC_SIZE : alloc;
  inst->data = (uint8_t *)malloc(sizeof(uint8_t) * inst->allocated);
  return inst;
}

void km_sz_free(km_serializer_t *sz) {
  free(sz->data);
  free(sz);
}

void km_sz_append_copy(km_serializer_t *sz, const uint8_t *data, size_t len) {
  while (sz->allocated <= sz->len + len) {
    sz->allocated *= 2;
    sz->data = (uint8_t *)realloc(sz->data, sz->allocated);
  }

  memcpy(sz->data + sz->len, data, len);
  sz->len += len;
}

void km_sz_u8(km_serializer_t *sz, uint8_t x) { km_sz_append_copy(sz, &x, 1); }

void km_sz_u16(km_serializer_t *sz, uint16_t x) {
  uint8_t buffer[2] = {(x >> 8) & 0xFF, x & 0XFF};
  km_sz_append_copy(sz, buffer, 2);
}

void km_sz_u32(km_serializer_t *sz, uint32_t x) {
  uint8_t buffer[4] = {(x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF,
                       x & 0xFF};
  km_sz_append_copy(sz, buffer, 4);
}

void km_sz_str(km_serializer_t *sz, const char *x) {
  size_t len = strlen(x);

  // Write string length, and then string
  km_sz_u32(sz, len);
  if (len > 0) {
    km_sz_append_copy(sz, (uint8_t *)x, len);
  }
}

inline void km_sz_bool(km_serializer_t *sz, bool x) { km_sz_u8(sz, x); }

// km_deserializer_t *km_dz_init_copy(const uint8_t *data, size_t len) {
//   km_deserializer_t *inst =
//       (km_deserializer_t *)malloc(sizeof(km_deserializer_t));
//
//   inst->data = (uint8_t *)malloc(sizeof(uint8_t) * len);
//   inst->len = len;
//   inst->cursor = 0;
//   inst->owned = true;
//   inst->failed = false;
//   memcpy(inst->data, data, len);
//
//   return inst;
// }

km_deserializer_t *km_dz_init_move(km_memory_pool_t *pool, uint8_t *data,
                                   size_t len) {
  km_deserializer_t *inst =
      (km_deserializer_t *)km_memory_alloc(pool, sizeof(km_deserializer_t));

  inst->data = data;
  inst->len = len;
  inst->cursor = 0;
  inst->owned = false;
  inst->failed = false;

  return inst;
}

km_deserializer_t *km_dz_init_copy(km_memory_pool_t *pool, const uint8_t *data,
                                   size_t len) {
  km_deserializer_t *inst =
      (km_deserializer_t *)km_memory_alloc(pool, sizeof(km_deserializer_t));

  inst->data = (uint8_t *)km_memory_alloc(pool, sizeof(uint8_t) * len);
  inst->len = len;
  inst->cursor = 0;
  inst->owned = false;
  inst->failed = false;
  memcpy(inst->data, data, len);

  return inst;
}

void km_dz_free(km_deserializer_t *dz) {
  if (dz->owned && dz->data) {
    free(dz->data);
    dz->data = NULL;
  }
  free(dz);
}

bool km_dz_u8(km_deserializer_t *dz, uint8_t *out) {
  if (dz->failed || dz->cursor + 1 > dz->len) {
    dz->failed = true;
    return false;
  }
  uint8_t read = dz->data[dz->cursor++];
  if (out != NULL)
    *out = read;
  return true;
}

bool km_dz_u16(km_deserializer_t *dz, uint16_t *out) {
  if (dz->failed || dz->cursor + 2 > dz->len) {
    dz->failed = true;
    return false;
  }
  uint8_t a = dz->data[dz->cursor++];
  uint8_t b = dz->data[dz->cursor++];

  if (out != NULL)
    *out = (uint16_t)((uint16_t)a << 8 | (uint16_t)b);
  return true;
}

bool km_dz_u32(km_deserializer_t *dz, uint32_t *out) {
  if (dz->failed || dz->cursor + 4 > dz->len) {
    dz->failed = true;
    return false;
  }
  uint8_t a = dz->data[dz->cursor++];
  uint8_t b = dz->data[dz->cursor++];
  uint8_t c = dz->data[dz->cursor++];
  uint8_t d = dz->data[dz->cursor++];

  if (out != NULL)
    *out = (uint32_t)((uint32_t)a << 24 | (uint32_t)b << 16 | (uint32_t)c << 8 |
                      (uint32_t)d);
  return true;
}

bool km_dz_str(km_memory_pool_t *pool, km_deserializer_t *dz, char **out) {
  if (dz->failed) {
    return false;
  }

  uint32_t str_len = 0;
  if (!km_dz_u32(dz, &str_len)) {
    ESP_LOGE(TAG, "Error reading string length");
    return false;
  }

  if (str_len == 0) {
    if (out != NULL) {
      *out = km_memory_alloc(pool, sizeof(char));
      *out[0] = '\0';
    }
    return true;
  }

  if (dz->cursor + str_len > dz->len) {
    ESP_LOGE(TAG,
             "String read out of bounds (cursor=%lu, strlen=%lu, blen=%lu)",
             dz->cursor, str_len, dz->len);
    dz->failed = true;
    return false;
  }

  char *str = (char *)km_memory_alloc(pool, sizeof(char) * (str_len + 1));
  memcpy(str, dz->data + dz->cursor, str_len);
  str[str_len] = '\0';
  dz->cursor += str_len;

  if (out != NULL)
    *out = str;
  return true;
}

inline bool km_dz_bool(km_deserializer_t *dz, bool *out) {
  return km_dz_u8(dz, (uint8_t *)out);
}
