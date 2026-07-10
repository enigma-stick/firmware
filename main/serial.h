#ifndef KEYMGR_SERIAL_H
#define KEYMGR_SERIAL_H

#include "memory.h"
#include <stdbool.h>
#include <stdint.h>

#define KEYMGR_SZ_DEFAULT_ALLOC 0
#define KEYMGR_SZ_DEFAULT_ALLOC_SIZE 32

// fn<T> :: (km_serializer_t*, T in) -> void
#define km_sz_array(fn, sz, arr, SIZE)                                         \
  do {                                                                         \
    km_sz_u32(sz, SIZE);                                                       \
    for (int i = 0; i < SIZE; i++) {                                           \
      fn(sz, arr[i]);                                                          \
    }                                                                          \
  } while (0)

// Requires reading the u32 _first_
// fn<T> :: (km_deserializer_t*, T* out) -> bool
#define km_dz_array(fn, dz, arr, size)                                         \
  do {                                                                         \
    for (int i = 0; i < size; i++) {                                           \
      if (!fn(dz, &arr[i])) {                                                  \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
  } while (0)

typedef struct _serializer_t {
  uint8_t *data;
  size_t len;
  size_t allocated;
} km_serializer_t;

typedef struct _deserializer_t {
  uint8_t *data;
  size_t len;
  size_t cursor;
  bool owned;
  bool failed;
} km_deserializer_t;

km_serializer_t *km_sz_init(size_t alloc);
void km_sz_free(km_serializer_t *sz);
void km_sz_u8(km_serializer_t *sz, uint8_t x);
void km_sz_u16(km_serializer_t *sz, uint16_t x);
void km_sz_u32(km_serializer_t *sz, uint32_t x);
void km_sz_str(km_serializer_t *sz, const char *x);
void km_sz_bool(km_serializer_t *sz, bool x);

// km_deserializer_t *km_dz_init_copy(const uint8_t *data, size_t len);
km_deserializer_t *km_dz_init_copy(km_memory_pool_t *pool, const uint8_t *data,
                                   size_t len);
km_deserializer_t *km_dz_init_move(km_memory_pool_t *pool, uint8_t *data,
                                   size_t len);
void km_dz_free(km_deserializer_t *dz);
bool km_dz_u8(km_deserializer_t *dz, uint8_t *out);
bool km_dz_u16(km_deserializer_t *dz, uint16_t *out);
bool km_dz_u32(km_deserializer_t *dz, uint32_t *out);
bool km_dz_str(km_memory_pool_t *pool, km_deserializer_t *dz, char **out);
bool km_dz_bool(km_deserializer_t *dz, bool *out);

#endif // KEYMGR_SERIAL_H
