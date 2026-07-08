#ifndef KEYMGR_SERIAL_H
#define KEYMGR_SERIAL_H

#include <stdbool.h>
#include <stdint.h>

#define KEYMGR_SZ_DEFAULT_ALLOC 0
#define KEYMGR_SZ_DEFAULT_ALLOC_SIZE 32

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

km_deserializer_t *km_dz_init_copy(uint8_t *data, size_t len);
km_deserializer_t *km_dz_init_move(uint8_t *data, size_t len);
void km_dz_free(km_deserializer_t *dz);
bool km_dz_u8(km_deserializer_t *dz, uint8_t *out);
bool km_dz_u16(km_deserializer_t *dz, uint16_t *out);
bool km_dz_u32(km_deserializer_t *dz, uint32_t *out);
bool km_dz_str(km_deserializer_t *dz, char **out);
bool km_dz_bool(km_deserializer_t *dz, bool *out);

#endif // KEYMGR_SERIAL_H
