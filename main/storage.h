#ifndef KEYMGR_STORAGE_H
#define KEYMGR_STORAGE_H

#include <stddef.h>
void km_store_init();
void *km_store_read(const char *key, size_t *len);
bool km_store_write(const char *key, const void *value, size_t len);

#endif // KEYMGR_STORAGE_H
