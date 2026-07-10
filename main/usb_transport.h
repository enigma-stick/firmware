#ifndef KEYMGR_USB_TRANSPORT_H
#define KEYMGR_USB_TRANSPORT_H

#include "app.h"
#include "protocol.h"
#include <stdint.h>

void km_usb_start(km_app_context_t *ctx);
void km_usb_write_response(enum km_command_response_type type,
                           const uint8_t *payload, uint16_t len);
void km_usb_write_error(const char *err);
void km_usb_write_success(void);
void km_usb_write_storage_get_response(char *value);

#endif // KEYMGR_USB_TRANSPORT_H
