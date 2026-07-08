#ifndef KEYMGR_USB_TRANSPORT_H
#define KEYMGR_USB_TRANSPORT_H

#include "protocol.h"
#include <stdint.h>

void km_usb_start(void);
void km_usb_write_response(enum km_command_response_type type,
                           const uint8_t *payload, uint16_t len);
void km_usb_write_error(const char *err);
void km_usb_write_success(void);
void km_usb_write_storage_get_response(char *value);

#endif // KEYMGR_USB_TRANSPORT_H
