#include "commands.h"
#include "usb_transport.h"

void km_commands_handle(const km_frame_header_t *frame_header,
                        const uint8_t *payload) {
  if (frame_header->version != KM_PROTOCOL_VERSION) {
    km_usb_write_error("Invalid command version");
    return;
  }

  switch (frame_header->command) {
  case km_command_ping:
    km_usb_write_success();
    break;
  default:
    km_usb_write_error("Invalid command");
  }
}
