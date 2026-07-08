#ifndef KEYMGR_COMMANDS_H
#define KEYMGR_COMMANDS_H

#include "protocol.h"
#include <stdint.h>

void km_commands_handle(const km_frame_header_t *frame_header,
                        const uint8_t *payload);

#endif // KEYMGR_COMMANDS_H
