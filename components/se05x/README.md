# SE051 ESP-IDF compatibility layer

This component pins NXP's Plug & Trust mini-package as a Git submodule and
supplies the platform code it needs on ESP-IDF:

- ESP-IDF I2C master transport
- FreeRTOS/ESP timing hooks
- an SE051C2-specific generated SSS feature configuration
- a small default-session diagnostic API
- read-only administrative helpers for memory and object inventory
- AES-key authenticated applet sessions backed by ESP-IDF's PSA crypto API

Initialize the vendor source after cloning the repository:

```sh
git submodule update --init --recursive
```

`se05x_esp_session_open()` deliberately opens a plain, unauthenticated session
for board bring-up and provisioning. `se05x_esp_session_open_aes_key()` opens an
encrypted applet session using an existing 128-bit AES authentication object.
Production object policies, provisioning, and key lifecycle remain outside the
component's compatibility API.

Normal key creation and cryptographic operations should use NXP's `sss_*` API
directly. `se05x_esp_admin.h` only wraps SE051-specific management commands for
which the generic SSS API has no equivalent. These helpers do not create,
update, or delete secure objects.
