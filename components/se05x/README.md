# SE051 ESP-IDF compatibility layer

This component pins NXP's Plug & Trust mini-package as a Git submodule and
supplies the platform code it needs on ESP-IDF:

- ESP-IDF I2C master transport
- FreeRTOS/ESP timing hooks
- an SE051C2-specific generated SSS feature configuration
- a small default-session diagnostic API

Initialize the vendor source after cloning the repository:

```sh
git submodule update --init --recursive
```

The initial configuration deliberately uses a plain, unauthenticated session.
It exists only for non-destructive board bring-up and identification. Production
object policies, authenticated sessions, provisioning, and key lifecycle are
outside this component's diagnostic API.
