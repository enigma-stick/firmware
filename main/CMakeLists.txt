idf_component_register(SRCS "main.c" "led.c" "storage.c" "serial.c" "protocol.c" "usb_transport.c" "commands.c" "crypto.c" "keys.c" "memory.c" "led_status.c" "se_worker.c" "se05x_impl.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES
                           se05x
                           esp_driver_gpio
                           esp_driver_usb_serial_jtag
                           mbedtls
                           nvs_flash)
