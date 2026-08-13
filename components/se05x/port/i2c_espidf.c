#include "i2c_a7.h"

#include "driver/i2c_master.h"
#include "esp_err.h"
#include "esp_log.h"
#include "sdkconfig.h"

#include <stdint.h>
#include <stdlib.h>

typedef struct {
  i2c_master_bus_handle_t bus;
  i2c_master_dev_handle_t device;
} se05x_i2c_context_t;

static const char *TAG = "se05x_i2c";

static i2c_error_t se05x_i2c_map_error(esp_err_t error) {
  if (error == ESP_OK) {
    return I2C_OK;
  }
  if (error == ESP_ERR_TIMEOUT) {
    return I2C_TIME_OUT;
  }
  return I2C_FAILED;
}

static void se05x_i2c_cleanup(se05x_i2c_context_t *context) {
  if (context == NULL) {
    return;
  }

  if (context->device != NULL) {
    i2c_master_bus_rm_device(context->device);
  }
  if (context->bus != NULL) {
    i2c_del_master_bus(context->bus);
  }
  free(context);
}

i2c_error_t axI2CInit(void **conn_ctx, const char *device_name) {
  if (conn_ctx == NULL) {
    return I2C_FAILED;
  }
  *conn_ctx = NULL;

  if (device_name != NULL) {
    ESP_LOGD(TAG, "Ignoring host connection string on ESP-IDF: %s",
             device_name);
  }

  se05x_i2c_context_t *context = calloc(1, sizeof(*context));
  if (context == NULL) {
    return I2C_FAILED;
  }

  const i2c_master_bus_config_t bus_config = {
      .i2c_port = CONFIG_SE05X_I2C_PORT,
      .sda_io_num = CONFIG_SE05X_I2C_SDA,
      .scl_io_num = CONFIG_SE05X_I2C_SCL,
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .glitch_ignore_cnt = 7,
      .flags.enable_internal_pullup = false,
  };

  esp_err_t error = i2c_new_master_bus(&bus_config, &context->bus);
  if (error != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize I2C controller: %s",
             esp_err_to_name(error));
    se05x_i2c_cleanup(context);
    return se05x_i2c_map_error(error);
  }

  error = i2c_master_probe(context->bus, CONFIG_SE05X_I2C_ADDRESS,
                           CONFIG_SE05X_I2C_TIMEOUT_MS);
  if (error != ESP_OK) {
    ESP_LOGE(TAG, "No SE051 response at I2C address 0x%02X: %s",
             CONFIG_SE05X_I2C_ADDRESS, esp_err_to_name(error));
    se05x_i2c_cleanup(context);
    return se05x_i2c_map_error(error);
  }

  const i2c_device_config_t device_config = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = CONFIG_SE05X_I2C_ADDRESS,
      .scl_speed_hz = CONFIG_SE05X_I2C_FREQUENCY,
  };

  error = i2c_master_bus_add_device(context->bus, &device_config,
                                    &context->device);
  if (error != ESP_OK) {
    ESP_LOGE(TAG, "Failed to attach SE051 to I2C controller: %s",
             esp_err_to_name(error));
    se05x_i2c_cleanup(context);
    return se05x_i2c_map_error(error);
  }

  ESP_LOGI(TAG, "SE051 acknowledged at 0x%02X (SDA=%d, SCL=%d, %d Hz)",
           CONFIG_SE05X_I2C_ADDRESS, CONFIG_SE05X_I2C_SDA,
           CONFIG_SE05X_I2C_SCL, CONFIG_SE05X_I2C_FREQUENCY);
  *conn_ctx = context;
  return I2C_OK;
}

void axI2CTerm(void *conn_ctx, int mode) {
  (void)mode;
  se05x_i2c_cleanup((se05x_i2c_context_t *)conn_ctx);
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus,
                       unsigned char addr, unsigned char *tx,
                       unsigned short tx_len) {
  (void)addr;
  if (conn_ctx == NULL || bus != I2C_BUS_0 || tx == NULL || tx_len == 0 ||
      tx_len > MAX_DATA_LEN) {
    return I2C_FAILED;
  }

  se05x_i2c_context_t *context = (se05x_i2c_context_t *)conn_ctx;
  esp_err_t error = i2c_master_transmit(context->device, tx, tx_len,
                                        CONFIG_SE05X_I2C_TIMEOUT_MS);
  return se05x_i2c_map_error(error);
}
i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr,
                      unsigned char *rx, unsigned short rx_len) {
  (void)addr;
  if (conn_ctx == NULL || bus != I2C_BUS_0 || rx == NULL || rx_len == 0 ||
      rx_len > MAX_DATA_LEN) {
    return I2C_FAILED;
  }

  se05x_i2c_context_t *context = (se05x_i2c_context_t *)conn_ctx;
  esp_err_t error = i2c_master_receive(context->device, rx, rx_len,
                                       CONFIG_SE05X_I2C_TIMEOUT_MS);
  return se05x_i2c_map_error(error);
}
