#ifndef KEYMGR_SE_WORKER_H
#define KEYMGR_SE_WORKER_H

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "key.h"
#include "memory.h"
#include "portmacro.h"
#include "se05x_esp.h"

#define KEYMGR_SE_ECDH_KEY_A_ID 0x4B4DFF33u
#define KEYMGR_SE_ECDH_KEY_B_ID 0x4B4DFF34u

#define KM_ERR_AUTH_REQUIRED 0xf000

typedef enum {
  SE_WORKER_SESSION_CLOSED,
  SE_WORKER_SESSION_AUTHENTICATED,
  SE_WORKER_SESSION_FAULT
} se_worker_session_state_t;

typedef enum {
  SE_REQUEST_GET_UID,
  SE_REQUEST_PROVISION_AUTH_OBJECT,
  SE_REQUEST_PROVISION_HMAC_MASTER,
  SE_REQUEST_OPEN_SESSION,
  SE_REQUEST_CLOSE_SESSION,
  SE_REQUEST_GET_SESSION_STATE,
  SE_REQUEST_GENERATE_AES,
  SE_REQUEST_GENERATE_RSA,
  SE_REQUEST_GENERATE_EC,
  SE_REQUEST_ENCRYPT_AES_GCM,
  SE_REQUEST_DECRYPT_AES_GCM,
  SE_REQUEST_DECRYPT_RSA_OAEP,
  SE_REQUEST_SIGN_RSA_PSS,
  SE_REQUEST_SIGN_EC_ECDSA,
  SE_REQUEST_GET_PUBLIC_KEY_RSA,
  SE_REQUEST_GET_PUBLIC_KEY_EC,
  SE_REQUEST_DESTROY_KEY
} se_request_type_t;

typedef struct _request_t {
  se_request_type_t type;

  StaticSemaphore_t completion_storage;
  SemaphoreHandle_t completion;

  esp_err_t result;

  union {
    struct {
      uint8_t *buffer;
      size_t *length;
    } get_uid;

    struct {
      uint32_t object_id;
      uint8_t key[16];
    } provision_auth_object;

    struct {
      uint32_t object_id;
    } provision_hmac_master;

    struct {
      uint32_t object_id;
      uint8_t auth_key[16];
    } open_session;

    struct {
      se_worker_session_state_t *state;
    } get_session_state;

    struct {
      uint32_t hmac_id;
      uint16_t bits;
      uint32_t *key_id;
    } generate_aes;

    struct {
      uint16_t bits;
      km_key_usage_t usage;
      uint32_t *key_id;
    } generate_rsa;

    struct {
      uint16_t size;
      km_key_usage_t usage;
      uint32_t *key_id;
    } generate_ec;

    struct {
      km_memory_pool_t *pool;
      km_key_metadata_t *key;
      uint8_t *plaintext;
      size_t plaintext_len;
      uint8_t **ciphertext;
      size_t *ciphertext_len;
    } encrypt_aes_gcm;

    struct {
      km_memory_pool_t *pool;
      km_key_metadata_t *key;
      uint8_t *ciphertext;
      size_t ciphertext_len;
      uint8_t **plaintext;
      size_t *plaintext_len;
    } decrypt;

    struct {
      km_memory_pool_t *pool;
      km_key_metadata_t *key;
      uint8_t *message;
      size_t message_len;
      uint8_t **signature;
      size_t *signature_len;
    } sign;

    struct {
      km_memory_pool_t *pool;
      km_key_metadata_t *key;
      uint8_t **public_key;
      size_t *public_key_len;
    } get_public_key;

    struct {
      uint32_t key_id;
    } destroy_key;
  } args;
} se_request_t;

typedef struct {
  QueueHandle_t queue;

  se05x_esp_session_t session;
  se_worker_session_state_t session_state;
  sss_key_store_t key_store;
  bool key_store_initialized;

  uint32_t auth_object_id;
  uint8_t auth_key[16];

  TickType_t last_activity;
} se_worker_context_t;

esp_err_t km_se_worker_start(void);
esp_err_t km_se_worker_get_uid(uint8_t *uid, size_t *length);
esp_err_t km_se_worker_provision_auth_object(uint32_t object_id,
                                             const uint8_t key[16]);
esp_err_t km_se_worker_provision_hmac_master(uint32_t object_id);
esp_err_t km_se_worker_open_session(uint32_t object_id,
                                    const uint8_t auth_key[16]);
esp_err_t km_se_worker_close_session(void);
esp_err_t km_se_worker_get_session_state(se_worker_session_state_t *state);
esp_err_t km_se_worker_generate_aes(uint32_t hmac_id, uint16_t bits,
                                    uint32_t *key_id);
esp_err_t km_se_worker_generate_rsa(uint16_t bits, km_key_usage_t usage,
                                    uint32_t *key_id);
esp_err_t km_se_worker_generate_ec(uint16_t size, km_key_usage_t usage,
                                   uint32_t *key_id);
esp_err_t km_se_worker_encrypt_aes_gcm(km_memory_pool_t *pool,
                                       km_key_metadata_t *key,
                                       uint8_t *plaintext, size_t plaintext_len,
                                       uint8_t **ciphertext,
                                       size_t *ciphertext_len);
esp_err_t
km_se_worker_decrypt_aes_gcm(km_memory_pool_t *pool, km_key_metadata_t *key,
                             uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t **plaintext, size_t *plaintext_len);
esp_err_t
km_se_worker_decrypt_rsa_oaep(km_memory_pool_t *pool, km_key_metadata_t *key,
                              uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t **plaintext, size_t *plaintext_len);
esp_err_t km_se_worker_sign_rsa_pss(km_memory_pool_t *pool,
                                    km_key_metadata_t *key, uint8_t *message,
                                    size_t message_len, uint8_t **signature,
                                    size_t *signature_len);
esp_err_t km_se_worker_sign_ec_ecdsa(km_memory_pool_t *pool,
                                     km_key_metadata_t *key, uint8_t *message,
                                     size_t message_len, uint8_t **signature,
                                     size_t *signature_len);
esp_err_t km_se_worker_get_public_key_rsa(km_memory_pool_t *pool,
                                          km_key_metadata_t *key,
                                          uint8_t **public_key,
                                          size_t *public_key_len);
esp_err_t km_se_worker_get_public_key_ec(km_memory_pool_t *pool,
                                         km_key_metadata_t *key,
                                         uint8_t **public_key,
                                         size_t *public_key_len);
esp_err_t km_se_worker_destroy_key(uint32_t key_id);

#endif // KEYMGR_SE_WORKER_H
