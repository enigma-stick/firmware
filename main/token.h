#ifndef KEYMGR_TOKEN_H
#define KEYMGR_TOKEN_H

#include "esp_err.h"
#include "key.h"
#include "memory.h"
#include "se05x_esp.h"
#include "se_worker.h"
#include <stdint.h>

#define KEYMGR_TOKEN_METADATA_VERSION 0x01u
#define KEYMGR_TOKEN_SALT_SIZE 16u

#define KEYMGR_SE_AUTH_OBJECT_ID 0x4B4D0001u
#define KEYMGR_SE_HMAC_MASTER_ID 0x4B4D0002u
#define KEYMGR_SE_APP_KEY_BASE 0x4B4D1000u
#define KEYMGR_ESP_HMAC_KEY_ID ((psa_key_id_t)0x004B4D01u)

#define TEST_AUTH_OBJECT_ID 0x4B4DFF30u
#define TEST_HMAC_MASTER_ID 0x4B4DFF31u
#define TEST_AES_CHILD_ID 0x4B4DFF32u

typedef enum {
  KM_TOKEN_UNINITIALIZED,
  KM_TOKEN_PROVISIONING,
  KM_TOKEN_READY
} km_token_state_t;

typedef struct {
  uint8_t version;
  km_token_state_t state;
  uint8_t uid[SE05X_ESP_UID_SIZE];
  uint8_t salt[KEYMGR_TOKEN_SALT_SIZE];
  uint32_t pbkdf2_rounds;
  uint32_t esp_key_id;
  uint32_t se_auth_object_id;
  uint32_t se_hmac_id;
} km_token_metadata_t;

typedef struct {
  km_token_state_t token_state;
  se_worker_session_state_t session_state;
} km_token_status_t;

/** Load the token record, creating an uninitialized record when it is absent.
 */
esp_err_t km_token_init(void);

/** Return the loaded metadata, or NULL if km_token_init has not succeeded. */
const km_token_metadata_t *km_token_get_metadata(void);

/** provision token keys **/
esp_err_t km_token_provision(char *pin, size_t pin_length);

/** derive auth key from PIN **/
esp_err_t km_token_authenticate(char *pin, size_t pin_length);

/** get token and session status **/
esp_err_t km_token_get_status(km_token_status_t *token_status);

/** get key metadata by key id **/
esp_err_t km_token_get_key_metadata(km_memory_pool_t *pool, uint32_t key_id,
                                    km_key_metadata_t *out);

/** generate a key **/
esp_err_t km_token_generate_key(km_key_type_t type, uint16_t bits,
                                km_key_usage_t usage, const char *label,
                                uint32_t timestamp, uint32_t *key_id);

/** encrypt with AES key **/
esp_err_t km_token_encrypt_aes_gcm(km_memory_pool_t *pool,
                                   km_key_metadata_t *key, uint8_t *plaintext,
                                   size_t plaintext_len, uint8_t **ciphertext,
                                   size_t *ciphertext_len);

/** decrypt with AES key **/
esp_err_t km_token_decrypt_aes_gcm(km_memory_pool_t *pool,
                                   km_key_metadata_t *key, uint8_t *ciphertext,
                                   size_t ciphertext_len, uint8_t **plaintext,
                                   size_t *plaintext_len);

/** decrypt with RSA key **/
esp_err_t km_token_decrypt_rsa_oaep(km_memory_pool_t *pool,
                                    km_key_metadata_t *key, uint8_t *ciphertext,
                                    size_t ciphertext_len, uint8_t **plaintext,
                                    size_t *plaintext_len);

/** sign with RSA private key **/
esp_err_t km_token_sign_rsa_pss(km_memory_pool_t *pool, km_key_metadata_t *key,
                                uint8_t *message, size_t message_len,
                                uint8_t **signature, size_t *signature_len);

/** sign with EC private key **/
esp_err_t km_token_sign_ec_ecdsa(km_memory_pool_t *pool, km_key_metadata_t *key,
                                 uint8_t *message, size_t message_len,
                                 uint8_t **signature, size_t *signature_len);

/** generate MAC for message **/
esp_err_t km_token_sign_hmac(km_memory_pool_t *pool, km_key_metadata_t *key,
                             uint8_t *message, size_t message_len,
                             uint8_t **mac, size_t *mac_len);

/** validate MAC for message **/
esp_err_t km_token_verify_hmac(km_memory_pool_t *pool, km_key_metadata_t *key,
                               uint8_t *message, size_t message_len,
                               uint8_t *mac, size_t mac_len, bool *verified);

/** perform ECDH + HKDF **/
esp_err_t km_token_derive_ecdh(km_memory_pool_t *pool, km_key_metadata_t *key,
                               const char *label, uint32_t timestamp,
                               uint8_t *pub_key, size_t pub_key_len,
                               uint8_t **salt, size_t *salt_len,
                               uint32_t *result_id);

/** get public key **/
esp_err_t km_token_get_public_key(km_memory_pool_t *pool,
                                  km_key_metadata_t *key, uint8_t **public_key,
                                  size_t *public_key_len);

/** list keys **/
esp_err_t km_token_list_keys(km_memory_pool_t *pool, km_key_metadata_t **keys,
                             size_t *count, const km_key_type_t *key_type,
                             const km_key_usage_t *key_usage, const char *label,
                             const uint32_t *key_id);

/** destroy key **/
esp_err_t km_token_destroy_key(uint32_t key_id);

#endif // KEYMGR_TOKEN_H
