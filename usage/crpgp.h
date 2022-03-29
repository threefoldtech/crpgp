#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
struct SecretKeyParamsBuilder;
struct SecretKeyParams;
struct SignedSecretKey;
struct SecretKey;
struct PublicKey;
struct Signature;
struct SignedPublicKey;
struct SignedPublicSubKey;
struct SubkeyParams;
struct SubkeyParamsBuilder;

typedef enum KeyType_Tag {
  /**
   * Encryption & Signing with RSA an the given bitsize.
   */
  Rsa,
  /**
   * Encrypting with Curve25519
   */
  ECDH,
  /**
   * Signing with Curve25519
   */
  EdDSA,
} KeyType_Tag;

typedef struct KeyType {
  KeyType_Tag tag;
  union {
    struct {
      uint32_t rsa;
    };
  };
} KeyType;

int last_error_length(void);

/**
 * Write the latest error message to a buffer.
 *
 * # Returns
 *
 * This returns the number of bytes written to the buffer. If no bytes were
 * written (i.e. there is no last error) then it returns `0`. If the buffer
 * isn't big enough or a `null` pointer was passed in, you'll get a `-1`.
 */
int error_message(char *buffer, int length);

char public_key_verify(struct PublicKey *public_key, uint8_t *data, size_t data_len, struct Signature *signature);

uint8_t *public_key_encrypt(struct PublicKey *public_key, uint8_t *data, size_t *len);

struct SignedPublicKey *public_key_sign_and_free(struct PublicKey *public_key, struct SignedSecretKey *secret_key);

char public_key_free(struct PublicKey *public_key);

struct SignedSecretKey *secret_key_sign(struct SecretKey *secret_key);

char secret_key_free(struct SecretKey *secret_key);

struct SecretKey *params_generate_secret_key_and_free(struct SecretKeyParams *params);

struct SecretKeyParamsBuilder *params_builder_new(void);

char params_builder_primary_user_id(struct SecretKeyParamsBuilder *builder, char *primary_user_id);

char params_builder_key_type(struct SecretKeyParamsBuilder *builder, struct KeyType key_type);

char params_builder_subkey(struct SecretKeyParamsBuilder *builder, struct SubkeyParams *subkey);

struct SecretKeyParams *params_builder_build(struct SecretKeyParamsBuilder *builder);

char params_builder_free(struct SecretKeyParamsBuilder *builder);

uint8_t *signature_serialize(struct Signature *signature, size_t *output_len);

struct Signature *signature_deserialize(uint8_t *signature_bytes, size_t len);

char *signature_to_armored(struct Signature *signature, size_t *output_len);

struct Signature *signature_from_armored(char *signature_bytes);

char signature_free(struct Signature *signature);

char signed_public_key_verify(struct SignedPublicKey *signed_public_key,
                              uint8_t *data,
                              size_t data_len,
                              struct Signature *signature);

uint8_t *signed_public_key_encrypt(struct SignedPublicKey *signed_public_key, uint8_t *data, size_t *len);

uint8_t *signed_public_key_encrypt_with_any(struct SignedPublicKey *signed_public_key,
                                            uint8_t *data,
                                            size_t *len);

uint8_t *signed_public_key_to_bytes(struct SignedPublicKey *signed_public_key, size_t *len);

struct SignedPublicKey *signed_public_key_from_bytes(uint8_t *bytes, size_t len);

char *signed_public_key_to_armored(struct SignedPublicKey *signed_public_key);

struct SignedPublicKey *signed_public_key_from_armored(char *s);

char signed_public_key_free(struct SignedPublicKey *public_key);

struct PublicKey *signed_secret_key_public_key(struct SignedSecretKey *signed_secret_key);

struct Signature *signed_secret_key_create_signature(struct SignedSecretKey *signed_secret_key,
                                              uint8_t *data,
                                              size_t len);

uint8_t *signed_secret_key_decrypt(struct SignedSecretKey *secret_key, uint8_t *encrypted, size_t *len);

char signed_secret_key_free(struct SignedSecretKey *signed_secret_key);

uint8_t *signed_secret_key_to_bytes(struct SignedSecretKey *signed_secret_key, size_t *len);

struct SignedSecretKey *signed_secret_key_from_bytes(uint8_t *bytes, size_t len);

char *signed_secret_key_to_armored(struct SignedSecretKey *signed_secret_key);

struct SignedSecretKey *signed_secret_key_from_armored(char *s);

char subkey_params_free(struct SubkeyParams *subkey_params);

struct SubkeyParamsBuilder *subkey_params_builder_new(void);

char subkey_params_builder_key_type(struct SubkeyParamsBuilder *builder, struct KeyType key_type);

char subkey_params_builder_free(struct SubkeyParamsBuilder *builder);

struct SubkeyParams *subkey_params_builder_build(struct SubkeyParamsBuilder *builder);

char ptr_free(uint8_t *ptr);
