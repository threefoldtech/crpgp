#include "crpgp.h"
#include <stdio.h>

int main() {
    char err_buf[1024];
    struct SecretKeyParamsBuilder *builder = params_builder_new();
    struct KeyType key_type = {EdDSA, {{0}}};
    if (params_builder_primary_user_id(builder, NULL) != 0) {
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);
    }
    params_builder_key_type(builder, key_type);
    struct SubkeyParamsBuilder *sbuilder = subkey_params_builder_new();
    struct KeyType subkey_type = {ECDH, {{0}}};
    subkey_params_builder_key_type(sbuilder, subkey_type);
    struct SubkeyParams *sparams = subkey_params_builder_build(sbuilder);
    subkey_params_builder_free(sbuilder);
    params_builder_subkey(builder, sparams);
    params_builder_primary_user_id(builder, "Omar Elawady <elawadio@incubaid.com>");    
    struct SecretKeyParams *params = params_builder_build(builder);
    params_builder_free(builder);
    struct SecretKey *sk = params_generate_secret_key_and_free(params);
    struct SignedSecretKey *signed_sk = secret_key_sign(sk);
    char *ser = signed_secret_key_to_armored(signed_sk);
    printf("signed secret key armored string:\n%s\n\n", ser);
    signed_secret_key_free(signed_sk);
    signed_sk = signed_secret_key_from_armored(ser);
    struct PublicKey *pk = signed_secret_key_public_key(signed_sk);
    struct SignedPublicKey *spk = public_key_sign_and_free(pk, signed_sk);
    ptr_free((uint8_t*)ser);
    ser = signed_public_key_to_armored(spk);
    printf("signed public key armored string:\n%s\n\n", ser);
    signed_public_key_free(spk);
    spk = signed_public_key_from_armored(ser);
    ptr_free((uint8_t*)ser);
    uint8_t *data = (uint8_t*)"omar";
    size_t len = sizeof(data);
    struct Signature *sig = signed_secret_key_create_signature(signed_sk, data, len);
    size_t sig_len;
    char *serialized = signature_to_armored(sig, &sig_len);
    printf("signature armored string:\n%s\n\n", serialized);
    struct Signature *deserialized = signature_from_armored(serialized, sig_len);
    if (signed_public_key_verify(spk, data, len, deserialized) == 0) {
        puts("success");
    } else {
        puts("failure");
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);
    }
    len = sizeof(data);
    uint8_t *encrypted = signed_public_key_encrypt_with_any(spk, data, &len);
    if (encrypted == NULL) {
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);    
        return -1;
    }
    uint8_t *decrypted = signed_secret_key_decrypt(signed_sk, encrypted, &len);
    if (decrypted == NULL) {
        error_message(err_buf, 1024);
        printf("error: %s\n", err_buf);    
        return -1;
    }
    printf("decrypted (should be omar): %s", (char*)decrypted);
    signature_free(sig);
    secret_key_free(sk);
    subkey_params_free(sparams);
    signed_secret_key_free(signed_sk);
    signed_public_key_free(spk);
    signature_free(deserialized);
    ptr_free((uint8_t*)serialized);
    ptr_free(encrypted);
    ptr_free(decrypted);
}
