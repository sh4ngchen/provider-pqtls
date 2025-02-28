#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "caesar_cipher.h"

#define SHIFT 3 // 移位 3 个字母

static int caesar_encrypt(unsigned char *out, const unsigned char *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? ((in[i] - 'A' + SHIFT) % 26 + 'A') :
                 (in[i] >= 'a' && in[i] <= 'z') ? ((in[i] - 'a' + SHIFT) % 26 + 'a') :
                 in[i];
    }
    return 1;
}

static int caesar_decrypt(unsigned char *out, const unsigned char *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? ((in[i] - 'A' - SHIFT + 26) % 26 + 'A') :
                 (in[i] >= 'a' && in[i] <= 'z') ? ((in[i] - 'a' - SHIFT + 26) % 26 + 'a') :
                 in[i];
    }
    return 1;
}

const OSSL_DISPATCH caesar_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_ENCRYPT, (void (*)(void))caesar_encrypt },
    { OSSL_FUNC_CIPHER_DECRYPT, (void (*)(void))caesar_decrypt },
    { 0, NULL }
};
