#ifndef KYBER_H
#define KYBER_H

#include "../../crypto/kyber/ref/api.h"

/* 定义Kyber的临时OID */
#define OID_kyber "1.3.6.1.4.1.54392.5.1812"

/* KYBER_KEY 结构体定义 */
typedef struct {
    unsigned char *public_key;
    unsigned char *secret_key;
    size_t public_key_len;
    size_t secret_key_len;
    int has_public;
    int has_private;
} KYBER_KEY;

/* KYBER_GEN_CTX 结构体定义 */
typedef struct {
    int selection;
    size_t public_key_len;
    size_t secret_key_len;
} KYBER_GEN_CTX;

/* Decoder context */
typedef struct
{
    char *keytype_name;
    OSSL_LIB_CTX *libctx;
} KYBER_DECODER_CTX;

/* Encoder context */
typedef struct {
    OSSL_LIB_CTX *libctx;
    int only_pub; // 1：只编码公钥
} KYBER_ENCODER_CTX;

#endif // KYBER_H
