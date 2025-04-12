#ifndef KYBER_H
#define KYBER_H

#include "../../crypto/kyber/ref/api.h"
#include "../../provider.h"

/* 定义Kyber的临时OID */
#define OID_kyber512 "1.3.6.1.4.1.2.267.8.2.2"
#define OID_kyber768 "1.3.6.1.4.1.2.267.8.3.3"
#define OID_kyber1024 "1.3.6.1.4.1.2.267.8.4.4"


/* KYBER_KEY 结构体定义 */
typedef struct {
    unsigned char *public_key;
    unsigned char *secret_key;
    size_t public_key_len;
    size_t secret_key_len;
    int has_public;
    int has_private;
    int version;
} KYBER_KEY;

/* KEM上下文结构 */
typedef struct {
    PROV_CTX *provctx;
    KYBER_KEY *pkey;         /* 当前KEM使用的密钥 */
} KYBER_KEM_CTX;

/* KYBER_GEN_CTX 结构体定义 */
typedef struct {
    int selection;
    size_t public_key_len;
    size_t secret_key_len;
    int version;
    char *tls_name;
    char *propq;
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
