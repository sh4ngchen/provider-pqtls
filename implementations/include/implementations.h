#include <openssl/core.h>
#include <openssl/types.h>

/* Provider Context 相关声明 */
typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;  /* OpenSSL核心句柄 */
    OSSL_LIB_CTX *libctx;            /* 库上下文 */
} PROV_CTX;

/* Provider Context 工具函数 */
OSSL_LIB_CTX *PROV_CTX_get0_libctx(const PROV_CTX *ctx);

/* Key Management */
extern const OSSL_DISPATCH kyber_keymgmt_512_functions[];
extern const OSSL_DISPATCH kyber_keymgmt_768_functions[];
extern const OSSL_DISPATCH kyber_keymgmt_1024_functions[];

/* Encoder & Decoder */
extern const OSSL_DISPATCH kyber_encoder_pem_functions[];
extern const OSSL_DISPATCH kyber_encoder_der_functions[];
extern const OSSL_DISPATCH kyber_decoder_der_functions[];

/* KEM */
extern const OSSL_DISPATCH kyber_kem_512_functions[];
extern const OSSL_DISPATCH kyber_kem_768_functions[];
extern const OSSL_DISPATCH kyber_kem_1024_functions[];