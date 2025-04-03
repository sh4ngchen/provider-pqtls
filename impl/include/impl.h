#include <openssl/core.h>
#include <openssl/types.h>

/* Key Management */
// Kyber
extern const OSSL_DISPATCH kyber512_keymgmt_functions[];
extern const OSSL_DISPATCH kyber768_keymgmt_functions[];
extern const OSSL_DISPATCH kyber1024_keymgmt_functions[];
// Dilithium
extern const OSSL_DISPATCH dilithium2_keymgmt_functions[];
extern const OSSL_DISPATCH dilithium3_keymgmt_functions[];
extern const OSSL_DISPATCH dilithium5_keymgmt_functions[];

/* Encoder & Decoder */
// Kyber
extern const OSSL_DISPATCH kyber_encoder_pem_functions[];
extern const OSSL_DISPATCH kyber_encoder_der_functions[];
extern const OSSL_DISPATCH kyber_decoder_der_functions[];
// Dilithium
extern const OSSL_DISPATCH dilithium_encoder_pem_functions[];
extern const OSSL_DISPATCH dilithium_encoder_der_functions[];
extern const OSSL_DISPATCH dilithium_decoder_der_functions[];

/* KEM */
extern const OSSL_DISPATCH kyber512_kem_functions[];
extern const OSSL_DISPATCH kyber768_kem_functions[];
extern const OSSL_DISPATCH kyber1024_kem_functions[];

/* Signature */
extern const OSSL_DISPATCH dilithium2_signature_functions[];
extern const OSSL_DISPATCH dilithium3_signature_functions[];
extern const OSSL_DISPATCH dilithium5_signature_functions[];