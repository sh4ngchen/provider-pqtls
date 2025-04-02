#ifndef PQTLS_UTIL_H
#define PQTLS_UTIL_H

#include <openssl/x509.h>
#include <openssl/types.h>

X509_PUBKEY *pltls_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp, long len,
                                           OSSL_LIB_CTX *libctx);

#endif /* PQTLS_UTIL_H */
