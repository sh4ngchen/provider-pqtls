#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/types.h>
#include "util.h"

struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;

    EVP_PKEY *pkey;

    /* extra data for the callback, used by d2i_PUBKEY_ex */
    OSSL_LIB_CTX *libctx;
    char *propq;

    /* Flag to force legacy keys */
    unsigned int flag_force_legacy : 1;
};

ASN1_SEQUENCE(X509_PUBKEY_INTERNAL) =
    {ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
     ASN1_SIMPLE(
         X509_PUBKEY, public_key,
         ASN1_BIT_STRING)} static_ASN1_SEQUENCE_END_name(X509_PUBKEY,
                                                         X509_PUBKEY_INTERNAL)

X509_PUBKEY
    * pltls_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp, long len,
                                    OSSL_LIB_CTX *libctx) {
    X509_PUBKEY *xpub = NULL;
    
    xpub = (X509_PUBKEY *)ASN1_item_d2i_ex((ASN1_VALUE **)&xpub, pp, len,
                                           ASN1_ITEM_rptr(X509_PUBKEY_INTERNAL),
                                           libctx, NULL);
    
    return xpub;
}