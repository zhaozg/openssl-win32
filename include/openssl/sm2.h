#ifndef CCSTC_SM2_H_
# define CCSTC_SM2_H_
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/asn1.h>
# include <openssl/asn1t.h>

typedef struct ecenc_cipher_st {
    BIGNUM *x;
    BIGNUM *y;
    ASN1_OCTET_STRING *digest;
    ASN1_OCTET_STRING *cipher;
} ECENC_CIPHER;

DECLARE_ASN1_FUNCTIONS_const(ECENC_CIPHER)
    DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECENC_CIPHER, ECENC_CIPHER)
ECENC_CIPHER *d2i_ECENC_CIPHER_bio(BIO * bp, ECENC_CIPHER ** cipher);

int SM2_generate_key_part(EC_KEY * eckey);
int SM2_private_decrypt(const BIGNUM * x, const BIGNUM * y,
                        const unsigned char *mac, unsigned int mac_len,
                        const unsigned char *from, unsigned int flen,
                        unsigned char *to, const BIGNUM * key);
int SM2_public_encrypt(const unsigned char *from, unsigned int flen, 
                       BIGNUM * x, BIGNUM * y, /* C1 */
                       unsigned char *mac, unsigned int *mac_len, /* C3 */
                       unsigned char *cipher, unsigned int *cipher_len, /* C2 */
                       EC_KEY * ec);

#endif
