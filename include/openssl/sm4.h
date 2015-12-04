#ifndef CCSTC_SM4_H
# define CCSTC_SM4_H

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes. 
 */
# define SM4_BLOCK_SIZE 16
# define SM4_KEY_SIZE 16

# ifdef  __cplusplus
extern "C" {
# endif

    /*
     * This should be a hidden type, but EVP requires that the size be known
     * * SM4 context structure 
     */
    struct sm4_key_st {
        unsigned long sk[32];   /* !< SM4 subkeys */
    };
    typedef struct sm4_key_st SM4_KEY;

    int SM4_set_encrypt_key(const unsigned char *userKey, const int bits,
                            SM4_KEY * key);
    int SM4_set_decrypt_key(const unsigned char *userKey, const int bits,
                            SM4_KEY * key);

    void SM4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                         const SM4_KEY * key, const int enc);
    void SM4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                         const unsigned long length, const SM4_KEY * key,
                         unsigned char *ivec, const int enc);
    void SM4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                            const unsigned long length, const SM4_KEY * key,
                            unsigned char *ivec, int *num, const int enc);

    void SM4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                            const unsigned long length, const SM4_KEY * key,
                            unsigned char *ivec, int *num);

# ifdef __cplusplus
}
# endif
#endif                          /* sm4.h */
