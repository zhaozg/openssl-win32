#ifndef CCSTC_SSL_H
#define CCSTC_SSL_H

# define SSL_TXT_aECC            "aECC"
# define SSL_TXT_ECC             "ECC"
# define SSL_TXT_SM1             "SM1"
# define SSL_TXT_SM4             "SM4"
# define SSL_TXT_SM3             "SM3"

# define SVTS1_1_VERSION                    0x0101
# define SVTS1_1_VERSION_MAJOR              0x01
# define SVTS1_1_VERSION_MINOR              0x01

/* China GM ciphersuites from SSLVPN */
#define SVTS_CK_ECDHE_SM1_SM3   0x00e00001  //{0xe0,0x01}
#define SVTS_CK_ECDHE_SM1_SHA1  0x00e00002  //{0xe0,0x02}
#define SVTS_CK_ECC_SM1_SM3     0x00e00003  //{0xe0,0x03}
#define SVTS_CK_ECC_SM1_SHA1    0x00e00004  //{0xe0,0x04}
#define SVTS_CK_IBSDH_SM1_SM3   0x00e00005  //{0xe0,0x05}
#define SVTS_CK_IBSDH_SM1_SHA1  0x00e00006  //{0xe0,0x06}
#define SVTS_CK_IBC_SM1_SM3     0x00e00007  //{0xe0,0x07}
#define SVTS_CK_IBC_SM1_SHA1    0x00e00008  //{0xe0,0x08}
#define SVTS_CK_RSA_SM1_SM3     0x00e00009  //{0xe0,0x09}
#define SVTS_CK_RSA_SM1_SHA1    0x00e0000a  //{0xe0,0x0a}

#define SVTS_CK_ECDHE_SM2_SM3   0x00e00011  //{0xe0,0x11}
#define SVTS_CK_ECDHE_SM4_SHA1  0x00e00012  //{0xe0,0x12}
#define SVTS_CK_ECC_SM4_SM3     0x00e00013  //{0xe0,0x13}
#define SVTS_CK_ECC_SM4_SHA1    0x00e00014  //{0xe0,0x14}
#define SVTS_CK_IBSDH_SM4_SM3   0x00e00015  //{0xe0,0x15}
#define SVTS_CK_IBSDH_SM4_SHA1  0x00e00016  //{0xe0,0x16}
#define SVTS_CK_IBC_SM4_SM3     0x00e00017  //{0xe0,0x17}
#define SVTS_CK_IBC_SM4_SHA1    0x00e00018  //{0xe0,0x18}
#define SVTS_CK_RSA_SM4_SM3     0x00e00019  //{0xe0,0x19}
#define SVTS_CK_RSA_SM4_SHA1    0x00e0001a  //{0xe0,0x1a}

#define SVTS_TXT_ECDHE_SM1_SM3   "ECDHE-SM1-SM3"    //{0xe0,0x01}
#define SVTS_TXT_ECDHE_SM1_SHA1  "ECDHE-SM1-SHA1"   //{0xe0,0x02}
#define SVTS_TXT_ECC_SM1_SM3     "ECC-SM1-SM3"      //{0xe0,0x03}
#define SVTS_TXT_ECC_SM1_SHA1    "ECC-SM1-SHA1"     //{0xe0,0x04}
#define SVTS_TXT_IBSDH_SM1_SM3   "IBSDH-SM1-SM3"    //{0xe0,0x05}
#define SVTS_TXT_IBSDH_SM1_SHA1  "IBSDH-SM1-SHA1"   //{0xe0,0x06}
#define SVTS_TXT_IBC_SM1_SM3     "IBC-SM1-SM3"      //{0xe0,0x07}
#define SVTS_TXT_IBC_SM1_SHA1    "IBC-SM1-SHA1"     //{0xe0,0x08}
#define SVTS_TXT_RSA_SM1_SM3     "RSA-SM1-SM3"      //{0xe0,0x09}
#define SVTS_TXT_RSA_SM1_SHA1    "RSA-SM1-SHA1"     //{0xe0,0x0a}
#define SVTS_TXT_ECDHE_SM4_SM3   "ECDHE-SM4-SM3"    //{0xe0,0x11}
#define SVTS_TXT_ECDHE_SM4_SHA1  "ECDHE-SM4-SHA1"   //{0xe0,0x12}
#define SVTS_TXT_ECC_SM4_SM3     "ECC-SM4-SM3"      //{0xe0,0x13}
#define SVTS_TXT_ECC_SM4_SHA1    "ECC-SM4-SHA1"     //{0xe0,0x14}
#define SVTS_TXT_IBSDH_SM4_SM3   "IBSDH-SM4-SM3"    //{0xe0,0x15}
#define SVTS_TXT_IBSDH_SM4_SHA1  "IBSDH-SM4-SHA1"   //{0xe0,0x16}
#define SVTS_TXT_IBC_SM4_SM3     "IBC-SM4-SM3"      //{0xe0,0x17}
#define SVTS_TXT_IBC_SM4_SHA1    "IBC-SM4-SHA1"     //{0xe0,0x18}
#define SVTS_TXT_RSA_SM4_SM3     "RSA-SM4-SM3"      //{0xe0,0x19}
#define SVTS_TXT_RSA_SM4_SHA1    "RSA-SM4-SHA1"     //{0xe0,0x1a}

int svts1_accept(SSL *s);

int svts1_num_ciphers(void);
const SSL_CIPHER *svts1_get_cipher(unsigned int u);
const SSL_CIPHER *svts1_get_cipher_by_char(const unsigned char *p);
int svts1_put_cipher_by_char(const SSL_CIPHER *c, unsigned char *p);
int svts1_write_bytes(SSL *s, int type, const void *buf_, int len);
int svts1_dispatch_alert(SSL *s);
int svts1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);

#if 1
# define IMPLEMENT_svts_meth_func(version, func_name, s_accept, s_connect, \
                                s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                tls1_new, \
                tls1_clear, \
                tls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                ssl3_get_message, \
                svts1_read_bytes, \
                svts1_write_bytes, \
                svts1_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                svts1_get_cipher_by_char, \
                svts1_put_cipher_by_char, \
                ssl3_pending, \
                svts1_num_ciphers, \
                svts1_get_cipher, \
                s_get_meth, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }
#endif

SSL_CIPHER *svts1_choose_cipher(SSL *s, STACK_OF(SSL_CIPHER) *clnt,
  STACK_OF(SSL_CIPHER) *srvr);
STACK_OF(SSL_CIPHER) *svts1_bytes_to_cipher_list(SSL *s, unsigned char *p,
  int num,
  STACK_OF(SSL_CIPHER) **skp);

const SSL_METHOD *SVTSv1_1_method(void); /* SVTSv1.1 */
const SSL_METHOD *SVTSv1_1_server_method(void); /* SVTSv1.1 */
const SSL_METHOD *SVTSv1_1_client_method(void); /* SVTSv1.1 */

int svts1_decrypt_keyexchange(const unsigned char*from, int flen, unsigned  char* to, const EC_KEY*key);
int svts1_encrypt_keyexchange(const unsigned char*from, int flen, unsigned char* to, const EC_KEY*key);
int svts1_check_srvr_ecc_cert_and_alg(X509 *x, SSL *s);
int svts1_cipher_get_cert_index(const SSL_CIPHER *c, int sign);
int svts1_get_req_cert_type(SSL *s, unsigned char *p);

#endif
