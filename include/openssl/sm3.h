#ifndef CCSTC_SM3_H_
# define CCSTC_SM3_H_

# define CCSTC_SM3_DIGEST_LENGTH		32
# define CCSTC_SM3_CBLOCK	64
# define CCSTC_SM3_LBLOCK	(CCSTC_SM3_CBLOCK/4)

typedef unsigned char UINT8;
typedef unsigned int UUINT32;

/*
 * SM3 context 
 */
typedef struct {
    UUINT32 stateIV[8];         /* state (ABCDEFGH) */
    UUINT32 count[2];           /* number of bits, modulo 2^64 (lsb first) */
    UUINT32 T[64];              /* the initial const list T. */
    UINT8 buffer[64];           /* input buffer */
} SM3_CONTEXT;

int SM3_Init(SM3_CONTEXT * ctx);
int SM3_Update(SM3_CONTEXT * ctx, const UINT8 * pData, UUINT32 lDataLen);
int SM3_Final(UINT8 Result[32], SM3_CONTEXT * ctx);

#endif                          /* CCSTC_SM3_H_ */
