#ifndef EMP_AES_OPT_KS_H__
#define EMP_AES_OPT_KS_H__

//#include "aes_c.h"
#include "emp-tool/emp-tool.h"

#ifdef __cplusplus
extern "C" {
#endif

	void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key);
    void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key);
    void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key);
    void AES_ECB_encrypt(const unsigned char *in, unsigned char *out,
                         unsigned long length, const char *key, int number_of_rounds);

#ifdef __cplusplus
}
#endif

#endif
