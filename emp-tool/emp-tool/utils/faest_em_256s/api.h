#ifndef FAEST_API_H
#define FAEST_API_H

#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 64
#define CRYPTO_BYTES 20956

#define CRYPTO_ALGNAME "faest_em_256s"

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk);
int crypto_sign(
	unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);
int crypto_sign_open(
	unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk);

	
// Rijndael_CCR 
/////////////////////////////////////
#include <stdint.h>

double run_test(uint32_t run_count);
double run_test_time(uint32_t run_count);
double run_test_rijndael256 (uint32_t run_count);
/////////////////////////////////////

#endif
