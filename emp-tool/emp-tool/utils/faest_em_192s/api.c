#include <assert.h>
#include <string.h>

#include "api.h"
#include "faest.h"
#include "randomness.h"

static_assert(CRYPTO_PUBLICKEYBYTES == FAEST_PUBLIC_KEY_BYTES, "");
static_assert(CRYPTO_SECRETKEYBYTES == FAEST_SECRET_KEY_BYTES, "");
static_assert(CRYPTO_BYTES == FAEST_SIGNATURE_BYTES, "");

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk)
{
	do
	{
		rand_bytes(sk, FAEST_SECRET_KEY_BYTES);
	} while (!faest_pubkey(pk, sk));
	return 0;
}

int crypto_sign(
	unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk)
{
	*smlen = mlen + FAEST_SIGNATURE_BYTES;
	memmove(sm, m, mlen);

	uint8_t random_seed[SECURITY_PARAM / 8];
	rand_bytes(random_seed, sizeof(random_seed));
	faest_sign(sm + mlen, sm, mlen, sk, random_seed, sizeof(random_seed));
	return 0;
}

int crypto_sign_open(
	unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk)
{
	unsigned long long m_length = smlen - FAEST_SIGNATURE_BYTES;
	if (!faest_verify(sm + m_length, sm, m_length, pk))
		return -1;

	*mlen = m_length;
	memmove(m, sm, m_length);
	return 0;
}

// Rijndael_CCR 
/////////////////////////////////////

//  Windows
#ifdef _WIN32

#include <intrin.h>
uint64_t rdtsc(){
    return __rdtsc();
}

//  Linux/GCC
#else

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif
#include <time.h>

void run_test_once (rijndael192_round_keys *round_keys, block192 *input, block192 *output) {
	//orthormorphism
	uint64_t *p64 = (uint64_t *) input;
	uint32_t *p32 = (uint32_t *) (p64 + 1);
	uint64_t temp64;
	uint32_t temp32;
	temp64 = *p64;
	*p64 ^= *(p64+2);
	*(p64+2) = temp64;
	temp32 = *p32;
	*p32 ^= *(p32+1);
	*(p32+1) = temp32;
	//encrypt
	*output = *input;
	rijndael192_encrypt_block(round_keys, output);
	//feedback
	*output = block192_xor(*input, *output);
}

double run_test (uint32_t run_count) {
	rijndael192_round_keys round_keys;
	block192 key;
	rijndael192_keygen(&round_keys, key);

	block192 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block192));
	bool direction = false;

	uint64_t start, end;
	double average = 0;

	start = rdtsc();
	for (uint32_t i = 0; i < run_count; i++) {
		if (direction) {
			run_test_once (&round_keys, &buffer1, &buffer2);
		} else {
			run_test_once (&round_keys, &buffer2, &buffer1);
		}
		direction = !direction;
	}
	end = rdtsc();
	average = (end - start) / (double) run_count;
	return average;
}

double run_test_time (uint32_t run_count) {
	rijndael192_round_keys round_keys;
	block192 key;
	rijndael192_keygen(&round_keys, key);

	block192 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block192));
	bool direction = false;

	time_t start, end;
	double average = 0;

	start = clock();
	for (uint32_t i = 0; i < run_count; i++) {
		if (direction) {
			run_test_once (&round_keys, &buffer1, &buffer2);
		} else {
			run_test_once (&round_keys, &buffer2, &buffer1);
		}
		direction = !direction;
	}
	end = clock();
	average = (end - start) / (double) run_count;
	average = average / (double) (CLOCKS_PER_SEC)*1e9;
	return average;
}


void run_test_once_naive (rijndael192_round_keys *round_keys, block192 *input, block192 *output) {
	//orthormorphism
	uint64_t *p64 = (uint64_t *) input;
	uint32_t *p32 = (uint32_t *) (p64 + 1);
	uint64_t temp64;
	uint32_t temp32;
	temp64 = *p64;
	*p64 ^= *(p64+2);
	*(p64+2) = temp64;
	temp32 = *p32;
	*p32 ^= *(p32+1);
	*(p32+1) = temp32;
	//encrypt
	*output = *input;
	block192 after_sbox;
	for (int round = 0; round < RIJNDAEL192_ROUNDS; round++) {
		rijndael192_round_function(round_keys, output, &after_sbox, round);
	}
	//feedback
	*output = block192_xor(*input, *output);
}


double run_test_naive (uint32_t run_count) {
	rijndael192_round_keys round_keys;
	block192 key;
	rijndael192_keygen(&round_keys, key);

	block192 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block192));
	bool direction = false;

	uint64_t start, end;
	double average = 0;

	start = rdtsc();
	for (uint32_t i = 0; i < run_count; i++) {
		if (direction) {
			run_test_once_naive (&round_keys, &buffer1, &buffer2);
		} else {
			run_test_once_naive (&round_keys, &buffer2, &buffer1);
		}
		direction = !direction;
	}
	end = rdtsc();
	average = (end - start) / (double) run_count;
	return average;
}

double run_test_time_naive (uint32_t run_count) {
	rijndael192_round_keys round_keys;
	block192 key;
	rijndael192_keygen(&round_keys, key);

	block192 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block192));
	bool direction = false;

	time_t start, end;
	double average = 0;

	start = clock();
	for (uint32_t i = 0; i < run_count; i++) {
		if (direction) {
			run_test_once_naive (&round_keys, &buffer1, &buffer2);
		} else {
			run_test_once_naive (&round_keys, &buffer2, &buffer1);
		}
		direction = !direction;
	}
	end = clock();
	average = (end - start) / (double) run_count;
	average = average / (double) (CLOCKS_PER_SEC)*1e9;
	return average;
}

double run_test_rijndael192(uint32_t run_count) {
	rijndael192_round_keys round_keys;
	block192 key;
	rijndael192_keygen(&round_keys, key);

	block192 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block192));
	bool direction = false;

	uint64_t start, end;
	double average = 0;

	start = rdtsc();
	for (int i = 0; i < run_count; i++) {
		rijndael192_encrypt_block(&round_keys, &buffer1);
	}
	end = rdtsc();
	average = (end - start) / (double) run_count;
	return average;
}

/////////////////////////////////////