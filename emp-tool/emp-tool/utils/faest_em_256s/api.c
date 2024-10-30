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



void run_test_once (rijndael256_round_keys *round_keys, block256 *input, block256 *output) {
	//orthormorphism
	__uint128_t *p128 = (__uint128_t *) input;
	__uint128_t temp128 = *p128;
	*p128 ^= *(p128+1);
	*(p128+1) = temp128;
	//encrypt
	*output = *input;
	rijndael256_encrypt_block(round_keys, output);
	//feedback
	*output = block256_xor(*input, *output);
}


double run_test (uint32_t run_count) {
	rijndael256_round_keys round_keys;
	block256 key;
	rijndael256_keygen(&round_keys, key);

	block256 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block256));
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
	rijndael256_round_keys round_keys;
	block256 key;
	rijndael256_keygen(&round_keys, key);

	block256 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block256));
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

double run_test_rijndael256 (uint32_t run_count) {
	rijndael256_round_keys round_keys;
	block256 key;
	rijndael256_keygen(&round_keys, key);

	block256 buffer1, buffer2;
	memset(&buffer1, 0, sizeof(block256));

	uint64_t clock_start, clock_end;
	double clock_average = 0;

	clock_start = rdtsc();
	for (int i = 0; i < run_count; i++) {
		rijndael256_encrypt_block(&round_keys, &buffer1);
	}
	clock_end = rdtsc();
	clock_average = (clock_end - clock_start) / (double) run_count;
	return clock_average;
}