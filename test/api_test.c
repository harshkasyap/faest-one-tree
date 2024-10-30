/*
 *  SPDX-License-Identifier: MIT
 */

#include "api.h"
#include <time.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if defined(__WIN32__)
#define LL_FMT "%I64u"
#else
#define LL_FMT "%llu"
#endif

#if defined(__WIN32__)
#define SIZET_FMT "%Iu"
#else
#define SIZET_FMT "%zu"
#endif

// cpu cycles
//  Windows
#ifdef _WIN32

#include <intrin.h>
uint64_t rdtsc(){
    return __rdtsc();
}

//  Linux/GCC
#else

uint64_t rdtsc() {
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif

int main(void) {
  unsigned char pk[CRYPTO_PUBLICKEYBYTES]          = {0};
  unsigned char sk[CRYPTO_SECRETKEYBYTES]          = {0};
  const unsigned char message[50]                  = {0};
  unsigned char omessage[sizeof(message)]          = {0};
  unsigned char sm[sizeof(message) + CRYPTO_BYTES] = {0};

  int ret = crypto_sign_keypair(pk, sk);
  if (ret != 0) {
    printf("Failed to generate key pair\n");
    return -1;
  }

  unsigned long long smlen = sizeof(sm);
  uint64_t sign_cycle = rdtsc();
  clock_t start_time = clock();
  ret                      = crypto_sign(sm, &smlen, message, sizeof(message), sk);
  clock_t end_time = clock();
  double time_taken = (double)(end_time - start_time) / CLOCKS_PER_SEC;
  printf("Time taken to sign: %f seconds\n", time_taken);
  printf("Sign cpu cycles: %ld\n", rdtsc() - sign_cycle);
  if (ret != 0) {
    printf("Failed to sign\n");
    return -1;
  }

  unsigned long long mlen = sizeof(omessage);
  uint64_t verify_cycle = rdtsc();
  clock_t start_time1 = clock();
  ret                     = crypto_sign_open(omessage, &mlen, sm, smlen, pk);
  printf("Time taken to verify: %f seconds\n",(double)(clock() - start_time1) / CLOCKS_PER_SEC);
  printf("Verify cpu cycles: %ld\n", rdtsc() - verify_cycle);
  if (ret != 0) {
    printf("Failed to verify (ret = %d)\n", ret);
    return -1;
  }

  if (mlen != sizeof(message)) {
    printf("length of message after verify incorrect, got " LL_FMT ", expected " SIZET_FMT "\n",
           mlen, sizeof(message));
    return -1;
  }
  if (memcmp(message, omessage, sizeof(message)) != 0) {
    printf("message mismatch after verification\n");
    return -1;
  }

  // test special case where message and signature overlap
  memcpy(sm, message, sizeof(message));

  smlen = sizeof(sm);
  ret   = crypto_sign(sm, &smlen, sm, sizeof(message), sk);
  if (ret != 0) {
    printf("Failed to sign\n");
    return -1;
  }

  mlen = smlen;
  ret  = crypto_sign_open(sm, &mlen, sm, smlen, pk);
  if (ret != 0) {
    printf("Failed to verify (ret = %d)\n", ret);
    return -1;
  }

  if (mlen != sizeof(message)) {
    printf("length of message after verify incorrect, got " LL_FMT ", expected " SIZET_FMT "\n",
           mlen, sizeof(message));
    return -1;
  }
  if (memcmp(message, sm, sizeof(message)) != 0) {
    printf("message mismatch after verification\n");
    return -1;
  }

  printf("Sign/Verify test passed\n");

  return 0;
}
