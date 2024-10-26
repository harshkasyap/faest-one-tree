#include <stdio.h>
#include <stdint.h>

#include "aes.h"

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

// naive sigma
block192 sigma(block192 x) {
  uint32_t *cop = (uint32_t*)x.data;
  uint32_t a = cop[0];
  cop[0] ^= cop[3];
  cop[3] = a;
  a = cop[1];
  cop[1] ^= cop[4];
  cop[4] = a;
  a = cop[2];
  cop[2] ^= cop[5];
  cop[5] = a;

  return x;
}

void rijndael_ccr() {

  // key scheduling
  rijndael192_round_keys schedule_keys;
  block192 sk;
  memset(&sk, 0, 24);


  uint64_t cycle_point_0 = rdtsc();
  rijndael192_keygen(&schedule_keys, sk);
  uint64_t cycle_point_1 = rdtsc();
  printf("key schedule cpu cycles: %ld\n", cycle_point_1 - cycle_point_0);

  block192 msg;
  memset(&msg, 0, 24);

  int test_n = 1000000;

  cycle_point_0 = rdtsc();
  for(int i = 0; i < test_n; ++i) {
    msg = sigma(msg);
    block192 sigma_msg = msg;
    rijndael192_encrypt_block(&schedule_keys, &msg);
    msg = block192_xor(msg, sigma_msg);
  }
  cycle_point_1 = rdtsc();
  printf("encryption cpu cycles: %ld\n", (cycle_point_1 - cycle_point_0)/test_n);


}

int main(void) {

  rijndael_ccr();
}
