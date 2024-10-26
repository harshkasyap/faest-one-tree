/*
 *  SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include "aes.h"

int main(void) {

  printf("Hello World\n");

  rijndael192_round_keys schedule_keys;
  block192 sk;
  memset(&sk, 0, 24);
  rijndael192_keygen(&schedule_keys, sk);

  uint8_t *sk_int8 = &sk;
  printf("sk: ");
  for(int i = 0; i < 24; ++i)
    printf("%X", sk_int8[i]);
  printf("\n");

  uint8_t *schedulek_int8 = &schedule_keys;
  printf("key schedule: ");
  for(int i = 0; i < 13; ++i) {
    for(int j = 0; j < 24; ++j) {
      printf("%X", schedulek_int8[i*24+j]);
    }
    printf("\n");
  }

  block192 msg;
  memset(&msg, 0, 24);

  uint8_t *msg_int8 = &msg;
  printf("message: ");
  for(int i = 0; i < 24; ++i)
    printf("%X", msg_int8[i]);
  printf("\n");

  rijndael192_encrypt_block(&schedule_keys, &msg);

  printf("cipher: ");
  for(int i = 0; i < 24; ++i)
    printf("%X", msg_int8[i]);
  printf("\n");

  return 0;
}
