//#include "ccr.h"
#include "emp-tool/emp-tool.h"
//#include "emp-tool/utils/aes_opt.h"

#include <iostream>
using namespace std;
using namespace emp;
#include <chrono>

extern "C" {
    void cppFunction() {
        std::cout << "Hello from C++ function!" << std::endl;
    }
    void ccr_aes_ctx_cpp(const uint8_t* in, const uint8_t* iv, uint8_t* out, unsigned int seclvl, size_t outlen) {
        block user_key_1 [2];
        block user_key_2 [2];
        block round_key_1 [15];
        block round_key_2 [15];
        block hash_in [2];
        block hash_out [2];

        if (seclvl == 128) {
            memcpy(&hash_in[0], in, sizeof(block));
        } else if (seclvl == 192) {
            uint8_t left_16[16];  //rl - 128
            uint8_t right_8[8];   //rr - 64
            memcpy(left_16, in, 16);
            memcpy(right_8, in + 16, 8);
            memcpy(&hash_in[0], left_16, sizeof(block));
            memcpy(&hash_in[1], right_8, sizeof(block));

            memset(user_key_1, 0, sizeof(user_key_1));
            memset(user_key_2, 1, sizeof(user_key_2));
            user_key_1[1] = hash_in[1];
            user_key_2[1] = hash_in[1];
        } else if (seclvl == 256) {  
            uint8_t _left_16[16];  //rl - 128
            uint8_t _right_16[16];   //rr - 128
            memcpy(_left_16, in, 16);
            memcpy(_right_16, in + 16, 16);
            memcpy(&hash_in[0], _left_16, sizeof(block));
            memcpy(&hash_in[1], _right_16, sizeof(block));

            memset(user_key_1, 0, sizeof(user_key_1));
            memset(user_key_2, 1, sizeof(user_key_2));
            user_key_1[1] = hash_in[1];
            user_key_2[1] = hash_in[1];
        }

        if (seclvl == 128) {
            block in = sigma(hash_in[0]);
            const block zero_block = makeBlock(0, 0);
            AES_128_Key_Expansion((unsigned char *) &zero_block, (unsigned char *) round_key_1);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out,
            sizeof(block),
            (const char *) round_key_1,
            10);
            hash_out[0] = in ^ hash_out[0];

        } else if (seclvl == 192) {
            //memset(user_key_1, 0, sizeof(block));
            //memset(user_key_2, 1, sizeof(block));
            user_key_1[1] = hash_in[1];
            user_key_2[1] = hash_in[1];
            AES_192_Key_Expansion((unsigned char *) user_key_1, (unsigned char *) round_key_1);
            AES_192_Key_Expansion((unsigned char *) user_key_2, (unsigned char *) round_key_2);
            memcpy(user_key_2, user_key_1, sizeof(user_key_1));
            block in = sigma(hash_in[0]);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out,
            sizeof(block),
            (char *) round_key_1,
            12);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out + 1,
            sizeof(block),
            (char *) round_key_2,
            12);
            hash_out[0] = in ^ hash_out[0];
            hash_out[1] = in ^ hash_out[1];
        } else if (seclvl == 256) {
            //memset(user_key_1, 0, sizeof(block));
            //memset(user_key_2, 1, sizeof(block));
            user_key_1[1] = hash_in[1];
            user_key_2[1] = hash_in[1];
            AES_256_Key_Expansion((unsigned char *) user_key_1, (unsigned char *) round_key_1);
            AES_256_Key_Expansion((unsigned char *) user_key_2, (unsigned char *) round_key_2);
            block in = sigma(hash_in[0]);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out,
            sizeof(block),
            (char *) round_key_1,
            14);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out + 1,
            sizeof(block),
            (char *) round_key_2,
            14);
            hash_out[0] = in ^ hash_out[0];
            hash_out[1] = in ^ hash_out[1];
        }
    }

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