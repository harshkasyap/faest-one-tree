#include "emp-tool/emp-tool.h"

#include <thread>
#include <iostream>
using namespace std;
using namespace emp;
#include <chrono>

#define SECLVL 256

// Define STRINGIZE to convert macro expressions into strings for _Pragma usage
#ifdef __GNUC__
    #define STRINGIZE(x) #x
    #define UNROLL_LOOP _Pragma(STRINGIZE(GCC unroll (4)))
#else
    #define UNROLL_LOOP
#endif

// Define AES_PREFERRED_WIDTH based on your needs (example: 4)
// #define AES_PREFERRED_WIDTH 4

extern "C" {
    void cppFunction() {
        std::cout << "Hello from C++ function!" << std::endl;
    }
    
    void process_hash1(block *hash_in, unsigned int seclvl, block *hash_out, unsigned int tweak = 0) {
        block user_key_1 [2];
        block user_key_2 [2];
        block round_key_1 [15];
        block round_key_2 [15];
        block in = sigma(hash_in[0]);

        if (tweak == 1) {
            in[0] ^= 1; //tweaked
        }

        if (tweak == 2) {
            in[0] ^= 2; //tweaked
        }

        if (seclvl == 192 || seclvl == 256) {
            memset(user_key_1, 0, sizeof(user_key_1));
            memset(user_key_2, 1, sizeof(user_key_2));                    

            user_key_1[1] = hash_in[1];
            user_key_2[1] = hash_in[1];
        }

        if (seclvl == 128) {
            const block zero_block = makeBlock(0, 0);
            AES_128_Key_Expansion((unsigned char *) &zero_block, (unsigned char *) round_key_1);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out,
            sizeof(block),
            (const char *) round_key_1,
            10);
            hash_out[0] = in ^ hash_out[0];
        } else if (seclvl == 192) {
            AES_192_Key_Expansion((unsigned char *) user_key_1, (unsigned char *) round_key_1);
            AES_192_Key_Expansion((unsigned char *) user_key_2, (unsigned char *) round_key_2);
            memcpy(user_key_2, user_key_1, sizeof(user_key_1));

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
            AES_256_Key_Expansion((unsigned char *) user_key_1, (unsigned char *) round_key_1);
            AES_256_Key_Expansion((unsigned char *) user_key_2, (unsigned char *) round_key_2);
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

    void process_hash(block *hash_in, unsigned int seclvl, block *hash_out, unsigned int tweak = 0) {
        block user_key_1 [2];
        block user_key_2 [2];
        block round_key_1 [15];
        block round_key_2 [15];
        block in = sigma(hash_in[0]);

        if (tweak == 1) {
            in[0] ^= 1; //tweaked
        }

        if (tweak == 2) {
            in[0] ^= 2; //tweaked
        }

        if (seclvl == 192 || seclvl == 256) {
            memset(user_key_1, 0, sizeof(user_key_1));
            memset(user_key_2, 1, sizeof(user_key_2));                    

            user_key_1[1] = hash_in[1];
            user_key_2[1] = hash_in[1];
        }

        if (seclvl == 128) {
            const block zero_block = makeBlock(0, 0);
            AES_128_Key_Expansion((unsigned char *) &zero_block, (unsigned char *) round_key_1);
            AES_ECB_encrypt((unsigned char *) &in,
            (unsigned char *) hash_out,
            sizeof(block),
            (const char *) round_key_1,
            10);
            hash_out[0] = in ^ hash_out[0];
        } else if (seclvl == 192) {
            AES_192_Key_Expansion((unsigned char *) user_key_1, (unsigned char *) round_key_1);
            AES_192_Key_Expansion((unsigned char *) user_key_2, (unsigned char *) round_key_2);
            memcpy(user_key_2, user_key_1, sizeof(user_key_1));

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
            AES_256_Key_Expansion((unsigned char *) user_key_1, (unsigned char *) round_key_1);
            AES_256_Key_Expansion((unsigned char *) user_key_2, (unsigned char *) round_key_2);
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

    void ccr_aes_ctx_cpp_batched(uint8_t tin[4][SECLVL/8], uint8_t tout[4][SECLVL/8], unsigned int seclvl, unsigned int tweak) {
        block hash_in [4][2];
        block hash_out [4][2];
        block user_key_1 [4][2];
        block user_key_2 [4][2];
        block round_key_1 [4][15];
        block round_key_2 [4][15];
        block in[4];
        
        for (size_t i = 0; i < 4; ++i) {
            if (seclvl == 128) {
                memcpy(&hash_in[i][0], tin[i], 16);
            } else if (seclvl == 192 || seclvl == 256) {
                size_t right_size = (seclvl == 192) ? 8 : 16; // size for right part
                memcpy(&hash_in[i][0], tin[i], 16);
                memcpy(&hash_in[i][1], tin[i] + 16, right_size);

                //dummy init
                memcpy(&hash_out[i][0], tin[i], 16);
                memcpy(&hash_out[i][1], tin[i] + 16, right_size);

                memset(user_key_1[i], 0, sizeof(user_key_1[i]));
                memset(user_key_2[i], 1, sizeof(user_key_2[i]));                    

                user_key_1[i][1] = hash_in[i][1];
                user_key_2[i][1] = hash_in[i][1];
            }

            in[i] = sigma(hash_in[i][0]);

            if (tweak == 1) {
                in[i][0] ^= 1; //tweaked
            }

            if (tweak == 2) {
                in[i][0] ^= 2; //tweaked
            }
        }

        if (seclvl == 128) {
            const block zero_block = makeBlock(0, 0);
    
            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_128_Key_Expansion((unsigned char *) &zero_block, (unsigned char *) round_key_1[i]);

            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_ECB_encrypt((unsigned char *) &in[i],
                (unsigned char *) hash_out[i],
                sizeof(block),
                (const char *) round_key_1[i],
                10);
        }

        if (seclvl == 192) {
            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_192_Key_Expansion((unsigned char *) user_key_1[i], (unsigned char *) round_key_1[i]);

            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_192_Key_Expansion((unsigned char *) user_key_2[i], (unsigned char *) round_key_2[i]);
            
            for (size_t i = 0; i < 4; ++i)
                memcpy(user_key_2[i], user_key_1[i], sizeof(user_key_1[i]));

            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_ECB_encrypt((unsigned char *) &in[i],
                (unsigned char *) hash_out[i],
                sizeof(block),
                (char *) round_key_1[i],
                12);
            
            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_ECB_encrypt((unsigned char *) &in[i],
                (unsigned char *) hash_out[i] + 1,
                sizeof(block),
                (char *) round_key_2[i],
                12);
        }

        if (seclvl == 256) {
            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_256_Key_Expansion((unsigned char *) user_key_1[i], (unsigned char *) round_key_1[i]);

            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_256_Key_Expansion((unsigned char *) user_key_2[i], (unsigned char *) round_key_2[i]);

            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_ECB_encrypt((unsigned char *) &in[i],
                (unsigned char *) hash_out[i],
                sizeof(block),
                (char *) round_key_1[i],
                14);
            
            UNROLL_LOOP
            for (size_t i = 0; i < 4; ++i)
                AES_ECB_encrypt((unsigned char *) &in[i],
                (unsigned char *) hash_out[i] + 1,
                sizeof(block),
                (char *) round_key_2[i],
                14);
        }

        for (size_t i = 0; i < 4; ++i) {   
            // Output results
            
            if (seclvl == 128) {
                hash_out[i][0] = in[i] ^ hash_out[i][0];
                memcpy(tout[i], &hash_out[i][0], 16);
            } else if (seclvl == 192) {
                hash_out[i][0] = in[i] ^ hash_out[i][0];
                hash_out[i][1] = in[i] ^ hash_out[i][1];
                
                memcpy(tout[i], &hash_out[i][0], 16);
                memcpy(tout[i] + 16, &hash_out[i][1], 8);
            } else if (seclvl == 256) {
                hash_out[i][0] = in[i] ^ hash_out[i][0];
                hash_out[i][1] = in[i] ^ hash_out[i][1];

                memcpy(tout[i], &hash_out[i][0], 16);
                memcpy(tout[i] + 16, &hash_out[i][1], 16);
            }
        }
    }

    /*
    void ccr_aes_ctx_cpp_batched(uint8_t tin[4][SECLVL/8], uint8_t tout[4][SECLVL/8], unsigned int seclvl) {
        for (size_t i = 0; i < 4; ++i) {
                block hash_in [2];
                block hash_out [2];

                if (seclvl == 128) {
                    memcpy(&hash_in[0], tin[i], 16);
                } else if (seclvl == 192 || seclvl == 256) {
                    size_t right_size = (seclvl == 192) ? 8 : 16; // size for right part
                    memcpy(&hash_in[0], tin[i], 16);
                    memcpy(&hash_in[1], tin[i] + 16, right_size);

                    //dummy init
                    memcpy(&hash_out[0], tin[i], 16);
                    memcpy(&hash_out[1], tin[i] + 16, right_size);
                }

                // Process the hash
                process_hash(hash_in, seclvl, hash_out);

                // Output results
                if (seclvl == 128) {
                    memcpy(tout[i], &hash_out[0], 16);
                } else if (seclvl == 192) {
                    memcpy(tout[i], &hash_out[0], 16);
                    memcpy(tout[i] + 16, &hash_out[1], 8);
                } else if (seclvl == 256) {
                    memcpy(tout[i], &hash_out[0], 16);
                    memcpy(tout[i] + 16, &hash_out[1], 16);
                }
        }
    }*/

    void ccr_aes_ctx_cpp(const uint8_t* tin, uint8_t* tout, unsigned int seclvl, unsigned int tweak = 0) {
        block hash_in [2];
        block hash_out [2];

        if (seclvl == 128) {
            memcpy(&hash_in[0], tin, 16);
        } else if (seclvl == 192 || seclvl == 256) {
            size_t right_size = (seclvl == 192) ? 8 : 16; // size for right part
            memcpy(&hash_in[0], tin, 16);
            memcpy(&hash_in[1], tin + 16, right_size);

            //dummy init
            memcpy(&hash_out[0], tin, 16);
            memcpy(&hash_out[1], tin + 16, right_size);
        }

        // Process the hash
        process_hash(hash_in, seclvl, hash_out, tweak);

        // Output results
        if (seclvl == 128) {
            memcpy(tout, &hash_out[0], 16);
        } else if (seclvl == 192) {
            memcpy(tout, &hash_out[0], 16);
            memcpy(tout + 16, &hash_out[1], 8);
        } else if (seclvl == 256) {
            memcpy(tout, &hash_out[0], 16);
            memcpy(tout + 16, &hash_out[1], 16);
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