#include "emp-tool/emp-tool.h"

#include <thread>
#include <iostream>
using namespace std;
using namespace emp;
#include <chrono>
#include <time.h>

// Define STRINGIZE to convert macro expressions into strings for _Pragma usage
/*
#ifdef __GNUC__
    #define STRINGIZE(x) #x
    //#define UNROLL_LOOP _Pragma(STRINGIZE(GCC unroll (10)))
#else
    //#define UNROLL_LOOP
#endif
*/
#define STRINGIZE_NO_EXPAND(x) #x
#define STRINGIZE(x) STRINGIZE_NO_EXPAND(x)

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

     void AES_ECB_encrypt1(block *in, // pointer to the PLAINTEXT
						  block out [4][2],	  // pointer to the CIPHERTEXT buffer
						  block key [4][15], int pos) // pointer to the expanded key schedule
	{
        int number_of_rounds = 10;
        __m128i tmp [4];

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 4; p++) {
            tmp[p] = _mm_loadu_si128(&((__m128i *)(unsigned char *)&in[p])[0]);
            tmp[p] = _mm_xor_si128(tmp[p], ((__m128i *)(char *)key[p])[0]);
        }

        for (int r = 1; r < number_of_rounds; r++) {
            #ifdef __GNUC__
            _Pragma(STRINGIZE(GCC unroll (2*4)))
            #endif
            for (int p = 0; p < 4; p++) { 
                tmp[p] = _mm_aesenc_si128(tmp[p], ((__m128i *)(char *)key[p])[r]);
            }
        }
        
        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 4; p++) {
            tmp[p] = _mm_aesenclast_si128(tmp[p], ((__m128i *)(char *)key[p])[number_of_rounds]);
            _mm_storeu_si128(&((__m128i *)((unsigned char *)out[p] + pos))[0], tmp[p]);
        }
	}

    void AES_128_Key_Expansion1(block key [4][15])
	{
        __m128i temp1 [4], temp2 [4];
		__m128i *Key_Schedule [4] = {
            (__m128i *)(unsigned char *)key[0],
            (__m128i *)(unsigned char *)key[1],
            (__m128i *)(unsigned char *)key[2],
            (__m128i *)(unsigned char *)key[3]
        };

        int number_of_rounds = 10;

        const block zero_block = makeBlock(0, 0);

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (4)))
        #endif
        for (int p = 0; p < 4; p++) {
            temp1[p] = _mm_load_si128((__m128i *)(unsigned char *) &zero_block);
		    Key_Schedule[p][0] = temp1[p];
        }

        for (int r = 1; r <= number_of_rounds; r++) {
            #ifdef __GNUC__
            _Pragma(STRINGIZE(GCC unroll (4)))
            #endif
            for (int p = 0; p < 4; p++) {
                switch (r) {
                    case 1:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x01);
                    break;

                    case 2:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x02);
                    break;

                    case 3:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x04);
                    break;

                    case 4:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x08);
                    break;

                    case 5:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x10);
                    break;

                    case 6:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x20);
                    break;

                    case 7:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x40);
                    break;

                    case 8:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x80);
                    break;

                    case 9:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x1b);
                    break;

                    case 10:
                    temp2[p] = _mm_aeskeygenassist_si128(temp1[p], 0x36);
                    break;
                }
                temp1[p] = AES_128_ASSIST(temp1[p], temp2[p]);
		        Key_Schedule[p][r] = temp1[p];
            }
        }
	}

    void AES_192_Key_Expansion1(block userkey [8][2], block key [8][15])
	{
        __m128i temp1 [8], temp2 [8], temp3 [8];
		__m128i *Key_Schedule [8] = {
            (__m128i *)(unsigned char *)key[0],
            (__m128i *)(unsigned char *)key[1],
            (__m128i *)(unsigned char *)key[2],
            (__m128i *)(unsigned char *)key[3],
            (__m128i *)(unsigned char *)key[4],
            (__m128i *)(unsigned char *)key[5],
            (__m128i *)(unsigned char *)key[6],
            (__m128i *)(unsigned char *)key[7]
        };

        int number_of_rounds = 12;

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp1[p] = _mm_load_si128((__m128i *)(const unsigned char *) userkey[p]);
            temp3[p] = _mm_load_si128((__m128i *)((const unsigned char *) userkey[p] + 16));
            Key_Schedule[p][0] = temp1[p];
            Key_Schedule[p][1] = temp3[p];
        }

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x1);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][1] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[p][1],
                                                    (__m128d)temp1[p], 0);
            Key_Schedule[p][2] = (__m128i)_mm_shuffle_pd((__m128d)temp1[p], (__m128d)temp3[p], 1);
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x2);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][3] = temp1[p];
            Key_Schedule[p][4] = temp3[p];
        }

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x4);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][4] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[p][4],
                                                    (__m128d)temp1[p], 0);
            Key_Schedule[p][5] = (__m128i)_mm_shuffle_pd((__m128d)temp1[p], (__m128d)temp3[p], 1);
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x8);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][6] = temp1[p];
            Key_Schedule[p][7] = temp3[p];
        }

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x10);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[p][7],
                                                    (__m128d)temp1[p], 0);
            Key_Schedule[p][8] = (__m128i)_mm_shuffle_pd((__m128d)temp1[p], (__m128d)temp3[p], 1);
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x20);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][9] = temp1[p];
            Key_Schedule[p][10] = temp3[p];
        }

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x40);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[p][10],
                                                    (__m128d)temp1[p], 0);
            Key_Schedule[p][11] = (__m128i)_mm_shuffle_pd((__m128d)temp1[p], (__m128d)temp3[p], 1);
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x80);
            KEY_192_ASSIST(&temp1[p], &temp2[p], &temp3[p]);
            Key_Schedule[p][12] = temp1[p];
        }
	}

    void AES_256_Key_Expansion1(block userkey [4][2], block key [4][15])
	{
        __m128i temp1 [4], temp2 [4], temp3 [4];
		__m128i *Key_Schedule [4] = {
            (__m128i *)(unsigned char *)key[0],
            (__m128i *)(unsigned char *)key[1],
            (__m128i *)(unsigned char *)key[2],
            (__m128i *)(unsigned char *)key[3]
        };

        int number_of_rounds = 14;

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 4; p++) {
            temp1[p] = _mm_loadu_si128((__m128i *)(const unsigned char *) userkey[p]);
            temp3[p] = _mm_loadu_si128((__m128i *)((const unsigned char *) userkey[p] + 16));
            Key_Schedule[p][0] = temp1[p];
            Key_Schedule[p][1] = temp3[p];
        }

        for (int r = 2; r < number_of_rounds; r+=2) {
            #ifdef __GNUC__
            _Pragma(STRINGIZE(GCC unroll (2*4)))
            #endif
            for (int p = 0; p < 4; p++) {
                switch (r/2) {
                    case 1:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x01);
                    break;

                    case 2:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x02);
                    break;

                    case 3:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x04);
                    break;

                    case 4:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x08);
                    break;

                    case 5:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x10);
                    break;

                    case 6:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x20);
                    break;
                }
                KEY_256_ASSIST_1(&temp1[p], &temp2[p]);
                Key_Schedule[p][r] = temp1[p];
                KEY_256_ASSIST_2(&temp1[p], &temp3[p]);
                Key_Schedule[p][r+1] = temp3[p];
            }
        }

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 4; p++) {
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x40);
            KEY_256_ASSIST_1(&temp1[p], &temp2[p]);
            Key_Schedule[p][14] = temp1[p];
        }
	}

    
    void AES_ECB_encrypt2(block *in, // pointer to the PLAINTEXT
						  block out [4][2],	  // pointer to the CIPHERTEXT buffer
						  block key [8][15], int number_of_rounds) // pointer to the expanded key schedule
	{
        __m128i tmp [8];

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            int pos = p % 4;
            tmp[p] = _mm_load_si128(&((__m128i *)(unsigned char *)&in[pos])[0]);
            tmp[p] = _mm_xor_si128(tmp[p], ((__m128i *)(char *)key[p])[0]);
        }

        for (int r = 1; r < number_of_rounds; r++) {
            #ifdef __GNUC__
            _Pragma(STRINGIZE(GCC unroll (2*4)))
            #endif
            for (int p = 0; p < 8; p++) { 
                tmp[p] = _mm_aesenc_si128(tmp[p], ((__m128i *)(char *)key[p])[r]);
            }
        }
        
        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            int pos1 = p % 4;
            int pos2 = p < 4 ? 0 : 1;
            tmp[p] = _mm_aesenclast_si128(tmp[p], ((__m128i *)(char *)key[p])[number_of_rounds]);
            _mm_storeu_si128(&((__m128i *)((unsigned char *)out[pos1] + pos2))[0], tmp[p]);
        }
	}

    void AES_256_Key_Expansion2(block userkey [8][2], block key [8][15])
	{
        __m128i temp1 [8], temp2 [8], temp3 [8];
		__m128i *Key_Schedule [8] = {
            (__m128i *)(unsigned char *)key[0],
            (__m128i *)(unsigned char *)key[1],
            (__m128i *)(unsigned char *)key[2],
            (__m128i *)(unsigned char *)key[3],
            (__m128i *)(unsigned char *)key[4],
            (__m128i *)(unsigned char *)key[5],
            (__m128i *)(unsigned char *)key[6],
            (__m128i *)(unsigned char *)key[7]
        };

        int number_of_rounds = 14;

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp1[p] = _mm_load_si128((__m128i *)(const unsigned char *) userkey[p]);
            temp3[p] = _mm_load_si128((__m128i *)((const unsigned char *) userkey[p] + 16));
            Key_Schedule[p][0] = temp1[p];
            Key_Schedule[p][1] = temp3[p];
        }

        for (int r = 2; r < number_of_rounds; r+=2) {
            #ifdef __GNUC__
            _Pragma(STRINGIZE(GCC unroll (2*4)))
            #endif
            for (int p = 0; p < 8; p++) {
                switch (r/2) {
                    case 1:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x01);
                    break;

                    case 2:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x02);
                    break;

                    case 3:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x04);
                    break;

                    case 4:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x08);
                    break;

                    case 5:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x10);
                    break;

                    case 6:
                    temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x20);
                    break;
                }
                KEY_256_ASSIST_1(&temp1[p], &temp2[p]);
                Key_Schedule[p][r] = temp1[p];
                KEY_256_ASSIST_2(&temp1[p], &temp3[p]);
                Key_Schedule[p][r+1] = temp3[p];
            }
        }

        #ifdef __GNUC__
        _Pragma(STRINGIZE(GCC unroll (2*4)))
        #endif
        for (int p = 0; p < 8; p++) {
            temp2[p] = _mm_aeskeygenassist_si128(temp3[p], 0x40);
            KEY_256_ASSIST_1(&temp1[p], &temp2[p]);
            Key_Schedule[p][14] = temp1[p];
        }
	}

    void ccr_aes_ctx_cpp_batched(uint8_t* tin, uint8_t* tout, unsigned int seclvl, unsigned int tweak) {
        alignas(16) block hash_in [4][2];
        alignas(16) block hash_out [4][2];
        alignas(16) block user_key_1 [4][2];
        alignas(16) block user_key_2 [4][2];
        alignas(16) block round_key_1 [4][15];
        alignas(16) block round_key_2 [4][15];
        alignas(16) block in[4];
        
        size_t outlen = seclvl / 8;

        for (size_t i = 0; i < 4; ++i) {
            memcpy(&hash_in[i][0], &tin[i * outlen], 16);
            
            if (seclvl > 128) {
                size_t right_size = (seclvl == 192) ? 8 : 16; // size for right part
                memcpy(&hash_in[i][1], &tin[i * outlen] + 16, right_size);

                //dummy init
                memcpy(&hash_out[i][0], &tin[i * outlen], 16);
                memcpy(&hash_out[i][1], &tin[i * outlen] + 16, right_size);

                memset(user_key_1[i], 0, sizeof(user_key_1[i]));
                memset(user_key_2[i], 1, sizeof(user_key_2[i]));                    

                user_key_1[i][1] = hash_in[i][1];
                user_key_2[i][1] = hash_in[i][1];
            }

            in[i] = sigma(hash_in[i][0]);
            in[i][0] ^= (tweak == 1) ? 1 : (tweak == 2) ? 2 : 0;
        }

        if (seclvl == 128) {
            AES_128_Key_Expansion1(round_key_1);
            AES_ECB_encrypt1(in, hash_out, round_key_1, 0);            
        }

        if (seclvl == 192) {
            alignas(16)block user_key[8][2];
            alignas(16)block round_key[8][15];

            memcpy(user_key[0], user_key_1, sizeof(user_key_1));
            memcpy(user_key[4], user_key_2, sizeof(user_key_2));

            AES_192_Key_Expansion1(user_key, round_key);
            AES_ECB_encrypt2(in, hash_out, round_key, 12);    
        }

        if (seclvl == 256) {
            alignas(16)block user_key[8][2];
            alignas(16)block round_key[8][15];

            memcpy(user_key[0], user_key_1, sizeof(user_key_1));
            memcpy(user_key[4], user_key_2, sizeof(user_key_2));

            AES_256_Key_Expansion2(user_key, round_key);
            AES_ECB_encrypt2(in, hash_out, round_key, 14);
        }

        for (size_t i = 0; i < 4; ++i) {   
            // Output results
            hash_out[i][0] ^= in[i]; // XOR with input
            memcpy(&tout[i * outlen], &hash_out[i][0], 16);

            if (seclvl > 128) {
                hash_out[i][1] = in[i] ^ hash_out[i][1];
                memcpy(&tout[i * outlen] + 16, &hash_out[i][1], (seclvl == 192) ? 8 : 16);
            }
        }
    }

    /*
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
    }*/

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