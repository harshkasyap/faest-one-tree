#include <openssl/evp.h>
#include <immintrin.h>
#include <wmmintrin.h>
//#include <emmintrin.h> // or <immintrin.h> if needed

typedef __m128i block;

void process_hash1(block *hash_in, unsigned int seclvl, block *hash_out, unsigned int tweak);
void process_hash(block *hash_in, unsigned int seclvl, block *hash_out, unsigned int tweak);
void AES_ECB_encrypt1(block *in, // pointer to the PLAINTEXT
						  block out [4][2],	  // pointer to the CIPHERTEXT buffer
						  block key [4][15], int pos);
void AES_128_Key_Expansion1(block key [4][15]);
void AES_192_Key_Expansion1(block userkey [8][2], block key [8][15]);
void AES_256_Key_Expansion1(block userkey [4][2], block key [4][15]);
void AES_ECB_encrypt2(block *in, // pointer to the PLAINTEXT
						  block out [4][2],	  // pointer to the CIPHERTEXT buffer
						  block key [8][15], int number_of_rounds);
void AES_256_Key_Expansion2(block userkey [8][2], block key [8][15]);
void ccr_aes_ctx_cpp_batched(uint8_t* tin, uint8_t* tout, unsigned int seclvl, unsigned int tweak);
void ccr_aes_ctx_cpp_all_batched(uint8_t* tin, uint8_t* tout, unsigned int seclvl);
void ccr_aes_ctx_cpp(const uint8_t* tin, uint8_t* tout, unsigned int seclvl, unsigned int tweak);

void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key);
void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key);
void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key);
void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
						 unsigned char *out,	  // pointer to the CIPHERTEXT buffer
						 unsigned long length,	  // text length in bytes
						 const char *key,		  // pointer to the expanded key schedule
						 int number_of_rounds);	  // number of AES rounds 10,12 or 14

	inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2)
	{
		__m128i temp3;
		temp2 = _mm_shuffle_epi32(temp2, 0xff);
		temp3 = _mm_slli_si128(temp1, 0x4);
		temp1 = _mm_xor_si128(temp1, temp3);
		temp3 = _mm_slli_si128(temp3, 0x4);
		temp1 = _mm_xor_si128(temp1, temp3);
		temp3 = _mm_slli_si128(temp3, 0x4);
		temp1 = _mm_xor_si128(temp1, temp3);
		temp1 = _mm_xor_si128(temp1, temp2);
		return temp1;
	}

	inline void KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3)
	{
		__m128i temp4;
		*temp2 = _mm_shuffle_epi32(*temp2, 0x55);
		temp4 = _mm_slli_si128(*temp1, 0x4);
		*temp1 = _mm_xor_si128(*temp1, temp4);
		temp4 = _mm_slli_si128(temp4, 0x4);
		*temp1 = _mm_xor_si128(*temp1, temp4);
		temp4 = _mm_slli_si128(temp4, 0x4);
		*temp1 = _mm_xor_si128(*temp1, temp4);
		*temp1 = _mm_xor_si128(*temp1, *temp2);
		*temp2 = _mm_shuffle_epi32(*temp1, 0xff);
		temp4 = _mm_slli_si128(*temp3, 0x4);
		*temp3 = _mm_xor_si128(*temp3, temp4);
		*temp3 = _mm_xor_si128(*temp3, *temp2);
	}

	inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2)
	{
		__m128i temp4;
		*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
		temp4 = _mm_slli_si128(*temp1, 0x4);
		*temp1 = _mm_xor_si128(*temp1, temp4);
		temp4 = _mm_slli_si128(temp4, 0x4);
		*temp1 = _mm_xor_si128(*temp1, temp4);
		temp4 = _mm_slli_si128(temp4, 0x4);
		*temp1 = _mm_xor_si128(*temp1, temp4);
		*temp1 = _mm_xor_si128(*temp1, *temp2);
	}
	inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3)
	{
		__m128i temp2, temp4;
		temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
		temp2 = _mm_shuffle_epi32(temp4, 0xaa);
		temp4 = _mm_slli_si128(*temp3, 0x4);
		*temp3 = _mm_xor_si128(*temp3, temp4);
		temp4 = _mm_slli_si128(temp4, 0x4);
		*temp3 = _mm_xor_si128(*temp3, temp4);
		temp4 = _mm_slli_si128(temp4, 0x4);
		*temp3 = _mm_xor_si128(*temp3, temp4);
		*temp3 = _mm_xor_si128(*temp3, temp2);
	}

