#ifndef EMP_AES_OPT_KS_H__
#define EMP_AES_OPT_KS_H__

#include "emp-tool/utils/aes.h"

namespace emp
{

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

	void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key)
	{
		__m128i temp1, temp2;
		__m128i *Key_Schedule = (__m128i *)key;
		temp1 = _mm_loadu_si128((__m128i *)userkey);
		Key_Schedule[0] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[1] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[2] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[3] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[4] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[5] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[6] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[7] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[8] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[9] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
		temp1 = AES_128_ASSIST(temp1, temp2);
		Key_Schedule[10] = temp1;
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
	void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key)
	{
		__m128i temp1, temp2, temp3, temp4;
		__m128i *Key_Schedule = (__m128i *)key;
		temp1 = _mm_loadu_si128((__m128i *)userkey);
		temp3 = _mm_loadu_si128((__m128i *)(userkey + 16));
		Key_Schedule[0] = temp1;
		Key_Schedule[1] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[1] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1],
												  (__m128d)temp1, 0);
		Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[3] = temp1;
		Key_Schedule[4] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[4] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4],
												  (__m128d)temp1, 0);
		Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[6] = temp1;
		Key_Schedule[7] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7],
												  (__m128d)temp1, 0);
		Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);

		temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[9] = temp1;
		Key_Schedule[10] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10],
												   (__m128d)temp1, 0);
		Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[12] = temp1;
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

	void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key)
	{
		__m128i temp1, temp2, temp3;
		__m128i *Key_Schedule = (__m128i *)key;
		temp1 = _mm_loadu_si128((__m128i *)userkey);
		temp3 = _mm_loadu_si128((__m128i *)(userkey + 16));
		Key_Schedule[0] = temp1;
		Key_Schedule[1] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[2] = temp1;
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[3] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[4] = temp1;
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[5] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[6] = temp1;
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[7] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[8] = temp1;
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[9] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[10] = temp1;
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[11] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[12] = temp1;
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[13] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[14] = temp1;
	}

	void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
						 unsigned char *out,	  // pointer to the CIPHERTEXT buffer
						 unsigned long length,	  // text length in bytes
						 const char *key,		  // pointer to the expanded key schedule
						 int number_of_rounds)	  // number of AES rounds 10,12 or 14

	{
		__m128i tmp;
		int i, j;
		if (length % 16)
			length = length / 16 + 1;
		else
			length = length / 16;
		for (i = 0; i < length; i++)
		{
			tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
			tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
			for (j = 1; j < number_of_rounds; j++)
			{
				tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
			}
			tmp = _mm_aesenclast_si128(tmp, ((__m128i *)key)[j]);
			_mm_storeu_si128(&((__m128i *)out)[i], tmp);
		}
	}

	template <int NumKeys>
	static inline void ks_rounds(AES_KEY *keys, block con, block con3, block mask, int r)
	{
		for (int i = 0; i < NumKeys; ++i)
		{
			block key = keys[i].rd_key[r - 1];
			block x2 = _mm_shuffle_epi8(key, mask);
			block aux = _mm_aesenclast_si128(x2, con);

			block globAux = _mm_slli_epi64(key, 32);
			key = _mm_xor_si128(globAux, key);
			globAux = _mm_shuffle_epi8(key, con3);
			key = _mm_xor_si128(globAux, key);
			keys[i].rd_key[r] = _mm_xor_si128(aux, key);
		}
	}
	/*
	 * AES key scheduling for 8 keys
	 * [REF] Implementation of "Fast Garbling of Circuits Under Standard Assumptions"
	 * https://eprint.iacr.org/2015/751.pdf
	 */
	template <int NumKeys>
	static inline void AES_opt_key_schedule(block *user_key, AES_KEY *keys)
	{
		block con = _mm_set_epi32(1, 1, 1, 1);
		block con2 = _mm_set_epi32(0x1b, 0x1b, 0x1b, 0x1b);
		block con3 = _mm_set_epi32(0x07060504, 0x07060504, 0x0ffffffff, 0x0ffffffff);
		block mask = _mm_set_epi32(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d);

		for (int i = 0; i < NumKeys; ++i)
		{
			keys[i].rounds = 10;
			keys[i].rd_key[0] = user_key[i];
		}

		ks_rounds<NumKeys>(keys, con, con3, mask, 1);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 2);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 3);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 4);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 5);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 6);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 7);
		con = _mm_slli_epi32(con, 1);
		ks_rounds<NumKeys>(keys, con, con3, mask, 8);
		ks_rounds<NumKeys>(keys, con2, con3, mask, 9);
		con2 = _mm_slli_epi32(con2, 1);
		ks_rounds<NumKeys>(keys, con2, con3, mask, 10);
	}

/*
 * With numKeys keys, use each key to encrypt numEncs blocks.
 */
#ifdef __x86_64__
	template <int numKeys, int numEncs>
	static inline void ParaEnc(block *blks, AES_KEY *keys)
	{
		block *first = blks;
		for (size_t i = 0; i < numKeys; ++i)
		{
			block K = keys[i].rd_key[0];
			for (size_t j = 0; j < numEncs; ++j)
			{
				*blks = *blks ^ K;
				++blks;
			}
		}

		for (unsigned int r = 1; r < 10; ++r)
		{
			blks = first;
			for (size_t i = 0; i < numKeys; ++i)
			{
				block K = keys[i].rd_key[r];
				for (size_t j = 0; j < numEncs; ++j)
				{
					*blks = _mm_aesenc_si128(*blks, K);
					++blks;
				}
			}
		}

		blks = first;
		for (size_t i = 0; i < numKeys; ++i)
		{
			block K = keys[i].rd_key[10];
			for (size_t j = 0; j < numEncs; ++j)
			{
				*blks = _mm_aesenclast_si128(*blks, K);
				++blks;
			}
		}
	}
#elif __aarch64__
	template <int numKeys, int numEncs>
	static inline void ParaEnc(block *_blks, AES_KEY *keys)
	{
		uint8x16_t *first = (uint8x16_t *)(_blks);

		for (unsigned int r = 0; r < 9; ++r)
		{
			auto blks = first;
			for (size_t i = 0; i < numKeys; ++i)
			{
				uint8x16_t K = vreinterpretq_u8_m128i(keys[i].rd_key[r]);
				for (size_t j = 0; j < numEncs; ++j, ++blks)
					*blks = vaesmcq_u8(vaeseq_u8(*blks, K));
			}
		}

		auto blks = first;
		for (size_t i = 0; i < numKeys; ++i)
		{
			uint8x16_t K = vreinterpretq_u8_m128i(keys[i].rd_key[9]);
			uint8x16_t K2 = vreinterpretq_u8_m128i(keys[i].rd_key[10]);
			for (size_t j = 0; j < numEncs; ++j, ++blks)
				*blks = vaeseq_u8(*blks, K) ^ K2;
		}
	}
#endif

}
#endif
