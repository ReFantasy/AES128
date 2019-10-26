/******************************************************************************************************************************************************
 *        
 *  https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
 *
 *  Reference:
 *            https://blog.csdn.net/qq_38289815/article/details/80900813
 *            https://www.jianshu.com/p/3840b344b27c?utm_campaign=maleskine&utm_content=note&utm_medium=seo_notes&utm_source=recommendation
 *            https://blog.csdn.net/github_39295111/article/details/75646459
 *            https://blog.csdn.net/bupt073114/article/details/27382533
 *            
 *
 ******************************************************************************************************************************************************/
#ifndef __AES_H__
#define __AES_H__
#include <bitset>
#include "help_function.h"
using byte = std::bitset<8>;
using word = std::bitset<32>;


// Number of columns (32-bit words) comprising the State. For this
// standard, Nb = 4.
const uint8_t Nb = 4;

// Number of 32-bit words comprising the Cipher Key. For this
// standard, Nk = 4, 6, or 8.
const uint8_t Nk = 4;

// Number of rounds, which is a function of Nk and Nb
const uint8_t Nr = 10;


// 轮常数，密钥扩展中用到。（AES-128只需要10轮）  
const word Rcon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
				 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

/*
 * Addition in GF(2^8)
 */
byte Gadd(byte a, byte b);

/*
 * multiplication in GF(2^8)
 */
byte Gmult(byte a, byte b);

class AES
{
public:
	AES();
	~AES();
	void Encrypt(byte(&in)[4 * Nb], byte(&out)[4 * Nb], byte(&key)[4 * Nk]);
	void InvEncrypt(byte(&in)[4 * Nb], byte(&out)[4 * Nb], byte(&key)[4 * Nk]);

	

//private:
	/** \brief The function SubWord() takes a four-byte input word and applies the S-box
	 *  \param[in] 
	 *  \return 
	 */
	word SubWord(const word& sw)const;

	/** \brief The function RotWord() takes a word [a0,a1,a2,a3] as input, performs a cyclic permutation, and returns the word [a1,a2,a3,a0].
	 *  \param[in] 
	 *  \return 
	 */
	word RotWord(const word &wd)const;

	/** \brief The Key Expansion generates a total of Nb (Nr + 1) words
     *  \param[in] 
     *  \return 
	 */
	void KeyExpansion(byte(&key)[4 * Nk], word(&w)[Nb*(Nr + 1)])const;


	/** \brief 
	 *  \param[in]
	 *  \return
	 */
	void SubBytes(byte(&state)[4][Nb]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void InvSubBytes(byte(&state)[4][Nb]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void ShiftRows(byte(&state)[4][Nb]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void InvShiftRows(byte(&state)[4][Nb]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void MixColumns(byte(&state)[4][Nb]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void InvMixColumns(byte(&state)[4][Nb]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void AddRoundKey(byte(&state)[4][4], byte(&key)[4][4]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void Cipher(byte(&in)[4 * Nb], byte(&out)[4 * Nb], word(&w)[Nb*(Nr + 1)]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void InvCipher(byte(&in)[4 * Nb], byte(&out)[4 * Nb], word(&w)[Nb*(Nr + 1)]);

	/** \brief
	 *  \param[in]
	 *  \return
	 */
	void GetKey(word(&w)[Nb*(Nr + 1)], int b, byte(&key)[4][4]);

	
};

#endif//__AES_H__

