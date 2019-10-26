/******************************************************************************************************************************************************
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2019  Tan DongLiang @cust
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy of
 *  this software and associated documentation files (the "Software"), to deal in
 *  the Software without restriction, including without limitation the rights to
 *  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 *  the Software, and to permit persons to whom the Software is furnished to do so,
 *  subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 *  FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 *  COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
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

	/** \brief AES-128 加密
	 *  \param[in] in 包含16(Nb=4)个字节的明文数据
	 *  \param[out] out 加密后的数据
	 *  \param[in] key 包含16(Nk=4)个字节的密钥
	 *  \return void
	 */
	void Encrypt(byte(&in)[4 * Nb], byte(&out)[4 * Nb], byte(&key)[4 * Nk]);


	/** \brief AES-128 解密
	 *  \param[in] in 包含16(Nb=4)个字节的加密数据
	 *  \param[out] out 解密后的明文数据
	 *  \param[in] key 包含16(Nk=4)个字节的密钥（加解密使用相同的密钥）
	 *  \return void
	 */
	void InvEncrypt(byte(&in)[4 * Nb], byte(&out)[4 * Nb], byte(&key)[4 * Nk]);



private:
	/** \brief 使用S-box进行字节映射
	 *  \param[in] sw 包含四个字节的字
	 *  \return 对sw的每个字节分别映射后的结果
	 */
	word SubWord(const word& sw)const;

	/** \brief 将具有四个字节的字左移一个字节 word [a0,a1,a2,a3] =》 [a1,a2,a3,a0].
	 *  \param[in] wd 包含四个字节的字
	 *  \return 移位结果
	 */
	word RotWord(const word &wd)const;

	/** \brief 密钥扩展
	 *  \param[in] key 初始密钥
	 *  \param[out] w 扩展后的(Nr+1)组密钥，包含初始密钥
	 *  \return void
	 */
	void KeyExpansion(byte(&key)[4 * Nk], word(&w)[Nb*(Nr + 1)])const;


	/** \brief 使用S-box对数组中的每个字节进行映射
	 *  \param[in][out] state 二维字节数组
	 *  \return void
	 */
	void SubBytes(byte(&state)[4][Nb]);

	/** \brief 使用S-box对数组中的每个字节进行逆映射
	 *  \param[in][out] state 二维字节数组
	 *  \return
	 */
	void InvSubBytes(byte(&state)[4][Nb]);

	/** \brief 循环移位，第r行进行左移r个字节
	 *  \param[in][out] state 二维字节数组
	 *  \return
	 */
	void ShiftRows(byte(&state)[4][Nb]);

	/** \brief ShiftRows()的逆操作
	 *  \param[in] state 二维字节数组
	 *  \return
	 */
	void InvShiftRows(byte(&state)[4][Nb]);

	/** \brief 列混淆，使用混淆矩阵进行矩阵乘法运算
	 *  \param[in][out] state 二维字节矩阵
	 *  \return
	 */
	void MixColumns(byte(&state)[4][Nb]);

	/** \brief 列混淆的逆运算
	 *  \param[in][out] state 二维字节矩阵
	 *  \return
	 */
	void InvMixColumns(byte(&state)[4][Nb]);

	/** \brief 轮密码加，矩阵对应元素进行异或操作
	 *  \param[in][out] state 状态矩阵
	 *  \param[in][out] key 密钥
	 *  \return
	 */
	void AddRoundKey(byte(&state)[4][4], byte(&key)[4][4]);

	/** \brief 加密驱动程序
	 *  \param[in] in 需要加密的数据
	 *  \param[out] out 加密后的数据
	 *  \param[in] w 加密过程中使用的密钥以及扩展密钥
	 *  \return
	 */
	void Cipher(byte(&in)[4 * Nb], byte(&out)[4 * Nb], word(&w)[Nb*(Nr + 1)]);

	/** \brief 解密驱动程序
	 *  \param[in] in 需要解密的数据
	 *  \param[out] out 解密后的数据
	 *  \param[in] w 解密过程中使用的密钥以及扩展密钥
	 *  \return
	 */
	void InvCipher(byte(&in)[4 * Nb], byte(&out)[4 * Nb], word(&w)[Nb*(Nr + 1)]);

	/** \brief 将四个字提取为二维字节数组
	 *  \param[in] w 字数组
	 *  \param[in] b 提取的位置索引
	 *  \param[out] 从b位置开始，连续四个字所组成的二维字节数组
	 *  \return
	 */
	void GetKey(word(&w)[Nb*(Nr + 1)], int b, byte(&key)[4][4]);


};

#endif//__AES_H__

