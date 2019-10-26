/********************************************************************************************
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
 *******************************************************************************************/
#include "AES.h"
#include <string>


word Word(const byte &b1, const byte &b2, const byte &b3, const byte &b4)
{
	std::string s = b1.to_string() + b2.to_string() + b3.to_string() + b4.to_string();
	return word{ s };
}

byte Gadd(byte a, byte b)
{
	return a ^ b;
}

byte Gmult(byte _a, byte _b)
{
	uint8_t a = _a.to_ulong();
	uint8_t b = _b.to_ulong();
	auto time_two = [](uint8_t x) {
		return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
	};

	uint8_t temp[8] = { a };
	uint8_t tempmultiply = 0x00;
	int i = 0;
	for (i = 1; i < 8; i++) {
		temp[i] = time_two(temp[i - 1]);
	}
	tempmultiply = (b & 0x01) * a;
	for (i = 1; i <= 7; i++) {
		tempmultiply ^= (((b >> i) & 0x01) * temp[i]);
	}
	return tempmultiply;
}



AES::AES()
{

}

AES::~AES()
{

}

void AES::Encrypt(byte(&in)[4 * Nb], byte(&out)[4 * Nb], byte(&key)[4 * Nk])
{
	word w[Nb*(Nr + 1)];
	KeyExpansion(key, w);
	Cipher(in, out, w);
}

void AES::InvEncrypt(byte(&in)[4 * Nb], byte(&out)[4 * Nb], byte(&key)[4 * Nk])
{
	word w[Nb*(Nr + 1)];
	KeyExpansion(key, w);
	InvCipher(in, out, w);
}

word AES::SubWord(const word& sw)const
{
	word temp;
	for (int i = 0; i < 32; i += 8)
	{
		int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
		int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
		byte val = s_box[row][col];
		for (int j = 0; j < 8; ++j)
			temp[i + j] = val[j];
	}
	return temp;
}


word AES::RotWord(const word &wd)const
{
	word high_bytes = wd << 8;
	word low_byte = wd >> 24;
	return (high_bytes | low_byte);
}


/*
 * 输入的初始密钥为二维字节输出，扩展后的密钥为一维“字”数组，从初始位置开始，连续相邻的
 * 四个字组成一组密钥，其中每个字代表该组密钥中的一列。
 */
void AES::KeyExpansion(byte(&key)[4 * Nk], word(&w)[Nb*(Nr + 1)])const
{
	word temp;
	int i = 0;
	while (i < Nk)
	{
		w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		i++;
	}
	i = Nk;
	while (i < Nb*(Nr + 1))
	{
		temp = w[i - 1];

		if (i%Nk == 0)
		{
			// Rcon[i], note that i starts at 1, not 0 in fips-197,the standard file
			temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
		}
		else if ((Nk > 6) && (i%Nk == 4))
		{
			temp = SubWord(temp);
		}

		w[i] = w[i - Nk] ^ temp;
		i = i + 1;
	}
}

void AES::SubBytes(byte(&state)[4][Nb])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			uint8_t v = state[i][j].to_ulong();
			uint8_t row = v >> 4;
			uint8_t col = (v & 0xf);
			state[i][j] = byte(s_box[row][col]);
		}
	}
}

void AES::InvSubBytes(byte(&state)[4][Nb])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			uint8_t v = state[i][j].to_ulong();
			uint8_t row = v >> 4;
			uint8_t col = (v & 0xf);
			state[i][j] = byte(inv_s_box[row][col]);
		}
	}
}

void AES::ShiftRows(byte(&state)[4][Nb])
{
	for (int r = 1; r < 4; r++)
	{
		CircleShiftToLeftByBytes(state[r], r);
	}
}

void AES::InvShiftRows(byte(&state)[4][Nb])
{
	for (int r = 1; r < 4; r++)
	{
		CircleShiftToLeftByBytes(state[r], 4 - r);
	}
}

void AES::MixColumns(byte(&state)[4][Nb])
{
	static byte M[4][4] = {
		{0x02,0x03,0x01,0x01},
		{0x01,0x02,0x03,0x01},
		{0x01,0x01,0x02,0x03},
		{0x03,0x01,0x01,0x02},
	};

	byte result[4][4];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			result[i][j] = Gmult(M[i][0], state[0][j]) ^ Gmult(M[i][1], state[1][j]) ^ Gmult(M[i][2], state[2][j]) ^ Gmult(M[i][3], state[3][j]);
		}
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[i][j] = result[i][j];
		}
	}
}

void AES::InvMixColumns(byte(&state)[4][Nb])
{
	static byte M[4][4] = {
		{0x0E,0x0B,0x0D,0x09},
		{0x09,0x0E,0x0B,0x0D},
		{0x0D,0x09,0x0E,0x0B},
		{0x0B,0x0D,0x09,0x0E},
	};

	byte result[4][4];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			result[i][j] = Gmult(M[i][0], state[0][j]) ^ Gmult(M[i][1], state[1][j]) ^ Gmult(M[i][2], state[2][j]) ^ Gmult(M[i][3], state[3][j]);
		}
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[i][j] = result[i][j];
		}
	}
}

void AES::AddRoundKey(byte(&state)[4][4], byte(&key)[4][4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[i][j] = state[i][j] ^ key[i][j];
		}
	}
}

void AES::Cipher(byte(&in)[4 * Nb], byte(&out)[4 * Nb], word(&w)[Nb*(Nr + 1)])
{
	byte state[4][Nb];
	for (int i = 0; i < 4 * Nb; i++)
	{
		state[i % 4][i / 4] = in[i];
	}
#ifdef DEBUG
	std::cout << "input:" << std::endl;
	PrintArray(state);
#endif

	static byte key[4][4];
	GetKey(w, 0, key);
	AddRoundKey(state, key);

#ifdef DEBUG
	std::cout << "Round Key:" << std::endl;
	PrintArray(key);
#endif


	for (int round = 1; round < Nr; round++)
	{
#ifdef DEBUG
		std::cout << "-------------------" << "Round: " << round << "-------------------" << std::endl;
		PrintArray(state);
#endif
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);

		GetKey(w, round*Nb, key); // 更新当前轮的key
		AddRoundKey(state, key);
	}

	SubBytes(state);
	ShiftRows(state);
	GetKey(w, Nr*Nb, key); // 更新当前轮的key
	AddRoundKey(state, key);

	// 输出
	for (int i = 0; i < 4 * Nb; i++)
	{
		out[i] = state[i % 4][i / 4];
	}

}

void AES::InvCipher(byte(&in)[4 * Nb], byte(&out)[4 * Nb], word(&w)[Nb*(Nr + 1)])
{
	byte state[4][Nb];
	for (int i = 0; i < 4 * Nb; i++)
	{
		state[i % 4][i / 4] = in[i];
	}

	static byte key[4][4];

	GetKey(w, Nr*Nb, key);
	AddRoundKey(state, key);

	for (int round = Nr - 1; round >= 1; round--)
	{

		InvShiftRows(state);
		InvSubBytes(state);
		GetKey(w, round*Nb, key);
		AddRoundKey(state, key);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);

	GetKey(w, 0, key);
	AddRoundKey(state, key);

	// 输出
	for (int i = 0; i < 4 * Nb; i++)
	{
		out[i] = state[i % 4][i / 4];
	}

}

void AES::GetKey(word(&w)[Nb*(Nr + 1)], int b, byte(&key)[4][4])
{
	for (int j = 0; j < 4; j++)
	{
		for (int i = 0; i < 4; i++)
		{
			key[i][j] = ExtractByte(w[b + j], i);
		}
	}
}
