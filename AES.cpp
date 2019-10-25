#include "AES.h"
#include <string>



word Word(const byte &b1, const byte &b2, const byte &b3, const byte &b4)
{
	std::string s = b1.to_string() + b2.to_string() + b3.to_string() + b4.to_string();
	return word{ s };
}

AES::AES()
{

}

AES::~AES()
{

}

word AES::SubWord(const word& sw)
{
	word temp;
	for (int i = 0; i < 32; i += 8)
	{
		int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
		int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
		byte val = S_Box[row][col];
		for (int j = 0; j < 8; ++j)
			temp[i + j] = val[j];
	}
	return temp;
}


word AES::RotWord(const word &wd)
{
	word high_bytes = wd << 8;
	word low_byte = wd >> 24;
	return (high_bytes | low_byte);
}


void AES::KeyExpansion(byte(&key)[4 * Nk], word(&w)[Nb*(Nr + 1)])
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
