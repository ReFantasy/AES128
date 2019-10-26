#include <iostream>

#include "AES.h"
using namespace std;
int main()
{
	AES aes;

	byte in[16] = {
		0x32,0x43,0xf6,0xa8,
		0x88,0x5a,0x30,0x8d,
		0x31,0x31,0x98,0xa2,
		0xe0,0x37,0x07,0x34
	};

	byte key[16] = {
		0x2b,0x7e,0x15,0x16,
		0x28,0xae,0xd2,0xa6,
		0xab,0xf7,0x15,0x88,
		0x09,0xcf,0x4f,0x3c
	};
	byte out[16];

	cout << "明文" << endl;
	PrintArray(in);
	std::cout<<std::endl;

	cout << "密钥" << endl;
	PrintArray(key);
	std::cout << std::endl;

	aes.Encrypt(in, out, key);

	
	cout << "密文" << endl;
	PrintArray(out);
	std::cout << std::endl;


	aes.InvEncrypt(out, out, key);
	cout << "解密后的数据" << endl;
	PrintArray(out);
	std::cout << std::endl;
	

	

	system("pause");
	return 0;
}